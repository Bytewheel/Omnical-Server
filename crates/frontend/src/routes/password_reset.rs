//! Public forgot-/reset-password flow (Omnical extension).
//!
//! The login page links here whenever password login, SMTP and a public URL
//! are configured:
//!
//! 1. `GET /frontend/forgot-password` renders the email form and sets a
//!    session-bound CSRF token.
//! 2. `POST /frontend/forgot-password` is rate-limited and CSRF-checked.
//!    When a principal with a stored password exists for the address, a
//!    single-use 64-char token is minted (only its SHA-256 digest is stored)
//!    and the reset link is emailed through the first `[[scheduling.smtp]]`
//!    account — the same sender the registration and guest-share emails
//!    use. A fresh request supersedes the account's older links.
//! 3. `GET /frontend/reset-password/{token}` renders the new-password form,
//!    or the generic invalid/expired page.
//! 4. `POST /frontend/reset-password/{token}` atomically redeems the token
//!    (single-use; also invalidates every other outstanding link of the
//!    account), stores the new argon2 hash via `update_password` (which
//!    also clears the forced-change nudge) and redirects to the login page.
//!
//! ## Security discipline
//!
//! - Unknown addresses, accounts without a stored password and successful
//!   requests all answer the *same* body — the endpoint is not an account
//!   enumeration oracle.
//! - Unknown / used / expired tokens all answer the same generic page.
//! - The token from the link is the only credential; the stored row keeps
//!   just its SHA-256 digest, so a database leak leaves no working links.
//! - Both POST endpoints share a sliding-window rate limiter (per client IP
//!   plus a global bucket), mirroring the registration flow.

use crate::{FrontendConfig, pages::DefaultLayoutData};
use argon2::password_hash::{PasswordHasher, SaltString, rand_core::OsRng};
use askama::Template;
use askama_web::WebTemplate;
use axum::{
    Extension, Form,
    extract::Path,
    response::{IntoResponse, Redirect, Response},
};
use chrono::{TimeDelta, Utc};
use http::{HeaderMap, StatusCode};
use rand::{RngExt, distr::Alphanumeric};
use rustical_scheduling::{SmtpAccount, mime, smtp};
use rustical_store::{PasswordResetStore, auth::AuthenticationProvider};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tower_sessions::Session;
use tracing::{error, instrument, warn};

/// Generic message shown after a forgot-password POST, whether or not the
/// address has an account (no enumeration oracle).
const RESET_SENT_MSG: &str =
    "If an account with that email address exists, an email with a reset link has been sent.";
/// Generic invalid-/expired-token message: unknown, used and expired tokens
/// are intentionally indistinguishable.
const INVALID_RESET_MSG: &str = "This password reset link is invalid or has expired.";
/// How long an emailed reset link stays usable.
const RESET_TOKEN_EXPIRY_SECS: i64 = 3600;

#[derive(Template, WebTemplate)]
#[template(path = "pages/forgot_password.html")]
pub struct ForgotPasswordPage {
    pub error: Option<String>,
    pub message: Option<String>,
    pub csrf: String,
}

impl DefaultLayoutData for ForgotPasswordPage {
    fn get_user(&self) -> Option<&rustical_store::auth::Principal> {
        None
    }
}

#[derive(Template, WebTemplate)]
#[template(path = "pages/reset_password.html")]
pub struct ResetPasswordPage {
    pub token: String,
    pub csrf: String,
    pub error: Option<String>,
    pub min_password_length: usize,
}

impl DefaultLayoutData for ResetPasswordPage {
    fn get_user(&self) -> Option<&rustical_store::auth::Principal> {
        None
    }
}

#[derive(Template, WebTemplate)]
#[template(path = "pages/password_reset_invalid.html")]
pub struct PasswordResetInvalidPage {
    pub message: String,
}

impl DefaultLayoutData for PasswordResetInvalidPage {
    fn get_user(&self) -> Option<&rustical_store::auth::Principal> {
        None
    }
}

/// Sliding-window rate limiter (one hour) for the reset POSTs, shared by
/// both endpoints (mirror of the registration limiter). The critical
/// sections never cross an `.await`, so the standard mutex is safe.
pub struct ResetRateLimiter {
    window: Duration,
    max_per_ip: usize,
    max_global: usize,
    per_ip: Mutex<HashMap<String, Vec<Instant>>>,
    global: Mutex<Vec<Instant>>,
}

impl Default for ResetRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl ResetRateLimiter {
    /// Per-IP budget: 5/h — each forgot-password POST may trigger one email.
    /// The global bucket (6× the per-IP budget) is a coarse safety net
    /// above the per-IP budget, like the registration limiter.
    #[must_use]
    pub fn new() -> Self {
        Self {
            window: Duration::from_secs(3600),
            max_per_ip: 5,
            max_global: 30,
            per_ip: Mutex::new(HashMap::new()),
            global: Mutex::new(Vec::new()),
        }
    }

    /// Returns `true` if the attempt is allowed, recording it. A rejected
    /// attempt is *not* recorded. Expired entries are pruned opportunistically.
    fn check_and_record(&self, ip: &str, now: Instant) -> bool {
        let Ok(mut buckets) = self.per_ip.lock() else {
            return false;
        };
        let entry = buckets.entry(ip.to_owned()).or_default();
        entry.retain(|at| now.duration_since(*at) < self.window);
        let allowed = entry.len() < self.max_per_ip;
        if allowed {
            entry.push(now);
        }
        if !allowed {
            return false;
        }
        drop(buckets);
        let Ok(mut bucket) = self.global.lock() else {
            return false;
        };
        bucket.retain(|at| now.duration_since(*at) < self.window);
        let allowed = bucket.len() < self.max_global;
        if allowed {
            bucket.push(now);
        }
        allowed
    }
}

/// Whether the forgot-password flow is operational: password login enabled,
/// an SMTP account to send from and a public URL to link back to. The login
/// page only advertises the link while this holds.
pub fn reset_available(
    config: &FrontendConfig,
    smtp_accounts: &[SmtpAccount],
    public_url: &str,
) -> bool {
    config.allow_password_login && !smtp_accounts.is_empty() && !public_url.trim().is_empty()
}

/// GET /frontend/forgot-password — the email form. Fresh CSRF token into the
/// session on every GET.
#[instrument(skip_all)]
pub async fn route_get_forgot_password(
    Extension(config): Extension<FrontendConfig>,
    Extension(smtp_accounts): Extension<Vec<SmtpAccount>>,
    Extension(public_url): Extension<String>,
    session: Session,
) -> Response {
    if !reset_available(&config, &smtp_accounts, &public_url) {
        // Without SMTP (or password login) the flow cannot deliver links —
        // the login page does not advertise it either.
        return Redirect::to("/frontend/login").into_response();
    }
    let csrf = random_token();
    if session.insert("csrf", &csrf).await.is_err() {
        // Tower-sessions failures degrade to a fresh form (session is best
        // effort here); the POST will reject the mismatched token.
        warn!("password reset: could not persist CSRF token");
    }
    ForgotPasswordPage {
        error: None,
        message: None,
        csrf,
    }
    .into_response()
}

#[derive(Debug, Default, serde::Deserialize)]
pub struct ForgotPasswordForm {
    #[serde(default)]
    email: String,
    #[serde(default)]
    csrf: String,
}

/// POST /frontend/forgot-password — rate-limited, CSRF-checked; mints and
/// emails a reset link when the address belongs to an account with a stored
/// password. The response is identical either way (see [`RESET_SENT_MSG`]).
#[allow(clippy::too_many_arguments)]
#[instrument(skip_all)]
pub async fn route_post_forgot_password<AP: AuthenticationProvider>(
    Extension(auth_provider): Extension<Arc<AP>>,
    Extension(config): Extension<FrontendConfig>,
    Extension(reset_store): Extension<Arc<dyn PasswordResetStore>>,
    Extension(smtp_accounts): Extension<Vec<SmtpAccount>>,
    Extension(public_url): Extension<String>,
    Extension(limiter): Extension<Arc<ResetRateLimiter>>,
    headers: HeaderMap,
    session: Session,
    Form(form): Form<ForgotPasswordForm>,
) -> Response {
    if !reset_available(&config, &smtp_accounts, &public_url) {
        return StatusCode::NOT_FOUND.into_response();
    }
    if !limiter.check_and_record(&client_ip(&headers), Instant::now()) {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    }

    let render = |error: Option<String>, message: Option<String>, csrf: String| {
        (
            StatusCode::BAD_REQUEST,
            ForgotPasswordPage {
                error,
                message,
                csrf,
            },
        )
            .into_response()
    };

    if !session
        .get::<String>("csrf")
        .await
        .is_ok_and(|t| t.as_deref() == Some(form.csrf.as_str()))
    {
        let csrf = rotate_csrf(&session).await;
        return render(
            Some("This form has expired. Please load it again.".to_owned()),
            None,
            csrf,
        );
    }

    let email = form.email.trim().to_lowercase();
    if !is_valid_email(&email) {
        let csrf = rotate_csrf(&session).await;
        return render(
            Some("Please enter a valid email address.".to_owned()),
            None,
            csrf,
        );
    }

    // Mint + email only when a principal with a stored password exists —
    // accounts without one (e.g. OIDC-only) have nothing to reset.
    if let Some(principal) = auth_provider
        .get_principal(&email)
        .await
        .ok()
        .flatten()
        .filter(|principal| principal.password.is_some())
        && let Err(err) = mint_and_send(
            &reset_store,
            smtp_accounts.first(),
            &public_url,
            &principal.id,
        )
        .await
    {
        // Logged, but the response stays generic — a store failure must
        // not leak whether the account exists.
        error!(%err, "password reset: could not mint/send token for {}", principal.id);
    }

    let csrf = rotate_csrf(&session).await;
    ForgotPasswordPage {
        error: None,
        message: Some(RESET_SENT_MSG.to_owned()),
        csrf,
    }
    .into_response()
}

/// Mint a single-use token for `email` and email the reset link (fire and
/// forget like the guest-share email: a slow SMTP handshake must not hold
/// the form; failures are logged, never user-facing).
async fn mint_and_send(
    reset_store: &Arc<dyn PasswordResetStore>,
    account: Option<&SmtpAccount>,
    public_url: &str,
    email: &str,
) -> Result<(), rustical_store::Error> {
    let Some(account) = account else {
        // The route gates on SMTP availability; this is unreachable there.
        return Ok(());
    };
    let token = random_token();
    let expires_at = expiry_str();
    reset_store
        .add_reset(&token_hash(&token), email, &expires_at, &now_str())
        .await?;
    let reset_url = format!("{public_url}/frontend/reset-password/{token}");
    let message = mime::build_password_reset(account, email, &reset_url, &expires_at);
    let account = account.clone();
    let to = email.to_owned();
    tokio::spawn(async move {
        match smtp::send_mail(&account, &account.identity, &to, &message).await {
            Ok(()) => tracing::debug!("emailed password reset link to {to}"),
            Err(err) => tracing::warn!("could not email password reset link: {err}"),
        }
    });
    Ok(())
}

/// GET /frontend/reset-password/{token} — the new-password form, or the
/// generic invalid/expired page. (SMTP is not required here: a link minted
/// while it was configured stays redeemable.)
#[instrument(skip_all)]
pub async fn route_get_reset_password(
    Path(token): Path<String>,
    Extension(config): Extension<FrontendConfig>,
    Extension(reset_store): Extension<Arc<dyn PasswordResetStore>>,
    session: Session,
) -> Response {
    if !config.allow_password_login {
        return Redirect::to("/frontend/login").into_response();
    }
    let now = now_str();
    let valid = matches!(
        reset_store.get_reset(&token_hash(&token)).await,
        Ok(Some(reset)) if reset.used_at.is_none() && reset.expires_at > now
    );
    if !valid {
        return PasswordResetInvalidPage {
            message: INVALID_RESET_MSG.to_owned(),
        }
        .into_response();
    }
    let csrf = random_token();
    if session.insert("csrf", &csrf).await.is_err() {
        warn!("password reset: could not persist CSRF token");
    }
    ResetPasswordPage {
        token,
        csrf,
        error: None,
        min_password_length: config.min_password_length,
    }
    .into_response()
}

#[derive(Debug, Default, serde::Deserialize)]
pub struct ResetPasswordForm {
    #[serde(default)]
    password: String,
    #[serde(default)]
    password_confirm: String,
    #[serde(default)]
    csrf: String,
}

/// POST /frontend/reset-password/{token} — validate, atomically redeem the
/// single-use token, store the new argon2 hash and redirect to the login
/// page (`update_password` also clears the forced-change nudge).
#[allow(clippy::too_many_arguments)]
#[instrument(skip_all)]
pub async fn route_post_reset_password<AP: AuthenticationProvider>(
    Path(token): Path<String>,
    Extension(auth_provider): Extension<Arc<AP>>,
    Extension(config): Extension<FrontendConfig>,
    Extension(reset_store): Extension<Arc<dyn PasswordResetStore>>,
    Extension(limiter): Extension<Arc<ResetRateLimiter>>,
    headers: HeaderMap,
    session: Session,
    Form(form): Form<ResetPasswordForm>,
) -> Response {
    if !config.allow_password_login {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    }
    if !limiter.check_and_record(&client_ip(&headers), Instant::now()) {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    }

    let render_error = |message: String, csrf: String| {
        (
            StatusCode::BAD_REQUEST,
            ResetPasswordPage {
                token: token.clone(),
                csrf,
                error: Some(message),
                min_password_length: config.min_password_length,
            },
        )
            .into_response()
    };

    if !session
        .get::<String>("csrf")
        .await
        .is_ok_and(|t| t.as_deref() == Some(form.csrf.as_str()))
    {
        let csrf = rotate_csrf(&session).await;
        return render_error(
            "This form has expired. Please load it again.".to_owned(),
            csrf,
        );
    }
    if form.password.len() < config.min_password_length {
        let csrf = rotate_csrf(&session).await;
        return render_error(
            format!(
                "Password must be at least {} characters.",
                config.min_password_length
            ),
            csrf,
        );
    }
    if form.password != form.password_confirm {
        let csrf = rotate_csrf(&session).await;
        return render_error("The passwords do not match.".to_owned(), csrf);
    }

    // Atomic commit point: only one concurrent redemption of the same link
    // can succeed, and success also invalidates the account's other links.
    let reset = match reset_store
        .redeem_reset(&token_hash(&token), &now_str())
        .await
    {
        Ok(reset) => reset,
        Err(rustical_store::Error::NotFound) => {
            // Unknown, already used or expired — one generic page.
            return PasswordResetInvalidPage {
                message: INVALID_RESET_MSG.to_owned(),
            }
            .into_response();
        }
        Err(err) => {
            error!(%err, "password reset: redemption failed");
            return PasswordResetInvalidPage {
                message: "Something went wrong. Please request a new reset link.".to_owned(),
            }
            .into_response();
        }
    };

    let salt = SaltString::generate(OsRng);
    let password_hash = argon2::Argon2::default()
        .hash_password(form.password.as_bytes(), &salt)
        .expect("argon2 hashing cannot fail for valid parameters")
        .to_string();
    if let Err(err) = auth_provider
        .update_password(&reset.principal_id, &password_hash)
        .await
    {
        // The token is spent — the account needs a fresh link either way.
        error!(%err, "password reset: update_password failed for {}", reset.principal_id);
        return PasswordResetInvalidPage {
            message: "Something went wrong while saving the new password. Please request a \
                      new reset link."
                .to_owned(),
        }
        .into_response();
    }

    tracing::info!(user = %reset.principal_id, "password reset via emailed link");
    Redirect::to("/frontend/login").into_response()
}

/// Replace the session CSRF token and return the fresh value (the response
/// pages re-render a form that must keep working).
async fn rotate_csrf(session: &Session) -> String {
    let csrf = random_token();
    if session.insert("csrf", &csrf).await.is_err() {
        warn!("password reset: could not persist CSRF token");
    }
    csrf
}

/// Client IP for the rate limiter: first hop of `X-Forwarded-For` (set by
/// the TLS tunnel in front of production), "<global>" otherwise.
fn client_ip(headers: &HeaderMap) -> String {
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("<global>")
        .to_owned()
}

fn random_token() -> String {
    rand::rng()
        .sample_iter(Alphanumeric)
        .map(char::from)
        .take(64)
        .collect()
}

/// SHA-256 hex digest of a token — the only form ever stored.
fn token_hash(token: &str) -> String {
    use sha2::Digest as _;
    hex::encode(sha2::Sha256::digest(token.as_bytes()))
}

fn now_str() -> String {
    Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

fn expiry_str() -> String {
    (Utc::now() + TimeDelta::seconds(RESET_TOKEN_EXPIRY_SECS))
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string()
}

fn is_valid_email(email: &str) -> bool {
    let Some((local, domain)) = email.split_once('@') else {
        return false;
    };
    !local.is_empty() && !domain.is_empty() && domain.contains('.') && !email.contains(' ')
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frontend_router;
    use axum::body::Body as AxBody;
    use http::{Request, header::SET_COOKIE};
    use rustical_store::{
        CalendarSourceStore, CollectionShareStore, InviteStore, Secret, SubscriptionStore,
        auth::{Principal, PrincipalType},
    };
    use rustical_store_sqlite::{
        SqliteAddressbookStore, SqliteCalendarSourceStore, SqliteCalendarStore,
        SqliteCollectionShareStore, SqliteInviteStore, SqlitePasswordResetStore,
        SqlitePrincipalStore, SqliteSubscriptionStore, create_db_pool,
    };
    use tower::ServiceExt;
    use tower_sessions::{MemoryStore, SessionManagerLayer};

    struct TestRig {
        router: axum::Router,
        principal_store: Arc<SqlitePrincipalStore>,
        reset_store: Arc<SqlitePasswordResetStore>,
        db: sqlx::SqlitePool,
        session_cookie: std::sync::Mutex<Option<String>>,
        csrf: std::sync::Mutex<String>,
    }

    impl TestRig {
        async fn new() -> Self {
            Self::new_with_smtp(vec![SmtpAccount {
                identity: "sender@example.com".to_owned(),
                host: "smtp.example.com".to_owned(),
                port: 587,
                username: "sender".to_owned(),
                password: "secret".to_owned(),
                displayname: None,
            }])
            .await
        }

        async fn new_with_smtp(smtp_accounts: Vec<SmtpAccount>) -> Self {
            let db = create_db_pool(":memory:", true).await.unwrap();
            let (send, _recv) = tokio::sync::mpsc::channel(1000);
            let addr_store = Arc::new(SqliteAddressbookStore::new(db.clone(), send.clone(), false));
            let cal_store = SqliteCalendarStore::new(db.clone(), send, false);
            let principal_store = Arc::new(SqlitePrincipalStore::new(db.clone()));
            let reset_store = Arc::new(SqlitePasswordResetStore::new(cal_store.clone()));
            let reset_store_dyn: Arc<dyn PasswordResetStore> = reset_store.clone();
            let invite_store: Arc<dyn InviteStore> =
                Arc::new(SqliteInviteStore::new(cal_store.clone()));
            let source_store: Arc<dyn CalendarSourceStore> =
                Arc::new(SqliteCalendarSourceStore::new(cal_store.clone()));
            let share_store: Arc<dyn CollectionShareStore> =
                Arc::new(SqliteCollectionShareStore::new(cal_store.clone()));
            let sub_store: Arc<dyn SubscriptionStore> =
                Arc::new(SqliteSubscriptionStore::new(cal_store.clone()));

            let router = frontend_router(
                "/frontend",
                principal_store.clone(),
                Arc::new(cal_store),
                addr_store,
                FrontendConfig::default(),
                None,
                Some(sub_store),
                source_store,
                "https://cal.example.com:8443".to_owned(),
                invite_store,
                share_store,
                reset_store_dyn,
                smtp_accounts,
            )
            .layer(
                SessionManagerLayer::new(MemoryStore::default())
                    .with_name("rustical_session")
                    .with_secure(true),
            );

            Self {
                router,
                principal_store,
                reset_store,
                db,
                session_cookie: std::sync::Mutex::new(None),
                csrf: std::sync::Mutex::new(String::new()),
            }
        }

        async fn get_form(&self, path: &str) {
            let req = Request::get(path).body(AxBody::empty()).unwrap();
            let resp = self.router.clone().oneshot(req).await.unwrap();
            assert_eq!(resp.status(), StatusCode::OK, "GET {path}");
            let (parts, body) = resp.into_parts();
            let html = body_to_string(body).await;
            for value in &parts.headers.get_all(SET_COOKIE) {
                let value = value.to_str().unwrap();
                if let Some(rest) = value.strip_prefix("rustical_session=") {
                    let id = rest.split(';').next().unwrap();
                    *self.session_cookie.lock().unwrap() = Some(format!("rustical_session={id}"));
                }
            }
            let token = html.split("name=\"csrf\" value=\"").nth(1).unwrap();
            *self.csrf.lock().unwrap() = token.split('"').next().unwrap().to_owned();
        }

        async fn get(&self, path: &str) -> (StatusCode, String) {
            let req = Request::get(path).body(AxBody::empty()).unwrap();
            let resp = self.router.clone().oneshot(req).await.unwrap();
            let status = resp.status();
            let (_, body) = resp.into_parts();
            (status, body_to_string(body).await)
        }

        async fn post(&self, path: &str, fields: &[(&str, &str)]) -> Response {
            let csrf = self.csrf.lock().unwrap().clone();
            let mut pairs = vec![("csrf", csrf.as_str())];
            pairs.extend_from_slice(fields);
            let body = pairs
                .iter()
                .map(|(k, v)| format!("{}={}", k, urlencode(v)))
                .collect::<Vec<_>>()
                .join("&");
            let mut req = Request::post(path)
                .header("content-type", "application/x-www-form-urlencoded")
                .header("host", "127.0.0.1:4000")
                .header("x-forwarded-for", "203.0.113.7")
                .body(AxBody::from(body))
                .unwrap();
            if let Some(cookie) = self.session_cookie.lock().unwrap().as_deref() {
                req.headers_mut()
                    .insert(http::header::COOKIE, cookie.parse().unwrap());
            }
            self.router.clone().oneshot(req).await.unwrap()
        }

        async fn post_status(&self, path: &str, fields: &[(&str, &str)]) -> (StatusCode, String) {
            let resp = self.post(path, fields).await;
            let status = resp.status();
            let (_, body) = resp.into_parts();
            (status, body_to_string(body).await)
        }

        /// (total, unused) rows in the `password_resets` table.
        async fn reset_rows(&self) -> (i64, i64) {
            let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM password_resets")
                .fetch_one(&self.db)
                .await
                .unwrap();
            let unused: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM password_resets WHERE used_at IS NULL")
                    .fetch_one(&self.db)
                    .await
                    .unwrap();
            (total, unused)
        }

        async fn insert_principal(&self, email: &str, password: Option<String>) {
            self.principal_store
                .insert_principal(
                    Principal {
                        id: email.to_owned(),
                        displayname: None,
                        principal_type: PrincipalType::default(),
                        password: password.map(Secret::from),
                        memberships: vec![],
                        needs_password_change: false,
                        privileges: std::collections::BTreeMap::new(),
                    },
                    false,
                )
                .await
                .unwrap();
        }

        /// Mint a reset row directly through the store (the handler path
        /// emails, which tests cannot intercept).
        async fn mint_reset(&self, email: &str, expires_at: &str) -> String {
            let token = random_token();
            self.reset_store
                .add_reset(&token_hash(&token), email, expires_at, &now_str())
                .await
                .unwrap();
            token
        }
    }

    async fn body_to_string(body: AxBody) -> String {
        let bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    fn urlencode(s: &str) -> String {
        let mut out = String::new();
        for b in s.bytes() {
            match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                    out.push(char::from(b));
                }
                b' ' => out.push('+'),
                _ => {
                    use std::fmt::Write as _;
                    write!(out, "%{b:02X}").unwrap();
                }
            }
        }
        out
    }

    /// The per-request CSRF value differs between responses; normalize it
    /// so bodies can be compared byte-for-byte.
    fn normalize_csrf(html: &str) -> String {
        let value = html
            .split("name=\"csrf\" value=\"")
            .nth(1)
            .and_then(|rest| rest.split('"').next())
            .unwrap_or_default();
        html.replace(value, "<csrf>")
    }

    fn argon2_hash(password: &str) -> String {
        argon2::Argon2::default()
            .hash_password(
                password.as_bytes(),
                &SaltString::generate(argon2::password_hash::rand_core::OsRng),
            )
            .unwrap()
            .to_string()
    }

    fn future_expiry() -> String {
        (Utc::now() + TimeDelta::hours(1))
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string()
    }

    fn past_expiry() -> String {
        (Utc::now() - TimeDelta::hours(1))
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string()
    }

    #[tokio::test]
    async fn login_page_links_forgot_password_only_when_operational() {
        let rig = TestRig::new().await;
        let (status, body) = rig.get("/frontend/login").await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            body.contains("href=\"/frontend/forgot-password\""),
            "{body}"
        );

        // Without SMTP the flow cannot deliver links: no link on the login
        // page, and the form itself bounces back to the login page.
        let rig = TestRig::new_with_smtp(vec![]).await;
        let (_, body) = rig.get("/frontend/login").await;
        assert!(!body.contains("/frontend/forgot-password"), "{body}");
        let (status, _) = rig.get("/frontend/forgot-password").await;
        assert_eq!(status, StatusCode::SEE_OTHER);
    }

    #[tokio::test]
    async fn forgot_password_is_generic_for_unknown_email() {
        let rig = TestRig::new().await;
        rig.get_form("/frontend/forgot-password").await;
        let (status, body) = rig
            .post_status(
                "/frontend/forgot-password",
                &[("email", "nobody@example.com")],
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(body.contains(RESET_SENT_MSG), "{body}");
        assert_eq!(rig.reset_rows().await, (0, 0));
    }

    #[tokio::test]
    async fn forgot_password_mints_and_supersedes_without_enumeration() {
        let rig = TestRig::new().await;
        rig.insert_principal("user@example.com", Some("argon2$hash".to_owned()))
            .await;

        rig.get_form("/frontend/forgot-password").await;
        let known = rig
            .post_status(
                "/frontend/forgot-password",
                &[("email", "user@example.com")],
            )
            .await;
        assert_eq!(known.0, StatusCode::OK, "{}", known.1);
        assert!(known.1.contains(RESET_SENT_MSG));
        assert_eq!(rig.reset_rows().await, (1, 1));

        // A second request supersedes the first link (only one outstanding).
        rig.get_form("/frontend/forgot-password").await;
        let second = rig
            .post_status(
                "/frontend/forgot-password",
                &[("email", "USER@EXAMPLE.COM")],
            )
            .await;
        assert_eq!(second.0, StatusCode::OK);
        assert_eq!(rig.reset_rows().await, (2, 1));

        // Known and unknown addresses answer byte-identical bodies.
        rig.get_form("/frontend/forgot-password").await;
        let unknown = rig
            .post_status(
                "/frontend/forgot-password",
                &[("email", "stranger@example.com")],
            )
            .await;
        assert_eq!(unknown.0, StatusCode::OK);
        assert_eq!(
            normalize_csrf(&known.1),
            normalize_csrf(&unknown.1),
            "responses must not reveal whether the account exists"
        );
    }

    #[tokio::test]
    async fn reset_flow_rotates_password() {
        let rig = TestRig::new().await;
        rig.insert_principal(
            "user@example.com",
            Some(argon2_hash("old horse battery staple")),
        )
        .await;
        let token = rig.mint_reset("user@example.com", &future_expiry()).await;

        // The form renders for a valid token.
        rig.get_form(&format!("/frontend/reset-password/{token}"))
            .await;
        let (status, body) = rig
            .post_status(
                &format!("/frontend/reset-password/{token}"),
                &[
                    ("password", "correct horse battery staple"),
                    ("password_confirm", "correct horse battery staple"),
                ],
            )
            .await;
        assert_eq!(status, StatusCode::SEE_OTHER, "{body}");

        // The new password verifies, the old one does not.
        assert!(
            rig.principal_store
                .validate_password("user@example.com", "correct horse battery staple")
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            rig.principal_store
                .validate_password("user@example.com", "old horse battery staple")
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(rig.reset_rows().await, (1, 0));

        // The link is single-use: a second POST answers the generic page.
        rig.get_form("/frontend/forgot-password").await;
        let (status, body) = rig
            .post_status(
                &format!("/frontend/reset-password/{token}"),
                &[
                    ("password", "another horse battery staple"),
                    ("password_confirm", "another horse battery staple"),
                ],
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(body.contains(INVALID_RESET_MSG), "{body}");
        // ... and it did not change the password again.
        assert!(
            rig.principal_store
                .validate_password("user@example.com", "correct horse battery staple")
                .await
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn unknown_used_expired_tokens_share_one_body() {
        let rig = TestRig::new().await;
        let mut bodies = std::collections::HashSet::new();

        // Unknown token.
        let (status, body) = rig.get("/frontend/reset-password/unknown64").await;
        assert_eq!(status, StatusCode::OK, "{body}");
        bodies.insert(body);

        // Used token.
        let used = rig.mint_reset("user@example.com", &future_expiry()).await;
        rig.reset_store
            .redeem_reset(&token_hash(&used), &now_str())
            .await
            .unwrap();
        let (status, body) = rig.get(&format!("/frontend/reset-password/{used}")).await;
        assert_eq!(status, StatusCode::OK);
        bodies.insert(body);

        // Expired token.
        let expired = rig.mint_reset("user@example.com", &past_expiry()).await;
        let (status, body) = rig
            .get(&format!("/frontend/reset-password/{expired}"))
            .await;
        assert_eq!(status, StatusCode::OK);
        bodies.insert(body);

        assert_eq!(bodies.len(), 1, "bodies must not differ: {bodies:?}");
        assert!(bodies.iter().next().unwrap().contains(INVALID_RESET_MSG));
    }

    #[tokio::test]
    async fn reset_rejects_short_and_mismatched_without_consuming() {
        let rig = TestRig::new().await;
        let token = rig.mint_reset("user@example.com", &future_expiry()).await;
        let path = format!("/frontend/reset-password/{token}");

        for (pw, confirm, expected) in [
            ("short", "short", "at least 12"),
            (
                "correct horse battery staple",
                "different passphrase",
                "do not match",
            ),
        ] {
            rig.get_form(&path).await;
            let (status, body) = rig
                .post_status(&path, &[("password", pw), ("password_confirm", confirm)])
                .await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
            assert!(body.contains(expected), "{expected}: {body}");
        }
        // Validation failures never consume the token.
        assert_eq!(rig.reset_rows().await, (1, 1));
    }

    #[tokio::test]
    async fn forgot_password_requires_csrf() {
        let rig = TestRig::new().await;
        // No GET: empty csrf, none stored in session.
        let (status, body) = rig
            .post_status("/frontend/forgot-password", &[("email", "a@b.cd")])
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert!(body.contains("expired"), "{body}");
        assert_eq!(rig.reset_rows().await, (0, 0));
    }

    #[tokio::test]
    async fn rate_limit_is_shared_by_both_endpoints() {
        let rig = TestRig::new().await;
        // Burn the per-IP budget (5/h) across both endpoints: 5 attempts are
        // allowed, the 6th is rejected no matter which endpoint it hits
        // (rejected attempts are not recorded).
        for i in 0..3 {
            let resp = rig
                .post("/frontend/forgot-password", &[("email", "a@b.cd")])
                .await;
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "forgot {i}");
        }
        for i in 0..2 {
            let resp = rig
                .post("/frontend/reset-password/whatever", &[("password", "x")])
                .await;
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "reset {i}");
        }
        let resp = rig
            .post("/frontend/forgot-password", &[("email", "a@b.cd")])
            .await;
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        let resp = rig
            .post("/frontend/reset-password/whatever", &[("password", "x")])
            .await;
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    }
}
