//! Public self-service registration (Omnical extension, PLAN.md §17.8).
//!
//! A single-use invitation code (issued by `rustical invites`) is the gate to
//! creating an account. The flow:
//!
//! 1. `GET /register` renders a form and sets a session-bound CSRF token.
//! 2. `POST /register`:
//!    - rate limit, CSRF, email shape, duplicate-account, password
//!      strength/confirmation, then a non-consuming invite pre-check
//!      (`get_invite`) so the *kind* of failure can be told apart;
//!    - the **atomic redemption** (`redeem_invite`) is the commit point — the
//!      single-use code is consumed before any account data is written, so two
//!      concurrent registrations with the same code yield exactly one account;
//!    - provisioning: principal (argon2), optional group membership, app
//!      tokens, seed collections, share feeds (PLAN.md §17.8.2);
//!    - the new user is auto-logged-in (session `user`) and a success card
//!      shows the credentials — the only time they are ever displayed.
//!
//! ## Security discipline
//!
//! - The router is only mounted while `[registration] enabled = true`; a
//!   disabled config has zero footprint.
//! - Unknown / used / expired codes all answer the *same* body
//!   ([`INVALID_INVITE_MSG`]), and that outcome is decided without leaking
//!   whether the code exists. The pre-checks distinguish only the
//!   easy-doesn't-matter email-binding case from the generic one.
//! - Attempts are rate-limited per client IP (first hop of `X-Forwarded-For`,
//!   set by the TLS tunnel in front of production) plus a larger global
//!   bucket, both sliding one-hour windows.
//! - POST is CSRF-protected by a session-bound token, so a cross-site form
//!   cannot mint accounts on behalf of a logged-in browser.
//! - The pages are self-contained inline HTML (no askama in the binary
//!   crate); the form is minimal and does not need the frontend's styles.

use crate::config::RegistrationConfig;
use argon2::password_hash::{PasswordHasher, SaltString, rand_core::OsRng};
use axum::Router;
use axum::extract::{Form, State};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::get;
use axum_extra::TypedHeader;
use chrono::Utc;
use headers::Host;
use http::HeaderMap;
use http::StatusCode;
use rand::{RngExt, distr::Alphanumeric};
use rustical_ical::{CalendarObject, CalendarObjectType};
use rustical_store::{
    Addressbook, AddressbookStore, Calendar, CalendarMetadata, CalendarStore, Error as StoreError,
    InviteStore, Secret, SubscriptionKind, SubscriptionStore,
    auth::{AuthenticationProvider, Principal, PrincipalType},
};
use std::collections::HashMap;
use std::fmt::Write as _;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tower_sessions::Session;
use tracing::{error, instrument, warn};

/// Generic invalid-/expired-code message: unknown, used, and expired codes
/// are intentionally indistinguishable.
const INVALID_INVITE_MSG: &str = "Invalid or expired invitation code.";
/// The one non-generic invite outcome: the code was bound to a different
/// email (this leaks nothing an attacker does not already know).
const INVALID_INVITE_EMAIL_MSG: &str = "That invitation code is for a different email address.";

/// Everything a `/register` mount needs. Built by `cmd_serve` only while
/// `config.registration.enabled`, so a disabled config never constructs it.
pub struct RegistrationContext {
    pub config: RegistrationConfig,
    pub invite_store: Arc<dyn InviteStore>,
    /// `Some` only while `[subscriptions] enabled` — share feeds are only
    /// created (and served) then.
    pub subscription_store: Option<Arc<dyn SubscriptionStore>>,
    pub subscriptions_public_url: Option<String>,
}

pub struct RegisterState<AS, CS> {
    context: Arc<RegistrationContext>,
    addr_store: Arc<AS>,
    cal_store: Arc<CS>,
    auth_provider: Arc<dyn AuthenticationProvider>,
    limiter: Arc<RateLimiter>,
    /// `[tenancy] trusted_proxies`, parsed (C5, §7.3.4). Empty means no peer's
    /// `X-Forwarded-For` is believed.
    trusted_proxies: Vec<rustical_frontend::client_ip::IpNet>,
}

// Manual `Clone` without store bounds, mirroring `ExportState`.
impl<AS, CS> Clone for RegisterState<AS, CS> {
    fn clone(&self) -> Self {
        Self {
            context: Arc::clone(&self.context),
            addr_store: Arc::clone(&self.addr_store),
            cal_store: Arc::clone(&self.cal_store),
            auth_provider: Arc::clone(&self.auth_provider),
            limiter: Arc::clone(&self.limiter),
            // A `Vec` of four-ish `IpNet`s, cloned per router clone. A
            // `TenancyAwareApp` is cloned per request on the single-tenant path,
            // so this is the cost of doing it here instead of in an
            // `Arc<[...]>` — and an `Arc` would be a second indirection to
            // avoid a four-element copy that a lock-free read of a shared
            // list would not avoid anyway.
            trusted_proxies: self.trusted_proxies.clone(),
        }
    }
}

/// Sliding-window rate limiter (one hour) backed by `std::sync::Mutex`. The
/// critical sections never cross an `.await`, so the standard mutex is safe.
struct RateLimiter {
    window: Duration,
    max_per_ip: usize,
    max_global: usize,
    per_ip: Mutex<HashMap<String, Vec<Instant>>>,
    global: Mutex<Vec<Instant>>,
}

impl RateLimiter {
    fn new(per_ip_limit: u32) -> Self {
        // The global bucket is a coarse safety net above the per-IP budget.
        Self {
            window: Duration::from_secs(3600),
            max_per_ip: per_ip_limit as usize,
            max_global: (per_ip_limit as usize).saturating_mul(6),
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

/// Build the unauthenticated registration router. Mounted OUTSIDE the DAV
/// `AuthenticationLayer` (like `export_router`); `SessionManagerLayer` is
/// applied by `make_app` to the whole router.
pub fn register_router<AS: AddressbookStore, CS: CalendarStore>(
    addr_store: Arc<AS>,
    cal_store: Arc<CS>,
    auth_provider: Arc<dyn AuthenticationProvider>,
    context: Arc<RegistrationContext>,
    // C5, §7.3.4. In the **state**, next to the limiter it keys, rather than as
    // a separate `Extension`: a limiter and the list of peers that decides what
    // "per-IP" means are one fact, and splitting them across two injectors is a
    // way for a future change to wire one without the other.
    trusted_proxies: Vec<rustical_frontend::client_ip::IpNet>,
) -> Router {
    let limiter = Arc::new(RateLimiter::new(context.config.rate_limit_per_hour));
    Router::new()
        .route(
            "/register",
            get(route_get_register).post(route_post_register::<AS, CS>),
        )
        .with_state(RegisterState {
            context,
            addr_store,
            cal_store,
            auth_provider,
            limiter,
            trusted_proxies,
        })
}

/// The public registration form. Fresh CSRF token into the session on every
/// GET; an already-logged-in visitor is bounced to their account page.
#[instrument(skip(state, session))]
async fn route_get_register<AS: AddressbookStore, CS: CalendarStore>(
    State(state): State<RegisterState<AS, CS>>,
    session: Session,
) -> Response {
    if let Ok(Some(user)) = session.get::<String>("user").await {
        return Redirect::to(&format!("/frontend/user/{user}")).into_response();
    }
    let csrf = random_token();
    if session.insert("csrf", &csrf).await.is_err() {
        // Tower-sessions failures degrade to a fresh form (session is best
        // effort here); the POST will reject the mismatched token.
        warn!("registration: could not persist CSRF token");
    }
    render_form(
        None,
        &RegisterFormFieldValues::default(),
        &state.context.config,
        &csrf,
    )
    .into_response()
}

#[derive(Debug, Default, serde::Deserialize)]
pub struct RegisterForm {
    #[serde(default)]
    email: String,
    #[serde(default)]
    displayname: String,
    #[serde(default)]
    password: String,
    #[serde(default)]
    password_confirm: String,
    #[serde(default)]
    invite: String,
    #[serde(default)]
    csrf: String,
}

/// Echo back the submitted values on validation errors (except secrets).
#[derive(Default)]
struct RegisterFormFieldValues<'a> {
    email: &'a str,
    displayname: &'a str,
}

#[derive(Debug)]
enum FormError {
    Render { message: String },
}

impl FormError {
    fn render(message: impl Into<String>) -> Self {
        Self::Render {
            message: message.into(),
        }
    }
}

#[instrument(skip(state, session))]
async fn route_post_register<AS: AddressbookStore, CS: CalendarStore>(
    State(state): State<RegisterState<AS, CS>>,
    session: Session,
    TypedHeader(host): TypedHeader<Host>,
    // C5, §7.3.4: the immediate peer, and the proxy trust list.
    rustical_frontend::client_ip::PeerAddr(peer): rustical_frontend::client_ip::PeerAddr,
    headers: HeaderMap,
    Form(form): Form<RegisterForm>,
) -> Response {
    // C5, §7.3.4. The old code took the **first** hop of `X-Forwarded-For`
    // unconditionally, which meant that behind a reverse proxy a client could
    // pick a fresh address per request and walk straight through the
    // per-IP limit — and this endpoint mints accounts.
    //
    // Now the header is believed only if the immediate peer is in
    // `[tenancy] trusted_proxies`, and even then only up to the first hop that
    // is not itself one of ours.
    rustical_frontend::client_ip::warn_once_if_header_ignored(
        &headers,
        peer,
        &state.trusted_proxies,
    );
    let client_ip = rustical_frontend::client_ip::client_ip(peer, &headers, &state.trusted_proxies);
    if !state.limiter.check_and_record(&client_ip, Instant::now()) {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    }

    let email = form.email.trim().to_lowercase();
    let displayname = form.displayname.trim();
    let values = RegisterFormFieldValues {
        email: &email,
        displayname,
    };

    if let Err(err) = validate(&state, &session, &form, &email).await {
        let FormError::Render { message } = err;
        return (
            StatusCode::BAD_REQUEST,
            render_form(Some(&message), &values, &state.context.config, &form.csrf),
        )
            .into_response();
    }

    provision(
        state,
        session,
        &email,
        displayname,
        &form.password,
        &host.to_string(),
        &form.invite,
    )
    .await
    .into_response()
}

/// Run every check that can produce a user-facing message. The invite is
/// only *read* here (code exists / used / expired / email-bound); the atomic
/// consumption happens in `provision`.
async fn validate<AS: AddressbookStore, CS: CalendarStore>(
    state: &RegisterState<AS, CS>,
    session: &Session,
    form: &RegisterForm,
    email: &str,
) -> Result<(), FormError> {
    if !is_valid_email(email) || email.contains(':') || email.contains('$') {
        return Err(FormError::render("Please enter a valid email address."));
    }

    let already_exists = state
        .auth_provider
        .get_principal(email)
        .await
        .is_ok_and(|p| p.is_some());

    // For existing users with a group invite, skip all other checks — just
    // join the group.
    if already_exists && state.context.config.invite_required {
        let now = now_str();
        if let Ok(Some(invite)) = state
            .context
            .invite_store
            .get_invite(form.invite.trim())
            .await
        {
            if invite.used_by.is_none()
                && invite
                    .expires_at
                    .as_deref()
                    .is_none_or(|at| at > now.as_str())
                && invite.target_group.is_some()
            {
                // Email binding check
                if let Some(target) = invite.target_email.as_deref() {
                    if target != email {
                        return Err(FormError::render(INVALID_INVITE_EMAIL_MSG));
                    }
                }
                return Ok(());
            }
        }
    }

    if already_exists {
        return Err(FormError::render(
            "An account with that email address already exists.",
        ));
    }

    if form.password.len() < state.context.config.min_password_length {
        return Err(FormError::render(format!(
            "Password must be at least {} characters.",
            state.context.config.min_password_length
        )));
    }
    if form.password != form.password_confirm {
        return Err(FormError::render("Passwords do not match."));
    }

    if !session
        .get::<String>("csrf")
        .await
        .is_ok_and(|t| t.as_deref() == Some(form.csrf.as_str()))
    {
        return Err(FormError::render(
            "This form has expired. Please load it again.",
        ));
    }

    if state.context.config.invite_required {
        let now = now_str();
        match state
            .context
            .invite_store
            .get_invite(form.invite.trim())
            .await
        {
            Ok(Some(invite)) => {
                if invite.used_by.is_some() {
                    return Err(FormError::render(INVALID_INVITE_MSG));
                }
                if invite
                    .expires_at
                    .as_deref()
                    .is_some_and(|at| at <= now.as_str())
                {
                    return Err(FormError::render(INVALID_INVITE_MSG));
                }
                if let Some(target) = invite.target_email.as_deref()
                    && target != email
                {
                    return Err(FormError::render(INVALID_INVITE_EMAIL_MSG));
                }
            }
            // Unknown code (or store error): identical body to used/expired —
            // no oracle.
            Ok(None) | Err(_) => return Err(FormError::render(INVALID_INVITE_MSG)),
        }
    }

    Ok(())
}

#[allow(clippy::missing_panics_doc, clippy::too_many_lines)]
async fn provision<AS: AddressbookStore, CS: CalendarStore>(
    state: RegisterState<AS, CS>,
    session: Session,
    email: &str,
    displayname: &str,
    password: &str,
    host: &str,
    invite_code: &str,
) -> Response {
    // Atomic commit point: only one concurrent redemption of the same code
    // can succeed. Everything written after this failing is a burned code by
    // design (PLAN.md §17.8.2) — admins reissue via `invites create`.
    let mut target_group: Option<String> = None;
    if state.context.config.invite_required {
        let now = now_str();
        // Look up the invite to get the target group before redemption
        // (the invite row is needed for group assignment).
        let invite = state
            .context
            .invite_store
            .get_invite(invite_code.trim())
            .await
            .ok()
            .flatten();
        target_group = invite.and_then(|i| i.target_group);
        if let Err(err) = state
            .context
            .invite_store
            .redeem_invite(invite_code.trim(), email, &now)
            .await
        {
            return match err {
                StoreError::NotFound => (
                    StatusCode::BAD_REQUEST,
                    render_form(
                        Some(INVALID_INVITE_MSG),
                        &RegisterFormFieldValues { email, displayname },
                        &state.context.config,
                        "",
                    ),
                )
                    .into_response(),
                err => {
                    error!(%err, "registration: invite redemption failed");
                    internal_error()
                }
            };
        }
    }

    // Check if the user already exists (invite-only group join path).
    let existing_user = state
        .auth_provider
        .get_principal(email)
        .await
        .ok()
        .flatten();

    if let Some(_existing) = existing_user {
        // User already exists — just join the target group if set.
        if let Some(group) = &target_group {
            if let Err(err) = state.auth_provider.add_membership(email, group).await {
                error!(%err, "registration: target_group membership failed");
            }
        }
        // Log them in and show success.
        if session.insert("user", email).await.is_err() {
            warn!("registration: session persist failed for {email}");
        }
        return render_existing_user_success(email, displayname, host, &target_group)
            .into_response();
    }

    // Provision the account. The invite is already burned, so a mid-provision
    // failure means the code is gone without an account (admin reissues) —
    // identical to the race outcome.
    let salt = SaltString::generate(OsRng);
    let password_hash = argon2::Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .expect("argon2 hashing cannot fail for valid parameters")
        .to_string();

    let principal = Principal {
        id: email.to_owned(),
        displayname: Some(displayname.to_owned()),
        principal_type: PrincipalType::default(),
        password: Some(Secret::from(password_hash)),
        memberships: vec![],
        needs_password_change: false,
        privileges: Default::default(),
    };
    if let Err(err) = state.auth_provider.insert_principal(principal, false).await {
        // A concurrent registration won the race for the same email.
        if matches!(err, StoreError::AlreadyExists) {
            return (
                StatusCode::BAD_REQUEST,
                render_form(
                    Some("An account with that email address already exists."),
                    &RegisterFormFieldValues { email, displayname },
                    &state.context.config,
                    "",
                ),
            )
                .into_response();
        }
        error!(%err, "registration: principal insert failed");
        return internal_error();
    }

    if !state.context.config.default_group.is_empty()
        && let Err(err) = state
            .auth_provider
            .add_membership(email, &state.context.config.default_group)
            .await
    {
        error!(%err, "registration: group membership failed");
    }

    // Auto-join the invite's target group (grants shared calendar access).
    if let Some(group) = &target_group {
        if let Err(err) = state.auth_provider.add_membership(email, group).await {
            error!(%err, "registration: invite target_group membership failed");
        }
    }

    // The registrant chose their password in this very request, so the
    // first-join password-change nudge must not force them to change it again.
    if let Err(err) = state
        .auth_provider
        .set_needs_password_change(email, false)
        .await
    {
        error!(%err, "registration: needs_password_change clear failed");
    }

    // App tokens (full values shown once on the card).
    let mut app_tokens = Vec::with_capacity(state.context.config.auto_app_tokens.len());
    for name in &state.context.config.auto_app_tokens {
        let token = random_token();
        match state
            .auth_provider
            .add_app_token(email, name.clone(), token.clone())
            .await
        {
            Ok(mut token_id) => {
                token_id.truncate(4);
                app_tokens.push((name.clone(), format!("{token_id}_{token}")));
            }
            Err(err) => error!(%err, "registration: app token {name} failed"),
        }
    }

    // Seed collections (discovery parity, PLAN.md §17.8.2). Shared with
    // `rustical setup` — see `seed_collections`.
    if let Err(err) = seed_collections(&*state.cal_store, &*state.addr_store, email).await {
        error!(%err, "registration: collection seeding failed");
        return internal_error();
    }

    // Auto share feed for `personal`.
    let mut feeds = Vec::new();
    if state.context.config.auto_subscription
        && let Some(sub_store) = state.context.subscription_store.as_ref()
    {
        if let Some(base) = state.context.subscriptions_public_url.as_deref() {
            for (kind, label, extension) in [
                (SubscriptionKind::Calendar, "Personal calendar", "ics"),
                (SubscriptionKind::Addressbook, "Personal addressbook", "vcf"),
            ] {
                let token = random_token();
                match sub_store
                    .add_subscription(email, kind, "personal", &token)
                    .await
                {
                    Ok(_) => feeds.push((
                        label.to_owned(),
                        format!("{base}/export/{token}.{extension}"),
                    )),
                    Err(err) => {
                        error!(%err, "registration: share feed {extension} failed");
                    }
                }
            }
        } else {
            warn!("registration: auto share feed skipped (no [subscriptions] public_url)");
        }
    }

    // Auto-login: the new user lands in their portal.
    if session.insert("user", email).await.is_err() {
        warn!("registration: session persist failed for {email}");
    }

    render_success(email, displayname, host, &app_tokens, &feeds).into_response()
}

/// Create the collections a new account needs to be useful: a `personal`
/// calendar, a `tasks` calendar and a `personal` addressbook, with a welcome
/// object in each.
///
/// **Shared with `rustical setup`**, deliberately. The wizard prints "sign in as
/// this administrator, then add a client from the calendar page" as its third
/// next step; before this was shared, that promise was false — the wizard's
/// administrator had no collections at all, so the first thing a client did,
/// `PROPFIND /caldav/principal/<admin>/personal/`, was a **404**, on an account
/// the installer had just created for them. Found by the §8.1 self-host gate
/// (`router-dav/scripts/selfhost-gate.sh`), not by reading the code: both
/// callers would have passed their own tests.
///
/// The signature takes the two stores rather than a `RegisterState` because the
/// wizard has a pool and a principal store, not a `RegisterState` — and
/// manufacturing one would have meant building a limiter and an
/// `AuthenticationProvider` to reach a function that needs neither.
///
/// # Errors
///
/// Propagates whatever the calendar or addressbook store returns. Registration
/// treats that as a failed sign-up; the wizard treats it as a failed install
/// and says so, rather than leaving a principal with no calendar behind it.
#[allow(clippy::missing_errors_doc)]
pub async fn seed_collections<AS: AddressbookStore, CS: CalendarStore>(
    cal_store: &CS,
    addr_store: &AS,
    email: &str,
) -> Result<(), StoreError> {
    let personal_calendar = Calendar {
        id: "personal".to_owned(),
        principal: email.to_owned(),
        meta: CalendarMetadata {
            // `displayname` is GLOBALLY unique (idx_calendars_displayname_unique
            // + check_displayname_unique), so a hard-coded "Personal" would
            // collide with any existing user's row — seed NULL like the
            // Phase 5.4 MKCOL results (clients fall back to the id "personal").
            displayname: None,
            order: 0,
            description: None,
            color: Some("blue".to_owned()),
        },
        timezone_id: None,
        deleted_at: None,
        synctoken: 0,
        subscription_url: None,
        push_topic: random_token(),
        components: vec![CalendarObjectType::Event, CalendarObjectType::Journal],
    };
    cal_store.insert_calendar(personal_calendar).await?;
    let tasks_calendar = Calendar {
        id: "tasks".to_owned(),
        principal: email.to_owned(),
        meta: CalendarMetadata {
            displayname: None,
            order: 1,
            description: None,
            color: Some("green".to_owned()),
        },
        timezone_id: None,
        deleted_at: None,
        synctoken: 0,
        subscription_url: None,
        push_topic: random_token(),
        components: vec![CalendarObjectType::Todo],
    };
    cal_store.insert_calendar(tasks_calendar).await?;

    cal_store
        .put_objects(
            email,
            "personal",
            vec![
                (random_token(), welcome_event()),
                (random_token(), welcome_journal()),
            ],
            false,
        )
        .await?;
    cal_store
        .put_objects(
            email,
            "tasks",
            vec![(random_token(), welcome_todo())],
            false,
        )
        .await?;

    let personal_book = Addressbook {
        id: "personal".to_owned(),
        principal: email.to_owned(),
        displayname: None,
        description: None,
        deleted_at: None,
        synctoken: 0,
        push_topic: random_token(),
    };
    addr_store.insert_addressbook(personal_book).await?;
    Ok(())
}

fn welcome_event() -> CalendarObject {
    let uid = random_token();
    let stamp = Utc::now().format("%Y%m%dT%H%M%SZ");
    let start = Utc::now().date_naive();
    let end = start.checked_add_days(chrono::Days::new(1)).unwrap();
    let ics = format!(
        "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Rustical//Registration//EN\r\nBEGIN:VEVENT\r\nUID:{uid}\r\nDTSTAMP:{stamp}\r\nDTSTART;VALUE=DATE:{}\r\nDTEND;VALUE=DATE:{}\r\nSUMMARY:Welcome to Rustical!\r\nDESCRIPTION:Your account was auto-created. This event can be deleted.\r\nEND:VEVENT\r\nEND:VCALENDAR",
        start.format("%Y%m%d"),
        end.format("%Y%m%d"),
    );
    CalendarObject::from_ics(ics).expect("static seed ICS is valid")
}

fn welcome_journal() -> CalendarObject {
    let ics = seed_ics("VJOURNAL", "Welcome");
    CalendarObject::from_ics(ics).expect("static seed ICS is valid")
}

fn welcome_todo() -> CalendarObject {
    let uid = random_token();
    let stamp = Utc::now().format("%Y%m%dT%H%M%SZ");
    let ics = format!(
        "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Rustical//Registration//EN\r\nBEGIN:VTODO\r\nUID:{uid}\r\nDTSTAMP:{stamp}\r\nSUMMARY:Try your new Tasks calendar\r\nEND:VTODO\r\nEND:VCALENDAR"
    );
    CalendarObject::from_ics(ics).expect("static seed ICS is valid")
}

fn seed_ics(component: &str, summary: &str) -> String {
    let uid = random_token();
    let stamp = Utc::now().format("%Y%m%dT%H%M%SZ");
    format!(
        "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Rustical//Registration//EN\r\nBEGIN:{component}\r\nUID:{uid}\r\nDTSTAMP:{stamp}\r\nSUMMARY:{summary}\r\nEND:{component}\r\nEND:VCALENDAR"
    )
}

fn random_token() -> String {
    rand::rng()
        .sample_iter(Alphanumeric)
        .map(char::from)
        .take(64)
        .collect()
}

fn now_str() -> String {
    Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

fn is_valid_email(email: &str) -> bool {
    let Some((local, domain)) = email.split_once('@') else {
        return false;
    };
    !local.is_empty() && !domain.is_empty() && domain.contains('.') && !email.contains(' ')
}

fn internal_error() -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        "Something went wrong. Please try again.",
    )
        .into_response()
}

/// Escape a value for safe embedding in the HTML pages below.
fn escape_html(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            _ => out.push(ch),
        }
    }
    out
}

fn render_form(
    error: Option<&str>,
    values: &RegisterFormFieldValues<'_>,
    config: &RegistrationConfig,
    csrf: &str,
) -> Html<String> {
    let error_html = error.map_or_else(String::new, |msg| {
        format!(r#"<p class="error" role="alert">{}</p>"#, escape_html(msg))
    });
    let invite_html = if config.invite_required {
        r#"<label>Invitation code
            <input type="text" name="invite" required autocomplete="off" autocapitalize="none" spellcheck="false" placeholder="e.g. abC3dEf7Gh12">
            </label>"#
    } else {
        ""
    };
    render_page(&format!(
        r#"<h1>Create your account</h1>
        <p class="muted">Registration on this server is invite-gated. Codes are single-use and issued by an administrator.</p>
        {error_html}
        <form method="post" action="/register">
          <input type="hidden" name="csrf" value="{csrf}">
          <label>Email
            <input type="email" name="email" required autocomplete="username" value="{}">
          </label>
          <label>Display name
            <input type="text" name="displayname" autocomplete="name" value="{}">
          </label>
          <label>Password
            <input type="password" name="password" required autocomplete="new-password" minlength="{minlen}">
          </label>
          <label>Confirm password
            <input type="password" name="password_confirm" required autocomplete="new-password">
          </label>
          {invite_html}
          <button type="submit">Create account</button>
        </form>"#,
        escape_html(values.email),
        escape_html(values.displayname),
        minlen = config.min_password_length,
    ))
}

fn render_success(
    email: &str,
    displayname: &str,
    host: &str,
    app_tokens: &[(String, String)],
    feeds: &[(String, String)],
) -> Html<String> {
    let mut tokens_html = String::new();
    for (name, token) in app_tokens {
        writeln!(
            tokens_html,
            "<tr><td>{}</td><td><code>{}</code></td></tr>",
            escape_html(name),
            escape_html(token),
        )
        .unwrap();
    }
    let mut feeds_html = String::new();
    for (label, url) in feeds {
        writeln!(
            feeds_html,
            r#"<li><span>{}</span> <a href="{}">{}</a></li>"#,
            escape_html(label),
            escape_html(url),
            escape_html(url),
        )
        .unwrap();
    }
    let host_html = if host.is_empty() {
        String::new()
    } else {
        format!(
            "<p>Server: <code>https://{host}/</code></p>",
            host = escape_html(host),
        )
    };
    let greeting = if displayname.is_empty() {
        String::new()
    } else {
        format!(" <strong>{}</strong>", escape_html(displayname))
    };

    render_page(&format!(
        r#"<h1>Account created</h1>
        <p>Welcome{greeting}! Your account <code>{email}</code> is ready and you have been signed in automatically.</p>
        <div class="warn"><strong>These credentials are shown only once.</strong>
        Copy them now — app tokens cannot be recovered later.</div>
        {host_html}
        <h2>App tokens</h2>
        <table>
          <thead><tr><th>Client</th><th>Token</th></tr></thead>
          <tbody>{tokens_html}</tbody>
        </table>
        <h2>Share feeds</h2>
        <ul>{feeds_html}</ul>
        <p><a class="button" href="/frontend/user/{email}">Continue to your account →</a></p>"#,
        email = escape_html(email),
    ))
}

/// Render the success page for an existing user who just joined a group.
fn render_existing_user_success(
    email: &str,
    displayname: &str,
    host: &str,
    target_group: &Option<String>,
) -> Html<String> {
    let host_html = if host.is_empty() {
        String::new()
    } else {
        format!(
            "<p>Server: <code>https://{host}/</code></p>",
            host = escape_html(host),
        )
    };
    let greeting = if displayname.is_empty() {
        String::new()
    } else {
        format!(" <strong>{}</strong>", escape_html(displayname))
    };
    let group_msg = match target_group {
        Some(group) => format!(
            "<p>You have been added to the <code>{}</code> group.</p>",
            escape_html(group)
        ),
        None => String::new(),
    };

    render_page(&format!(
        r#"<h1>Welcome back{greeting}</h1>
        <p>Your account <code>{email}</code> already exists. You have been signed in automatically.</p>
        {group_msg}
        {host_html}
        <p><a class="button" href="/frontend/user/{email}">Continue to your account →</a></p>"#,
        email = escape_html(email),
    ))
}

fn render_page(body: &str) -> Html<String> {
    Html(format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>RustiCal — Registration</title>
<style>
  body {{ font-family: system-ui, sans-serif; max-width: 34rem; margin: 3rem auto; padding: 0 1rem; line-height: 1.5; }}
  h1 {{ font-size: 1.4rem; }} h2 {{ font-size: 1.05rem; margin-top: 2rem; }}
  label {{ display: block; margin-bottom: 1rem; font-weight: 600; }}
  input {{ display: block; width: 100%; padding: 0.5rem; margin-top: 0.25rem; font-size: 1rem; box-sizing: border-box; }}
  button {{ padding: 0.6rem 1.2rem; font-size: 1rem; cursor: pointer; }}
  .error {{ color: #b00020; border: 1px solid currentColor; padding: 0.6rem; }}
  .warn {{ border-left: 4px solid #f0ad4e; padding: 0.5rem 0.8rem; background: rgba(240,173,78,.15); }}
  .muted {{ color: #666; }} .button {{ display: inline-block; margin-top: 1rem; }}
  table {{ border-collapse: collapse; width: 100%; }} td, th {{ border: 1px solid #ccc; padding: 0.35rem 0.5rem; text-align: left; }}
  code {{ word-break: break-all; }}
</style>
</head>
<body>
{body}
</body>
</html>"#
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body as AxBody;
    use http::{Request, header::SET_COOKIE};
    use rustical_store::CalendarReadStore as _;
    use rustical_store_sqlite::{
        SqliteAddressbookStore, SqliteCalendarStore, SqliteInviteStore, SqlitePrincipalStore,
        SqliteSubscriptionStore, create_db_pool,
    };
    use tower::ServiceExt;
    use tower_sessions::{MemoryStore, SessionManagerLayer};

    struct TestRig {
        router: axum::Router,
        invite_store: Arc<dyn InviteStore>,
        principal_store: Arc<SqlitePrincipalStore>,
        cal_store: Arc<SqliteCalendarStore>,
        subscription_store: Arc<SqliteSubscriptionStore>,
        session_cookie: std::sync::Mutex<Option<String>>,
        csrf: std::sync::Mutex<String>,
    }

    impl TestRig {
        async fn new(config: RegistrationConfig) -> Self {
            let db = create_db_pool(":memory:", true).await.unwrap();
            let (send, _recv) = tokio::sync::mpsc::channel(1000);
            let addr_store = Arc::new(SqliteAddressbookStore::new(db.clone(), send.clone(), false));
            let cal_store = Arc::new(SqliteCalendarStore::new(db.clone(), send, false));
            let principal_store = Arc::new(SqlitePrincipalStore::new(db));
            let invite_store: Arc<dyn InviteStore> =
                Arc::new(SqliteInviteStore::new((*cal_store).clone()));
            let subscription_store = Arc::new(SqliteSubscriptionStore::new((*cal_store).clone()));
            let subscription_store_dyn: Arc<dyn SubscriptionStore> = subscription_store.clone();

            let context = Arc::new(RegistrationContext {
                config,
                invite_store: invite_store.clone(),
                subscription_store: Some(subscription_store_dyn),
                subscriptions_public_url: Some("https://0115d8cf.duckdns.org:8443".to_owned()),
            });

            let router = register_router(
                addr_store,
                cal_store.clone(),
                principal_store.clone(),
                context,
                // The in-tree test is not behind a proxy, so it passes the
                // fail-closed default. That is also the honest thing for a test
                // to do: it is testing registration, not the trust list, and
                // `tests/trusted_proxies.rs` covers that.
                Vec::new(),
            )
            .layer(
                SessionManagerLayer::new(MemoryStore::default())
                    .with_name("rustical_session")
                    .with_secure(true),
            );

            Self {
                router,
                invite_store,
                principal_store,
                cal_store,
                subscription_store,
                session_cookie: std::sync::Mutex::new(None),
                csrf: std::sync::Mutex::new(String::new()),
            }
        }

        async fn get_form(&self) {
            let req = Request::get("/register").body(AxBody::empty()).unwrap();
            let resp = self.router.clone().oneshot(req).await.unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
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

        async fn post(&self, fields: &[(&str, &str)]) -> Response {
            let csrf = self.csrf.lock().unwrap().clone();
            let mut pairs = vec![("csrf", csrf.as_str())];
            pairs.extend_from_slice(fields);
            let body = pairs
                .iter()
                .map(|(k, v)| format!("{}={}", k, urlencode(v)))
                .collect::<Vec<_>>()
                .join("&");
            let mut req = Request::post("/register")
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

        async fn post_status(&self, fields: &[(&str, &str)]) -> (StatusCode, String) {
            let resp = self.post(fields).await;
            let status = resp.status();
            let (_, body) = resp.into_parts();
            (status, body_to_string(body).await)
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
                _ => write!(out, "%{b:02X}").unwrap(),
            }
        }
        out
    }

    fn base_config() -> RegistrationConfig {
        RegistrationConfig {
            enabled: true,
            invite_required: true,
            min_password_length: 12,
            auto_app_tokens: vec!["vdirsyncer".to_owned(), "davx5".to_owned()],
            auto_subscription: true,
            default_group: String::new(),
            rate_limit_per_hour: 10,
        }
    }

    fn alert_msg(body: &str) -> String {
        body.split("role=\"alert\">")
            .nth(1)
            .and_then(|rest| rest.split("</p>").next())
            .unwrap_or_default()
            .to_owned()
    }

    #[tokio::test]
    async fn registers_provisions_and_auto_logs_in() {
        let rig = TestRig::new(base_config()).await;
        rig.get_form().await;
        rig.invite_store
            .add_invite(
                "unused-abc",
                &Some("new@example.com".to_owned()),
                &None,
                "test",
                &None,
                &None,
                &None,
            )
            .await
            .unwrap();
        let (status, body) = rig
            .post_status(&[
                ("email", "new@example.com"),
                ("displayname", "New User"),
                ("password", "correct horse battery staple"),
                ("password_confirm", "correct horse battery staple"),
                ("invite", "unused-abc"),
            ])
            .await;
        assert_eq!(status, StatusCode::OK, "body: {body}");
        assert!(body.contains("Share feeds"), "body: {body}");
        assert!(body.contains("new@example.com"), "body: {body}");

        // Account exists, redemption was recorded, tokens + collections + feeds.
        let principal = rig
            .principal_store
            .get_principal("new@example.com")
            .await
            .unwrap()
            .unwrap();
        assert!(principal.password.is_some());
        let invite = rig
            .invite_store
            .get_invite("unused-abc")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(invite.used_by.as_deref(), Some("new@example.com"));
        let tokens = rig
            .principal_store
            .get_app_tokens(&principal.id)
            .await
            .unwrap();
        assert_eq!(tokens.len(), 2);
        for name in ["personal", "tasks"] {
            rig.cal_store
                .get_calendar(&principal.id, name, false)
                .await
                .unwrap();
        }
        let subs = rig
            .subscription_store
            .get_subscriptions(&principal.id)
            .await
            .unwrap();
        assert_eq!(subs.len(), 2);

        // The new user was auto-logged-in (GET /register redirects away).
        let req = Request::get("/register")
            .header(
                http::header::COOKIE,
                rig.session_cookie.lock().unwrap().clone().unwrap(),
            )
            .body(AxBody::empty())
            .unwrap();
        let resp = rig.router.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    }

    #[tokio::test]
    async fn success_card_renders_feeds() {
        let rig = TestRig::new(base_config()).await;
        rig.get_form().await;
        rig.invite_store
            .add_invite(
                "used-cde",
                &Some("sess@example.com".to_owned()),
                &None,
                "test",
                &None,
                &None,
                &None,
            )
            .await
            .unwrap();
        let (status, body) = rig
            .post_status(&[
                ("email", "sess@example.com"),
                ("password", "correct horse battery staple"),
                ("password_confirm", "correct horse battery staple"),
                ("invite", "used-cde"),
            ])
            .await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            body.contains("https://0115d8cf.duckdns.org:8443/export/"),
            "{body}"
        );
        assert!(body.contains(".ics"), "{body}");
        assert!(body.contains(".vcf"), "{body}");
    }

    #[tokio::test]
    async fn invite_is_single_use() {
        let rig = TestRig::new(base_config()).await;
        rig.get_form().await;
        rig.invite_store
            .add_invite("single-use", &None, &None, "test", &None, &None, &None)
            .await
            .unwrap();
        let fields = &[
            ("email", "one@example.com"),
            ("password", "correct horse battery staple"),
            ("password_confirm", "correct horse battery staple"),
            ("invite", "single-use"),
        ];
        assert_eq!(rig.post_status(fields).await.0, StatusCode::OK);
        // Fresh CSRF+session for the second attempt.
        rig.get_form().await;
        let (status, body) = rig
            .post_status(&[
                ("email", "two@example.com"),
                ("password", "correct horse battery staple"),
                ("password_confirm", "correct horse battery staple"),
                ("invite", "single-use"),
            ])
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(alert_msg(&body), INVALID_INVITE_MSG);
        assert!(
            rig.principal_store
                .get_principal("two@example.com")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn unknown_used_and_expired_codes_share_one_body() {
        let rig = TestRig::new(base_config()).await;
        let mut alerts = std::collections::HashSet::new();

        // Unknown code: never created.
        rig.get_form().await;
        let (status, body) = rig
            .post_status(&[
                ("email", "unknown@example.com"),
                ("password", "correct horse battery staple"),
                ("password_confirm", "correct horse battery staple"),
                ("invite", "no-such-code-zz"),
            ])
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        alerts.insert(alert_msg(&body));

        // Used code.
        rig.get_form().await;
        rig.invite_store
            .add_invite("used-zz", &None, &None, "test", &None, &None, &None)
            .await
            .unwrap();
        rig.invite_store
            .redeem_invite("used-zz", "someone@example.com", &now_str())
            .await
            .unwrap();
        let (status, body) = rig
            .post_status(&[
                ("email", "usedone@example.com"),
                ("password", "correct horse battery staple"),
                ("password_confirm", "correct horse battery staple"),
                ("invite", "used-zz"),
            ])
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        alerts.insert(alert_msg(&body));

        // Expired code.
        rig.get_form().await;
        rig.invite_store
            .add_invite(
                "expired-1",
                &None,
                &None,
                "test",
                &Some("2000-01-01T00:00:00Z".to_owned()),
                &None,
                &None,
            )
            .await
            .unwrap();
        let (status, body) = rig
            .post_status(&[
                ("email", "expired@example.com"),
                ("password", "correct horse battery staple"),
                ("password_confirm", "correct horse battery staple"),
                ("invite", "expired-1"),
            ])
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        alerts.insert(alert_msg(&body));

        assert_eq!(alerts.len(), 1, "bodies must not differ: {alerts:?}");
    }

    #[tokio::test]
    async fn email_bind_mismatch_has_distinct_response() {
        let rig = TestRig::new(base_config()).await;
        rig.get_form().await;
        rig.invite_store
            .add_invite(
                "bound-1",
                &Some("expected@example.com".to_owned()),
                &None,
                "test",
                &None,
                &None,
                &None,
            )
            .await
            .unwrap();
        let (status, body) = rig
            .post_status(&[
                ("email", "other@example.com"),
                ("password", "correct horse battery staple"),
                ("password_confirm", "correct horse battery staple"),
                ("invite", "bound-1"),
            ])
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(alert_msg(&body), INVALID_INVITE_EMAIL_MSG);
        // The code is still redeemable by its intended target.
        let invite = rig
            .invite_store
            .get_invite("bound-1")
            .await
            .unwrap()
            .unwrap();
        assert!(invite.used_by.is_none());
    }

    #[tokio::test]
    async fn existing_account_rejected() {
        let rig = TestRig::new(base_config()).await;
        rig.get_form().await;
        rig.invite_store
            .add_invite("repeat-1", &None, &None, "test", &None, &None, &None)
            .await
            .unwrap();
        rig.principal_store
            .insert_principal(
                Principal {
                    id: "exists@example.com".to_owned(),
                    displayname: None,
                    principal_type: PrincipalType::default(),
                    password: None,
                    memberships: vec![],
                    needs_password_change: false,
                    privileges: Default::default(),
                },
                false,
            )
            .await
            .unwrap();
        let (status, body) = rig
            .post_status(&[
                ("email", "exists@example.com"),
                ("password", "correct horse battery staple"),
                ("password_confirm", "correct horse battery staple"),
                ("invite", "repeat-1"),
            ])
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body.contains("already exists"), "body: {body}");
        // A failed pre-check must not consume the code.
        let invite = rig
            .invite_store
            .get_invite("repeat-1")
            .await
            .unwrap()
            .unwrap();
        assert!(invite.used_by.is_none());
    }

    #[tokio::test]
    async fn short_password_and_mismatch_rejected() {
        let rig = TestRig::new(base_config()).await;
        for (pw, confirm, expected) in [
            ("short", "short", "at least 12"),
            (
                "correct horse battery staple",
                "different passphrase",
                "do not match",
            ),
        ] {
            rig.get_form().await;
            let (status, body) = rig
                .post_status(&[
                    ("email", "pw@example.com"),
                    ("password", pw),
                    ("password_confirm", confirm),
                    ("invite", "no-such-code-pw"),
                ])
                .await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
            assert!(body.contains(expected), "{expected}: {body}");
        }
    }

    #[tokio::test]
    async fn csrf_missing_or_stale_rejected() {
        let rig = TestRig::new(base_config()).await;
        // No GET: empty csrf, none stored in session.
        let (status, body) = rig
            .post_status(&[
                ("email", "csrf@example.com"),
                ("password", "correct horse battery staple"),
                ("password_confirm", "correct horse battery staple"),
                ("invite", "no-such-code-csrf"),
            ])
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body.contains("expired"), "body: {body}");
    }

    #[tokio::test]
    async fn rate_limited_after_budget() {
        let mut config = base_config();
        config.rate_limit_per_hour = 2;
        let rig = TestRig::new(config).await;
        for _ in 0..2 {
            let req = Request::post("/register")
                .header("content-type", "application/x-www-form-urlencoded")
                .header("host", "127.0.0.1:4000")
                .header("x-forwarded-for", "203.0.113.9")
                .body(AxBody::from("email=a@b.cd&csrf=nope"))
                .unwrap();
            let resp = rig.router.clone().oneshot(req).await.unwrap();
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        }
        let req = Request::post("/register")
            .header("content-type", "application/x-www-form-urlencoded")
            .header("host", "127.0.0.1:4000")
            .header("x-forwarded-for", "203.0.113.9")
            .body(AxBody::from("email=a@b.cd&csrf=nope"))
            .unwrap();
        let resp = rig.router.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    }
}
