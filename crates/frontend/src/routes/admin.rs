//! The admin panel — `PLAN_DEPLOYMENTS.md` §6.6.1, §6.6.5, §6.6.6.
//!
//! ## What this is, structurally
//!
//! A **control-plane** router, mounted ahead of `HostDispatch` (see
//! [`TenancyAwareApp`](crate::host_dispatch::TenancyAwareApp)) and reachable on
//! **exactly one host**, `[tenancy] admin_host`.
//!
//! The ordering is the design rather than a detail. Two properties follow from
//! it, and both are the point of the item:
//!
//! - **The admin host serves no tenant data at all** — not "metadata about
//!   tenants", but no tenant's portal, no DAV, no export feed. There is no
//!   request this router forwards downward, so there is no path from an admin
//!   session to customer content.
//! - **On every other host the panel does not exist.** A `/frontend/admin/*`
//!   request falls through to that tenant's own router, which has no such
//!   route. §6.6.1 notes that a tenant's `/{user}` route means
//!   `/frontend/admin` can match a tenant principal *named* `admin` and render
//!   that tenant's own page — which leaks nothing, but is why the panel's own
//!   404s are the real gate and they are tested on the admin host.
//!
//! ## What it can never do
//!
//! - **Open a tenant's database.** Every value on every page comes from the
//!   control plane. [`AdminPanel`] holds [`TenantStore`] and
//!   [`AdminCredentialStore`] as trait objects and has no way to reach a
//!   `StoreBundle`: §3.2's isolation argument is untouched because there is
//!   simply no code here that could violate it.
//! - **Delete a tenant** (§6.6.1). A browser form is the only irreversible,
//!   easily-misclicked path to a customer's data, and the CLI already does it
//!   with `--confirm`/`--purge-data` deliberately separate. There is no delete
//!   route and no code path in this module that deletes anything.
//! - **Show usage.** Quota *limits* are control-plane data; usage would mean
//!   counting rows in a tenant's store, which would be the first thing in the
//!   design to read across the boundary. A deferred `rustical tenant usage` job
//!   writes a snapshot to the control plane and this page reads that.
//!
//! ## The three things a new credential surface must get right (§6.6.5)
//!
//! Copied from `password_reset.rs` rather than invented, because that is the
//! **only** precedent in the tree — and the portal's own `POST /register` has no
//! CSRF check, so the panel must not copy *that*:
//!
//! 1. **Rate limiting per name *and* per source** ([`AdminRateLimiter`]).
//! 2. **Lockout**, which lives in the store (phase 2) so it survives a restart.
//! 3. **A session-bound CSRF token on every POST**, rotated on every failure.
//!
//! ## The invariant this module must not get wrong
//!
//! **Config is authoritative** (§6.6.3). [`authenticate`] checks the allowlist
//! *before* the store, and returns one [`LoginFailure`] for "not allowlisted",
//! "no credential row" and "wrong password" alike — because telling an attacker
//! which of the three they hit is the difference between a rate limit and a
//! username oracle.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::client_ip::{IpNet, PeerAddr, client_ip, warn_once_if_header_ignored};
use askama::Template;
use askama_web::WebTemplate;
use axum::Router;
use axum::extract::{Form, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use rand::RngExt;
use rand::distr::Alphanumeric;
use rustical_store::admin_store::{
    AdminAuthOutcome, AdminCredentialStore, admin_lockout_until, admin_now,
};
use rustical_store::tenant::{Tenant, TenantId, TenantStatus};
use rustical_store::tenant_store::{NewTenant, TenantQuota, TenantStore};
use tower_sessions::Session;
use tracing::{error, instrument, warn};

/// The panel's own session cookie name.
///
/// **Must differ from the portal's `rustical_session`.** §6.6.4: the panel's
/// session store is separate from every tenant's — necessarily, since each
/// tenant has its own `MemoryStore` — so a panel session and a portal session
/// have to be impossible to confuse on a shared host. A deployment serving
/// `admin.example.com` and `portal.example.com` off one registrable domain
/// would otherwise carry two different session ids under one cookie name.
pub const ADMIN_SESSION_COOKIE: &str = "omnical_admin_session";

/// One message for every credential failure, used by every failure path.
///
/// **One constant, three causes** — not three constants that happen to agree,
/// because constants that agree today are edited independently tomorrow and a
/// login form that says "unknown name" is a username oracle.
const BAD_CREDENTIALS: &str = "That name and password combination is not valid.";

/// The form-expired message, which is about CSRF rather than credentials.
const EXPIRED_FORM: &str = "This form has expired. Please load it again.";

/// How a login attempt failed. Carried to the log, never to the browser —
/// except [`Self::Locked`], below.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LoginFailure {
    /// Locked out in the store.
    ///
    /// The one failure a caller may distinguish in the *response*, because an
    /// attacker who is being rate limited against a name has already learned
    /// that the name is real. Every other cause renders as one message.
    Locked,
    /// Not allowlisted, no credential row, or wrong password — deliberately one
    /// value, and the reason the enum is worth having at all.
    Refused,
}

impl LoginFailure {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Locked => "locked",
            Self::Refused => "refused",
        }
    }
}

/// Sliding-window rate limiter for the login POST (§6.6.5).
///
/// **Per name *and* per source, and both are needed.** Per source alone lets one
/// host grind through a password list; per name alone lets a botnet take one
/// account down from many hosts. The global bucket is the coarse net above both,
/// copied from `password_reset.rs`'s shape.
///
/// A rejected attempt is **not** recorded, matching that precedent: recording it
/// would let a client lock *itself* out with a few requests, which is a denial
/// of service it can inflict on its own account.
#[derive(Debug)]
pub struct AdminRateLimiter {
    window: Duration,
    max_per_name: usize,
    max_per_source: usize,
    max_global: usize,
    per_name: Mutex<HashMap<String, Vec<Instant>>>,
    per_source: Mutex<HashMap<String, Vec<Instant>>>,
    global: Mutex<Vec<Instant>>,
}

impl Default for AdminRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl AdminRateLimiter {
    /// Per-name 10/h, per-source 30/h, global 300/h.
    ///
    /// Looser than `password_reset.rs`'s 5/h because a legitimate admin can
    /// mistype a password several times in a morning, and the **lockout** — not
    /// this — is the control that must be unbypassable. Generous enough not to
    /// be the thing that annoys, small enough that a list is not walkable.
    #[must_use]
    pub fn new() -> Self {
        Self {
            window: Duration::from_secs(3600),
            max_per_name: 10,
            max_per_source: 30,
            max_global: 300,
            per_name: Mutex::new(HashMap::new()),
            per_source: Mutex::new(HashMap::new()),
            global: Mutex::new(Vec::new()),
        }
    }

    /// `true` if the attempt is allowed, recording it.
    ///
    /// Every critical section is lock-then-drop and none crosses an `.await`, so
    /// a poisoned mutex means **deny** rather than a panic: a rate limiter that
    /// stops working under memory pressure is worse than one that is briefly
    /// strict.
    fn check_and_record(&self, name: &str, source: &str, now: Instant) -> bool {
        // All three locks at once, in one scope, and the whole check-then-record
        // is atomic with respect to other attempts.
        //
        // Holding them one at a time and dropping between check and record was
        // the first draft, and it has a real bug: a per-name entry recorded for
        // an attempt the *global* bucket then refuses would drain the admin's
        // name budget from attempts that never happened. A client hammering one
        // name from many sources would lock itself out of its own account by
        // making requests it was never allowed to make.
        let Ok(mut names) = self.per_name.lock() else {
            return false;
        };
        let Ok(mut sources) = self.per_source.lock() else {
            return false;
        };
        let Ok(mut global) = self.global.lock() else {
            return false;
        };

        let name_entry = names.entry(name.to_owned()).or_default();
        let source_entry = sources.entry(source.to_owned()).or_default();
        name_entry.retain(|at| now.duration_since(*at) < self.window);
        source_entry.retain(|at| now.duration_since(*at) < self.window);
        global.retain(|at| now.duration_since(*at) < self.window);

        let over_name = name_entry.len() >= self.max_per_name;
        let over_source = source_entry.len() >= self.max_per_source;
        let over_global = global.len() >= self.max_global;
        if over_name || over_source || over_global {
            // Nothing recorded: a rejected attempt does not count against
            // anything, so a client cannot lock itself out.
            return false;
        }
        name_entry.push(now);
        source_entry.push(now);
        global.push(now);
        true
    }
}

/// One tenant as the panel shows it: control-plane fields only.
#[derive(Debug, Clone)]
pub struct TenantRow {
    pub id: String,
    pub slug: String,
    pub display_name: String,
    pub status: &'static str,
    pub plan: String,
    pub hosts: Vec<String>,
    pub is_suspended: bool,
    pub created_at: String,
    pub suspended_at: String,
    /// `/suspend` or `/resume`, computed server-side.
    ///
    /// In the template rather than an `{% if %}` because a URL is not a
    /// boolean: askingama cannot do string concatenation from a field, and a
    /// hand-built action URL in the template is exactly where a mismatched
    /// branch would hide.
    pub status_action: &'static str,
}

impl TenantRow {
    /// Build a row from a control-plane [`Tenant`] and its explicit host claims.
    fn new(tenant: &Tenant, hosts: Vec<String>) -> Self {
        Self {
            id: tenant.id.as_str().to_owned(),
            slug: tenant.slug.as_str().to_owned(),
            display_name: tenant.display_name.clone(),
            status: tenant.status.as_str(),
            plan: tenant.plan.clone(),
            hosts,
            is_suspended: tenant.status == TenantStatus::Suspended,
            created_at: tenant.created_at.clone().unwrap_or_else(|| "-".to_owned()),
            suspended_at: tenant
                .suspended_at
                .clone()
                .unwrap_or_else(|| "-".to_owned()),
            status_action: if tenant.status == TenantStatus::Suspended {
                "resume"
            } else {
                "suspend"
            },
        }
    }
}

#[derive(Template, WebTemplate)]
#[template(path = "pages/admin_tenants.html")]
struct AdminTenantsPage {
    admin: String,
    csrf: String,
    tenants: Vec<TenantRow>,
    message: Option<String>,
    error: Option<String>,
}

#[derive(Template, WebTemplate)]
#[template(path = "pages/admin_tenant.html")]
struct AdminTenantPage {
    admin: String,
    csrf: String,
    tenant: TenantRow,
    quota: Vec<(String, String)>,
    /// §7.5 item 20a. Read from `control_tenant_usage` — one row in a store the
    /// panel already holds open. **Not** from the tenant's database, and row 37a
    /// is the test that makes that a property rather than an intention.
    usage: Vec<(String, String)>,
    error: Option<String>,
}

#[derive(Template, WebTemplate)]
#[template(path = "pages/admin_login.html")]
struct AdminLoginPage {
    csrf: String,
    error: Option<String>,
}

/// The panel's shared state.
///
/// Two trait objects, one config value, and **deliberately no `StoreBundle`** —
/// that absence is what makes "the panel never opens a tenant's database" a
/// property of the types rather than a promise in a doc comment.
pub struct AdminPanel {
    store: Arc<dyn TenantStore>,
    admins: Arc<dyn AdminCredentialStore>,
    /// `[tenancy] platform_admins` (§6.6.3). Authoritative.
    allowlist: Vec<String>,
    /// The reserved panel host, normalised. Checked by `tenant create`'s form so
    /// a collision cannot be *introduced* through the panel either — the CLI's
    /// refusal and this are the same rule at two doors.
    admin_host: String,
    /// `[tenancy] trusted_proxies`, parsed (C5, §7.3.4). Empty means no peer's
    /// `X-Forwarded-For` is believed, which is the fail-closed default and the
    /// whole security property of this rate limiter.
    trusted_proxies: Vec<IpNet>,
    limiter: Arc<AdminRateLimiter>,
}

impl AdminPanel {
    /// `store` and `admins` are the **same** database in production, and two
    /// arguments because the two traits are separately implementable.
    ///
    /// # Panics
    /// Never. Kept `#[must_use]` rather than panicking so a bad `admin_host`
    /// degrades to "the panel does not reserve a host" instead of a boot
    /// failure — the startup refusals in [`crate::admin`] already refuse the
    /// configurations that matter, and a second panic path here would be a
    /// second way to be wrong.
    #[must_use]
    pub fn new(
        store: Arc<dyn TenantStore>,
        admins: Arc<dyn AdminCredentialStore>,
        allowlist: Vec<String>,
        admin_host: &str,
        trusted_proxies: Vec<IpNet>,
    ) -> Self {
        Self {
            store,
            admins,
            allowlist,
            admin_host: normalise_host(admin_host),
            trusted_proxies,
            limiter: Arc::new(AdminRateLimiter::new()),
        }
    }

    /// The routes, plus the panel's **own** session layer.
    ///
    /// A `SessionManagerLayer` over a *fresh* `MemoryStore` with
    /// [`ADMIN_SESSION_COOKIE`]. Every tenant's router has its own store and the
    /// portal's cookie name, so an admin session cannot be read by a tenant
    /// router — and, again, none is reachable from here.
    pub fn router(self: Arc<Self>) -> Router {
        let sessions = tower_sessions::MemoryStore::default();
        Router::new()
            .route("/frontend/admin/login", get(login_page))
            .route("/frontend/admin/login", post(login_submit))
            .route("/frontend/admin/logout", post(logout))
            .route("/frontend/admin/tenants", get(tenants_page))
            .route("/frontend/admin/tenants", post(create_tenant))
            .route("/frontend/admin/tenants/{id}", get(tenant_page))
            .route(
                "/frontend/admin/tenants/{id}/suspend",
                post(set_suspended::<true>),
            )
            .route(
                "/frontend/admin/tenants/{id}/resume",
                post(set_suspended::<false>),
            )
            // **No delete route** (§6.6.1). A `DELETE` on
            // `/frontend/admin/tenants/{id}` is a 405 from axum's router, and
            // there is no other path in this module that deletes a tenant.
            //
            // Everything unrouted is the panel's own 404, which is the real
            // half of row 32.
            .fallback(not_found)
            .with_state(self)
            .layer(
                tower_sessions::SessionManagerLayer::new(sessions)
                    .with_name(ADMIN_SESSION_COOKIE)
                    .with_secure(true)
                    .with_same_site(tower_sessions::cookie::SameSite::Strict)
                    .with_expiry(tower_sessions::Expiry::OnInactivity(
                        tower_sessions::cookie::time::Duration::hours(2),
                    )),
            )
    }

    /// The address this login is rate-limited by (C5, §7.3.4).
    ///
    /// Delegates to [`client_ip`] with this panel's own `trusted_proxies`, and
    /// emits the once-per-process warning when a forwarded header arrived from a
    /// peer that is not configured. The warning matters more here than at the
    /// other two call sites: a self-hosted panel behind a reverse proxy with no
    /// `trusted_proxies` is rate-limiting **every** admin login attempt as one
    /// address, which is a much tighter bucket than an operator would expect
    /// from a 10/hour per-name limit.
    fn client_ip(&self, peer: Option<SocketAddr>, headers: &HeaderMap) -> String {
        warn_once_if_header_ignored(headers, peer, &self.trusted_proxies);
        client_ip(peer, headers, &self.trusted_proxies)
    }

    /// The authenticated admin's name, or `None`.
    ///
    /// Note what it does **not** do: consult the allowlist. A session minted
    /// while a name was allowlisted stays valid until it expires, and that is
    /// the *eventual* consequence §6.6.3 accepts — revoking an admin is a config
    /// edit and a row delete, and a config edit does not reach into a running
    /// process's memory. Pretending otherwise would be a lie about what a config
    /// change can do. The revocation that *is* immediate is the row delete.
    async fn current_admin(&self, session: &Session) -> Option<String> {
        session.get::<String>("admin").await.ok().flatten()
    }

    /// The session's CSRF token, checked against `submitted`.
    ///
    /// One function so no handler can check the session and forget the token.
    /// `Err(StatusCode)` rather than `Err(Response)`: an `axum::Response` in the
    /// error slot is 128 bytes and this runs on every mutating POST.
    ///
    /// The two refusals are **not** collapsed, and that was learned the hard way:
    /// an earlier version returned `Err(())` for both, which made every failing
    /// POST answer 404 — so a request with a *valid* session and a *stale* token
    /// reported "nothing here" instead of "your token expired". Two tests caught
    /// it, and the distinction is now explicit in the type.
    async fn require_admin(
        &self,
        session: &Session,
        submitted: Option<&str>,
    ) -> Result<String, StatusCode> {
        let Some(admin) = self.current_admin(session).await else {
            // 404, not 401: row 32 wants a 404, and a 401 with a login link on
            // an unauthenticated request would confirm a panel exists.
            return Err(StatusCode::NOT_FOUND);
        };
        check_csrf(session, submitted)
            .await
            .map_err(|()| StatusCode::FORBIDDEN)?;
        Ok(admin)
    }
}

// ─────────────────────────────────── login ──────────────────────────────────

#[instrument(skip_all)]
async fn login_page(State(panel): State<Arc<AdminPanel>>, session: Session) -> Response {
    if panel.current_admin(&session).await.is_some() {
        return Redirect::to("/frontend/admin/tenants").into_response();
    }
    let csrf = session_csrf(&session).await;
    AdminLoginPage { csrf, error: None }.into_response()
}

#[derive(Debug, serde::Deserialize)]
struct LoginForm {
    #[serde(default)]
    name: String,
    #[serde(default)]
    password: String,
    #[serde(default)]
    csrf: String,
}

#[instrument(skip_all)]
async fn login_submit(
    State(panel): State<Arc<AdminPanel>>,
    PeerAddr(peer): PeerAddr,
    headers: HeaderMap,
    session: Session,
    Form(form): Form<LoginForm>,
) -> Response {
    // A CSRF failure is **not** counted against the rate limiter: it is not a
    // credential guess, and counting it would let a third party lock an admin
    // out by forging POSTs from a browser.
    if check_csrf(&session, Some(&form.csrf)).await.is_err() {
        // Re-rendered rather than a bare 403, because the operator holding a
        // stale form needs a *usable* one, and `check_csrf` has already rotated
        // the token out from under the old page. The rate limiter is
        // deliberately not touched: a CSRF failure is not a credential guess,
        // and counting it would let a third party lock an admin out by forging
        // POSTs from a browser they control.
        return render_login_failure(&session, EXPIRED_FORM).await;
    }

    let name = form.name.trim().to_owned();
    let source = panel.client_ip(peer, &headers);
    if !panel
        .limiter
        .check_and_record(&name, &source, Instant::now())
    {
        warn!(admin = %name, %source, "admin login: rate limited");
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    }

    match authenticate(&panel, &name, &form.password).await {
        Ok(()) => {
            if let Err(e) = session.insert("admin", &name).await {
                // A login that succeeded but cannot be recorded must not report
                // success: the operator would believe they were in, and find out
                // on the next request.
                error!(%e, admin = %name, "admin login: could not persist the session");
                return render_login_failure(&session, BAD_CREDENTIALS).await;
            }
            Redirect::to("/frontend/admin/tenants").into_response()
        }
        Err(LoginFailure::Locked) => {
            warn!(admin = %name, %source, "admin login: locked out");
            render_login_failure(
                &session,
                "This name is temporarily locked after repeated failures.",
            )
            .await
        }
        Err(failure) => {
            warn!(admin = %name, %source, reason = failure.as_str(), "admin login refused");
            render_login_failure(&session, BAD_CREDENTIALS).await
        }
    }
}

/// Re-render the login form with one message.
async fn render_login_failure(session: &Session, message: &str) -> Response {
    // Rotate: a token that has been seen once and failed must not be replayable
    // against the next form.
    let csrf = rotate_csrf(session).await;
    (
        StatusCode::UNAUTHORIZED,
        AdminLoginPage {
            csrf,
            error: Some(message.to_owned()),
        },
    )
        .into_response()
}

/// Authenticate one admin, in the order that makes the refusals mean something.
///
/// 1. **The allowlist, first** (§6.6.3). A name the config does not list cannot
///    authenticate whatever the control plane holds. This check is the security
///    property and it lives here rather than in the store, because the store
///    cannot see config.
/// 2. The store's `authenticate_admin`, which does lookup → lockout → verify →
///    record. That order is the trait's, because the order is load-bearing.
///
/// **No argon2 runs for an unlisted name**, which is both the cheap answer and
/// the right one: a hash nobody may use is not worth computing.
async fn authenticate(panel: &AdminPanel, name: &str, password: &str) -> Result<(), LoginFailure> {
    if !panel.allowlist.iter().any(|n| n == name) {
        return Err(LoginFailure::Refused);
    }
    let now = admin_now();
    let outcome = panel
        .admins
        .authenticate_admin(name, password, &now, &admin_lockout_until(&now))
        .await
        .map_err(|e| {
            // Logged, reported as a plain refusal. A store failure is not a
            // credential failure, and saying so would let an attacker turn a
            // disk error into an oracle for which names exist.
            error!(%e, admin = %name, "admin login: store failure");
            LoginFailure::Refused
        })?;
    match outcome {
        AdminAuthOutcome::Ok => Ok(()),
        AdminAuthOutcome::Locked => Err(LoginFailure::Locked),
        AdminAuthOutcome::Refused => Err(LoginFailure::Refused),
    }
}

// ────────────────────────────── tenant metadata ──────────────────────────────

#[instrument(skip_all)]
async fn tenants_page(State(panel): State<Arc<AdminPanel>>, session: Session) -> Response {
    let Some(admin) = panel.current_admin(&session).await else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Ok(tenants) = panel.store.list_tenants(true).await else {
        error!("admin panel: could not list tenants");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    // Control-plane reads only. No tenant database is opened anywhere in this
    // function, which is the point: `list_tenant_hosts` and `get_quota` are
    // both queries against `control.sqlite3`.
    let mut rows = Vec::with_capacity(tenants.len());
    for tenant in &tenants {
        let hosts = panel
            .store
            .list_tenant_hosts(&tenant.id)
            .await
            .unwrap_or_default();
        rows.push(TenantRow::new(tenant, hosts));
    }
    AdminTenantsPage {
        admin,
        csrf: session_csrf(&session).await,
        tenants: rows,
        message: None,
        error: None,
    }
    .into_response()
}

#[instrument(skip_all)]
async fn tenant_page(
    State(panel): State<Arc<AdminPanel>>,
    Path(id): Path<String>,
    session: Session,
) -> Response {
    let Some(admin) = panel.current_admin(&session).await else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Ok(tenant_id) = id.parse::<TenantId>() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Ok(Some(tenant)) = panel.store.get_tenant_by_id(&tenant_id).await else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let hosts = panel
        .store
        .list_tenant_hosts(&tenant_id)
        .await
        .unwrap_or_default();
    let quota = match panel.store.get_quota(&tenant_id).await {
        Ok(q) => quota_rows(&q),
        Err(e) => {
            warn!(%e, "admin panel: could not read a quota");
            Vec::new()
        }
    };
    let usage = match panel.store.usage_for(tenant.id.as_str()).await {
        Ok(snapshot) => usage_rows(snapshot.as_ref()),
        Err(e) => {
            // An unreadable usage table must not take the tenant page down: the
            // operator came here to see the tenant, and an error page that
            // hides the hostname because a *measurement* table is broken is a
            // worse outcome than "not measured".
            warn!(%e, "admin panel: could not read the usage snapshot");
            usage_rows(None)
        }
    };
    AdminTenantPage {
        admin,
        csrf: session_csrf(&session).await,
        tenant: TenantRow::new(&tenant, hosts),
        quota,
        usage,
        error: None,
    }
    .into_response()
}

/// The quota **limits**, as `(label, value)` pairs.
///
/// All three always. `TenantQuota`'s limits are `Option<i64>`, and `None` is
/// **"no limit configured"** while `Some(0)` is **"a limit of zero"** — two
/// different states that a table rendering both as a bare `0` would conflate.
/// So `None` renders as `unlimited` and `Some(0)` renders as `0`.
///
/// §6.6.6: limits only, never usage. Usage would mean counting rows in a
/// tenant's store, which is the first thing in the design that would read across
/// the tenant boundary.
fn quota_rows(quota: &TenantQuota) -> Vec<(String, String)> {
    let show = |value: Option<i64>| value.map_or_else(|| "unlimited".to_owned(), |v| v.to_string());
    vec![
        ("Principals".to_owned(), show(quota.principals)),
        ("Calendars".to_owned(), show(quota.calendars)),
        ("Storage (MiB)".to_owned(), show(quota.megabytes)),
    ]
}

/// Usage rows for the tenant page.
///
/// **"not measured" is not "0", and this function is where that is decided.** A
/// usage figure rendered as zero tells a customer they are at their limit when
/// nothing at all is known about them, and the failure is invisible: the number
/// looks like a number. Every absent dimension renders as words.
///
/// `quota_rows` above uses "unlimited" for an absent *quota*, which is the
/// opposite case and deliberately reads differently — a limit that is not set is
/// a fact, and a measurement that was not taken is not.
fn usage_rows(
    snapshot: Option<&rustical_store::tenant_usage::TenantUsage>,
) -> Vec<(String, String)> {
    let Some(s) = snapshot else {
        return vec![("Usage".to_owned(), "not measured yet".to_owned())];
    };
    let show =
        |value: Option<i64>| value.map_or_else(|| "not measured".to_owned(), |v| v.to_string());
    let mut rows = vec![
        ("Principals used".to_owned(), show(s.principals)),
        ("Calendars used".to_owned(), show(s.calendars)),
        ("Address books used".to_owned(), show(s.addressbooks)),
        ("Objects".to_owned(), show(s.object_count)),
    ];
    if let Some(bytes) = s.bytes_on_disk {
        rows.push(("Storage".to_owned(), format_mib(bytes)));
    } else {
        rows.push(("Storage".to_owned(), "not measured".to_owned()));
    }
    rows.push(("Measured".to_owned(), s.measured_at.clone()));
    if !s.is_measured() {
        rows.push((
            "Note".to_owned(),
            "nothing has been counted for this tenant yet — these are not zeros".to_owned(),
        ));
    }
    rows
}

/// Bytes as MiB, rounded, because the quota is in MiB and a panel showing bytes
/// against a limit in MiB makes the reader do arithmetic.
fn format_mib(bytes: i64) -> String {
    const MIB: i64 = 1024 * 1024;
    #[allow(
        clippy::cast_possible_truncation,
        reason = "a display value, not a count"
    )]
    let mib = (bytes / MIB) as f64;
    let exact = bytes as f64 / MIB as f64;
    if (mib - exact).abs() < 0.01 {
        format!("{mib:.0} MiB")
    } else {
        format!("{exact:.2} MiB")
    }
}

#[derive(Debug, Default, serde::Deserialize)]
struct CreateForm {
    #[serde(default)]
    slug: String,
    #[serde(default)]
    display_name: String,
    #[serde(default)]
    plan: String,
    #[serde(default)]
    host: String,
    #[serde(default)]
    csrf: String,
}

#[instrument(skip_all)]
async fn create_tenant(
    State(panel): State<Arc<AdminPanel>>,
    session: Session,
    Form(form): Form<CreateForm>,
) -> Response {
    let admin = match panel.require_admin(&session, Some(&form.csrf)).await {
        Ok(admin) => admin,
        Err(status) => return status.into_response(),
    };
    let Ok(slug) = form.slug.trim().parse::<TenantId>() else {
        return render_create_failure(&session, &admin, "That is not a valid slug.").await;
    };

    // §6.6.2's second door: the CLI refuses a tenant claiming `admin_host`, and
    // so does the panel's own create form. Otherwise the reservation would be
    // enforced only for the tool an operator is told to use, and the browser
    // would be the way around it.
    let host = form.host.trim();
    if !host.is_empty() && !panel.admin_host.is_empty() && panel.admin_host == normalise_host(host)
    {
        return render_create_failure(
            &session,
            &admin,
            "That host is the admin panel's, and is reserved.",
        )
        .await;
    }

    // The admin's name becomes the audit actor. It is validated rather than
    // trusted: `Actor::new` rejects an empty or control-character name, and an
    // audit row that cannot say who did the thing is not a row worth writing.
    let actor = match rustical_store::Actor::new(&admin) {
        Ok(actor) => actor,
        Err(e) => {
            warn!(%e, "admin panel: the admin name is not a valid audit actor");
            return render_create_failure(
                &session,
                &admin,
                "That name cannot be recorded in the audit trail.",
            )
            .await;
        }
    };

    let new = NewTenant {
        tenant: Tenant {
            id: TenantId::generate(),
            slug: slug.clone(),
            display_name: if form.display_name.trim().is_empty() {
                form.slug.trim().to_owned()
            } else {
                form.display_name.trim().to_owned()
            },
            status: TenantStatus::Active,
            config_json: "{}".to_owned(),
            plan: if form.plan.trim().is_empty() {
                "free".to_owned()
            } else {
                form.plan.trim().to_owned()
            },
            suspended_at: None,
            created_at: None,
        },
        hosts: if host.is_empty() {
            Vec::new()
        } else {
            vec![host.to_owned()]
        },
    };
    match panel.store.create_tenant(&new, &actor).await {
        Ok(()) => Redirect::to("/frontend/admin/tenants").into_response(),
        Err(e) => {
            warn!(%e, admin = %admin, slug = %slug, "admin panel: create failed");
            render_create_failure(&session, &admin, "That tenant could not be created.").await
        }
    }
}

/// Re-render the tenant list with an error, on a create that failed.
async fn render_create_failure(session: &Session, admin: &str, error: &str) -> Response {
    (
        StatusCode::BAD_REQUEST,
        AdminTenantsPage {
            admin: admin.to_owned(),
            csrf: session_csrf(session).await,
            tenants: Vec::new(),
            message: None,
            error: Some(error.to_owned()),
        },
    )
        .into_response()
}

#[derive(Debug, Default, serde::Deserialize)]
struct ActionForm {
    #[serde(default)]
    csrf: String,
}

/// Suspend or resume, as one handler.
///
/// Const-generic on the direction so there is **one** implementation of the
/// CSRF check, the actor validation and the audit write. Two handlers would be
/// two chances to forget one of them, and the audit row is the thing that must
/// not vary between the two.
#[instrument(skip_all)]
async fn set_suspended<const SUSPEND: bool>(
    State(panel): State<Arc<AdminPanel>>,
    Path(id): Path<String>,
    session: Session,
    Form(form): Form<ActionForm>,
) -> Response {
    let admin = match panel.require_admin(&session, Some(&form.csrf)).await {
        Ok(admin) => admin,
        Err(status) => return status.into_response(),
    };
    let Ok(tenant_id) = id.parse::<TenantId>() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Ok(actor) = rustical_store::Actor::new(&admin) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let status = if SUSPEND {
        TenantStatus::Suspended
    } else {
        TenantStatus::Active
    };
    match panel
        .store
        .update_tenant_status(&tenant_id, status, &actor)
        .await
    {
        Ok(()) => Redirect::to("/frontend/admin/tenants").into_response(),
        Err(e) => {
            warn!(%e, admin = %admin, tenant = %id, "admin panel: status change failed");
            StatusCode::BAD_REQUEST.into_response()
        }
    }
}

#[instrument(skip_all)]
async fn logout(session: Session) -> Response {
    if let Err(e) = session.delete().await {
        warn!(%e, "admin panel: could not end the session");
    }
    Redirect::to("/frontend/admin/login").into_response()
}

/// The panel's own 404.
///
/// **Not** a redirect to the login form. Row 32 wants a 404, not a 403, and a
/// login form on an unauthenticated request would both leak that a panel exists
/// and turn every probe into a 200.
async fn not_found() -> Response {
    StatusCode::NOT_FOUND.into_response()
}

// ─────────────────────────────────── helpers ────────────────────────────────

/// The session's CSRF token, minting one if it has none.
///
/// A page reached by a browser that already has a session reuses the token; a
/// direct navigation mints one, so the form it renders is one that works rather
/// than one whose every POST is rejected.
async fn session_csrf(session: &Session) -> String {
    if let Ok(Some(existing)) = session.get::<String>("csrf").await {
        return existing;
    }
    rotate_csrf(session).await
}

async fn rotate_csrf(session: &Session) -> String {
    let token: String = rand::rng()
        .sample_iter(Alphanumeric)
        .map(char::from)
        .take(64)
        .collect();
    if let Err(e) = session.insert("csrf", &token).await {
        warn!(%e, "admin panel: could not persist a CSRF token");
    }
    token
}

/// Compare the submitted token with the session's, rotating on mismatch.
///
/// Rotating is why this is not a bare equality check: a session-bound token that
/// survives a failed attempt is a token that is valid twice, so an attacker who
/// observes one (over a shared referer, say) gets one use out of it and not two.
async fn check_csrf(session: &Session, submitted: Option<&str>) -> Result<(), ()> {
    let Some(submitted) = submitted.filter(|t| !t.is_empty()) else {
        return Err(());
    };
    let stored = session.get::<String>("csrf").await.ok().flatten();
    let Some(matched) = stored.as_deref() else {
        return Err(());
    };
    if matched != submitted {
        rotate_csrf(session).await;
        return Err(());
    }
    Ok(())
}

/// Reduce a `Host`-shaped string to the form hosts are compared in:
/// lowercased, port removed, one trailing dot removed.
///
/// **A duplicate of `rustical::host_dispatch::normalise_host`**, which is the
/// authority, and a duplicate because this crate cannot import from the binary
/// crate that defines it and the alternative — threading a closure through
/// `AdminPanel` for one string comparison — is worse.
///
/// Duplication is only acceptable while it is *checked*, so
/// `tests/admin_panel.rs` asserts the two agree on a table of cases including
/// ports, case, trailing dots and a bracketed IPv6 literal. If that test fails,
/// one of them changed and the copy is wrong.
///
/// Public, and named without a `for_test` suffix, because a shim that exists
/// only for a test is a shim the production code cannot be forced to agree
/// with.
#[must_use]
pub fn normalise_host(raw: &str) -> String {
    let host = raw.trim();
    let host = host.find(']').map_or_else(
        || host.split(':').next().unwrap_or(host),
        |close| &host[..=close],
    );
    host.trim_end_matches('.').to_ascii_lowercase()
}
