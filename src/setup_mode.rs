//! **Setup mode** — the appliance's first boot, in a browser (§9.3, item 13).
//!
//! An appliance has no terminal and no `pass` store, so §8.2's `rustical setup`
//! is unavailable to the person who owns it. §9.3's answer: the box boots into
//! setup mode, serves a wizard on the LAN, and the owner completes it with a
//! browser.
//!
//! # The hard requirement, and why it is a check rather than a bind
//!
//! §9.3, quoted:
//!
//! > Bind to the LAN only until setup completes. A CalDAV server reachable
//! > from the WAN with an unconfigured admin account is how appliances get
//! > compromised. This is a hard requirement, not a nicety.
//!
//! The obvious implementation is to bind the LAN address. That is not enough,
//! and on a DHCP-assigned retail unit it is not even available: the address is
//! not known until after DHCP completes, and §9.5 already records that
//! hard-pinning an address is what breaks on retail hardware. So the binding is
//! left to the operator and **the LAN restriction is enforced per request**, on
//! the peer address.
//!
//! # X-Forwarded-For is deliberately ignored here
//!
//! Everything else in this server resolves a client IP through
//! [`crate::host_dispatch`]'s `client_ip`, which honours `X-Forwarded-For` from
//! a *trusted* peer. Setup mode must not use it. There are no trusted proxies
//! configured in setup mode — the whole point is that nothing is set up — so
//! there is no legitimate `XFF` to honour and only an attacker's to believe. A
//! remote client that sent `X-Forwarded-For: 192.168.1.5` would be believed by
//! any implementation that looked at the header, and would be exactly the
//! compromise §9.3 warns about. So [`is_lan_peer`] reads the socket and nothing
//! else, and there is a test that proves it.
//!
//! # No HTTP route can turn setup mode on
//!
//! Re-entering setup mode rewrites the admin account, so a URL that triggers it
//! is a URL that lets anyone who can reach the box take it over. Setup mode is
//! therefore entered only from the filesystem: no config file, or the reset
//! marker. [`RESET_MARKER`] documents the button that writes it. There is
//! deliberately no `POST /frontend/setup/reset`, and a test asserts every such
//! path is a 404 rather than leaving that to review.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, anyhow};
use axum::Router;
use axum::extract::{Form, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use serde::Deserialize;

use rustical_frontend::client_ip::PeerAddr;
use rustical_scheduling::config::SmtpAccount;
use rustical_store::Actor;
use rustical_store::auth::{AuthenticationProvider, Principal, PrincipalType};
use rustical_store::tenant::{Tenant, TenantId, TenantStatus};
use rustical_store::tenant_store::{NewTenant, TenantStore};
use rustical_store_sqlite::{SqlitePrincipalStore, create_db_pool};

use crate::commands::setup::{
    MIN_ADMIN_PASSWORD, create_data_dir, generate_rsvp_secret, hash_password, validate_email,
    validate_url, write_config,
};
use crate::config::Config;

/// The file an operator's button (or a hand) creates to re-enter setup mode.
///
/// In `/tmp`, which is tmpfs on this platform and therefore gone every boot —
/// so a unit that was once reset does not stay in setup mode after a power
/// cycle. Deliberately *not* settable over HTTP; see the module docs.
pub const RESET_MARKER: &str = "rustical-setup-again";

/// One POST, not one page per question.
///
/// A multi-step wizard needs server state, which means a session, which means
/// a cookie — and a cookie on the one surface that must not have one.
#[derive(Debug, Default, Deserialize)]
pub struct SetupForm {
    /// The durable data directory. The appliance default is under `/usr/local`,
    /// because `/var` is tmpfs (§9.5).
    pub data_dir: String,
    /// The public base URL clients are handed.
    pub public_url: String,
    /// The first administrator.
    pub admin_email: String,
    pub admin_password: String,
    /// `open` or `invite` (§7.5's per-tenant registration choice).
    pub registration: String,
    /// Optional SMTP, for sending invites. Empty is legitimate on a LAN-only
    /// appliance; it is not legitimate for a hosted one.
    pub smtp_host: String,
    pub smtp_port: String,
    pub smtp_username: String,
    pub smtp_password: String,
    pub smtp_from: String,
}

/// A per-field error, so the page can re-render with the answers still in it.
#[derive(Debug)]
pub struct FieldError {
    pub field: &'static str,
    pub message: String,
}

impl FieldError {
    fn new(field: &'static str, message: impl Into<String>) -> Self {
        Self {
            field,
            message: message.into(),
        }
    }
}

/// The one rule this module exists to enforce: is this peer on the LAN?
///
/// Private ranges plus loopback plus link-local, and nothing else. A public
/// address — including CGNAT (`100.64.0.0/10`, which some ISPs hand out) and
/// including anything IPv6-global — is refused. CGNAT is refused on purpose:
/// it is not a LAN, and a box that trusted it would be reachable from an
/// upstream network the owner has never thought about.
///
/// The peer address is the socket's, not a header's. See the module docs.
#[must_use]
pub fn is_lan_peer(addr: &SocketAddr) -> bool {
    match addr.ip() {
        IpAddr::V4(v4) => {
            v4.is_private()            // `10.0.0.0/8`, `172.16/12`, `192.168/16`
                || v4.is_loopback()     // 127/8
                || v4.is_link_local()   // 169.254/16
                // 0.0.0.0/8 — "this network", which a client never legitimately
                // sends from, and which several stacks report instead of a real
                // address when a connection is refused upstream.
                || (v4.octets()[0] == 0)
                // The appliance's own WAN on a typical retail unit is a
                // *private* address too (192.168.1.x behind a NAT), so
                // "private" is necessary but not sufficient — the firewall and
                // the port-forward are the other two thirds of this control, and
                // §9.5's "or the appliance ships LAN-only on 443" is the third.
                || v4 == Ipv4Addr::UNSPECIFIED
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                // fc00::/7 — unique local, the IPv6 LAN equivalent.
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                // fe80::/10 — link local.
                || (v6.segments()[0] & 0xffc0) == 0xfe80
                // ::ffff:0:0/96 — IPv4-mapped, judged as the IPv4 it wraps, so
                // an IPv4-mapped *public* address is still refused. A dual-stack
                // listener hands these out for IPv4 peers and testing the v6
                // shape alone would wave a public client through.
                || v6
                    .to_ipv4_mapped()
                    .is_some_and(|v4| is_lan_peer(&SocketAddr::new(IpAddr::V4(v4), addr.port())))
        }
    }
}

/// Should the server come up in setup mode?
///
/// **Two** ways in, both filesystem facts, and the shortness is the point:
///
/// 1. **No config file.** A factory flash's first boot.
/// 2. **The reset marker** exists. Deliberately *not* reachable over HTTP.
///
/// # Why "tenancy on and no tenants" is deliberately NOT a third
///
/// It looks like the obvious third case — the box has a config, but no tenant
/// and no administrator, so it is unconfigured in every way that matters. It is
/// also the worst possible third case, and the pinned test
/// `a_misconfigured_tenancy_section_refuses_to_start` is what caught it.
///
/// A config that *parses* but cannot resolve any Host is a **broken install**,
/// and §3.3's `TenancyConfig::validate` exists to name the fix. Treating it as
/// "unconfigured" silently swallowed that error and served a setup wizard
/// instead — so a server with a bad `base_domain` would have sat there asking
/// anyone on the LAN to re-create the administrator, which is precisely the
/// takeover §9.3's LAN restriction exists to prevent, performed by the device
/// itself. The failure is silent, permanent, and looks like working hardware.
///
/// The fix is at the other end: §9.2's postinst does **not** seed a base
/// `config.toml` on a factory flash, so "no config" and "not configured" are
/// the same state and the ambiguity never arises.
///
/// A malformed config is likewise **not** setup mode: it gets the ordinary parse
/// error, because offering to overwrite a working install because of a stray
/// bracket is how a device loses its configuration.
/// # Errors
///
/// Only if the control plane cannot be opened *and* the caller treats that as
/// fatal. An unreadable control plane is deliberately **not** an error here:
/// see the last arm of the function.
#[must_use]
pub fn should_enter_setup_mode(config_file: &Path) -> bool {
    if reset_marker_path(config_file).exists() {
        return true;
    }
    if !config_file.is_file() {
        return true;
    }
    // A config exists. Whether it is *valid* is not this function's question —
    // the normal path validates it and refuses to start if it is broken, which
    // is the behaviour the operator needs. See this function's docs for why
    // "parses but resolves nothing" must not be read as "unconfigured".
    false
}

fn reset_marker_path(config_file: &Path) -> PathBuf {
    // /tmp is tmpfs on the appliance, so the marker cannot survive a reboot. If
    // /tmp is not writable (an unusual container), fall back to the config's own
    // directory rather than refusing to start.
    let tmp = Path::new("/tmp").join(RESET_MARKER);
    if tmp.is_file() {
        return tmp;
    }
    config_file
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(RESET_MARKER)
}

/// The restart, injected so a test can assert it was asked for.
///
/// On the appliance this is procd: the init script sets `respawn 3600 5 0`, so
/// a `SIGTERM` brings the service straight back — and the *next* boot finds a
/// config and a tenant, so it comes up in normal mode. That is the whole
/// mechanism, and it is why there is no "reload config" path here.
pub trait SetupRestart: Send + Sync + std::fmt::Debug {
    fn request_restart(&self);
}

/// The real one: `SIGTERM` to ourselves, which is what a supervisor expects.
#[derive(Debug, Default)]
pub struct ProcdRestart;

impl SetupRestart for ProcdRestart {
    fn request_restart(&self) {
        // Signalled from a detached task after the response has been written,
        // so the owner actually sees the "done, restarting" page instead of a
        // dropped connection. procd's respawn handles the rest.
        tokio::spawn(async {
            tokio::time::sleep(std::time::Duration::from_millis(400)).await;
            // SAFETY: `kill(getpid(), SIGTERM)` with a pid we obtained ourselves
            // and a constant signal. Async-signal-safe, and the supervisor —
            // not this process — decides what happens next.
            unsafe {
                libc::kill(libc::getpid(), libc::SIGTERM);
            }
        });
    }
}

/// Everything the setup page needs. Kept behind an `Arc` because it is shared
/// by the router and every handler, and because the restart handle has to
/// outlive the request.
#[derive(Debug)]
pub struct SetupMode {
    pub config_file: PathBuf,
    /// Bound and reported on the page, so the owner is told the address to open
    /// rather than having to guess it.
    pub bind: SocketAddr,
    restart: Arc<dyn SetupRestart>,
}

impl SetupMode {
    #[must_use]
    pub fn new(config_file: PathBuf, bind: SocketAddr, restart: Arc<dyn SetupRestart>) -> Self {
        Self {
            config_file,
            bind,
            restart,
        }
    }

    /// The routes. **Two**, and the absence of a third is deliberate: there is
    /// no `reset`, no `reconfigure` and no `delete`. Setup mode is entered from
    /// the filesystem and left by writing a config.
    pub fn router(self: Arc<Self>) -> Router {
        Router::new()
            .route("/frontend/setup", get(get_page))
            .route("/frontend/setup", post(submit))
            // Not a route. Axum answers 405 for a wrong method and 404 for the
            // reset paths -- see the module docs. There is deliberately no
            // fallback handler either: a setup-mode server that answered 200
            // for unknown paths would be a convenient scanner target.
            .with_state(self)
    }

    async fn apply(&self, form: &SetupForm) -> Result<SetupSummary, ApplyError> {
        // Validate everything first, and write nothing until it all passes: a
        // half-applied setup leaves a config with no tenant, which is the one
        // state from which the box serves nothing and explains nothing.
        let errors = validate(form);
        if !errors.is_empty() {
            return Err(ApplyError::Fields(errors));
        }
        self.write(form).await
    }

    /// Build the config the answers describe. Pure — no filesystem, no database
    /// — so it is separated from the half that touches both.
    fn build_config(&self, form: &SetupForm, data_dir: &Path, db_path: &Path) -> Config {
        let mut config = Config::default_config();
        config.data_store =
            crate::config::DataStoreConfig::Sqlite(crate::config::SqliteDataStoreConfig {
                db_url: format!("file:{}", db_path.display()),
                run_repairs: true,
                skip_broken: true,
            });
        // The setup page is on the LAN and the server keeps listening there, so
        // the bind is the appliance's own address — not `0.0.0.0` by default and
        // not `127.0.0.1`, which a browser on another machine cannot reach.
        config.http.bind = Some(self.bind.to_string());
        config.http.host = None;
        config.http.port = None;

        if let Ok(url) = validate_url("public_url", form.public_url.trim()) {
            config.subscriptions.public_url = Some(url);
        }

        // Tenancy on, one tenant, and the control plane beside it (§9.3: "the
        // control DB + tenant #1"). A separate file from the tenant store is
        // §3.4's whole point and is what lets a second tenant exist later.
        let control_db = data_dir.join("control.sqlite3");
        config.tenancy = crate::config::TenancyConfig {
            enabled: true,
            base_domain: default_base_domain(form),
            default_tenant: "default".to_owned(),
            control_db_url: format!("file:{}", control_db.display()),
            ..Default::default()
        };

        // `invite` is the default for an appliance: the device is on a home
        // network and the first thing an open form does is let anyone who can
        // reach the LAN create an account. §9.3 asks for this choice; the
        // answer defaults to the safe one.
        config.registration.enabled = true;
        config.registration.invite_required = form.registration.trim() != "open";

        // SMTP is optional: a LAN-only appliance can hand out accounts in person,
        // and a half-filled block is refused by `validate` rather than written
        // as a config whose invites silently fail.
        let smtp = form.smtp_host.trim();
        if !smtp.is_empty() {
            let port: u16 = form.smtp_port.trim().parse().unwrap_or(587);
            config.scheduling.smtp = vec![SmtpAccount {
                identity: form.smtp_from.trim().to_owned(),
                host: smtp.to_owned(),
                port,
                username: form.smtp_username.trim().to_owned(),
                password: form.smtp_password.clone(),
                displayname: None,
            }];
            config.scheduling.enabled = true;
        }

        // The RSVP secret is the one secret the wizard ever *creates*. It is
        // written to the config and never printed.
        config.scheduling.rsvp_secret = Some(generate_rsvp_secret());

        config
    }

    /// Write the config, then the two databases, in that order.
    async fn write(&self, form: &SetupForm) -> Result<SetupSummary, ApplyError> {
        let data_dir = PathBuf::from(form.data_dir.trim());
        let db_path = data_dir.join("db.sqlite3");
        let config = self.build_config(form, &data_dir, &db_path);
        let smtp = form.smtp_host.trim().to_owned();
        // The control plane is a *different file* from any tenant store (§3.4),
        // and it lives beside them.
        let control_db = data_dir.join("control.sqlite3");
        create_data_dir(&data_dir)?;
        write_config(&self.config_file, &config)?;

        let pool = create_db_pool(&format!("sqlite://{}", db_path.display()), true)
            .await
            .with_context(|| {
                format!(
                    "preparing the tenant database at {} — is the data directory writable?",
                    db_path.display()
                )
            })?;

        let control_url = format!("sqlite://{}", control_db.display());
        let control = crate::tenancy::open_control_plane(&control_url).await?;
        let actor = Actor::new("setup-wizard").map_err(|e| anyhow!("bad actor name: {e}"))?;
        let slug: TenantId = "default"
            .parse()
            .map_err(|e| anyhow!("the tenant slug 'default' is not valid: {e}"))?;
        control
            .create_tenant(
                &NewTenant {
                    tenant: Tenant {
                        id: TenantId::generate(),
                        slug,
                        display_name: "Default".to_owned(),
                        status: TenantStatus::Active,
                        config_json: "{}".to_owned(),
                        plan: "appliance".to_owned(),
                        suspended_at: None,
                        created_at: None,
                    },
                    hosts: vec![default_base_domain(form).clone()],
                },
                &actor,
            )
            .await
            .map_err(|e| anyhow!("could not create tenant #1: {e}"))?;

        // The administrator, with the collections a client needs, using the
        // *same* password hashing and seeding as the CLI wizard and as
        // self-registration. Three code paths that must not drift.
        // **Principal first, then its collections.** `calendars.principal` has a
        // foreign key to `principals.id`, so the other order is a 787 FOREIGN KEY
        // constraint failure — the wizard's first draft had it backwards and the
        // only symptom was an opaque 500 on a device with no terminal.
        let principal_store = SqlitePrincipalStore::new(pool.clone());
        principal_store
            .insert_principal(
                Principal {
                    id: form.admin_email.trim().to_owned(),
                    displayname: None,
                    memberships: vec![],
                    password: Some(hash_password(form.admin_password.trim())),
                    principal_type: PrincipalType::Individual,
                    needs_password_change: false,
                    privileges: std::collections::BTreeMap::default(),
                },
                false,
            )
            .await
            .map_err(|e| anyhow!("could not create the administrator: {e}"))?;

        let (send, _recv) = tokio::sync::mpsc::channel(1000);
        let cal_store =
            rustical_store_sqlite::SqliteCalendarStore::new(pool.clone(), send.clone(), true);
        let addr_store =
            rustical_store_sqlite::SqliteAddressbookStore::new(pool.clone(), send, true);
        crate::register::seed_collections(&cal_store, &addr_store, form.admin_email.trim())
            .await
            .context("seeding the administrator's calendar and addressbook")?;

        // The marker, if there was one, has done its job. Left in place it would
        // put the *next* boot back into setup mode, and the owner would find
        // their working appliance offering to re-create the admin.
        let marker = reset_marker_path(&self.config_file);
        let _ = std::fs::remove_file(&marker);

        Ok(SetupSummary {
            admin: form.admin_email.trim().to_owned(),
            tenant: "default".to_owned(),
            public_url: form.public_url.trim().to_owned(),
            data_dir: data_dir.display().to_string(),
            smtp_configured: !smtp.is_empty(),
        })
    }
}

/// `GET /frontend/setup` -- the form.
async fn get_page(State(mode): State<Arc<SetupMode>>, PeerAddr(peer): PeerAddr) -> Response {
    if let Some(denied) = refuse_non_lan(peer) {
        return denied;
    }
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        render_page(None, &mode.bind),
    )
        .into_response()
}

/// `POST /frontend/setup` -- validate, write, restart.
async fn submit(
    State(mode): State<Arc<SetupMode>>,
    PeerAddr(peer): PeerAddr,
    Form(form): Form<SetupForm>,
) -> Response {
    if let Some(denied) = refuse_non_lan(peer) {
        return denied;
    }
    match mode.apply(&form).await {
        Ok(summary) => {
            // Written and durable. The restart is the last step and is
            // requested *after* the work succeeded, so a failed setup never
            // bounces the box into a boot loop.
            mode.restart.request_restart();
            (
                StatusCode::OK,
                [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
                render_done(&summary),
            )
                .into_response()
        }
        Err(ApplyError::Fields(errors)) => (
            StatusCode::BAD_REQUEST,
            [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
            render_page(Some((&form, &errors)), &mode.bind),
        )
            .into_response(),
        Err(ApplyError::Fatal(e)) => {
            // The whole chain, not `to_string()`. "seeding the administrator's
            // calendar" is useless to whoever is holding the device; the SQLite
            // error underneath it is the part that names the file.
            tracing::error!(error = ?e, "setup submission failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
                format!(
                    "<!doctype html><meta charset=utf-8><h1>Setup failed</h1><pre>{}</pre>",
                    escape(&format!("{e:?}"))
                ),
            )
                .into_response()
        }
    }
}

/// The two ways a submission can fail.
///
/// Kept apart because they mean different things to the person filling in the
/// form: "you typed something wrong" (stay here and fix it) versus "the device
/// could not do it" (stop and read the message).
#[derive(Debug)]
pub enum ApplyError {
    Fields(Vec<FieldError>),
    Fatal(anyhow::Error),
}

impl From<anyhow::Error> for ApplyError {
    fn from(e: anyhow::Error) -> Self {
        Self::Fatal(e)
    }
}

impl std::fmt::Display for ApplyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Fields(errors) => {
                for e in errors {
                    writeln!(f, "{}: {}", e.field, e.message)?;
                }
                Ok(())
            }
            Self::Fatal(e) => write!(f, "{e}"),
        }
    }
}

/// Validate every field. Runs to completion and reports *all* the problems, so
/// a person filling in a form on a phone is not sent round one error at a time.
#[must_use]
pub fn validate(form: &SetupForm) -> Vec<FieldError> {
    let mut errors = Vec::new();

    if form.data_dir.trim().is_empty() {
        errors.push(FieldError::new("data_dir", "a data directory is required"));
    } else if form.data_dir.trim().starts_with("/var") {
        // §9.5: /var is tmpfs. This is worth catching in the form because the
        // symptom otherwise appears days later, as an empty calendar after a
        // power cut, with nothing in the logs to explain it.
        errors.push(FieldError::new(
            "data_dir",
            "/var is a RAM disk on this platform and is wiped on every reboot — use \
             something under /usr/local",
        ));
    }

    if let Err(e) = validate_email(form.admin_email.trim()) {
        errors.push(FieldError::new("admin_email", e.to_string()));
    }

    let password = form.admin_password.trim();
    if password.len() < MIN_ADMIN_PASSWORD {
        errors.push(FieldError::new(
            "admin_password",
            format!(
                "at least {MIN_ADMIN_PASSWORD} characters (this is the only account on the \
                 appliance)"
            ),
        ));
    }

    match form.registration.trim() {
        "open" | "invite" => {}
        other => errors.push(FieldError::new(
            "registration",
            format!("expected `open` or `invite`, got `{other}`"),
        )),
    }

    // SMTP is all-or-nothing. A half-filled form would write a config whose
    // invites silently fail to send, which reads as "registration is broken".
    let smtp = form.smtp_host.trim();
    if !smtp.is_empty() {
        for (field, value, what) in [
            ("smtp_username", form.smtp_username.trim(), "a username"),
            ("smtp_password", form.smtp_password.as_str(), "a password"),
            ("smtp_from", form.smtp_from.trim(), "a From address"),
        ] {
            if value.trim().is_empty() {
                errors.push(FieldError::new(
                    field,
                    format!("an SMTP host was given, so {what} is required"),
                ));
            }
        }
    }
    if let Ok(port) = form.smtp_port.trim().parse::<u16>() {
        if port == 0 {
            errors.push(FieldError::new("smtp_port", "a port cannot be 0"));
        }
    } else if !form.smtp_port.trim().is_empty() {
        errors.push(FieldError::new("smtp_port", "the port must be a number"));
    }

    errors
}

/// The public base URL, or the host the wizard is being read on.
///
/// A first boot usually has no DNS yet — the whole reason the owner is at
/// `192.168.x.x/setup` — so a missing public URL falls back to the host that
/// served the page rather than to nothing. An appliance reachable only by IP is
/// a working appliance.
fn default_base_domain(form: &SetupForm) -> String {
    let host = form.public_url.trim();
    if host.is_empty() {
        return "localhost".to_owned();
    }
    host.trim_start_matches("https://")
        .trim_start_matches("http://")
        .trim_end_matches('/')
        .to_owned()
}

#[derive(Debug)]
pub struct SetupSummary {
    pub admin: String,
    pub tenant: String,
    pub public_url: String,
    pub data_dir: String,
    pub smtp_configured: bool,
}

fn refuse_non_lan(peer: Option<SocketAddr>) -> Option<Response> {
    // No peer means a Unix socket or an in-process test. There is nobody to
    // judge, and a CalDAV server must not serve a CalDAV server to "somebody"
    // on that basis -- so it is a refusal, not a pass.
    let Some(addr) = peer else {
        return Some(
            (
                StatusCode::FORBIDDEN,
                [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
                "setup mode needs a TCP peer address; there is none, so this request is refused.\n",
            )
                .into_response(),
        );
    };
    if is_lan_peer(&addr) {
        return None;
    }
    tracing::warn!(
        peer = %addr,
        "refused a setup-mode request from a non-LAN address (§9.3: a CalDAV server reachable \
         from the WAN with an unconfigured admin account is how appliances get compromised)"
    );
    Some(
        (
            StatusCode::FORBIDDEN,
            [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
            format!(
                "setup mode is only available from the local network.\n\
                 This request came from {addr}, which is not a LAN address.\n"
            ),
        )
            .into_response(),
    )
}

#[must_use]
fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn render_page(errors: Option<(&SetupForm, &[FieldError])>, bind: &SocketAddr) -> String {
    // Writing into a `String` is infallible, but the type system cannot know
    // that, so every `write!` here is `let _ =`.
    use std::fmt::Write as _;
    let (form, errs) = errors.map_or((None, &[][..]), |(f, e)| (Some(f), e));
    let v = |s: Option<&str>| escape(s.unwrap_or_default());
    let mut out = String::new();
    out.push_str(
        "<!doctype html><html><head><meta charset=utf-8>\
         <meta name=viewport content='width=device-width,initial-scale=1'>\
         <title>Omnical setup</title><style>\
         body{font:16px/1.5 system-ui,sans-serif;max-width:34rem;margin:3rem auto;padding:0 1rem}\
         label{display:block;margin:1rem 0 .25rem;font-weight:600}\
         input{width:100%;padding:.5rem;font:inherit;box-sizing:border-box}\
         button{margin-top:1.5rem;padding:.6rem 1.2rem;font:inherit}\
         .e{color:#a00;font-size:.9rem;margin:.25rem 0}\
         .warn{background:#fff4e5;border-left:3px solid #e90;padding:.6rem .8rem;margin:1rem 0}\
         </style></head><body>",
    );
    out.push_str("<h1>Set up Omnical</h1>");
    let _ = write!(
        out,
        "<p>Open from a browser on the same network as this device. \
         It is listening on <code>{}</code> and is <strong>not reachable from \
         the internet</strong> until setup is finished.</p>",
        escape(&bind.to_string())
    );
    if !errs.is_empty() {
        out.push_str("<div class=e><strong>Please fix:</strong><ul>");
        for e in errs {
            let _ = write!(
                out,
                "<li><code>{}</code>: {}</li>",
                e.field,
                escape(&e.message)
            );
        }
        out.push_str("</ul></div>");
    }
    out.push_str("<form method=post action=/frontend/setup>");
    let _ = write!(
        out,
        "<label for=data_dir>Data directory</label>\
         <input id=data_dir name=data_dir value='{}'>\
         <div class=e>The database lives here. Use something under /usr/local — \
         /var is wiped on every reboot.</div>",
        v(form.map(|f| f.data_dir.as_str()))
            .replace("value=''", "value='/usr/local/share/omnical'")
    );
    let _ = write!(
        out,
        "<label for=public_url>Public URL</label>\
         <input id=public_url name=public_url value='{}' placeholder='https://cal.example.com'>\
         <div class=e>Optional. Leave empty until you have a name or a dynamic-DNS address.</div>",
        v(form.map(|f| f.public_url.as_str()))
    );
    let _ = write!(
        out,
        "<label for=admin_email>Administrator email</label>\
         <input id=admin_email name=admin_email type=email value='{}'>",
        v(form.map(|f| f.admin_email.as_str()))
    );
    let _ = write!(
        out,
        "<label for=admin_password>Administrator password</label>\
         <input id=admin_password name=admin_password type=password minlength=12>\
         <div class=e>At least 12 characters. This is the only account on the device.</div>",
    );
    let _ = write!(out, "{}", registration_select(form));
    out.push_str(
        "<div class=warn><strong>Leaving SMTP blank</strong> means registration invitations \
         cannot be emailed. Fine on a home network; fill this in before giving anyone outside \
         the network an account.</div>",
    );
    let _ = write!(
        out,
        "<label for=smtp_host>SMTP host (optional)</label>\
         <input id=smtp_host name=smtp_host value='{}'>",
        v(form.map(|f| f.smtp_host.as_str()))
    );
    let _ = write!(
        out,
        "<div class=e>Port <input style='width:6rem' name=smtp_port value='{}' placeholder=587> \
         · username <input style='width:12rem' name=smtp_username value='{}'> \
         · password <input style='width:12rem' type=password name=smtp_password value='{}'> \
         · from <input style='width:12rem' name=smtp_from value='{}'></div>",
        v(form.map(|f| f.smtp_port.as_str())),
        v(form.map(|f| f.smtp_username.as_str())),
        escape(form.map_or("", |f| f.smtp_password.as_str())),
        v(form.map(|f| f.smtp_from.as_str()))
    );
    out.push_str("<button type=submit>Finish setup</button></form>");
    out.push_str(
        "<p style='font-size:.85rem;color:#666;margin-top:2rem'>\
         To start over later, remove <code>/etc/rustical/config.toml</code> from a shell, or \
         create the file <code>/tmp/rustical-setup-again</code> and restart the service. \
         There is deliberately no web link for this.</p>",
    );
    out.push_str("</body></html>");
    out
}

/// The registration `<select>`, defaulting to `invite`.
///
/// The default matters: the device is on a home network, and the first thing an
/// open form does is let anyone who can reach the LAN create an account. §9.3
/// asks for the choice; the answer somebody hits return on is the safe one.
fn registration_select(form: Option<&SetupForm>) -> String {
    let open = form.is_some_and(|f| f.registration.trim() == "open");
    let sel = |b: bool| if b { " selected" } else { "" };
    format!(
        "<label for=registration>Who may register</label>\
         <select id=registration name=registration>\
         <option value=invite{}>Invite only (recommended)</option>\
         <option value=open{}>Anyone</option></select>",
        sel(!open),
        sel(open)
    )
}

fn render_done(summary: &SetupSummary) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    let _ = write!(
        out,
        "<!doctype html><html><head><meta charset=utf-8>\
         <meta name=viewport content='width=device-width,initial-scale=1'>\
         <title>Omnical is ready</title></head><body style='font:16px/1.6 system-ui,sans-serif;\
         max-width:34rem;margin:3rem auto;padding:0 1rem'>\
         <h1>Setup complete</h1>\
         <p>Omnical is restarting. This page will stop working in a moment — that is expected.</p>\
         <ul>\
         <li>Administrator: <code>{}</code></li>\
         <li>Tenant: <code>{}</code></li>\
         <li>Data directory: <code>{}</code></li>\
         <li>Public URL: <code>{}</code></li>\
         <li>SMTP: {}</li>\
         </ul>\
         <p>After the restart, sign in at <code>/frontend/login</code>.\
         The setup page will be gone: setup mode is only offered when there is no \
         configuration at all.</p></body></html>",
        escape(&summary.admin),
        escape(&summary.tenant),
        escape(&summary.data_dir),
        escape(if summary.public_url.is_empty() {
            "(not set — using the address you reached this page on)"
        } else {
            &summary.public_url
        }),
        if summary.smtp_configured {
            "configured"
        } else {
            "<strong>not configured</strong> — invitations cannot be emailed yet"
        }
    );
    out
}

/// Serve setup mode on `bind` until the wizard completes.
///
/// # Errors
///
/// If `bind` cannot be bound, or the listener fails.
pub async fn serve_setup_mode(config_file: &Path, bind: SocketAddr) -> Result<()> {
    let app = Arc::new(SetupMode::new(
        config_file.to_path_buf(),
        bind,
        Arc::new(ProcdRestart),
    ));
    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .with_context(|| format!("could not bind the setup page to {bind}"))?;
    tracing::warn!(
        bind = %bind,
        "SERVING SETUP MODE — this device has no configuration yet. \
         The wizard is reachable from the local network only, and the service will restart \
         into normal mode once it completes (§9.3)."
    );
    let make = axum::ServiceExt::<axum::extract::Request>::into_make_service_with_connect_info::<
        SocketAddr,
    >(app.router());
    axum::serve(listener, make).await?;
    Ok(())
}
