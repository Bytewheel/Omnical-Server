//! The appliance panel — Data / Network / Firmware (`NEXT_AGENT_ITEM14_PANEL.md`,
//! item 14, §9.4).
//!
//! ## Why this is beside the admin panel and not inside it
//!
//! The admin panel has a load-bearing invariant: **it never opens a tenant's
//! database**, proved behaviourally by `tests/admin_panel.rs:1085` (a tenant
//! whose store directory does not exist still lists, still shows a detail page,
//! and can still be suspended). `AdminPanel` holds two control-plane trait
//! objects and has no path to a `StoreBundle`, so the invariant is a property of
//! the types rather than a promise.
//!
//! This panel *does* have to reach a database — a restore replaces one. So it is
//! a **separate router on the same hosts**, and it never gains a `TenantStore`.
//! What it holds instead is an [`ApplianceService`], which is a trait the
//! `rustical` crate implements. The dependency runs one way: this crate declares
//! the interface, the binary provides the implementation. `AdminPanel` is
//! untouched, so its test still means what it meant.
//!
//! ## Why the service is a trait and not a path
//!
//! `crates/frontend` has no `rustical` dependency (`Cargo.toml:187` is one-way),
//! so it cannot call `statvfs`, run `ip`, or read the config. Rather than
//! reimplement those — or take a `&Path` and let the view layer shell out — the
//! binary hands over a trait object whose every string has **already been
//! redacted** by `rustical::commands::support_bundle::redact`. The panel renders
//! values it cannot derive a secret from, and there is exactly one redaction
//! implementation in the workspace.
//!
//! ## The three things that destroy data, and what each one demands
//!
//! | Action | Demand | Why |
//! |---|---|---|
//! | restore | confirmation **and** a row-count check afterwards | it overwrites the live database; `cmd_restore` already takes a safety copy |
//! | flash | confirmation, a space check, and an injected writer | `sysupgrade` writes flash and cannot be undone |
//! | backup | nothing | it only reads |
//!
//! The restore's row-count check is deliberately **not** available as a preview.
//! It runs after the swap, in `main`, and its result is read back from disk — see
//! `rustical::appliance::complete_staged_restore`. A panel that showed a
//! "verified" badge *before* restoring would be claiming something it has not
//! measured.
//!
//! ## Auth, CSRF and audit
//!
//! **Reused, not duplicated.** [`AdminPanel::require_admin`] is the only gate, and
//! this router calls it rather than reimplementing the 404-vs-403 distinction
//! that `admin.rs:427-431` records as learned the hard way. Session and CSRF
//! helpers are shared module-locals. The panel's own cookie and session layer
//! are the admin panel's, so there is one login.

use std::sync::Arc;

use askama::Template;
use askama_web::WebTemplate;
use axum::Extension;
use axum::Router;
use axum::extract::{Form, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use tower_sessions::Session;
use tracing::{error, instrument, warn};

use super::admin::{AdminPanel, session_csrf};

/// What the panel can ask the host about itself.
///
/// Implemented in the `rustical` crate, which is where `statvfs`, `ip -j addr`
/// and [`redact`](https://docs.rs) — sorry, the crate's own `redact` — live.
///
/// **Every `String` this trait returns has already been redacted.** That is the
/// trait's contract, and it is the whole reason the panel is safe to screenshot
/// into a support ticket. A test asserts it by handing the fake service a
/// config holding a password and checking the rendered HTML.
#[async_trait::async_trait]
pub trait ApplianceService: Send + Sync + std::fmt::Debug {
    /// The Data section: restore points, the live database, and any restore
    /// waiting for a restart.
    ///
    /// `Err` when the backup directory cannot be listed. **Never** an empty list
    /// for a failure — see the trait's docs on absence.
    async fn data(&self) -> Result<DataView, String>;

    /// The Network section: addresses, bind, public URL, data root.
    ///
    /// `Err` when `ip` cannot be run or its output will not parse. An
    /// unmeasurable network is an error the page shows, never a silent empty
    /// list that reads as "this box is offline".
    async fn network(&self) -> Result<NetworkView, String>;

    /// The Firmware section: version, sizes, free space, whether a flash fits.
    async fn firmware(&self) -> Result<FirmwareView, String>;

    /// Stage a restore of the named archive, and request the restart that
    /// completes it.
    ///
    /// # Errors
    /// Everything verification can fail with, plus an I/O failure. On any of
    /// them the live database is untouched.
    async fn stage_restore(&self, archive_name: &str, admin: &str) -> Result<StagedView, String>;

    /// Is a restore waiting for a restart? Checked before the button is offered
    /// so a second one cannot be pressed on top of the first.
    async fn restore_pending(&self) -> bool;

    /// The last completed restore's report, if one exists.
    async fn last_report(&self) -> Option<Result<ReportView, String>>;

    /// Flash `image_name`, which is a **file name**, never a path.
    ///
    /// # Errors
    /// Whatever stopped the flash. A real implementation's message is the only
    /// thing an operator has, so it is surfaced rather than replaced.
    async fn flash(&self, image_name: &str, admin: &str) -> Result<(), String>;

    /// The firmware images available to flash, by file name.
    async fn firmware_images(&self) -> Result<Vec<ImageView>, String>;

    /// Is a flashing tool present? False on a host that is not an appliance, and
    /// the flash button is not offered at all.
    async fn can_flash(&self) -> bool;

    /// Record a destructive action in the control plane's audit trail.
    ///
    /// # Errors
    /// A store failure. Callers **log and continue** rather than failing the
    /// action: the action already happened, and refusing to record it does not
    /// un-do it. A missing audit row is a real problem, so it is a `warn!`.
    async fn audit(&self, admin: &str, action: &str, detail: &str) -> Result<(), String>;

    /// Request the restart that completes a staged restore.
    fn request_restart(&self);
}

// ───────────────────────────────── views ────────────────────────────────────

/// The Data section, as the template sees it.
#[derive(Debug, Clone)]
pub struct DataView {
    pub database: String,
    pub backup_dir: String,
    pub database_exists: bool,
    pub restore_points: Vec<RestorePointView>,
    /// Set when a restore is staged and waiting. The page must say so plainly,
    /// because until the restart happens **nothing has been restored**.
    pub pending: Option<PendingView>,
    pub last_report: Option<ReportView>,
    /// A report file that exists but will not parse. Distinct from
    /// `last_report == None`, which means "no restore has been run".
    pub report_error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct RestorePointView {
    /// The archive's **file name**, which is what the form field carries. The
    /// server re-joins it against the configured directory, so a client cannot
    /// use this field to read an arbitrary path.
    pub name: String,
    pub size_text: String,
    pub modified_text: String,
}

#[derive(Debug, Clone)]
pub struct PendingView {
    pub archive: String,
    pub archive_created_at: String,
    pub staged: String,
    pub safety_copy: Option<String>,
    pub requested_by: String,
}

#[derive(Debug, Clone)]
pub struct ReportView {
    pub archive: String,
    pub archive_created_at: String,
    pub completed_at: String,
    pub requested_by: String,
    /// `None` when the integrity check did not pass, which the template renders
    /// as a failure rather than as an absent value.
    pub verified: bool,
    pub integrity_check: String,
    /// The one claim a row count supports. **Never** says no data was lost.
    pub claim: String,
    pub rows: Vec<(String, String, String)>,
    pub mismatches: Vec<String>,
    pub missing: Vec<String>,
    pub added_by_migration: Vec<String>,
    pub losses: Vec<(String, String, String)>,
    pub safety_copy: Option<String>,
}

#[derive(Debug, Clone)]
pub struct NetworkView {
    pub addresses: Vec<AddressView>,
    pub bind: String,
    pub public_url: Option<String>,
    pub data_root: String,
    pub admin_hosts: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct AddressView {
    pub interface: String,
    pub family: String,
    pub address: String,
    pub prefix_len: u8,
}

#[derive(Debug, Clone)]
pub struct FirmwareView {
    pub version: String,
    pub commit: String,
    pub size_text: String,
    pub free_text: String,
    pub overlay_mount: String,
    /// Where images are looked for. Rendered because "no images to flash" is a
    /// very different problem when the operator can see that the panel is
    /// looking in the wrong directory.
    pub firmware_dir: String,
    /// `false` when free space could not be measured. The template says so, and
    /// the flash button refuses — "not measured" is not "measured and empty".
    pub has_room: bool,
    pub space_known: bool,
    pub can_flash: bool,
    pub images: Vec<ImageView>,
}

#[derive(Debug, Clone)]
pub struct ImageView {
    pub name: String,
    pub size_text: String,
}

#[derive(Debug, Clone)]
pub struct StagedView {
    pub archive: String,
    pub archive_created_at: String,
    pub staged: String,
    pub safety_copy: Option<String>,
    pub expected_tables: usize,
    pub requested_by: String,
}

// ──────────────────────────────── templates ─────────────────────────────────

#[derive(Template, WebTemplate)]
#[template(path = "pages/appliance.html")]
struct AppliancePage {
    admin: String,
    csrf: String,
    data: Result<DataView, String>,
    network: Result<NetworkView, String>,
    firmware: Result<FirmwareView, String>,
}

#[derive(Template, WebTemplate)]
#[template(path = "pages/appliance_confirm.html")]
struct ApplianceConfirmPage {
    admin: String,
    csrf: String,
    /// `restore` or `firmware`. One template for both because the *structure* of
    /// a confirmation is the same and only the facts differ — and two templates
    /// would be two places for the "what this will do" list to go stale.
    action: &'static str,
    title: String,
    /// The bullet list of what is about to happen. Rendered as a list because a
    /// destructive action described in a paragraph is one nobody reads twice.
    consequences: Vec<String>,
    /// The hidden field naming what is being acted on. A file name, never a
    /// path.
    target: String,
    /// Extra context shown above the consequences (the archive's age, the free
    /// space).
    detail: Vec<String>,
    error: Option<String>,
    /// Why the action is unavailable, if it is. `None` when it is available.
    blocked: Option<String>,
}

#[derive(Template, WebTemplate)]
#[template(path = "pages/appliance_staged.html")]
struct ApplianceStagedPage {
    admin: String,
    csrf: String,
    staged: StagedView,
}

// ──────────────────────────────── the panel ─────────────────────────────────

/// The appliance panel's state.
///
/// Holds only an [`ApplianceService`]. **No store, no `StoreBundle`, and no
/// tenant database** — the one thing this panel must never gain, because the
/// admin panel beside it is forbidden from having it and a restore is a good
/// excuse to add it "just this once".
///
/// The admin handle arrives per-request as the router's own
/// `State<Arc<AdminPanel>>` and this struct as an `Extension`, rather than this
/// struct holding a copy of the admin panel. Two states, one router: axum's
/// `State` is one type per router, and an `Extension` is the supported way to
/// carry a second value into the same routes.
pub struct AppliancePanel {
    service: Arc<dyn ApplianceService>,
}

impl AppliancePanel {
    /// # Panics
    /// Never. Kept `#[must_use]` for the same reason `AdminPanel::new` is: a
    /// misconfiguration should degrade to "the section is not there", not to a
    /// boot panic, and every refusal that matters is a startup refusal in
    /// `rustical::admin` already.
    #[must_use]
    pub const fn new(service: Arc<dyn ApplianceService>) -> Self {
        Self { service }
    }

    /// The routes, to be merged into the admin panel's router.
    ///
    /// **Merged, not mounted beside.** A second `SessionManagerLayer` over a
    /// second `MemoryStore` would mean a second login and two session cookies
    /// for one operator, and the admin session would not be visible here — so
    /// these routes go *inside* the panel's existing router and share its
    /// session, its cookie and its CSRF token. That is the "reuse, do not
    /// duplicate" instruction implemented rather than merely quoted.
    ///
    /// The state is [`State<Arc<AdminPanel>>`] because that is what the merged
    /// router carries; the appliance panel itself arrives as an `Extension`.
    pub fn routes(self: Arc<Self>) -> Router<Arc<AdminPanel>> {
        Router::new()
            .route("/frontend/admin/appliance", get(appliance_page))
            .route("/frontend/admin/appliance/restore", get(confirm_restore))
            .route("/frontend/admin/appliance/restore", post(do_restore))
            .route("/frontend/admin/appliance/firmware", get(confirm_flash))
            .route("/frontend/admin/appliance/firmware", post(do_flash))
    }
}

// ──────────────────────────────── handlers ──────────────────────────────────

/// The three sections, on one page.
///
/// Each section's failure is kept separate: an unreadable Network section must
/// not blank Data, and neither may render as "nothing to report".
#[instrument(skip_all)]
async fn appliance_page(
    State(panel): State<Arc<AdminPanel>>,
    Extension(appliance): Extension<Arc<AppliancePanel>>,
    session: Session,
) -> Response {
    let Some(admin) = panel.require_admin_read(&session).await else {
        return StatusCode::NOT_FOUND.into_response();
    };
    // Gathered concurrently: these are three independent reads and the page is
    // the thing an operator opens when something is already wrong.
    let (data, network, firmware) = tokio::join!(
        appliance.service.data(),
        appliance.service.network(),
        appliance.service.firmware(),
    );
    AppliancePage {
        admin,
        csrf: session_csrf(&session).await,
        // Logged, not rendered raw: a service error is a message for the
        // operator, and it goes in the page so they can act on it.
        data: log_section("data", data),
        network: log_section("network", network),
        firmware: log_section("firmware", firmware),
    }
    .into_response()
}

/// Turn a section's error into a rendered one, after logging it.
fn log_section<T>(name: &'static str, result: Result<T, String>) -> Result<T, String> {
    if let Err(message) = &result {
        warn!(section = name, %message, "appliance panel: a section could not be read");
    }
    result
}

#[derive(Debug, Default, serde::Deserialize)]
struct RestoreForm {
    #[serde(default)]
    csrf: String,
    /// The archive's **file name**. Re-validated against the configured backup
    /// directory by the service; never joined onto a path the client chose.
    #[serde(default)]
    archive: String,
    /// The operator must type the archive's name to confirm.
    ///
    /// **A checkbox would be too weak.** The cost of a wrong restore is the
    /// customer's data at an older timestamp, and a checkbox is a reflex, not a
    /// decision. Typing the name forces the operator to read which archive they
    /// picked — the same treatment `rustical tenant delete --confirm` gets.
    #[serde(default)]
    confirm: String,
}

#[derive(Debug, Default, serde::Deserialize)]
struct FlashForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    image: String,
    /// Typed confirmation, for the same reason as the restore's.
    #[serde(default)]
    confirm: String,
}

/// The restore confirmation page.
///
/// Reached by GET with the archive's name, so an operator can *see* what they
/// are about to do before the POST. The POST alone would be a form that
/// destroys data on submit.
#[instrument(skip_all)]
async fn confirm_restore(
    State(panel): State<Arc<AdminPanel>>,
    Extension(appliance): Extension<Arc<AppliancePanel>>,
    session: Session,
    Query(form): Query<RestoreForm>,
) -> Response {
    let Some(admin) = panel.require_admin_read(&session).await else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let blocked = if appliance.service.restore_pending().await {
        Some(
            "A restore is already staged and waiting for a restart. Complete or discard it before \
             staging another."
                .to_owned(),
        )
    } else {
        None
    };
    let (consequences, detail) = restore_consequences(&form.archive, &appliance.service).await;
    ApplianceConfirmPage {
        admin,
        csrf: session_csrf(&session).await,
        action: "restore",
        title: format!("Restore {}", form.archive),
        consequences,
        target: form.archive.clone(),
        detail,
        error: None,
        blocked,
    }
    .into_response()
}

/// What a restore of this archive will do, in the order it happens.
async fn restore_consequences(
    archive: &str,
    service: &Arc<dyn ApplianceService>,
) -> (Vec<String>, Vec<String>) {
    let consequences = vec![
        "The archive is verified against its manifest. A corrupt archive changes nothing."
            .to_owned(),
        "A copy of the current database is kept as the way back.".to_owned(),
        "The restored database is written **beside** the live one, not over it.".to_owned(),
        "The service restarts, and the swap happens before anything opens the database.".to_owned(),
        "Row counts are compared against the archive's manifest, and the result is shown here."
            .to_owned(),
    ];
    let detail = if archive.is_empty() {
        vec!["No archive was named.".to_owned()]
    } else {
        vec![format!("Archive: {archive}")]
    };
    // The archive's own age, if it can be read. An unreadable archive is not
    // fatal here — the POST will refuse it with a better message.
    if let Ok(data) = service.data().await
        && let Some(point) = data.restore_points.iter().find(|p| p.name == archive)
    {
        return (
            consequences,
            [
                detail,
                vec![format!(
                    "Taken {} ({}).",
                    point.modified_text, point.size_text
                )],
            ]
            .concat(),
        );
    }
    (consequences, detail)
}

#[instrument(skip_all)]
async fn do_restore(
    State(panel): State<Arc<AdminPanel>>,
    Extension(appliance): Extension<Arc<AppliancePanel>>,
    session: Session,
    Form(form): Form<RestoreForm>,
) -> Response {
    let admin = match panel.require_admin(&session, Some(&form.csrf)).await {
        Ok(admin) => admin,
        Err(status) => return status.into_response(),
    };
    // Typed confirmation, checked before anything else.
    if form.confirm != form.archive {
        return restore_refusal(
            &appliance,
            &session,
            &admin,
            &form.archive,
            "The confirmation did not match the archive name. Nothing was changed.",
        )
        .await;
    }
    if appliance.service.restore_pending().await {
        return restore_refusal(
            &appliance,
            &session,
            &admin,
            &form.archive,
            "A restore is already staged. Nothing was changed.",
        )
        .await;
    }

    match appliance.service.stage_restore(&form.archive, &admin).await {
        Ok(staged) => {
            // Logged, and a failure here is a `warn` rather than a refusal: the
            // restore is already staged and the restart is the next step. A
            // missing audit row is bad; not completing a staged restore is
            // worse.
            if let Err(e) = appliance
                .service
                .audit(
                    &admin,
                    "appliance_restore_staged",
                    &format!("archive={}", staged.archive),
                )
                .await
            {
                warn!(%e, "appliance panel: the restore was staged but not audited");
            }
            // The restart is signalled **after** the response, exactly as
            // `ProcdRestart` does, so the operator sees "staged, restarting"
            // rather than a dropped connection.
            appliance.service.request_restart();
            ApplianceStagedPage {
                admin,
                csrf: session_csrf(&session).await,
                staged,
            }
            .into_response()
        }
        Err(message) => {
            warn!(%message, %admin, "appliance panel: staging a restore failed");
            restore_refusal(&appliance, &session, &admin, &form.archive, &message).await
        }
    }
}

async fn restore_refusal(
    appliance: &Arc<AppliancePanel>,
    session: &Session,
    admin: &str,
    archive: &str,
    message: &str,
) -> Response {
    let blocked = if appliance.service.restore_pending().await {
        Some("A restore is already staged and waiting for a restart.".to_owned())
    } else {
        None
    };
    ApplianceConfirmPage {
        admin: admin.to_owned(),
        csrf: session_csrf(session).await,
        action: "restore",
        title: format!("Restore {archive}"),
        consequences: vec![],
        target: archive.to_owned(),
        detail: vec![],
        error: Some(message.to_owned()),
        blocked,
    }
    .into_response()
}

#[instrument(skip_all)]
async fn confirm_flash(
    State(panel): State<Arc<AdminPanel>>,
    Extension(appliance): Extension<Arc<AppliancePanel>>,
    session: Session,
    Query(form): Query<FlashForm>,
) -> Response {
    let Some(admin) = panel.require_admin_read(&session).await else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Ok(firmware) = appliance.service.firmware().await else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };

    // Blocked, with the reason, rather than a button that will fail. Each of
    // these is a *refusal with a cause* — "no tool", "no room", "not measured"
    // are three different problems and an operator needs to know which.
    let blocked = if !firmware.can_flash {
        Some("No flashing tool is present on this host, so there is nothing to run.".to_owned())
    } else if !firmware.space_known {
        Some(
            "Free space on the overlay could not be measured. This is not the same as having no \
             free space, and a flash will not be started on an unmeasured filesystem."
                .to_owned(),
        )
    } else if !firmware.has_room {
        Some(format!(
            "Not enough free space on {} ({}). A flash needs room for the new image and the \
             current one.",
            firmware.overlay_mount, firmware.free_text
        ))
    } else {
        None
    };

    let consequences = vec![
        "The image is written to flash. **There is no undo.**".to_owned(),
        "The unit reboots into the new firmware.".to_owned(),
        "`sysupgrade -n` is used, so the config partition is **not** restored from the backup \
         partition — a tenancy install's control plane and SMTP passwords survive."
            .to_owned(),
        "If the flash fails, the unit is left on its current firmware and this panel comes back."
            .to_owned(),
    ];
    let detail = vec![
        format!("Running version: {}", firmware.version),
        format!("Overlay {}: {}", firmware.overlay_mount, firmware.free_text),
    ];

    ApplianceConfirmPage {
        admin,
        csrf: session_csrf(&session).await,
        action: "firmware",
        title: format!("Flash {}", form.image),
        consequences,
        target: form.image.clone(),
        detail,
        error: None,
        blocked,
    }
    .into_response()
}

#[instrument(skip_all)]
async fn do_flash(
    State(panel): State<Arc<AdminPanel>>,
    Extension(appliance): Extension<Arc<AppliancePanel>>,
    session: Session,
    Form(form): Form<FlashForm>,
) -> Response {
    let admin = match panel.require_admin(&session, Some(&form.csrf)).await {
        Ok(admin) => admin,
        Err(status) => return status.into_response(),
    };
    if form.confirm != form.image {
        return flash_refusal(
            &appliance,
            &session,
            &admin,
            &form.image,
            "The confirmation did not match the image name. Nothing was flashed.",
        )
        .await;
    }

    // Re-checked **at the point of the write**, not only on the confirmation
    // page. The confirmation page is a snapshot; free space can change in the
    // seconds between an operator reading it and pressing the button, and a
    // flash that runs out of space mid-write is how a unit becomes unbootable.
    let Ok(firmware) = appliance.service.firmware().await else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    if !firmware.can_flash {
        return flash_refusal(
            &appliance,
            &session,
            &admin,
            &form.image,
            "No flashing tool is present on this host. Nothing was flashed.",
        )
        .await;
    }
    if !firmware.space_known || !firmware.has_room {
        return flash_refusal(
            &appliance,
            &session,
            &admin,
            &form.image,
            "Free space on the overlay is unknown or insufficient. Nothing was flashed.",
        )
        .await;
    }

    // The one irreversible call. Its result is rendered rather than redirected
    // away, because a failed flash is the single most important thing this panel
    // will ever tell someone.
    match appliance.service.flash(&form.image, &admin).await {
        Ok(()) => {
            if let Err(e) = appliance
                .service
                .audit(
                    &admin,
                    "appliance_firmware_flashed",
                    &format!("image={}", form.image),
                )
                .await
            {
                warn!(%e, "appliance panel: the flash ran but was not audited");
            }
            Redirect::to("/frontend/admin/appliance").into_response()
        }
        Err(message) => {
            error!(%message, %admin, "appliance panel: the flash failed");
            flash_refusal(
                &appliance,
                &session,
                &admin,
                &form.image,
                &format!("The flash failed and the unit was not changed. {message}"),
            )
            .await
        }
    }
}

async fn flash_refusal(
    appliance: &Arc<AppliancePanel>,
    session: &Session,
    admin: &str,
    image: &str,
    message: &str,
) -> Response {
    let blocked = appliance
        .service
        .firmware()
        .await
        .ok()
        .filter(|f| !f.has_room || !f.space_known || !f.can_flash)
        .map(|f| {
            if !f.can_flash {
                "No flashing tool is present on this host.".to_owned()
            } else if !f.space_known {
                "Free space could not be measured.".to_owned()
            } else {
                format!("Not enough free space on {}.", f.overlay_mount)
            }
        });
    ApplianceConfirmPage {
        admin: admin.to_owned(),
        csrf: session_csrf(session).await,
        action: "firmware",
        title: format!("Flash {image}"),
        consequences: vec![],
        target: image.to_owned(),
        detail: vec![],
        error: Some(message.to_owned()),
        blocked,
    }
    .into_response()
}
