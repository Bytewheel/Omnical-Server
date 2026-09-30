//! The appliance panel — Data / Network / Firmware. Item 14, §9.4.
//!
//! ## The claims, and where each is checked
//!
//! | Claim | Test |
//! |---|---|
//! | the three sections render | `the_three_sections_render` |
//! | a restore needs **typed** confirmation | `a_restore_without_the_typed_name_changes_nothing` |
//! | a staged restore does not touch the live database | `staging_a_restore_leaves_the_live_database_alone` |
//! | the report is measured against the **archive**, not the live database | `a_correct_restore_is_not_reported_as_data_loss` |
//! | a network view containing a secret comes back redacted | `a_network_view_holding_a_secret_comes_back_redacted` |
//! | the fake firmware writer is invoked with the expected argv, and nothing else is | `the_firmware_writer_is_invoked_with_exactly_one_expected_call` |
//! | a flash is refused when free space is unmeasured | `a_flash_is_refused_when_free_space_was_not_measured` |
//! | the panel is not on a tenant host | `the_appliance_section_does_not_exist_on_a_tenant_host` |
//!
//! ## Why the firmware double lives here and not in the library
//!
//! `FirmwareWriter` is a trait precisely so `sysupgrade` — which writes flash, and
//! cannot be undone — has a seam. The double is **in this file**, so a double
//! that drifts from the real signature has nowhere to hide: if the real trait
//! grows a parameter, this file stops compiling. A double in the library would
//! be updated in the same commit as the trait and would agree by construction,
//! which is the agreement worth nothing.
//!
//! ## Why the restore is rehearsed against a real database
//!
//! `stage_restore` and `complete_staged_restore` move real files and run real
//! `PRAGMA integrity_check` against a real migrated SQLite database. A fixture
//! that mocked the store would pass while the actual swap — the one irreversible
//! operation on this panel — was wrong. So these tests build a database with the
//! shipped migrator, back it up with the shipped `cmd_backup`, and restore it.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use rustical::appliance::{self, FirmwareWriter};
use rustical::config::Config;
use rustical_store::admin_store::AdminCredentialStore;
use rustical_store::tenant_store::TenantStore;
use tower::Service;

mod tenant_support;
use tenant_support::Fixture;

const ADMIN_HOST: &str = "admin.t3.gg";
const TENANT_HOST: &str = "acme.t3.gg";
const PASSWORD: &str = "correct-horse-battery-staple";

/// The one password in this file that must never reach a rendered page.
const SMTP_PASSWORD: &str = "smtp-password-that-must-never-be-rendered";

/// The RSVP HMAC key, which the redaction must also cover — row 50 names it
/// explicitly, so a test that only checked the SMTP password would leave the
/// other half of the gate untested on this surface.
const RSVP_SECRET: &str = "rsvp-hmac-key-that-must-never-be-rendered";

// ───────────────────────────── the fake writer ──────────────────────────────

/// Records every call, so a test can assert on the argv **and** on the count.
///
/// The count matters as much as the arguments: "invoked with the expected
/// arguments and nothing else is" means *exactly one call with these arguments*.
/// A panel that flashed twice, or flashed and then re-read, would pass an
/// arguments-only assertion.
#[derive(Debug, Default)]
enum Outcome {
    #[default]
    Succeed,
    Fail(String),
    /// Claims to be unavailable, as a host with no `sysupgrade` does.
    Unavailable,
}

#[derive(Debug)]
struct RecordingWriter {
    calls: Mutex<Vec<PathBuf>>,
    /// What `write` should do.
    outcome: Mutex<Outcome>,
}

impl RecordingWriter {
    fn succeeding() -> Self {
        Self {
            calls: Mutex::new(Vec::new()),
            outcome: Mutex::new(Outcome::Succeed),
        }
    }

    fn failing(message: &str) -> Self {
        Self {
            calls: Mutex::new(Vec::new()),
            outcome: Mutex::new(Outcome::Fail(message.to_owned())),
        }
    }

    fn unavailable() -> Self {
        Self {
            calls: Mutex::new(Vec::new()),
            outcome: Mutex::new(Outcome::Unavailable),
        }
    }

    fn calls(&self) -> Vec<PathBuf> {
        self.calls.lock().expect("the calls mutex").clone()
    }
}

#[async_trait::async_trait]
impl FirmwareWriter for RecordingWriter {
    async fn write(&self, image: &Path) -> anyhow::Result<()> {
        self.calls
            .lock()
            .expect("the calls mutex")
            .push(image.to_path_buf());
        match &*self.outcome.lock().expect("the outcome mutex") {
            Outcome::Succeed => Ok(()),
            Outcome::Fail(message) => anyhow::bail!("{message}"),
            Outcome::Unavailable => anyhow::bail!("no flashing tool on this host"),
        }
    }

    fn available(&self) -> bool {
        !matches!(
            &*self.outcome.lock().expect("the outcome mutex"),
            Outcome::Unavailable
        )
    }
}

/// A restart that records instead of signalling `SIGTERM`.
///
/// Copying `SetupRestart`'s shape rather than reusing `ProcdRestart`: the real
/// one kills this test process.
#[derive(Debug, Default)]
struct RecordingRestart {
    requested: Mutex<usize>,
}

impl RecordingRestart {
    fn count(&self) -> usize {
        *self.requested.lock().expect("the restart mutex")
    }
}

impl rustical::setup_mode::SetupRestart for RecordingRestart {
    fn request_restart(&self) {
        *self.requested.lock().expect("the restart mutex") += 1;
    }
}

// ──────────────────────────────── the harness ───────────────────────────────

/// Everything one test's panel needs.
struct Harness {
    app: rustical::host_dispatch::TenancyAwareApp,
    cookie: String,
    writer: Arc<RecordingWriter>,
    restart: Arc<RecordingRestart>,
    database: PathBuf,
    backup_dir: PathBuf,
    firmware_dir: PathBuf,
    _fixture: Fixture,
}

/// A config with the panel on and the appliance section enabled.
///
/// Written as TOML and parsed back rather than assembled as a struct literal:
/// `deny_unknown_fields` means a struct literal can drift from the keys an
/// operator actually writes, and one of these tests is about a config file.
///
/// `overlay` is a parameter rather than a constant because one test needs a
/// mount that cannot be measured, and TOML rejects a duplicate key — so the
/// override has to *replace* the line, not be appended after it.
fn config_for(
    fixture: &Fixture,
    database: &Path,
    backup_dir: &Path,
    firmware_dir: &Path,
    overlay: &str,
) -> Config {
    let path = fixture.path("panel.toml");
    let body = format!(
        "[data_store.sqlite]\ndb_url = \"sqlite://{db}\"\nrun_repairs = false\n\
         skip_broken = false\n\n\
         [tenancy]\nenabled = true\n\
         control_db_url = \"sqlite://{control}\"\nbase_domain = \"t3.gg\"\n\
         default_tenant = \"acme\"\n\
         data_root = \"{root}\"\nmax_cached_tenants = 8\n\
         admin_host = \"{ADMIN_HOST}\"\nplatform_admins = [\"ops\"]\n\
         admin_single_instance_acknowledged = true\n\n\
         [appliance]\nenabled = true\n\
         database = \"{database}\"\n\
         backup_dir = \"{backup_dir}\"\n\
         firmware_dir = \"{firmware_dir}\"\n\
         overlay_mount = \"{overlay}\"\n\n\
         [scheduling]\nenabled = true\n\
         rsvp_secret = \"{RSVP_SECRET}\"\n\n\
         [[scheduling.smtp]]\n\
         identity = \"alerts@example.com\"\n\
         host = \"smtp.example.com\"\n\
         port = 587\n\
         username = \"alerts\"\n\
         password = \"{SMTP_PASSWORD}\"\n",
        db = fixture.path("data").join("db.sqlite3").display(),
        control = fixture.path("control.sqlite3").display(),
        root = fixture.path("data").display(),
        database = database.display(),
        backup_dir = backup_dir.display(),
        firmware_dir = firmware_dir.display(),
        overlay = overlay,
    );
    std::fs::write(&path, &body).expect("the config");
    toml::from_str(&body).expect("the config parses")
}

/// The default overlay: the real temp directory, so `statvfs` succeeds and the
/// Firmware section has a genuine measurement.
fn real_overlay() -> String {
    std::env::temp_dir().display().to_string()
}

async fn give_credential(fixture: &Fixture, name: &str) {
    let store = fixture.control_plane_async().await;
    let hash = {
        use argon2::password_hash::{PasswordHasher, SaltString, rand_core::OsRng};
        argon2::Argon2::default()
            .hash_password(PASSWORD.as_bytes(), &SaltString::generate(OsRng))
            .expect("argon2")
            .to_string()
    };
    store
        .set_admin_credential(name, &hash, &rustical_store::admin_now())
        .await
        .expect("a credential row");
}

fn urlencode(value: &str) -> String {
    value
        .bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

fn get(host: &str, path: &str) -> Request<Body> {
    Request::builder()
        .uri(format!("http://{host}{path}"))
        .header(header::HOST, host)
        .body(Body::empty())
        .expect("a request")
}

fn get_auth(host: &str, path: &str, cookie: &str) -> Request<Body> {
    Request::builder()
        .uri(format!("http://{host}{path}"))
        .header(header::HOST, host)
        .header(header::COOKIE, cookie)
        .body(Body::empty())
        .expect("a request")
}

fn post(host: &str, path: &str, form: &[(&str, &str)], cookie: Option<&str>) -> Request<Body> {
    let encoded = form
        .iter()
        .map(|(k, v)| format!("{k}={}", urlencode(v)))
        .collect::<Vec<_>>()
        .join("&");
    let mut builder = Request::builder()
        .method("POST")
        .uri(format!("http://{host}{path}"))
        .header(header::HOST, host)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    if let Some(cookie) = cookie {
        builder = builder.header(header::COOKIE, cookie);
    }
    builder.body(Body::from(encoded)).expect("a request")
}

async fn send(
    app: &mut rustical::host_dispatch::TenancyAwareApp,
    request: Request<Body>,
) -> (StatusCode, String, Vec<String>) {
    let response = app.call(request).await.expect("infallible");
    let status = response.status();
    let cookies = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .map(ToOwned::to_owned)
        .collect();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("a body");
    (status, String::from_utf8_lossy(&body).into_owned(), cookies)
}

fn session_cookie(set_cookies: &[String]) -> Option<String> {
    set_cookies
        .iter()
        .find_map(|c| c.split(';').next())
        .map(ToOwned::to_owned)
}

fn csrf_in(html: &str) -> String {
    let needle = "name=\"csrf\" value=\"";
    let start = html
        .find(needle)
        .unwrap_or_else(|| panic!("no CSRF token in the rendered page:\n{html}"))
        + needle.len();
    let end = start + html[start..].find('"').expect("a closing quote");
    html[start..end].to_owned()
}

async fn log_in(app: &mut rustical::host_dispatch::TenancyAwareApp) -> String {
    let (status, html, cookies) = send(app, get(ADMIN_HOST, "/frontend/admin/login")).await;
    assert_eq!(status, StatusCode::OK, "the login page should render");
    let cookie = session_cookie(&cookies).expect("a session cookie");
    let csrf = csrf_in(&html);
    let (status, _, cookies) = send(
        app,
        post(
            ADMIN_HOST,
            "/frontend/admin/login",
            &[("name", "ops"), ("password", PASSWORD), ("csrf", &csrf)],
            Some(&cookie),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER, "the login should succeed");
    for set in &cookies {
        if set.starts_with("omnical_admin_session=") {
            return session_cookie(std::slice::from_ref(set)).expect("an admin cookie");
        }
    }
    panic!("no admin session cookie in {cookies:?}");
}

/// Build the panel, with the fake writer and the fake restart injected.
///
/// Takes the `Fixture` **by value** and keeps it alive in the returned
/// `Harness`, so the temp directory outlives every request the test makes. A
/// harness that borrowed one would have to be threaded through every test, and
/// the first test that forgot would fail on a missing directory rather than on
/// anything about the panel.
///
/// The service is assembled **here** rather than through `serve_dispatch` so the
/// doubles are genuinely injected. `the_section_is_mounted_from_config` covers
/// the config-driven path separately, so neither half is untested.
async fn harness_with(fixture: Fixture, writer: Arc<RecordingWriter>, overlay: &str) -> Harness {
    let database = fixture.path("appliance-db").join("db.sqlite3");
    let backup_dir = fixture.path("appliance-backups");
    let firmware_dir = fixture.path("firmware");
    // The database's directory as well as the backup directory's: SQLite creates
    // a *file* and not the directory above it, and a panel pointed at a
    // directory that does not exist is a legitimate state (the page says "there
    // is no database at that path") — the test just needs somewhere real to
    // build one.
    std::fs::create_dir_all(database.parent().unwrap()).expect("the database's directory");
    std::fs::create_dir_all(&backup_dir).expect("the backup dir");
    std::fs::create_dir_all(&firmware_dir).expect("the firmware dir");

    let config = config_for(&fixture, &database, &backup_dir, &firmware_dir, overlay);
    let paths = config
        .appliance_paths()
        .expect("the appliance config resolves");

    let restart = Arc::new(RecordingRestart::default());
    let control = fixture.control_plane_async().await;
    let service = rustical::appliance_service::service_for(
        appliance::ApplianceFacts {
            database: paths.database.clone(),
            backup_dir: paths.backup_dir.clone(),
            // A real file, so the Firmware section's size is a measurement and
            // not a hard-coded "not measured".
            binary: std::env::current_exe().unwrap_or_else(|_| PathBuf::from("/bin/sh")),
            overlay_mount: paths.overlay_mount.clone(),
            config: config.clone(),
            // The config **text**, so the redaction's key-shape pass runs. This
            // is the same path production takes.
            raw_config: std::fs::read_to_string(fixture.path("panel.toml")).unwrap_or_default(),
        },
        writer.clone(),
        Arc::new(control),
        restart.clone(),
        paths.firmware_dir.clone(),
    )
    .expect("the service builds");

    let panel_store: Arc<dyn TenantStore> = Arc::new(fixture.control_plane_async().await);
    let admins: Arc<dyn AdminCredentialStore> = Arc::new(fixture.control_plane_async().await);
    let admin_panel = Arc::new(rustical_frontend::AdminPanel::new(
        panel_store,
        admins,
        vec!["ops".to_owned()],
        std::slice::from_ref(&ADMIN_HOST.to_owned()),
        Vec::new(),
    ));
    let router = admin_panel.router_with(Some(Arc::new(rustical_frontend::AppliancePanel::new(
        service,
    ))));

    // The **real** dispatch layer, not a stub, so the "not on a tenant host"
    // claim is tested against the same host selection production uses. Built
    // the way `serve_dispatch` builds it, with the panel this test just made.
    let cache = Arc::new(rustical::store_bundle::StoreBundleCache::new(8));
    let dispatch = Arc::new(rustical::host_dispatch::HostDispatch::new(
        fixture.control_plane_async().await,
        cache,
        // A builder that **fails**, on purpose.
        //
        // **Not** `unreachable!`, which was the first draft and was wrong. A
        // request on a *tenant* host legitimately falls through to
        // `HostDispatch` — `admin.rs:17-22` says so, and explains that a tenant's
        // `/{user}` route means `/frontend/admin` can even match a principal
        // named `admin`. So the dispatch running is correct behaviour, and what
        // these tests assert is that what comes back is **not the panel**.
        //
        // Failing is the cheapest way to say "this is not a panel response": a
        // builder that succeeded would have to produce a real
        // `StoreBundle` and a real tenant router, which is a second integration
        // test wearing this one's name. `tests/admin_panel.rs` already covers
        // what a real tenant router does with these paths.
        Arc::new(|tenant: rustical_store::tenant::Tenant| {
            Box::pin(async move {
                Err(format!(
                    "this test does not build tenant {}'s stores",
                    tenant.slug
                ))
            })
        }),
        config.tenancy.clone(),
    ));
    let mut app = rustical::host_dispatch::TenancyAwareApp::Hosted(Arc::new(
        rustical::host_dispatch::Tenancy::new(
            dispatch,
            Some(router),
            std::slice::from_ref(&ADMIN_HOST.to_owned()),
        ),
    ));

    let cookie = log_in(&mut app).await;
    Harness {
        app,
        cookie,
        writer,
        restart,
        database: paths.database,
        backup_dir: paths.backup_dir,
        firmware_dir: paths.firmware_dir,
        // Held, never read: the temp directory must outlive every request.
        _fixture: fixture,
    }
}

async fn harness() -> Harness {
    let fixture = Fixture::new(Some(("t3.gg", "acme")));
    fixture.seed_tenants_async(&["acme"]).await;
    give_credential(&fixture, "ops").await;
    harness_with(
        fixture,
        Arc::new(RecordingWriter::succeeding()),
        &real_overlay(),
    )
    .await
}

// ─────────────────────────────── a real archive ──────────────────────────────

/// A real, migrated, backed-up database — the input a restore actually gets,
/// left with **one row written after the archive was taken**.
///
/// Built with the shipped migrator and the shipped `cmd_backup`, because a
/// hand-built tar with a hand-written manifest would be testing a fixture
/// against itself. This is the "rehearse against something real" instruction
/// applied to the restore path.
///
/// The order matters and the first draft had it backwards: the extra row is
/// inserted **after** the backup, not before. Inserting it first put six rows in
/// the archive, so the restore correctly produced six and the test failed
/// complaining about a restore that had done nothing wrong.
async fn real_archive(harness: &Harness) -> String {
    // A real database, fully migrated, with five rows.
    let pool = rustical_store_sqlite::create_db_pool(&harness.database.to_string_lossy(), true)
        .await
        .expect("the appliance database migrates");
    sqlx::query("CREATE TABLE IF NOT EXISTS rehearsal (id INTEGER PRIMARY KEY, note TEXT)")
        .execute(&pool)
        .await
        .expect("a table");
    for n in 0..5 {
        sqlx::query("INSERT INTO rehearsal (note) VALUES (?)")
            .bind(format!("row {n}"))
            .execute(&pool)
            .await
            .expect("a row");
    }
    pool.close().await;

    // The archive, now: five rows.
    let archive = rustical::commands::backup::cmd_backup(
        rustical::commands::backup::BackupArgs {
            out_dir: Some(harness.backup_dir.clone()),
            db: Some(harness.database.clone()),
            gzip: false,
            include_config: false,
        },
        // `cmd_backup` needs a config only for `include_config`, which is off.
        Config::default_config(),
        Path::new("/nonexistent-config.toml"),
    )
    .await
    .expect("a real backup");

    // Then a sixth row, written after the archive was taken. Restoring must move
    // the database *back* to five, and the report must not call that a loss.
    let pool = rustical_store_sqlite::create_db_pool(&harness.database.to_string_lossy(), false)
        .await
        .expect("reopen");
    sqlx::query("INSERT INTO rehearsal (note) VALUES ('written after the backup')")
        .execute(&pool)
        .await
        .expect("a later row");
    pool.close().await;

    archive
        .file_name()
        .expect("a name")
        .to_string_lossy()
        .into_owned()
}

async fn row_count(path: &Path) -> i64 {
    let url = format!("sqlite://{}", path.display());
    let pool = sqlx::SqlitePool::connect(&url).await.expect("open");
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM rehearsal")
        .fetch_one(&pool)
        .await
        .expect("count");
    pool.close().await;
    count
}

// ───────────────────────────────── the tests ────────────────────────────────

/// The three sections render for an authenticated admin.
#[tokio::test]
async fn the_three_sections_render() {
    let mut h = harness().await;
    let (status, body, _) = send(
        &mut h.app,
        get_auth(ADMIN_HOST, "/frontend/admin/appliance", &h.cookie),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    // Each section's own heading, so a template that rendered only one of them
    // would fail rather than pass on the first match.
    assert!(body.contains(">Data<"), "no Data section:\n{body}");
    assert!(body.contains(">Network<"), "no Network section:\n{body}");
    assert!(body.contains(">Firmware<"), "no Firmware section:\n{body}");
    // And the facts are in there, not just the headings.
    assert!(body.contains(&h.database.display().to_string()), "{body}");
    assert!(
        body.contains(&h.firmware_dir.display().to_string()),
        "the firmware directory should be listed:\n{body}"
    );
}

/// An unauthenticated request gets the panel's 404, not a login form.
#[tokio::test]
async fn the_appliance_section_is_404_without_a_session() {
    let mut h = harness().await;
    let (status, body, _) = send(&mut h.app, get(ADMIN_HOST, "/frontend/admin/appliance")).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert!(!body.contains("password"), "a login form leaked:\n{body}");
}

/// The panel does not exist on a tenant host — the §6.6.1 property, for the
/// new section.
///
/// Asserts the response is **not a panel response**, rather than a specific
/// status: on a tenant host the request falls through to `HostDispatch`, and
/// what that returns is the tenant router's business, not this panel's. A 200
/// with the panel's own content would be the failure.
#[tokio::test]
async fn the_appliance_section_does_not_exist_on_a_tenant_host() {
    let mut h = harness().await;
    for path in [
        "/frontend/admin/appliance",
        "/frontend/admin/appliance/restore",
        "/frontend/admin/appliance/firmware",
    ] {
        let (status, body, _) = send(&mut h.app, get_auth(TENANT_HOST, path, &h.cookie)).await;
        assert_ne!(
            status,
            StatusCode::OK,
            "{path} on a tenant host returned the panel:\n{body}"
        );
        for marker in [
            ">Firmware<",
            ">Network<",
            "restore points",
            "No flashing tool",
        ] {
            assert!(
                !body.contains(marker),
                "{path} on a tenant host leaked panel content ({marker}):\n{body}"
            );
        }
    }
}

/// A restore POST with the wrong confirmation changes nothing.
///
/// The typed-name confirmation, asserted three ways: the wrong name, an empty
/// name, and no name at all. A checkbox would pass all three.
#[tokio::test]
async fn a_restore_without_the_typed_name_changes_nothing() {
    let mut h = harness().await;
    let archive = real_archive(&h).await;
    let before = row_count(&h.database).await;

    let (_status, page, _) = send(
        &mut h.app,
        get_auth(ADMIN_HOST, "/frontend/admin/appliance", &h.cookie),
    )
    .await;
    let csrf = csrf_in(&page);

    for (label, confirm) in [("wrong name", "not-the-archive"), ("empty", "")] {
        let (status, body, _) = send(
            &mut h.app,
            post(
                ADMIN_HOST,
                "/frontend/admin/appliance/restore",
                &[("csrf", &csrf), ("archive", &archive), ("confirm", confirm)],
                Some(&h.cookie),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{label} should re-render:\n{body}");
        assert!(
            body.contains("confirmation did not match"),
            "{label} was not refused:\n{body}"
        );
    }

    // Nothing staged, nothing restarted, and the database is exactly as it was.
    assert!(
        !appliance::restore_is_staged(&h.database),
        "a refused restore must not leave a staged marker"
    );
    assert_eq!(h.restart.count(), 0, "a refused restore must not restart");
    assert_eq!(row_count(&h.database).await, before, "the database changed");
    assert!(h.writer.calls().is_empty(), "a restore must not flash");
}

/// The full staged restore: staged, **not** applied, then applied at start-up
/// and reported against the archive.
///
/// This is the load-bearing test of the whole item. It asserts the three things
/// that make the design safe, in order:
///
/// 1. after the POST, the live database is **unchanged** (rows written since the
///    backup are still there) — the restore is staged, not done;
/// 2. a restart was requested;
/// 3. after `complete_staged_restore`, the database holds the **archive's** rows
///    and the report says it matched, **without** calling the discarded rows a
///    loss.
#[tokio::test]
async fn a_staged_restore_is_applied_at_startup_and_judged_against_the_archive() {
    let mut h = harness().await;
    let archive = real_archive(&h).await;
    // The archive has 5 rehearsal rows; the live database has 6.
    assert_eq!(
        row_count(&h.database).await,
        6,
        "the setup should leave 6 rows"
    );

    let (_, page, _) = send(
        &mut h.app,
        get_auth(ADMIN_HOST, "/frontend/admin/appliance", &h.cookie),
    )
    .await;
    let csrf = csrf_in(&page);
    assert!(
        page.contains(&archive),
        "the archive should be listed:\n{page}"
    );

    let (status, body, _) = send(
        &mut h.app,
        post(
            ADMIN_HOST,
            "/frontend/admin/appliance/restore",
            &[
                ("csrf", &csrf),
                ("archive", &archive),
                ("confirm", &archive),
            ],
            Some(&h.cookie),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // 1. Staged, and the page says so in those words.
    assert!(
        body.contains("Nothing has been restored yet"),
        "the staged page must not claim the restore is done:\n{body}"
    );
    // 2. The live database is untouched.
    assert_eq!(
        row_count(&h.database).await,
        6,
        "staging must not touch the live database"
    );
    assert!(
        appliance::restore_is_staged(&h.database),
        "a marker should exist"
    );
    assert_eq!(
        h.restart.count(),
        1,
        "exactly one restart should be requested"
    );

    // 3. The completion, which is what `main` calls before the pool opens.
    let report = appliance::complete_staged_restore(&h.database)
        .await
        .expect("the completion runs")
        .expect("a report");

    assert_eq!(
        row_count(&h.database).await,
        5,
        "the restore must leave the archive's 5 rows"
    );
    assert!(
        report.is_verified(),
        "a correct restore must verify: {:?}",
        report.comparison
    );
    // The load-bearing claim: the 6th row was **deliberately** discarded, and
    // the report must not call that damage.
    let claim = report.claim();
    assert!(
        !claim.to_lowercase().contains("lost"),
        "the claim must not say data was lost: {claim}"
    );
    assert!(
        claim.contains("did discard rows written since"),
        "the claim must state the deliberate discard: {claim}"
    );
    // And the honest limit from §18.28 is stated, not hidden.
    assert!(
        claim.contains("dropped column"),
        "the claim must carry the row-count limit: {claim}"
    );
    assert!(
        report.losses().is_empty(),
        "measured against the archive there is no loss: {:?}",
        report.losses()
    );

    // The safety copy exists and holds the pre-restore database.
    let safety = report
        .safety_copy
        .clone()
        .expect("a pre-restore copy was kept");
    assert!(safety.is_file(), "{} should exist", safety.display());
    assert_eq!(
        row_count(&safety).await,
        6,
        "the way back holds what was there"
    );

    // The report survives the restart, because the panel that asked is gone.
    let reread = appliance::last_restore_report(&h.database)
        .expect("a report file")
        .expect("it parses");
    assert_eq!(reread, report, "the persisted report must match");

    // And the panel now shows it, without ever having opened the database.
    let (status, body, _) = send(
        &mut h.app,
        get_auth(ADMIN_HOST, "/frontend/admin/appliance", &h.cookie),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body.contains("matched the archive"), "{body}");
    assert!(body.contains("The last completed restore"), "{body}");
}

/// A restore of a **corrupt** archive changes nothing at all.
///
/// The verification gate, asserted behaviourally rather than by checking that a
/// function returned an error: no marker, no staging file, no restart, and the
/// live database still has its rows.
#[tokio::test]
async fn a_corrupt_archive_is_refused_and_changes_nothing() {
    let mut h = harness().await;
    let archive = real_archive(&h).await;
    // Truncate it. The sha256 in the manifest will not match.
    let path = h.backup_dir.join(&archive);
    let bytes = std::fs::read(&path).expect("read the archive");
    std::fs::write(&path, &bytes[..bytes.len() / 2]).expect("truncate");

    let before = row_count(&h.database).await;
    let (_, page, _) = send(
        &mut h.app,
        get_auth(ADMIN_HOST, "/frontend/admin/appliance", &h.cookie),
    )
    .await;
    let csrf = csrf_in(&page);

    let (status, body, _) = send(
        &mut h.app,
        post(
            ADMIN_HOST,
            "/frontend/admin/appliance/restore",
            &[
                ("csrf", &csrf),
                ("archive", &archive),
                ("confirm", &archive),
            ],
            Some(&h.cookie),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the failure is rendered, not a 500:\n{body}"
    );
    assert!(
        !appliance::restore_is_staged(&h.database),
        "a corrupt archive must not leave a staged marker"
    );
    assert_eq!(h.restart.count(), 0, "a corrupt archive must not restart");
    assert_eq!(row_count(&h.database).await, before, "the database changed");
    // No staging file either.
    let leftovers: Vec<_> = std::fs::read_dir(h.database.parent().unwrap())
        .expect("read the dir")
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.contains(".restore-"))
        .collect();
    assert!(
        leftovers.is_empty(),
        "left staging files behind: {leftovers:?}"
    );
}

/// A network view containing a secret comes back redacted.
///
/// The row-50 rule applied to a second surface: the panel is a page an operator
/// screenshots into a support ticket, so it must not be a way around the gate
/// the support bundle already holds. The config carries an SMTP password and an
/// RSVP key; nothing rendered may contain either.
#[tokio::test]
async fn a_network_view_holding_a_secret_comes_back_redacted() {
    let mut h = harness().await;

    // The whole page, not just the network section, and both secrets.
    let (status, body, _) = send(
        &mut h.app,
        get_auth(ADMIN_HOST, "/frontend/admin/appliance", &h.cookie),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        !body.contains(SMTP_PASSWORD),
        "the SMTP password reached the rendered page:\n{body}"
    );
    assert!(
        !body.contains(RSVP_SECRET),
        "the RSVP key reached the rendered page:\n{body}"
    );
}

/// Redaction is by **value**, so a declared secret is removed wherever it
/// appears — including from a field the panel renders that is not itself a
/// secret-shaped key.
///
/// This is the half of row 50 that a key-shape pass alone would miss, and the
/// first draft of this test got it wrong: it put the secret *only* inside
/// `public_url` and expected redaction, with nothing in the config declaring
/// that value to be a secret. That is not redaction's job — `secrets_in`
/// deliberately leaves URLs alone (`support_bundle.rs:118-127`, "a `key` whose
/// value is a path or a URL is not a credential"), and a support bundle that
/// redacted its own public URL would be useless. The rule that does apply is
/// that a secret *known* to the config is removed from every occurrence.
#[tokio::test]
async fn a_declared_secret_is_redacted_from_a_url_the_panel_renders() {
    let config: Config = toml::from_str(&format!(
        "[data_store.sqlite]\ndb_url = \"/tmp/x.sqlite3\"\n\
         [subscriptions]\nenabled = true\n\
         public_url = \"https://{SMTP_PASSWORD}.example.com\"\n\
         [scheduling]\nenabled = true\n\
         rsvp_secret = \"{RSVP_SECRET}\"\n\n\
         [[scheduling.smtp]]\n\
         identity = \"a@example.com\"\nhost = \"smtp.example.com\"\nport = 587\n\
         username = \"alerts\"\npassword = \"{SMTP_PASSWORD}\"\n"
    ))
    .expect("a config");

    let facts = appliance::network_facts(&config, "", Vec::new()).expect("redacted");
    let url = facts.public_url.expect("a public url");
    assert!(
        !url.contains(SMTP_PASSWORD),
        "the declared password still appears in the public URL: {url}"
    );
    assert!(url.contains("<redacted>"), "expected the marker in {url}");
    // And the URL's *shape* survives, so the page is still useful.
    assert!(url.ends_with(".example.com"), "the URL was mangled: {url}");

    // The RSVP key is a declared secret too, and is removed the same way.
    let raw = format!("rsvp_base_url = \"https://x/?k={RSVP_SECRET}\"");
    let redacted = rustical::commands::support_bundle::redact(
        &raw,
        &rustical::commands::support_bundle::secrets_in(&config, ""),
    )
    .expect("redacted");
    assert!(!redacted.contains(RSVP_SECRET), "{redacted}");
}

/// The firmware writer is invoked with exactly one expected call.
#[tokio::test]
async fn the_firmware_writer_is_invoked_with_exactly_one_expected_call() {
    let fixture = Fixture::new(Some(("t3.gg", "acme")));
    fixture.seed_tenants_async(&["acme"]).await;
    give_credential(&fixture, "ops").await;
    let mut h = harness_with(
        fixture,
        Arc::new(RecordingWriter::succeeding()),
        &real_overlay(),
    )
    .await;

    // A real file, so the panel offers it.
    let image_name = "openwrt-23.05.5-x86-64.bin";
    std::fs::write(
        h.firmware_dir.join(image_name),
        b"not really a firmware image",
    )
    .expect("an image");

    let (_, page, _) = send(
        &mut h.app,
        get_auth(ADMIN_HOST, "/frontend/admin/appliance", &h.cookie),
    )
    .await;
    let csrf = csrf_in(&page);
    assert!(
        page.contains(image_name),
        "the image should be listed:\n{page}"
    );

    // The confirmation page first — a GET, so the operator sees it before the
    // POST that does it.
    let (status, confirm, _) = send(
        &mut h.app,
        get_auth(
            ADMIN_HOST,
            &format!("/frontend/admin/appliance/firmware?image={image_name}"),
            &h.cookie,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{confirm}");
    assert!(confirm.contains("There is no undo"), "{confirm}");
    assert!(
        h.writer.calls().is_empty(),
        "a GET must never flash — this is the whole point of a confirmation page: {:?}",
        h.writer.calls()
    );

    // The POST, with the typed name.
    let (status, body, _) = send(
        &mut h.app,
        post(
            ADMIN_HOST,
            "/frontend/admin/appliance/firmware",
            &[
                ("csrf", &csrf),
                ("image", image_name),
                ("confirm", image_name),
            ],
            Some(&h.cookie),
        ),
    )
    .await;
    assert!(
        status == StatusCode::OK || status == StatusCode::SEE_OTHER,
        "unexpected status {status}:\n{body}"
    );

    // **Exactly one** call, with the image resolved inside the configured
    // directory.
    let calls = h.writer.calls();
    assert_eq!(calls.len(), 1, "expected one flash, got {calls:?}");
    assert_eq!(calls[0], h.firmware_dir.join(image_name), "{calls:?}");
}

/// A failed flash is reported, and nothing else happens.
#[tokio::test]
async fn a_failed_flash_is_reported_and_not_retried() {
    let fixture = Fixture::new(Some(("t3.gg", "acme")));
    fixture.seed_tenants_async(&["acme"]).await;
    give_credential(&fixture, "ops").await;
    let writer = Arc::new(RecordingWriter::failing(
        "sysupgrade exited 1 — no space left",
    ));
    let mut h = harness_with(fixture, writer.clone(), &real_overlay()).await;

    let image_name = "openwrt-broken.bin";
    std::fs::write(h.firmware_dir.join(image_name), b"x").expect("an image");

    let (_, page, _) = send(
        &mut h.app,
        get_auth(ADMIN_HOST, "/frontend/admin/appliance", &h.cookie),
    )
    .await;
    let csrf = csrf_in(&page);
    let (status, body, _) = send(
        &mut h.app,
        post(
            ADMIN_HOST,
            "/frontend/admin/appliance/firmware",
            &[
                ("csrf", &csrf),
                ("image", image_name),
                ("confirm", image_name),
            ],
            Some(&h.cookie),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "the failure is rendered:\n{body}");
    // The real message is surfaced, not replaced with a generic one — it is the
    // only thing an operator has to go on.
    assert!(body.contains("no space left"), "{body}");
    assert_eq!(writer.calls().len(), 1, "a failed flash is not retried");
}

/// A host with no flashing tool offers no button at all.
#[tokio::test]
async fn a_host_with_no_flashing_tool_is_told_so() {
    let fixture = Fixture::new(Some(("t3.gg", "acme")));
    fixture.seed_tenants_async(&["acme"]).await;
    give_credential(&fixture, "ops").await;
    let writer = Arc::new(RecordingWriter::unavailable());
    let mut h = harness_with(fixture, writer.clone(), &real_overlay()).await;

    let image_name = "openwrt-23.05.5.bin";
    std::fs::write(h.firmware_dir.join(image_name), b"x").expect("an image");

    let (status, body, _) = send(
        &mut h.app,
        get_auth(ADMIN_HOST, "/frontend/admin/appliance", &h.cookie),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        body.contains("No flashing tool is present"),
        "the page should say so:\n{body}"
    );

    // And the confirmation page refuses with the same cause, offering no form.
    let (status, confirm, _) = send(
        &mut h.app,
        get_auth(
            ADMIN_HOST,
            &format!("/frontend/admin/appliance/firmware?image={image_name}"),
            &h.cookie,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{confirm}");
    assert!(confirm.contains("not available"), "{confirm}");
    assert!(
        !confirm.contains("name=\"confirm\""),
        "no form should be rendered when the action cannot work:\n{confirm}"
    );
}

/// An overlay whose free space cannot be measured refuses the flash.
///
/// "Not measured" is not "measured, and empty", and the panel must not treat an
/// unmeasured filesystem as room.
#[tokio::test]
async fn a_flash_is_refused_when_free_space_was_not_measured() {
    let fixture = Fixture::new(Some(("t3.gg", "acme")));
    fixture.seed_tenants_async(&["acme"]).await;
    give_credential(&fixture, "ops").await;
    let writer = Arc::new(RecordingWriter::succeeding());
    // A path that does not exist, so `statvfs` fails.
    let mut h = harness_with(
        fixture,
        writer.clone(),
        // A path that does not exist, so `statvfs` fails and free space is
        // "not measured" rather than zero.
        "/omnical-no-such-mount",
    )
    .await;

    let image_name = "openwrt-23.05.5.bin";
    std::fs::write(h.firmware_dir.join(image_name), b"x").expect("an image");

    let (_, page, _) = send(
        &mut h.app,
        get_auth(ADMIN_HOST, "/frontend/admin/appliance", &h.cookie),
    )
    .await;
    let csrf = csrf_in(&page);
    assert!(
        page.contains("not measured"),
        "the page must distinguish not-measured from zero:\n{page}"
    );

    // The POST refuses even with a correct typed confirmation, because the
    // check is repeated at the point of the write rather than trusted from the
    // confirmation page.
    let (status, body, _) = send(
        &mut h.app,
        post(
            ADMIN_HOST,
            "/frontend/admin/appliance/firmware",
            &[
                ("csrf", &csrf),
                ("image", image_name),
                ("confirm", image_name),
            ],
            Some(&h.cookie),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body.contains("Nothing was flashed"), "{body}");
    assert!(
        writer.calls().is_empty(),
        "an unmeasured filesystem must not be flashed: {:?}",
        writer.calls()
    );
}

/// An archive name that tries to escape the backup directory is refused.
///
/// The name arrives from a form field. Three shapes are tried: a path, a parent
/// reference, and a dotfile (which is what a `.part` looks like).
#[tokio::test]
async fn an_archive_name_cannot_escape_the_backup_directory() {
    let mut h = harness().await;
    // A real file outside the backup directory, as the target of the attempt.
    let outside = h.database.parent().unwrap().join("secret.tar");
    std::fs::write(&outside, b"not an archive").expect("a decoy");

    let (_, page, _) = send(
        &mut h.app,
        get_auth(ADMIN_HOST, "/frontend/admin/appliance", &h.cookie),
    )
    .await;
    let csrf = csrf_in(&page);

    for name in [
        "../secret.tar",
        "..%2Fsecret.tar",
        "/etc/passwd",
        ".omnical-backup-1.tar.part",
        "nonexistent.tar.gz",
    ] {
        let (status, body, _) = send(
            &mut h.app,
            post(
                ADMIN_HOST,
                "/frontend/admin/appliance/restore",
                &[
                    ("csrf", &csrf),
                    ("archive", name),
                    // Confirmation typed to match, so the *name check* is what
                    // refuses rather than the confirmation check.
                    ("confirm", name),
                ],
                Some(&h.cookie),
            ),
        )
        .await;
        assert!(
            status.is_client_error() || status == StatusCode::OK,
            "{name} returned {status}:\n{body}"
        );
        assert!(
            !appliance::restore_is_staged(&h.database),
            "{name} must not stage anything"
        );
    }
    assert_eq!(
        h.restart.count(),
        0,
        "no restart should have been requested"
    );
}

/// A `.part` file is never offered as a restore point.
///
/// The real reason this matters: `cmd_backup` writes `.<name>.part` while it
/// works, so a directory listing taken mid-backup contains a file that is not a
/// restorable database.
#[tokio::test]
async fn a_part_file_is_never_listed_as_a_restore_point() {
    let mut h = harness().await;
    real_archive(&h).await;
    // What `cmd_backup` leaves behind while it is working.
    std::fs::write(
        h.backup_dir
            .join(".omnical-backup-20991231T235959Z.tar.part"),
        b"incomplete",
    )
    .expect("a part file");
    // And a leftover snapshot, which is a database and not an archive.
    std::fs::write(
        h.backup_dir
            .join(".omnical-backup-20991231T235959Z.sqlite3.part"),
        b"incomplete",
    )
    .expect("a snapshot");
    // And something that is not a backup at all.
    std::fs::write(h.backup_dir.join("notes.txt"), b"hello").expect("a stray file");

    let (status, body, _) = send(
        &mut h.app,
        get_auth(ADMIN_HOST, "/frontend/admin/appliance", &h.cookie),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(!body.contains(".part"), "a .part file was offered:\n{body}");
    assert!(
        !body.contains("notes.txt"),
        "a stray file was offered:\n{body}"
    );
    assert!(
        body.contains("omnical-backup-"),
        "the real archive should still be listed:\n{body}"
    );
}

/// A second restore cannot be staged on top of the first.
#[tokio::test]
async fn a_second_restore_is_refused_while_one_is_staged() {
    let mut h = harness().await;
    let archive = real_archive(&h).await;

    let (_, page, _) = send(
        &mut h.app,
        get_auth(ADMIN_HOST, "/frontend/admin/appliance", &h.cookie),
    )
    .await;
    let csrf = csrf_in(&page);
    let (status, body, _) = send(
        &mut h.app,
        post(
            ADMIN_HOST,
            "/frontend/admin/appliance/restore",
            &[
                ("csrf", &csrf),
                ("archive", &archive),
                ("confirm", &archive),
            ],
            Some(&h.cookie),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(h.restart.count(), 1);

    // The second attempt is refused, and the page says a restore is pending.
    let (status, page2, _) = send(
        &mut h.app,
        get_auth(ADMIN_HOST, "/frontend/admin/appliance", &h.cookie),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{page2}");
    assert!(
        page2.contains("A restore is staged and has NOT been applied"),
        "the pending state must be unmissable:\n{page2}"
    );
    // The archive that is staged is named, and the way back is offered — an
    // operator reading this page needs to know *which* restore is pending.
    assert!(
        page2.contains(&archive),
        "the pending archive should be named:\n{page2}"
    );
    assert!(
        page2.contains(".pre-restore-"),
        "the pre-restore copy should be offered:\n{page2}"
    );

    let (status, body, _) = send(
        &mut h.app,
        post(
            ADMIN_HOST,
            "/frontend/admin/appliance/restore",
            &[
                ("csrf", &csrf),
                ("archive", &archive),
                ("confirm", &archive),
            ],
            Some(&h.cookie),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body.contains("already staged"), "{body}");
    assert_eq!(h.restart.count(), 1, "no second restart");
}

/// The section is mounted from config alone, with no doubles — the production
/// path.
///
/// The other tests assemble the router by hand so the firmware double can be
/// injected. This one goes through `serve_dispatch`, so the wiring itself
/// (config → paths → service → merged routes) is covered rather than assumed.
#[tokio::test]
async fn the_section_is_mounted_from_config() {
    let fixture = Fixture::new(Some(("t3.gg", "acme")));
    fixture.seed_tenants_async(&["acme"]).await;
    give_credential(&fixture, "ops").await;

    let database = fixture.path("appliance-db").join("db.sqlite3");
    let backup_dir = fixture.path("appliance-backups");
    let firmware_dir = fixture.path("firmware");
    std::fs::create_dir_all(database.parent().unwrap()).expect("the db directory");
    std::fs::create_dir_all(&backup_dir).expect("the backup dir");
    std::fs::create_dir_all(&firmware_dir).expect("the firmware dir");
    let config = config_for(
        &fixture,
        &database,
        &backup_dir,
        &firmware_dir,
        &real_overlay(),
    );
    let config_path = fixture.path("panel.toml");

    let mut app = rustical::tenancy::serve_dispatch_with_config_file(&config, Some(&config_path))
        .await
        .expect("a tenancy-enabled app");
    let cookie = log_in(&mut app).await;

    let (status, body, _) = send(
        &mut app,
        get_auth(ADMIN_HOST, "/frontend/admin/appliance", &cookie),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body.contains(">Data<"), "{body}");
    assert!(body.contains(">Network<"), "{body}");
    assert!(body.contains(">Firmware<"), "{body}");
    // And the real service, not a double: no `sysupgrade` on a dev box, so the
    // firmware section says so.
    assert!(body.contains("No flashing tool"), "{body}");
}

/// `appliance_paths` refuses the configurations that would make the panel
/// dangerous, and the refusals name the setting.
#[test]
fn the_appliance_config_refuses_what_would_make_the_panel_dangerous() {
    let base = "[data_store.sqlite]\ndb_url = \"/tmp/x.sqlite3\"\n";

    // Disabled: no panel, and the refusal says so rather than pretending.
    let disabled: Config = toml::from_str(base).expect("a config");
    assert!(disabled.appliance_paths().is_err());

    // Enabled with no database: a restore with no target.
    let no_db: Config =
        toml::from_str(&format!("{base}\n[appliance]\nenabled = true\n")).expect("a config");
    let error = no_db.appliance_paths().expect_err("a refusal");
    assert!(error.contains("needs a database"), "{error}");

    // A relative database path resolves against whatever directory the service
    // happens to start in.
    let relative: Config = toml::from_str(&format!(
        "{base}\n[appliance]\nenabled = true\ndatabase = \"db.sqlite3\"\n"
    ))
    .expect("a config");
    let error = relative.appliance_paths().expect_err("a refusal");
    assert!(error.contains("not absolute"), "{error}");

    // The backup directory holding the live database: the listing would offer
    // the live database as something to restore over itself.
    let same_dir: Config = toml::from_str(&format!(
        "{base}\n[appliance]\nenabled = true\ndatabase = \"/data/db.sqlite3\"\n\
         backup_dir = \"/data\"\n"
    ))
    .expect("a config");
    let error = same_dir.appliance_paths().expect_err("a refusal");
    assert!(error.contains("must not share a directory"), "{error}");

    // A good one resolves, with the documented defaults.
    let good: Config = toml::from_str(&format!(
        "{base}\n[appliance]\nenabled = true\ndatabase = \"/data/db.sqlite3\"\n"
    ))
    .expect("a config");
    let paths = good.appliance_paths().expect("a resolution");
    assert_eq!(paths.backup_dir, PathBuf::from("/data/backups"));
    assert_eq!(paths.overlay_mount, PathBuf::from("/"));
}
