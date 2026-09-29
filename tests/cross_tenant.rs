//! **Rows 24 and 25**, the isolation claim of §3.2, end to end.
//! `PLAN_DEPLOYMENTS.md` §12, and item 8's gate.
//!
//! ## What these rows actually say
//!
//! | Row | Claim | Expected |
//! |---|---|---|
//! | 24 | Cross-tenant **auth** isolation: tenant A's principal + app token against tenant B's host | 401 |
//! | 25 | Cross-tenant **resource** isolation: tenant A's calendar id on tenant B's host | 404 |
//!
//! ## Why the fixture is built with the CLI
//!
//! Both rows are stated in terms of credentials and calendar ids that exist in
//! one tenant's data. Creating them by hand-inserting rows would prove the rows
//! are *readable*; it would not prove the product can *produce* them, and a test
//! fixture that bypasses the real path is a fixture that stops resembling
//! production without anyone noticing. So each tenant gets a real config file
//! pointing at its own database, and the real `rustical app-token create` mints
//! its token.
//!
//! The interesting half of row 24 is the **same principal id in both tenants**:
//! `alice` exists in Acme and in Globex, with the same password. That is the
//! case a `WHERE tenant_id = ?` design gets wrong, and it is the case §3.2's
//! separate-database design is supposed to make impossible. If the password were
//! different per tenant the test would pass trivially and prove nothing.
//!
//! ## What still is not proven
//!
//! Rows 26-28 — the three routers mounted *outside* the auth layer
//! (`export_`, `rsvp_`, `register_`) — are **item 9**, still safety-critical and
//! not started. Those are token-only routes where a tenant check can be silently
//! absent, and nothing in this file touches them. A green run here is the
//! precondition for row 24, not a substitute for item 9.

use reqwest::StatusCode;
use rustical::host_dispatch::HEALTH_PATH;
use rustical_store::TenantId;
use rustical_store::auth::AuthenticationProvider;
use rustical_store::tenant_store::TenantStore;
use rustical_store_sqlite::{SqlitePrincipalStore, SqliteTenantStore, create_control_plane_pool};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// A fixed actor for these tests. Not a credential, and it never leaves the test
/// process — the point of these tests is the *shape* of an audit row, not who
/// wrote it.
///
/// A function rather than a `static`, because `Actor::new` validates and is
/// therefore not `const`.
fn test_actor() -> rustical_store::Actor {
    rustical_store::Actor::new("test").expect("a valid actor")
}

/// A running server plus per-tenant data directories.
struct Cluster {
    dir: tempfile::TempDir,
    port: u16,
    child: Option<std::process::Child>,
    tenants: Vec<(String, TenantId)>,
}

impl Cluster {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("a temp dir");
        std::fs::create_dir_all(dir.path().join("data")).expect("the data directory");
        let port = {
            let l = TcpListener::bind("127.0.0.1:0").expect("a free port");
            l.local_addr().expect("an address").port()
        };

        let config = format!(
            "[http]\nbind = \"127.0.0.1:{port}\"\n\n\
             [data_store.sqlite]\ndb_url = \"{db}\"\nrun_repairs = false\nskip_broken = false\n\n\
             [frontend]\nenabled = true\nallow_password_login = true\n\n\
             [tenancy]\nenabled = true\ncontrol_db_url = \"sqlite://{control}\"\n\
             base_domain = \"t3.gg\"\nmax_cached_tenants = 8\ndata_root = \"{root}\"\n",
            db = dir.path().join("data").join("db.sqlite3").display(),
            control = dir.path().join("control.sqlite3").display(),
            root = dir.path().join("data").display(),
        );
        std::fs::write(dir.path().join("config.toml"), config).expect("the config");

        Self {
            dir,
            port,
            child: None,
            tenants: Vec::new(),
        }
    }

    fn path(&self, rel: &str) -> PathBuf {
        self.dir.path().join(rel)
    }

    fn tenant_db(&self, id: &TenantId) -> PathBuf {
        self.path("data")
            .join("tenants")
            .join(id.as_str())
            .join("db.sqlite3")
    }

    /// Materialise a tenant's store, the way `rustical tenant create` must.
    ///
    /// A tenant's database is otherwise created **lazily**, on the first request
    /// that resolves to it — which is fine for serving and useless for
    /// administering: there is no way to point a config at a store path that
    /// does not exist yet, so `rustical principals add` against a new tenant
    /// would fail on the missing directory. Item 11's `tenant create` is
    /// therefore obliged to do this, and until it exists the gate does it by
    /// hand.
    fn materialise(&self, id: &TenantId) {
        // The directory first: SQLite's `create_if_missing` creates the *file*
        // and not its parent, which is the whole reason
        // `TenancyConfig::ensure_tenant_store_dir` exists.
        std::fs::create_dir_all(self.tenant_db(id).parent().expect("a parent"))
            .expect("the tenant directory");
        let rt = tokio::runtime::Runtime::new().expect("a runtime");
        rt.block_on(async {
            rustical_store_sqlite::create_db_pool(
                &format!("sqlite://{}", self.tenant_db(id).display()),
                true,
            )
            .await
            .expect("the tenant store migrates");
        });
    }

    /// Seed the control plane, then read back each tenant's id.
    fn seed(&mut self) {
        let url = format!("sqlite://{}", self.path("control.sqlite3").display());
        let rt = tokio::runtime::Runtime::new().expect("a runtime");
        rt.block_on(async {
            let pool = create_control_plane_pool(&url, true)
                .await
                .expect("the control plane migrates");
            let store = SqliteTenantStore::new(pool);
            for slug in ["acme", "globex"] {
                let new = rustical_store_sqlite::new_tenant(&slug.parse().expect("a slug"), None);
                store
                    .create_tenant(&new, &test_actor())
                    .await
                    .unwrap_or_else(|e| panic!("seeding {slug} failed: {e}"));
            }
        });
        self.tenants = rt.block_on(async {
            let pool = create_control_plane_pool(&url, false)
                .await
                .expect("the control plane opens");
            let store = SqliteTenantStore::new(pool);
            let mut out = Vec::new();
            for slug in ["acme", "globex"] {
                let tenant = store
                    .get_tenant_by_slug(slug)
                    .await
                    .expect("a lookup")
                    .unwrap_or_else(|| panic!("{slug} was seeded"));
                out.push((tenant.slug.to_string(), tenant.id));
            }
            out
        });
        for (_, id) in &self.tenants {
            self.materialise(id);
        }
    }

    /// A config file for one tenant's own data, for the CLI to use.
    ///
    /// One per tenant, pointing at that tenant's own database. This is what lets
    /// `rustical principals` and `rustical app-token` operate on a single
    /// tenant's data — the shape item 11's `rustical tenant` will replace.
    fn tenant_config(&self, id: &TenantId) -> PathBuf {
        let path = self.path(&format!("tenant-{}.toml", id.as_str()));
        let body = format!(
            "[data_store.sqlite]\ndb_url = \"{db}\"\nrun_repairs = false\nskip_broken = false\n",
            db = self.tenant_db(id).display()
        );
        std::fs::write(&path, body).expect("the tenant config");
        path
    }

    /// Run a CLI subcommand against one tenant's data.
    fn cli(&self, id: &TenantId, args: &[&str]) -> String {
        let config = self.tenant_config(id);
        let out = Command::new(env!("CARGO_BIN_EXE_rustical"))
            .arg("--config-file")
            .arg(&config)
            .args(args)
            .output()
            .expect("the CLI runs");
        assert!(
            out.status.success(),
            "`{args:?}` failed: {}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).trim().to_owned()
    }

    fn start(&mut self) {
        let log = std::fs::File::create(self.path("server.log")).expect("a log file");
        let err = log.try_clone().expect("a second handle");
        self.child = Some(
            Command::new(env!("CARGO_BIN_EXE_rustical"))
                .arg("--config-file")
                .arg(self.path("config.toml"))
                .arg("serve")
                .stdout(Stdio::from(log))
                .stderr(Stdio::from(err))
                .spawn()
                .expect("the server starts"),
        );
    }

    fn wait_ready(&self) {
        let rt = tokio::runtime::Runtime::new().expect("a runtime");
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .expect("a client");
        let deadline = Instant::now() + Duration::from_secs(60);
        while Instant::now() < deadline {
            let ok = rt.block_on(async {
                client
                    .get(format!("http://127.0.0.1:{}{HEALTH_PATH}", self.port))
                    .send()
                    .await
                    .is_ok_and(|r| r.status().is_success())
            });
            if ok {
                return;
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        panic!(
            "the server never became ready.\n--- log ---\n{}",
            std::fs::read_to_string(self.path("server.log")).unwrap_or_default()
        );
    }

    /// A request against one tenant's host, with one credential.
    ///
    /// `redirect(Policy::none())` matters: with redirects followed, a 302 to a
    /// login page would arrive as a 200 and every 401 assertion in this file
    /// would be an assertion about the portal rather than about isolation.
    fn request(
        &self,
        host: &str,
        method: &str,
        path: &str,
        user: &str,
        password: &str,
        body: Option<&str>,
    ) -> (StatusCode, String) {
        let rt = tokio::runtime::Runtime::new().expect("a runtime");
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("a client");
        let verb = reqwest::Method::from_bytes(method.as_bytes())
            .unwrap_or_else(|e| panic!("{method} is not a method: {e}"));
        rt.block_on(async {
            let mut builder = client
                .request(verb, format!("http://127.0.0.1:{}{path}", self.port))
                .header("Host", host)
                .basic_auth(user, Some(password));
            if let Some(body) = body {
                // An explicit content-type: without one the extractor rejects
                // the body with a bare 400 that says nothing about why.
                builder = builder
                    .header("Content-Type", "application/xml; charset=utf-8")
                    .body(body.to_owned());
            }
            let response = builder
                .send()
                .await
                .unwrap_or_else(|e| panic!("{method} {host}{path} failed: {e}"));
            (response.status(), response.text().await.unwrap_or_default())
        })
    }

    /// `PROPFIND` a collection, the way a CalDAV client enumerates calendars.
    fn propfind(&self, host: &str, path: &str, user: &str, password: &str) -> (StatusCode, String) {
        self.request(
            host,
            "PROPFIND",
            path,
            user,
            password,
            Some(
                "<?xml version=\"1.0\" encoding=\"utf-8\"?>\
<propfind xmlns=\"DAV:\"><prop><resourcetype/></prop></propfind>",
            ),
        )
    }

    /// `MKCALENDAR`, which is how a calendar is actually created.
    ///
    /// The body is one long string with no `\`-continuations between the
    /// elements. An earlier draft wrapped it for readability, and the `\` ate
    /// the newline *and* the following indentation, which silently mangled the
    /// `xmlns:CAL` binding and produced `Unknown(CAL)mkcalendar` rather than an
    /// error anyone could act on. A request body is not a place to be clever.
    fn mkcalendar(
        &self,
        host: &str,
        name: &str,
        user: &str,
        password: &str,
    ) -> (StatusCode, String) {
        let body = format!(
            "<?xml version='1.0' encoding='UTF-8' ?>\
<CAL:mkcalendar xmlns=\"DAV:\" xmlns:CAL=\"urn:ietf:params:xml:ns:caldav\">\
<set><prop><resourcetype><collection /><CAL:calendar /></resourcetype>\
<displayname>{name}</displayname></prop></set></CAL:mkcalendar>"
        );
        self.request(
            host,
            "MKCALENDAR",
            &format!("/caldav/principal/{user}/{name}"),
            user,
            password,
            Some(&body),
        )
    }

    fn log(&self) -> String {
        std::fs::read_to_string(self.path("server.log")).unwrap_or_default()
    }

    fn id(&self, slug: &str) -> TenantId {
        self.tenants
            .iter()
            .find(|(s, _)| s == slug)
            .unwrap_or_else(|| panic!("{slug} was seeded"))
            .1
            .clone()
    }
}

impl Drop for Cluster {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// The same principal id and password in two tenants.
///
/// Deliberately identical: row 24's claim is that A's credential does not work
/// on B's host, and a per-tenant-different password would make that true for a
/// reason that has nothing to do with tenancy.
const PRINCIPAL: &str = "alice";
const PASSWORD: &str = "correct-horse-battery-staple";

/// Provision one tenant: the principal, then its app token — **both through the
/// shipped CLI**.
///
/// `--for-testing-password-from-arg` is a hidden flag that exists in upstream
/// `rustical principals create` for integration tests, and using it keeps this
/// fixture entirely on the product path. A fixture that inserts rows directly
/// proves the rows are *readable*; it does not prove the product can *produce*
/// them, and it drifts from production without anyone noticing.
fn provision(cluster: &Cluster, id: &TenantId) -> String {
    cluster.cli(
        id,
        &[
            "principals",
            "create",
            PRINCIPAL,
            "--for-testing-password-from-arg",
            PASSWORD,
        ],
    );
    cluster.cli(
        id,
        &[
            "principals",
            "app-token",
            "create",
            PRINCIPAL,
            "--name",
            "gate",
        ],
    )
}

/// Row 24: a credential from tenant A must not authenticate on tenant B's host.
#[test]
fn an_app_token_from_one_tenant_does_not_authenticate_on_another() {
    let mut cluster = Cluster::new();
    cluster.seed();
    let acme = cluster.id("acme");
    let globex = cluster.id("globex");

    let acme_token = provision(&cluster, &acme);
    let globex_token = provision(&cluster, &globex);
    assert!(acme_token.contains('_'), "the token is {acme_token:?}");
    assert_ne!(acme_token, globex_token, "the tokens must differ");

    // A calendar in each tenant, so the credential has something real to reach.
    // `MKCALENDAR` is an HTTP request, so this is *after* the server is up —
    // creating the calendar is part of the product path, not fixture setup.
    cluster.start();
    cluster.wait_ready();
    let m = cluster.mkcalendar("acme.t3.gg", "work", PRINCIPAL, &acme_token);
    assert_eq!(m.0, 201, "MKCALENDAR debug: {} body={:?}", m.0, m.1);
    let m2 = cluster.mkcalendar("globex.t3.gg", "work", PRINCIPAL, &globex_token);
    assert_eq!(m2.0, 201, "MKCALENDAR debug: {} body={:?}", m2.0, m2.1);

    let cal = "/caldav/principal/alice/work";

    // Each tenant's own token works on its own host. Without this, the 401s
    // below could be explained by the tokens being broken — which is the failure
    // mode a row that only asserts the negative is open to.
    let (status, body) = cluster.propfind("acme.t3.gg", cal, PRINCIPAL, &acme_token);
    assert_eq!(
        status,
        207,
        "acme's own token must reach acme's own calendar; got {status} {body:?}\nlog:\n{}",
        cluster.log()
    );

    // **Row 24.** Acme's token against Globex's host.
    let (status, body) = cluster.propfind("globex.t3.gg", cal, PRINCIPAL, &acme_token);
    assert_eq!(
        status, 401,
        "row 24: acme's app token must not authenticate on globex; got {status} {body:?}"
    );

    // And the reverse, because a one-directional leak is still a leak.
    let (status, _) = cluster.propfind("acme.t3.gg", cal, PRINCIPAL, &globex_token);
    assert_eq!(status, 401, "row 24, reverse direction");
}

/// The credential material is **duplicated per tenant**, not shared.
///
/// This started as "a password from tenant A must not authenticate on tenant B"
/// and the test failed — in tenant **A**, with its own password. The reason is
/// worth recording, because it is a fact about the product and not about the
/// test: `AuthenticationLayer` in this fork has **no password path for HTTP
/// Basic**. It calls `validate_app_token` and nothing else; `validate_password`
/// exists on the provider but is only reached by the portal's form login, which
/// establishes a session. So a `Principal`'s `password` field is not an HTTP
/// credential, and "Basic auth with a password" is not a thing this server does.
///
/// §12's row 24 says "tenant A's principal **+ app token**", which is consistent
/// with that — the app token is the HTTP credential and it is what the row is
/// about. This test therefore asserts the claim that is actually available: both
/// tenants hold a *separate* principal row for the same id, each verifying
/// against the same password, with different stored hashes.
#[test]
fn each_tenant_holds_its_own_principal_row() {
    let mut cluster = Cluster::new();
    cluster.seed();
    let acme = cluster.id("acme");
    let globex = cluster.id("globex");
    let _ = provision(&cluster, &acme);
    let _ = provision(&cluster, &globex);

    // Read the principal out of each tenant, and check the password against
    // each tenant's *own* store — the check has to happen where the data is,
    // which is the point.
    let read = |id: &TenantId| {
        let url = format!("sqlite://{}", cluster.tenant_db(id).display());
        tokio::runtime::Runtime::new()
            .expect("a runtime")
            .block_on(async {
                let pool = rustical_store_sqlite::create_db_pool(&url, false)
                    .await
                    .expect("the store opens");
                let principals = SqlitePrincipalStore::new(pool);
                let principal = AuthenticationProvider::get_principal(&principals, PRINCIPAL)
                    .await
                    .expect("a lookup")
                    .expect("the principal exists");
                let verifies = principals
                    .validate_password(PRINCIPAL, PASSWORD)
                    .await
                    .expect("a password check");
                (principal, verifies)
            })
    };

    let (acme_principal, acme_verifies) = read(&acme);
    let (globex_principal, globex_verifies) = read(&globex);

    // Same id, and the password verifies in both — so neither tenant's row is a
    // copy of the other's, and neither is missing.
    assert_eq!(acme_principal.id, globex_principal.id);
    assert_eq!(acme_principal.id, PRINCIPAL);
    assert!(acme_verifies.is_some(), "the password must verify in acme");
    assert!(
        globex_verifies.is_some(),
        "the password must verify in globex"
    );

    let acme_hash = acme_principal
        .password
        .as_ref()
        .expect("a password")
        .as_ref()
        .clone();
    let globex_hash = globex_principal
        .password
        .as_ref()
        .expect("a password")
        .as_ref()
        .clone();
    assert_ne!(
        acme_hash, globex_hash,
        "the two tenants must not share a credential row"
    );
}

/// Row 25: a calendar that exists in one tenant is **not found** on the other.
///
/// The calendar is real — created by a real `MKCALENDAR` in Acme — and it has
/// the *same name* in the path as a calendar in Globex, so the only thing
/// separating the two answers is which database the request reached.
#[test]
fn a_calendar_from_one_tenant_is_not_found_on_another() {
    let mut cluster = Cluster::new();
    cluster.seed();
    let acme = cluster.id("acme");
    let globex = cluster.id("globex");
    let acme_token = provision(&cluster, &acme);
    let globex_token = provision(&cluster, &globex);

    cluster.start();
    cluster.wait_ready();

    // Acme gets `secret-project`; Globex does not.
    assert_eq!(
        cluster
            .mkcalendar("acme.t3.gg", "secret-project", PRINCIPAL, &acme_token)
            .0,
        201
    );

    let secret = "/caldav/principal/alice/secret-project";

    // It exists in Acme, read with Acme's own credential.
    let (status, _) = cluster.propfind("acme.t3.gg", secret, PRINCIPAL, &acme_token);
    assert_eq!(status, 207, "acme's own calendar must be readable");

    // **Row 25.** Read from Globex's host with **Globex's own valid app token**.
    // This is the strong form: the credential is genuine, so a 404 can only mean
    // the calendar is not in the database this request reached. A 401 here would
    // prove nothing about resource isolation — it would only say the credential
    // was wrong, which is row 24's job and a different test.
    let (status, body) = cluster.propfind("globex.t3.gg", secret, PRINCIPAL, &globex_token);
    assert_eq!(
        status,
        404,
        "row 25: globex must not serve acme's calendar; got {status} {body:?}\nlog:\n{}",
        cluster.log()
    );

    // Globex creating the same name must succeed, which is the same fact from
    // the other side: the two namespaces are independent, so this is 201 and not
    // 409.
    assert_eq!(
        cluster
            .mkcalendar("globex.t3.gg", "secret-project", PRINCIPAL, &globex_token)
            .0,
        201,
        "the same calendar name must be creatable in both tenants"
    );
}

/// The two tenants' databases are separate **files**, which is the mechanism
/// rows 24-25 rest on.
///
/// A row asserting an outcome is worth one asserting the structure that makes
/// the outcome structural. If these ever became one file, isolation would be a
/// promise rather than a fact — and the tests above would still pass for as long
/// as the data had not yet diverged.
#[test]
fn the_two_tenants_never_share_a_database_file() {
    let mut cluster = Cluster::new();
    cluster.seed();
    let acme = cluster.id("acme");
    let globex = cluster.id("globex");

    assert_ne!(acme, globex);
    let acme_db = cluster.tenant_db(&acme);
    let globex_db = cluster.tenant_db(&globex);
    assert!(acme_db.exists(), "{}", acme_db.display());
    assert!(globex_db.exists(), "{}", globex_db.display());
    assert_ne!(acme_db, globex_db);

    // And with tenancy on the **global** store is never opened at all: no
    // request is ever dispatched to it, so it is not even created. That is the
    // §3.2 claim in its strongest form — there is no store for a request to be
    // served from by mistake.
    assert!(
        !cluster.path("data").join("db.sqlite3").exists(),
        "with tenancy on, the single-tenant store must never be opened"
    );
}
