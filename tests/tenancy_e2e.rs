//! End-to-end: a real `rustical serve` process, two tenants, one port.
//! `PLAN_DEPLOYMENTS.md` §3.3, and the precondition for **rows 24-25 and 29**.
//!
//! ## Why a separate target driving a real process
//!
//! §12's rows 24, 25 and 29 are claims about a *server*: "tenant A's principal +
//! app token against tenant B's host", "tenant A's calendar id on tenant B's
//! host", "suspend, then request the same URL". None of that can be asserted by
//! calling `HostDispatch` directly — a test that constructs the dispatcher itself
//! tests a component, and the component is not where the claim lives.
//!
//! ## The one thing this file exists to prevent
//!
//! **The config the server reads and the paths the test seeds must be the same
//! paths.** The first draft of this file built `[tenancy] control_db_url` from
//! `/tmp/omnical-e2e-<pid>.sqlite3` and seeded
//! `<tempdir>/control.sqlite3`. The server therefore opened a control plane of
//! its own making, found no tenants, and answered 404 to every host — which
//! looked exactly like a dispatch bug. The symptom was identical to the thing
//! this file is meant to detect, which is the worst possible failure mode for a
//! test. So `Install` owns the directory and writes the config out of it; there
//! is exactly one source of paths.
//!
//! ## What it cannot prove
//!
//! Cross-tenant **auth** isolation (row 24) needs two tenants holding the same
//! principal, and `AuthenticationLayer` is the thing under test — which item 9
//! covers, with rows 26-28. What this target proves is the *dispatch* half: that
//! a request for tenant A's host reaches A's database and cannot reach B's, and
//! that suspension takes effect on the next request. A green run here is a
//! precondition for row 24, not the row.

use reqwest::{Client, StatusCode};
use rustical::host_dispatch::HEALTH_PATH;
use rustical_store::TenantId;
use rustical_store::tenant_store::TenantStore;
use rustical_store_sqlite::{SqliteTenantStore, create_control_plane_pool, new_tenant};
use std::io::Write;
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// A temporary install: a directory, a config written out of it, a server.
struct Install {
    dir: tempfile::TempDir,
    port: u16,
    child: Option<Child>,
    tenancy_enabled: bool,
}

impl Install {
    /// A new install. `Some((base_domain, default_tenant))` turns tenancy on;
    /// `None` writes a config with no `[tenancy]` section at all, which is the
    /// §3.6 "enabled = false" case.
    fn new(tenancy: Option<(&str, &str)>) -> Self {
        let dir = tempfile::tempdir().expect("a temp dir");
        // SQLite creates a *file* but not the directory above it. For a
        // single-tenant store an operator creates that themselves; for a tenant
        // store `TenancyConfig::ensure_tenant_store_dir` does it. Here it is the
        // test's job, and doing it explicitly keeps the two paths distinguishable.
        std::fs::create_dir_all(dir.path().join("data")).expect("the data directory");

        let port = {
            let listener = TcpListener::bind("127.0.0.1:0").expect("a free port");
            listener.local_addr().expect("an address").port()
        };

        let mut config = format!(
            "[http]\nbind = \"127.0.0.1:{port}\"\n\n\
             [data_store.sqlite]\ndb_url = \"{db}\"\nrun_repairs = false\nskip_broken = false\n\n\
             [frontend]\nenabled = true\nallow_password_login = true\n",
            db = dir.path().join("data").join("db.sqlite3").display(),
        );
        if let Some((base_domain, default_tenant)) = tenancy {
            // Every path in the config comes from `dir`, which is the same place
            // `seed` and `tenant_id` read. One source of truth, by construction.
            config.push_str(&format!(
                "\n[tenancy]\nenabled = true\n\
                 control_db_url = \"sqlite://{control}\"\n\
                 base_domain = \"{base_domain}\"\ndefault_tenant = \"{default_tenant}\"\n\
                 max_cached_tenants = 8\ndata_root = \"{root}\"\n",
                control = dir.path().join("control.sqlite3").display(),
                root = dir.path().join("data").display(),
            ));
        }

        let mut file = std::fs::File::create(dir.path().join("config.toml")).expect("a config");
        file.write_all(config.as_bytes()).expect("written");
        drop(file);

        Self {
            dir,
            port,
            child: None,
            tenancy_enabled: tenancy.is_some(),
        }
    }

    /// The path a health check should use in this install's mode.
    ///
    /// `/healthz` exists **only** when tenancy is on — with tenancy off, `/ping`
    /// answers for every host, and §3.6's "exactly as today" means not adding a
    /// second unauthenticated route to the single-tenant surface.
    fn health_path(&self) -> &'static str {
        if self.tenancy_enabled {
            HEALTH_PATH
        } else {
            "/ping"
        }
    }

    fn path(&self, rel: &str) -> PathBuf {
        self.dir.path().join(rel)
    }

    fn start(&mut self) {
        let log = std::fs::File::create(self.path("server.log")).expect("a log file");
        let err = log.try_clone().expect("a second handle");
        // `--config-file` is a *global* arg, so it has to precede the subcommand;
        // clap rejects it after `serve`.
        let child = Command::new(env!("CARGO_BIN_EXE_rustical"))
            .arg("--config-file")
            .arg(self.path("config.toml"))
            .arg("serve")
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(err))
            .spawn()
            .expect("the server starts");
        self.child = Some(child);
    }

    /// Wait until the health path answers, or fail with the server's own log.
    ///
    /// The log is in the panic message on purpose: every "the server did not come
    /// up" failure in this file is a config or a startup error, and hunting for
    /// them in a test harness's stdout is how hours go missing.
    fn wait_ready(&self) {
        let rt = tokio::runtime::Runtime::new().expect("a runtime");
        let client = Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .expect("a client");
        let probe = self.health_path();
        let deadline = Instant::now() + Duration::from_secs(60);
        while Instant::now() < deadline {
            let ready = rt.block_on(async {
                client
                    .get(format!("http://127.0.0.1:{}{probe}", self.port))
                    .send()
                    .await
                    .is_ok_and(|r| r.status().is_success())
            });
            if ready {
                return;
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        panic!(
            "the server never became ready on {probe}.\n--- config ---\n{}\n--- log ---\n{}",
            self.config_text(),
            self.log()
        );
    }

    fn config_text(&self) -> String {
        std::fs::read_to_string(self.path("config.toml")).unwrap_or_default()
    }

    fn log(&self) -> String {
        std::fs::read_to_string(self.path("server.log")).unwrap_or_default()
    }

    fn stop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }

    /// One request, with an explicit `Host` header.
    fn get(&self, host: &str, path: &str) -> (StatusCode, String) {
        let rt = tokio::runtime::Runtime::new().expect("a runtime");
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("a client");
        rt.block_on(async {
            let response = client
                .get(format!("http://127.0.0.1:{}{path}", self.port))
                .header("Host", host)
                .send()
                .await
                .unwrap_or_else(|e| panic!("GET http://{host}{path} failed: {e}"));
            (response.status(), response.text().await.unwrap_or_default())
        })
    }

    /// Seed the control plane the server is about to read.
    ///
    /// Written in-process rather than by shelling out to `rustical tenant`,
    /// because that CLI is **item 11** and does not exist yet — a test must not
    /// depend on a command two commits away.
    fn seed(&self, tenants: &[(&str, &str, &[&str])]) {
        let url = format!("sqlite://{}", self.path("control.sqlite3").display());
        let rt = tokio::runtime::Runtime::new().expect("a runtime");
        rt.block_on(async {
            let pool = create_control_plane_pool(&url, true)
                .await
                .expect("the control plane migrates");
            let store = SqliteTenantStore::new(pool);
            for (slug, display, hosts) in tenants {
                let mut new = new_tenant(&slug.parse().expect("a valid slug"), Some(display));
                new.hosts = hosts.iter().map(|h| (*h).to_owned()).collect();
                store
                    .create_tenant(&new)
                    .await
                    .unwrap_or_else(|e| panic!("seeding {slug} failed: {e}"));
            }
        });
    }

    fn tenant_id(&self, slug: &str) -> TenantId {
        let url = format!("sqlite://{}", self.path("control.sqlite3").display());
        let rt = tokio::runtime::Runtime::new().expect("a runtime");
        rt.block_on(async {
            let pool = create_control_plane_pool(&url, false)
                .await
                .expect("the control plane opens");
            SqliteTenantStore::new(pool)
                .get_tenant_by_slug(slug)
                .await
                .expect("a lookup")
                .unwrap_or_else(|| panic!("{slug} was seeded"))
                .id
        })
    }

    fn tenant_db(&self, id: &TenantId) -> PathBuf {
        self.path("data")
            .join("tenants")
            .join(id.as_str())
            .join("db.sqlite3")
    }

    /// Suspend a tenant, as `rustical tenant suspend` (item 11) will.
    fn suspend(&self, id: &TenantId) {
        let url = format!("sqlite://{}", self.path("control.sqlite3").display());
        let rt = tokio::runtime::Runtime::new().expect("a runtime");
        rt.block_on(async {
            let pool = create_control_plane_pool(&url, false)
                .await
                .expect("the control plane opens");
            SqliteTenantStore::new(pool)
                .update_tenant_status(id, rustical_store::TenantStatus::Suspended)
                .await
                .expect("suspended");
        });
    }
}

impl Drop for Install {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Block until the child exits, or fail.
fn wait_for_exit(install: &mut Install) -> std::process::ExitStatus {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(child) = install.child.as_mut()
            && let Some(status) = child.try_wait().expect("a wait status")
        {
            return status;
        }
        assert!(
            Instant::now() < deadline,
            "the server neither started nor exited"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
}

#[test]
fn two_tenants_are_served_from_one_port_by_host() {
    // §3.2's claim, end to end: one process, one port, two databases, and the
    // `Host` header decides which one answers.
    let mut install = Install::new(Some(("t3.gg", "")));
    install.seed(&[("acme", "Acme Corp", &[]), ("globex", "Globex", &[])]);
    install.start();
    install.wait_ready();

    for host in ["acme.t3.gg", "globex.t3.gg"] {
        let (status, body) = install.get(host, "/ping");
        assert_eq!(
            status,
            200,
            "{host}: {body}\n--- server log ---\n{}",
            install.log()
        );
        assert_eq!(body, "Pong!", "{host}");
    }

    // And their databases really are separate files on disk.
    let acme = install.tenant_id("acme");
    let globex = install.tenant_id("globex");
    assert_ne!(acme, globex, "ids must differ");
    assert!(install.tenant_db(&acme).exists(), "acme's database");
    assert!(install.tenant_db(&globex).exists(), "globex's database");
}

#[test]
fn the_health_path_answers_even_though_no_tenant_owns_the_instance_address() {
    // The bug this endpoint exists for. The health check arrives on
    // `127.0.0.1:<port>`, which is not a tenant's host; if the health answer
    // depended on tenant resolution, a load balancer would take a perfectly
    // healthy instance out of rotation.
    let mut install = Install::new(Some(("t3.gg", "")));
    install.seed(&[("acme", "Acme Corp", &[])]);
    install.start();
    install.wait_ready();

    let (status, _) = install.get("127.0.0.1", HEALTH_PATH);
    assert_eq!(status, 200, "the health path must not be tenant-scoped");
    // While `/ping` on the same address is correctly a 404: it *is* an
    // application route, and no tenant claims this address.
    let (status, _) = install.get("127.0.0.1", "/ping");
    assert_eq!(status, 404);
}

#[test]
fn an_unknown_host_is_a_404_and_says_nothing_about_any_tenant() {
    let mut install = Install::new(Some(("t3.gg", "")));
    install.seed(&[("acme", "Acme Corp", &[])]);
    install.start();
    install.wait_ready();

    let (status, body) = install.get("nobody.t3.gg", "/ping");
    assert_eq!(status, 404);
    // Three distinguishable outcomes here would be a tenant-enumeration oracle.
    assert!(!body.contains("acme"), "must not name a tenant: {body}");
    assert!(
        !body.contains("t3.gg"),
        "must not name the base domain: {body}"
    );
}

#[test]
fn suspension_takes_effect_on_the_next_request() {
    // **Row 29**, through a real server. The router for the tenant is already
    // built and cached; the control plane says suspended; the next request 404s.
    let mut install = Install::new(Some(("t3.gg", "")));
    install.seed(&[("acme", "Acme Corp", &[]), ("globex", "Globex", &[])]);
    let acme = install.tenant_id("acme");
    install.start();
    install.wait_ready();

    // Serving first, so the "after" is a transition rather than a tenant that
    // never worked — and so the router really is cached before the suspension.
    let (status, body) = install.get("acme.t3.gg", "/ping");
    assert_eq!(status, 200, "{body}");

    install.suspend(&acme);

    let (status, _) = install.get("acme.t3.gg", "/ping");
    assert_eq!(
        status, 404,
        "row 29: suspended tenants stop on the next request"
    );
    // The other tenant is untouched.
    let (status, _) = install.get("globex.t3.gg", "/ping");
    assert_eq!(status, 200, "suspending one tenant must not affect another");
}

#[test]
fn tenancy_disabled_ignores_the_host_header_entirely() {
    // §3.6's headline property, on a real process: with no `[tenancy]` section
    // the `Host` header must change nothing, because there is no dispatch layer
    // in front of the router to read it.
    let mut install = Install::new(None);
    install.start();
    install.wait_ready();

    for host in [
        "acme.t3.gg",
        "unknown.invalid",
        "127.0.0.1:1",
        "Acme.T3.GG:8443",
        "[::1]",
    ] {
        let (status, body) = install.get(host, "/ping");
        assert_eq!(status, 200, "host {host} must be served");
        assert_eq!(body, "Pong!", "host {host}");
    }
    // And nothing tenant-shaped was created, because nothing was dispatched.
    assert!(
        !install.path("data").join("tenants").exists(),
        "single-tenant mode must not create per-tenant directories"
    );
    // Nor was a control plane, because none is opened.
    assert!(
        !install.path("control.sqlite3").exists(),
        "single-tenant mode must not open a control plane"
    );
}

#[test]
fn a_misconfigured_tenancy_section_refuses_to_start() {
    // `enabled = true` with nothing that can resolve a Host. This must fail at
    // startup with a message naming the fix — not boot and 404 every request,
    // which would look like a working server to a load balancer.
    let mut install = Install::new(None);
    // Overwrite the config with a tenancy section that cannot resolve anything.
    let broken = install.config_text()
        + "\n[tenancy]\nenabled = true\ncontrol_db_url = \"sqlite:///tmp/omnical-nope.sqlite3\"\n";
    std::fs::write(install.path("config.toml"), broken).expect("the config is rewritten");

    install.start();
    let status = wait_for_exit(&mut install);
    assert!(
        !status.success(),
        "a server that cannot resolve any host must refuse to start"
    );
    let log = install.log();
    assert!(
        log.contains("default_tenant") && log.contains("base_domain"),
        "the failure must name the missing settings; log was:\n{log}"
    );
}

#[test]
fn an_unknown_tenancy_key_is_rejected_rather_than_ignored() {
    // §18.14's rule: a config key that is accepted and does nothing is worse
    // than a missing one. `deny_unknown_fields` is what makes `store = "redis"`
    // (the `session-redis` feature does not exist yet) a loud error instead of a
    // silent no-op.
    let mut install = Install::new(None);
    let bogus = install.config_text()
        + "\n[tenancy]\nenabled = false\nstore = \"redis\"\ntrusted_proxies = [\"10.0.0.1\"]\n";
    std::fs::write(install.path("config.toml"), bogus).expect("the config is rewritten");

    install.start();
    let status = wait_for_exit(&mut install);
    assert!(
        !status.success(),
        "an unknown [tenancy] key must be refused"
    );
    let log = install.log();
    assert!(
        log.contains("unknown field") || log.contains("tenancy"),
        "the error must name the offending section; log was:\n{log}"
    );
}
