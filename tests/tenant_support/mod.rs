//! Shared fixture for the multi-tenant end-to-end tests.
//!
//! `cross_tenant.rs` (rows 24-25) and `public_routes.rs` (rows 26-28) both need
//! a real server, two real tenant databases, and the shipped CLI to populate
//! them. Duplicating a 200-line fixture across the two would guarantee they drift
//! — and a fixture that drifts from the product is worse than no fixture, because
//! the tests stay green while testing something else.
//!
//! Not a test target of its own: Rust does not compile `tests/*/mod.rs` as one.

#![allow(dead_code, reason = "each test binary uses a different subset")]

use rustical_store::auth::AuthenticationProvider;
use rustical_store::tenant::{Tenant, TenantId};
use rustical_store::tenant_store::{NewTenant, TenantQuota, TenantStore};
use rustical_store_sqlite::{
    SqlitePrincipalStore, SqliteTenantStore, create_control_plane_pool, new_tenant,
};

/// A fixed actor for the fixtures. Not a credential, and it never leaves the test
/// process — the point of these tests is the *shape* of an audit row, not who
/// wrote it.
///
/// A function rather than a `static`, because [`rustical_store::Actor::new`]
/// validates and is therefore not `const`.
fn test_actor() -> rustical_store::Actor {
    rustical_store::Actor::new("test").expect("a valid actor")
}

use sqlx::Row;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// The RSVP secret in the **global** config, which a tenant with no per-tenant
/// override inherits.
pub const GLOBAL_RSVP_SECRET: &str = "global-rsvp-secret-do-not-share";

/// A temporary install: a directory, a config written out of it, a server.
pub struct Fixture {
    pub dir: tempfile::TempDir,
    pub port: u16,
    pub child: Option<Child>,
    pub tenancy: bool,
    /// The listener that reserved [`Self::port`], held from `new()` until
    /// `start()`.
    ///
    /// **This exists because of a CI failure, not a theory.** The first version
    /// bound port 0, read the number off it, and dropped the listener
    /// immediately — so the port was unreserved for the whole of setup (writing
    /// the config, seeding tenants, provisioning principals) and only claimed
    /// when the child spawned. Linux reuses ephemeral ports, so a second
    /// `Fixture` created in that window could take the same one. The symptom was
    /// a **401** on an authenticated MKCALENDAR in `public_routes.rs`: the
    /// request reached the *other* fixture's server, whose store had no such
    /// principal. Nothing in the failure said "port collision", and the test
    /// passed locally every time.
    ///
    /// Holding the listener shrinks the window from the whole of setup to the
    /// microseconds between dropping it and the child's `bind`. A residual
    /// collision now shows up as the child failing to bind, which
    /// [`Self::wait_ready`] reports with the child's own log instead of as a
    /// mysterious 401 somewhere else.
    port_reservation: Option<std::net::TcpListener>,
}

impl Fixture {
    /// A new install. `Some((base_domain, default_tenant))` turns tenancy on;
    /// `None` writes a config with no `[tenancy]` section at all — the §3.6
    /// "enabled = false" case.
    ///
    /// Every path in the config comes from `self.dir`, which is also where
    /// [`Self::seed_tenants`] and [`Self::tenant_db`] look. One source of paths,
    /// because the first draft of the cross-tenant target built the config from
    /// one path and seeded another, and the server then answered 404 to every
    /// host — a symptom indistinguishable from the dispatch bug it was looking
    /// for.
    pub fn new(tenancy: Option<(&str, &str)>) -> Self {
        let dir = tempfile::tempdir().expect("a temp dir");
        // SQLite creates a *file* but not the directory above it.
        std::fs::create_dir_all(dir.path().join("data")).expect("the data directory");
        // Kept alive in the struct, not a temporary.
        let port_reservation = std::net::TcpListener::bind("127.0.0.1:0").expect("a free port");
        let port = port_reservation.local_addr().expect("an address").port();

        let mut config = format!(
            "[http]\nbind = \"127.0.0.1:{port}\"\n\n\
             [data_store.sqlite]\ndb_url = \"{db}\"\nrun_repairs = false\nskip_broken = false\n\n\
             [frontend]\nenabled = true\nallow_password_login = true\n\n\
             [subscriptions]\nenabled = true\npublic_url = \"https://{base}\"\n\n\
             [registration]\nenabled = true\n",
            db = dir.path().join("data").join("db.sqlite3").display(),
            base = tenancy.map_or("single.example", |(b, _)| b),
        );
        if let Some((base_domain, default_tenant)) = tenancy {
            config.push_str(&format!(
                "\n[tenancy]\nenabled = true\n\
                 control_db_url = \"sqlite://{control}\"\n\
                 base_domain = \"{base_domain}\"\ndefault_tenant = \"{default_tenant}\"\n\
                 max_cached_tenants = 8\ndata_root = \"{root}\"\n\
                 [scheduling]\nenabled = true\n\
                 rsvp_secret = \"{global}\"\n\
                 rsvp_base_url = \"https://{base_domain}\"\n",
                control = dir.path().join("control.sqlite3").display(),
                root = dir.path().join("data").display(),
                global = GLOBAL_RSVP_SECRET,
            ));
        }
        std::fs::write(dir.path().join("config.toml"), config).expect("the config");

        Self {
            dir,
            port,
            child: None,
            tenancy: tenancy.is_some(),
            port_reservation: Some(port_reservation),
        }
    }

    /// The RSVP secret in the **global** config, which a tenant with no override
    /// inherits.
    #[must_use]
    pub fn global_rsvp_secret(&self) -> String {
        GLOBAL_RSVP_SECRET.to_owned()
    }

    pub fn path(&self, rel: &str) -> PathBuf {
        self.dir.path().join(rel)
    }

    /// The health path for this install's mode.
    ///
    /// `/healthz` exists **only** when tenancy is on; with tenancy off `/ping`
    /// answers for every host and §3.6 says not to widen that surface.
    pub fn health_path(&self) -> &'static str {
        if self.tenancy {
            rustical::host_dispatch::HEALTH_PATH
        } else {
            "/ping"
        }
    }

    // ------------------------------------------------------------ control plane

    pub fn control_plane(&self) -> SqliteTenantStore {
        let url = format!("sqlite://{}", self.path("control.sqlite3").display());
        let pool = rt()
            .block_on(create_control_plane_pool(&url, true))
            .expect("the control plane migrates");
        SqliteTenantStore::new(pool)
    }

    /// [`Self::control_plane`], for a test that is **already** inside a runtime.
    ///
    /// The sync version builds its own runtime, and nesting one inside
    /// `#[tokio::test]` panics with "Cannot start a runtime from within a
    /// runtime" — which is a confusing way to learn that a fixture decided
    /// which executor the test would use. `host_dispatch.rs` sets the precedent
    /// of async fixture methods for exactly this reason.
    pub async fn control_plane_async(&self) -> SqliteTenantStore {
        let url = format!("sqlite://{}", self.path("control.sqlite3").display());
        let pool = create_control_plane_pool(&url, true)
            .await
            .expect("the control plane migrates");
        SqliteTenantStore::new(pool)
    }

    /// [`Self::tenant_id_any`], for a test already inside a runtime. Suspended
    /// tenants included, so it is the "any" variant and not the active-only one.
    pub async fn tenant_id_async(&self, slug: &str) -> TenantId {
        self.control_plane_async()
            .await
            .get_any_tenant_by_slug(slug)
            .await
            .expect("a lookup")
            .unwrap_or_else(|| panic!("{slug} was seeded"))
            .id
    }

    /// [`Self::seed_tenants`], for a test already inside a runtime.
    ///
    /// The sync version builds its own runtime, and nesting one inside
    /// `#[tokio::test]` panics with "Cannot start a runtime from within a
    /// runtime". `admin_panel.rs` needs this because its tests are async (the
    /// panel is driven by awaiting its own `Service`), and every fixture call in
    /// them has to agree about the executor.
    pub async fn seed_tenants_async(&self, slugs: &[&str]) {
        let store = self.control_plane_async().await;
        for slug in slugs {
            let new: NewTenant = new_tenant(&(*slug).parse().expect("a valid slug"), None);
            store
                .create_tenant(&new, &test_actor())
                .await
                .unwrap_or_else(|e| panic!("seeding {slug} failed: {e}"));
        }
    }

    /// Seed tenants with optional per-tenant `config_json`.
    ///
    /// `config_json` is where §3.6's per-tenant overrides live, and `rsvp_secret`
    /// is the one item 9 needs: it is an HMAC key, so "which tenant" is a
    /// question about the *key*, not about a database row.
    pub fn seed_tenants_with(&self, tenants: &[(&str, &str)]) {
        let store = self.control_plane();
        rt().block_on(async {
            for (slug, config_json) in tenants {
                let mut new: NewTenant = new_tenant(&(*slug).parse().expect("a valid slug"), None);
                new.tenant.config_json = (*config_json).to_owned();
                store
                    .create_tenant(&new, &test_actor())
                    .await
                    .unwrap_or_else(|e| panic!("seeding {slug} failed: {e}"));
            }
        });
    }

    /// Seed tenants with **no** overrides, so each inherits the global config.
    pub fn seed_tenants(&self, slugs: &[&str]) {
        let pairs: Vec<(&str, &str)> = slugs.iter().map(|s| (*s, "{}")).collect();
        self.seed_tenants_with(&pairs);
    }

    /// Seed tenants with a **distinct** `rsvp_secret` each.
    ///
    /// This is the configuration row 27 exists to make safe, and it is what a
    /// hosted deployment actually runs: if both tenants inherited one secret
    /// there would be nothing to scope, and the gate would be measuring the
    /// fixture rather than the code.
    pub fn seed_tenants_with_distinct_secrets(&self, slugs: &[&str]) {
        let pairs: Vec<(&str, &str)> = slugs
            .iter()
            .map(|s| {
                let blob = format!(r#"{{"rsvp_secret":"rsvp-secret-for-{s}"}}"#);
                (*s, Box::leak(blob.into_boxed_str()) as &str)
            })
            .collect();
        self.seed_tenants_with(&pairs);
    }

    /// A tenant's id, from the **active-only** lookup.
    ///
    /// Panics for a suspended tenant, which is the store's own semantics and not
    /// a test convenience: a suspended tenant does not resolve. Use
    /// [`Self::tenant_id_any`] to reach a suspended tenant's *data*.
    pub fn tenant_id(&self, slug: &str) -> TenantId {
        let store = self.control_plane();
        rt().block_on(async {
            store
                .get_tenant_by_slug(slug)
                .await
                .expect("a lookup")
                .unwrap_or_else(|| panic!("{slug} was seeded and is active"))
                .id
        })
    }

    /// A tenant's id, active or not.
    ///
    /// Needed by anything that addresses a tenant's *store* — an admin still has
    /// to be able to reach a suspended tenant's data, and a fixture that used the
    /// active-only lookup would make "refuse to select a suspended tenant"
    /// untestable, because the fixture could not even name the tenant.
    pub fn tenant_id_any(&self, slug: &str) -> TenantId {
        let store = self.control_plane();
        rt().block_on(async {
            store
                .get_any_tenant_by_slug(slug)
                .await
                .expect("a lookup")
                .unwrap_or_else(|| panic!("{slug} was seeded"))
                .id
        })
    }

    pub fn tenant(&self, slug: &str) -> Tenant {
        let store = self.control_plane();
        rt().block_on(async {
            store
                .get_tenant_by_slug(slug)
                .await
                .expect("a lookup")
                .unwrap_or_else(|| panic!("{slug} was seeded"))
        })
    }

    pub fn set_status(&self, id: &TenantId, status: rustical_store::TenantStatus) {
        let store = self.control_plane();
        rt().block_on(async { store.update_tenant_status(id, status, &test_actor()).await })
            .expect("a status update");
    }

    pub fn suspend(&self, id: &TenantId) {
        self.set_status(id, rustical_store::TenantStatus::Suspended);
    }

    // ------------------------------------------------------------ tenant stores

    pub fn tenant_db(&self, id: &TenantId) -> PathBuf {
        self.path("data")
            .join("tenants")
            .join(id.as_str())
            .join("db.sqlite3")
    }

    /// Create a tenant's store directory and file.
    ///
    /// A tenant's store is otherwise created **lazily**, on the first request
    /// that resolves to it — fine for serving, useless for administering, because
    /// a config cannot point at a path that does not exist. `rustical tenant
    /// create` (item 11) is therefore obliged to do this; until it exists, the
    /// gates do it by hand.
    pub fn materialise_tenant(&self, slug: &str) {
        let id = self.tenant_id(slug);
        // The directory first: `create_if_missing` creates the *file*.
        std::fs::create_dir_all(self.tenant_db(&id).parent().expect("a parent"))
            .expect("the tenant directory");
        let url = format!("sqlite://{}", self.tenant_db(&id).display());
        rt().block_on(async {
            rustical_store_sqlite::create_db_pool(&url, true)
                .await
                .expect("the tenant store migrates");
        });
    }

    /// A config file pointing at one tenant's own data, for the CLI.
    ///
    /// Two things in it matter and are easy to miss:
    ///
    /// - **`[tenancy] enabled = true`.** `OMNICAL_TENANT` is a no-op on a
    ///   config with tenancy off, by design — a single-tenant install has no
    ///   per-tenant overrides to apply, and silently reading them would be
    ///   surprising. So the config an admin uses to operate on one tenant's data
    ///   has to name the control plane as well as the store. This is the shape
    ///   `rustical tenant` (item 11) will replace with an explicit subcommand.
    /// - **`[subscriptions] enabled = true`.** `subscriptions add` refuses to
    ///   mint a feed whose routes are not mounted.
    pub fn tenant_config(&self, id: &TenantId) -> PathBuf {
        let path = self.path(&format!("tenant-{}.toml", id.as_str()));
        let body = format!(
            "[data_store.sqlite]\ndb_url = \"{db}\"\nrun_repairs = false\nskip_broken = false\n\n\
             [subscriptions]\nenabled = true\npublic_url = \"https://global.example\"\n\n\
             [tenancy]\nenabled = true\ncontrol_db_url = \"sqlite://{control}\"\n\
             data_root = \"{root}\"\n",
            db = self.tenant_db(id).display(),
            control = self.path("control.sqlite3").display(),
            root = self.path("data").display(),
        );
        std::fs::write(&path, body).expect("the tenant config");
        path
    }

    /// Run a CLI subcommand against one tenant's data **as a selected tenant**.
    ///
    /// `OMNICAL_TENANT=slug` is what makes the command merge that tenant's
    /// `config_json` over the global config — §6.3 rows 30-31, which are about
    /// commands rather than about the server.
    pub fn cli_as(&self, slug: &str, as_tenant: &str, args: &[&str]) -> String {
        let id = self.tenant_id(slug);
        let config = self.tenant_config(&id);
        let out = Command::new(env!("CARGO_BIN_EXE_rustical"))
            .arg("--config-file")
            .arg(&config)
            .args(args)
            .env("OMNICAL_TENANT", as_tenant)
            .output()
            .expect("the CLI runs");
        assert!(
            out.status.success(),
            "`{args:?}` as {as_tenant} failed: {}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).trim().to_owned()
    }

    /// Run a CLI subcommand expecting **failure**, returning the full output.
    ///
    /// Used by the gates that assert a refusal, so a command which starts
    /// succeeding is a test failure rather than a silent pass.
    pub fn cli_expect_failure(
        &self,
        slug: &str,
        as_tenant: &str,
        args: &[&str],
    ) -> std::process::Output {
        let id = self.tenant_id_any(slug);
        let config = self.tenant_config(&id);
        let out = Command::new(env!("CARGO_BIN_EXE_rustical"))
            .arg("--config-file")
            .arg(&config)
            .args(args)
            .env("OMNICAL_TENANT", as_tenant)
            .output()
            .expect("the CLI runs");
        assert!(
            !out.status.success(),
            "`{args:?}` as {as_tenant} unexpectedly succeeded: {}",
            String::from_utf8_lossy(&out.stdout)
        );
        out
    }

    /// A config the **control-plane** commands can use: the server config, with
    /// `[tenancy] enabled` and a `data_root`.
    ///
    /// The server's own config is not usable for `rustical tenant …` because its
    /// `[data_store]` points at the *single-tenant* store. A config the control
    /// plane accepts and a tenant store path derived from the same `data_root` is
    /// what makes the CLI and the server agree, which is the point of
    /// `TenancyConfig::data_root` being one function.
    pub fn control_config(&self) -> PathBuf {
        let path = self.path("control-cli.toml");
        let body = format!(
            "[data_store.sqlite]\ndb_url = \"sqlite://{db}\"\nrun_repairs = false\n\
             skip_broken = false\n\n\
             [tenancy]\nenabled = true\ncontrol_db_url = \"sqlite://{control}\"\n\
             data_root = \"{root}\"\nmax_cached_tenants = 8\n",
            db = self.path("data").join("db.sqlite3").display(),
            control = self.path("control.sqlite3").display(),
            root = self.path("data").display(),
        );
        std::fs::write(&path, body).expect("the control config");
        path
    }

    /// A **server** config with the admin surface configured (§6.6.2).
    ///
    /// Separate from [`Self::control_config`] because that one is a CLI config —
    /// its `[data_store]` points at the single-tenant store. This one is a real
    /// serve config, so it can be booted to prove a startup refusal, which is
    /// the only way to gate "refuses to start".
    ///
    /// The parameters exist so a test can express the *bad* combinations without
    /// hand-writing TOML: `admin_host = ""` (no panel), `ack = false` (set but
    /// unacknowledged), and an empty `admins` list.
    pub fn admin_server_config(
        &self,
        admin_host: &str,
        admins: &[&str],
        ack: bool,
        port: u16,
    ) -> PathBuf {
        let path = self.path(&format!("admin-server-{port}.toml"));
        let body = format!(
            "[http]\nbind = \"127.0.0.1:{port}\"\n\n\
             [data_store.sqlite]\ndb_url = \"sqlite://{db}\"\nrun_repairs = false\n\
             skip_broken = false\n\n\
             [frontend]\nenabled = true\n\n\
             [tenancy]\nenabled = true\n\
             control_db_url = \"sqlite://{control}\"\n\
             base_domain = \"t3.gg\"\n\
             data_root = \"{root}\"\nmax_cached_tenants = 8\n\
             admin_host = \"{admin_host}\"\n\
             platform_admins = [{admins}]\n\
             admin_single_instance_acknowledged = {ack}\n",
            db = self.path("data").join("db.sqlite3").display(),
            control = self.path("control.sqlite3").display(),
            root = self.path("data").display(),
            admins = admins
                .iter()
                .map(|a| format!("\"{a}\""))
                .collect::<Vec<_>>()
                .join(", "),
        );
        std::fs::write(&path, body).expect("the admin server config");
        path
    }

    /// Boot `rustical serve` on `config`, wait for it to **exit**, and return
    /// what it printed.
    ///
    /// Panics if the process was still running after the deadline, because
    /// "refuses to start" and "hangs" are different failures and a test that
    /// conflates them passes on the second one. It also panics if the server
    /// *succeeded*, so a refusal that stops firing is a failure rather than a
    /// silent pass.
    ///
    /// The log is returned rather than left on disk so a test asserting on the
    /// refusal's **message** does not have to guess the log file's name — which
    /// is the kind of coupling that makes a test fail for the wrong reason the
    /// first time a fixture is renamed.
    #[must_use]
    pub fn serve_expecting_refusal(&self, config: &PathBuf) -> String {
        let log_path = self.path(&format!(
            "serve-{}.log",
            config.file_stem().expect("a config stem").display()
        ));
        let log = std::fs::File::create(&log_path).expect("a log file");
        let err = log.try_clone().expect("a second handle");
        // `--config-file` is a *global* arg and must precede the subcommand.
        let mut child = Command::new(env!("CARGO_BIN_EXE_rustical"))
            .arg("--config-file")
            .arg(config)
            .arg("serve")
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(err))
            .spawn()
            .expect("the server starts");
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if let Some(status) = child.try_wait().expect("a wait status") {
                let log = std::fs::read_to_string(&log_path).unwrap_or_default();
                assert!(
                    !status.success(),
                    "serve on {} exited successfully; the startup refusal never fired.\n\
                     --- log ---\n{log}",
                    config.display()
                );
                return log;
            }
            assert!(
                Instant::now() < deadline,
                "serve on {} was still running after 30s; it did not refuse to start.\n\
                 --- log ---\n{}",
                config.display(),
                std::fs::read_to_string(&log_path).unwrap_or_default()
            );
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// Run a subcommand against an arbitrary config file.
    pub fn cli_raw(&self, config: &PathBuf, args: &[&str]) -> String {
        let out = Command::new(env!("CARGO_BIN_EXE_rustical"))
            .arg("--config-file")
            .arg(config)
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

    /// Run a subcommand, returning stdout **and** stderr together.
    ///
    /// For the destructive commands, whose notices go to stderr on purpose — an
    /// operator reading only stdout must not be able to miss that a data
    /// directory was removed.
    pub fn cli_raw_combined(&self, config: &PathBuf, args: &[&str]) -> String {
        let out = Command::new(env!("CARGO_BIN_EXE_rustical"))
            .arg("--config-file")
            .arg(config)
            .args(args)
            .output()
            .expect("the CLI runs");
        assert!(
            out.status.success(),
            "`{args:?}` failed: {}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
    }

    /// Run a subcommand with the given environment overrides.
    ///
    /// Each entry is `(key, Some(value))` to set or `(key, None)` to **remove**.
    /// Removal is the point: `OMNICAL_ACTOR`/`SUDO_USER`/`USER` are the actor
    /// fallbacks, so a test of "refuses with no actor" has to clear them rather
    /// than trust that the harness happens to have none — otherwise the test
    /// passes for a reason that has nothing to do with the code.
    pub fn cli_env(
        &self,
        config: &PathBuf,
        args: &[&str],
        env: &[(&str, Option<&str>)],
    ) -> std::process::Output {
        // The config is used **as given**. Resolving a tenant id here would make
        // `tenant create` untestable, since that is the command that brings the
        // first tenant into existence.
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_rustical"));
        cmd.arg("--config-file").arg(config).args(args);
        for (key, value) in env {
            match value {
                Some(v) => {
                    cmd.env(key, v);
                }
                None => {
                    cmd.env_remove(key);
                }
            }
        }
        cmd.output().expect("the CLI runs")
    }

    /// Run a subcommand expecting **failure**, with the given env overrides.
    pub fn cli_fail_with_env(
        &self,
        config: &PathBuf,
        args: &[&str],
        env: &[(&str, Option<&str>)],
    ) -> std::process::Output {
        let out = self.cli_env(config, args, env);
        assert!(
            !out.status.success(),
            "`{args:?}` unexpectedly succeeded: {}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        out
    }

    /// Expect failure with every one of `cleared` removed from the environment.
    pub fn cli_fail_bare_env(
        &self,
        config: &PathBuf,
        args: &[&str],
        cleared: &[&str],
    ) -> std::process::Output {
        let env: Vec<(&str, Option<&str>)> = cleared.iter().map(|k| (*k, None)).collect();
        self.cli_fail_with_env(config, args, &env)
    }

    /// Run a subcommand expecting success, with `env` **set**.
    pub fn cli_raw_with_env(
        &self,
        config: &PathBuf,
        args: &[&str],
        env: &[(&str, &str)],
    ) -> String {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_rustical"));
        cmd.arg("--config-file").arg(config).args(args);
        for (key, value) in env {
            cmd.env(key, value);
        }
        let out = cmd.output().expect("the CLI runs");
        assert!(
            out.status.success(),
            "`{args:?}` failed: {}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).trim().to_owned()
    }

    /// Run a subcommand expecting **failure**.
    pub fn cli_fail(&self, config: &PathBuf, args: &[&str]) -> std::process::Output {
        let out = Command::new(env!("CARGO_BIN_EXE_rustical"))
            .arg("--config-file")
            .arg(config)
            .args(args)
            .output()
            .expect("the CLI runs");
        assert!(
            !out.status.success(),
            "`{args:?}` unexpectedly succeeded: {}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        out
    }

    /// Run a CLI subcommand against one tenant's data, returning its stdout.
    pub fn cli(&self, slug: &str, args: &[&str]) -> String {
        let id = self.tenant_id_any(slug);
        let config = self.tenant_config(&id);
        let out = Command::new(env!("CARGO_BIN_EXE_rustical"))
            .arg("--config-file")
            .arg(&config)
            .args(args)
            .output()
            .expect("the CLI runs");
        assert!(
            out.status.success(),
            "`{args:?}` against {slug} failed: {}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).trim().to_owned()
    }

    // ---------------------------------------------------------------- fixtures

    /// Create a principal, then mint an app token, both through the shipped CLI.
    ///
    /// `--for-testing-password-from-arg` is a hidden upstream flag that exists
    /// for integration tests, and using it keeps this on the product path.
    pub fn provision(&self, slug: &str, principal: &str, password: &str) -> String {
        self.cli(
            slug,
            &[
                "principals",
                "create",
                principal,
                "--for-testing-password-from-arg",
                password,
            ],
        );
        self.cli(
            slug,
            &[
                "principals",
                "app-token",
                "create",
                principal,
                "--name",
                "gate",
            ],
        )
    }

    /// The password the shared fixtures provision principals with.
    pub const PRINCIPAL_PASSWORD: &'static str = "correct-horse-battery-staple";

    /// A share-link token backed by a **real** calendar, in one tenant only.
    ///
    /// The calendar is created with `MKCALENDAR` over HTTP against the running
    /// server, so the fixture uses the same store the export router will read.
    /// That ordering matters: the export handler resolves the subscription's
    /// `collection_id` and 404s if the collection is gone, so a subscription
    /// pointing at a made-up id returns 404 for *every* host and the gate would
    /// pass while measuring nothing.
    ///
    /// Returns `(token, collection_name, app_token)`.
    pub fn share_link(
        &self,
        host: &str,
        slug: &str,
        principal: &str,
        app_token: &str,
    ) -> (String, String) {
        let collection = "shared-calendar".to_owned();
        let (status, body) = self.mkcalendar(host, &collection, principal, app_token);
        assert_eq!(
            status, 201,
            "creating a calendar in {slug} failed: {status} {body:?}"
        );
        let token = format!("token-for-{slug}");
        let id = self.tenant_id(slug);
        let url = format!("sqlite://{}", self.tenant_db(&id).display());
        rt().block_on(async {
            let pool = rustical_store_sqlite::create_db_pool(&url, false)
                .await
                .expect("the tenant store opens");
            let store = rustical_store_sqlite::SqliteSubscriptionStore::new(
                rustical_store_sqlite::SqliteCalendarStore::new(
                    pool,
                    tokio::sync::mpsc::channel(1).0,
                    false,
                ),
            );
            store
                .add_subscription(principal, SubscriptionKind::Calendar, &collection, &token)
                .await
                .unwrap_or_else(|e| panic!("adding a subscription in {slug} failed: {e}"));
        });
        (token, collection)
    }

    /// Copy a subscription row from one tenant's store into another's.
    ///
    /// This is the **positive control** for row 26, and it matters more than the
    /// negative assertion does. "Tenant A's token 404s under tenant B" is
    /// consistent with the token being broken, the route being unmounted, or the
    /// extension being disabled — any of which would make the gate green while
    /// proving nothing. Putting *the same token* in tenant B's own store and
    /// watching it export proves the 404 came from the store the request reached
    /// and from nothing else.
    pub fn copy_subscription_into(&self, from: &str, to: &str, token: &str, collection: &str) {
        let from_id = self.tenant_id(from);
        let to_id = self.tenant_id(to);
        let from_url = format!("sqlite://{}", self.tenant_db(&from_id).display());
        let to_url = format!("sqlite://{}", self.tenant_db(&to_id).display());
        rt().block_on(async {
            let source = rustical_store_sqlite::create_db_pool(&from_url, false)
                .await
                .expect("the source store opens");
            let row = sqlx::query("SELECT principal, kind FROM subscriptions WHERE token = ?")
                .bind(token)
                .fetch_one(&source)
                .await
                .expect("the source subscription");
            let principal: String = row.get("principal");
            let kind: String = row.get("kind");

            let target = rustical_store_sqlite::create_db_pool(&to_url, false)
                .await
                .expect("the target store opens");
            sqlx::query(
                "INSERT INTO subscriptions (id, principal, kind, collection_id, token) \
                 VALUES (?, ?, ?, ?, ?)",
            )
            .bind(uuid::Uuid::new_v4().to_string())
            .bind(&principal)
            .bind(&kind)
            .bind(collection)
            .bind(token)
            .execute(&target)
            .await
            .expect("the copy is inserted");
        });
    }

    /// Copy an invite row from one tenant's store into another's.
    ///
    /// The positive control for row 28, for the same reason as
    /// [`Self::copy_subscription_into`].
    pub fn copy_invite_into(&self, from: &str, to: &str, code: &str) {
        let from_id = self.tenant_id(from);
        let to_id = self.tenant_id(to);
        let from_url = format!("sqlite://{}", self.tenant_db(&from_id).display());
        let to_url = format!("sqlite://{}", self.tenant_db(&to_id).display());
        rt().block_on(async {
            let source = rustical_store_sqlite::create_db_pool(&from_url, false)
                .await
                .expect("the source store opens");
            let row = sqlx::query("SELECT * FROM invites WHERE code = ?")
                .bind(code)
                .fetch_one(&source)
                .await
                .expect("the source invite");
            let target = rustical_store_sqlite::create_db_pool(&to_url, false)
                .await
                .expect("the target store opens");
            sqlx::query(
                // The column list is spelled out against the *migrated* schema
                // rather than assumed: an earlier draft named a collection
                // column that the 20260907 invites migration does not have.
                "INSERT INTO invites (id, code, target_email, created_by, created_at) \
                 VALUES (?, ?, NULL, ?, ?)",
            )
            .bind(uuid::Uuid::new_v4().to_string())
            .bind(code)
            .bind(row.get::<String, _>("created_by"))
            .bind(row.get::<Option<String>, _>("created_at"))
            .execute(&target)
            .await
            .expect("the copy is inserted");
        });
    }

    /// An invite code, minted by the shipped CLI, which prints it.
    pub fn invite_code(&self, slug: &str) -> String {
        let out = self.cli(slug, &["invites", "create"]);
        out.lines()
            .find_map(|line| {
                let trimmed = line.trim();
                (!trimmed.is_empty() && trimmed.chars().all(|c| c.is_ascii_alphanumeric()))
                    .then(|| trimmed.to_owned())
            })
            .unwrap_or_else(|| panic!("could not find an invite code in {out:?}"))
    }

    /// Whether an invite code is still unredeemed in a tenant.
    pub fn invite_exists(&self, slug: &str, code: &str) -> bool {
        let id = self.tenant_id(slug);
        let url = format!("sqlite://{}", self.tenant_db(&id).display());
        rt().block_on(async {
            let pool = rustical_store_sqlite::create_db_pool(&url, false)
                .await
                .expect("the tenant store opens");
            let store = rustical_store_sqlite::SqliteInviteStore::new(
                rustical_store_sqlite::SqliteCalendarStore::new(
                    pool,
                    tokio::sync::mpsc::channel(1).0,
                    false,
                ),
            );
            store.get_invite(code).await.expect("a lookup").is_some()
        })
    }

    /// The RSVP secret each tenant actually resolves to.
    pub fn rsvp_secrets(&self) -> (String, String) {
        (self.rsvp_secret("acme"), self.rsvp_secret("globex"))
    }

    /// The RSVP secret for one tenant, after §3.6's merge.
    pub fn rsvp_secret(&self, slug: &str) -> String {
        merge_rsvp_secret(&self.tenant(slug).config_json, &self.global_rsvp_secret())
    }

    // ----------------------------------------------------------------- process

    pub fn start(&mut self) {
        let log = std::fs::File::create(self.path("server.log")).expect("a log file");
        let err = log.try_clone().expect("a second handle");
        // Released here, and only here: the child binds it on the next line, so
        // the port is unreserved for as short a time as possible. Dropping it
        // any earlier re-opens the window this field exists to close.
        drop(self.port_reservation.take());
        // `--config-file` is a *global* arg and must precede the subcommand.
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

    pub fn stop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }

    /// Wait until the health path answers, or fail with the server's own log.
    pub fn wait_ready(&mut self, probe: &str) {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .expect("a client");
        let deadline = Instant::now() + Duration::from_secs(60);
        while Instant::now() < deadline {
            let ok = rt().block_on(async {
                client
                    .get(format!("http://127.0.0.1:{}{probe}", self.port))
                    .send()
                    .await
                    .is_ok_and(|r| r.status().is_success())
            });
            if ok {
                return;
            }
            // A child that has *exited* will never become ready, and on a
            // collision it exits immediately. Polling to the 60s deadline would
            // report "never became ready" for a server that died in
            // milliseconds with the reason in its log.
            if let Some(child) = self.child.as_mut()
                && let Ok(Some(status)) = child.try_wait()
            {
                panic!(
                    "the server exited with {status} before becoming ready on {probe}.\n\
                     This is usually a port collision: another fixture took 127.0.0.1:{}\
                     between this one reserving it and spawning.\n\
                     --- config ---\n{}\n--- log ---\n{}",
                    self.port,
                    self.config_text(),
                    self.log()
                );
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        panic!(
            "the server never became ready on {probe}.\n--- config ---\n{}\n--- log ---\n{}",
            self.config_text(),
            self.log()
        );
    }

    pub fn config_text(&self) -> String {
        std::fs::read_to_string(self.path("config.toml")).unwrap_or_default()
    }

    pub fn log(&self) -> String {
        std::fs::read_to_string(self.path("server.log")).unwrap_or_default()
    }

    /// Block until the server exits, or fail.
    pub fn wait_for_exit(&mut self) -> std::process::ExitStatus {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if let Some(child) = self.child.as_mut()
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

    // ---------------------------------------------------------------- requests

    /// A request against one tenant's host, with one credential.
    ///
    /// `redirect(Policy::none())` matters: with redirects followed a 302 to a
    /// login page arrives as a 200, and every 401 assertion in these files would
    /// be an assertion about the portal instead of about isolation.
    pub fn request(
        &self,
        host: &str,
        method: &str,
        path: &str,
        user: &str,
        password: &str,
        body: Option<&str>,
    ) -> (reqwest::StatusCode, String) {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("a client");
        let verb = reqwest::Method::from_bytes(method.as_bytes())
            .unwrap_or_else(|e| panic!("{method} is not a method: {e}"));
        rt().block_on(async {
            let mut builder = client
                .request(verb, format!("http://127.0.0.1:{}{path}", self.port))
                .header("Host", host)
                .basic_auth(user, Some(password));
            if let Some(body) = body {
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

    /// An unauthenticated request — which is what the three public routers are.
    pub fn get(&self, host: &str, path: &str) -> (reqwest::StatusCode, String) {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("a client");
        rt().block_on(async {
            let response = client
                .get(format!("http://127.0.0.1:{}{path}", self.port))
                .header("Host", host)
                .send()
                .await
                .unwrap_or_else(|e| panic!("GET {host}{path} failed: {e}"));
            (response.status(), response.text().await.unwrap_or_default())
        })
    }

    /// `PROPFIND` a collection, the way a CalDAV client enumerates calendars.
    pub fn propfind(
        &self,
        host: &str,
        path: &str,
        user: &str,
        password: &str,
    ) -> (reqwest::StatusCode, String) {
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
    /// One long string with no `\`-continuations between elements: an earlier
    /// draft wrapped it, and the `\` ate the newline *and* the following
    /// indentation, silently mangling the `xmlns:CAL` binding into
    /// `Unknown(CAL)mkcalendar`.
    pub fn mkcalendar(
        &self,
        host: &str,
        name: &str,
        user: &str,
        password: &str,
    ) -> (reqwest::StatusCode, String) {
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

    /// Post a form, the way the portal's registration form does.
    pub fn post_form(
        &self,
        host: &str,
        path: &str,
        fields: &[(&str, &str)],
    ) -> (reqwest::StatusCode, String) {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("a client");
        let url = format!("http://127.0.0.1:{}{path}", self.port);
        rt().block_on(async {
            let response = client
                .post(url)
                .header("Host", host)
                .form(fields)
                .send()
                .await
                .unwrap_or_else(|e| panic!("POST {host}{path} failed: {e}"));
            (response.status(), response.text().await.unwrap_or_default())
        })
    }

    /// Read one tenant's principal row, and separately check a password against
    /// **that tenant's own store** — the check has to happen where the data is,
    /// which is the point.
    pub fn read_principal(
        &self,
        slug: &str,
        principal: &str,
    ) -> (
        rustical_store::auth::Principal,
        Option<rustical_store::auth::Principal>,
    ) {
        let id = self.tenant_id(slug);
        let url = format!("sqlite://{}", self.tenant_db(&id).display());
        let password = Self::PRINCIPAL_PASSWORD.to_owned();
        rt().block_on(async {
            let pool = rustical_store_sqlite::create_db_pool(&url, false)
                .await
                .expect("the store opens");
            let principals = SqlitePrincipalStore::new(pool);
            let found = AuthenticationProvider::get_principal(&principals, principal)
                .await
                .expect("a lookup")
                .unwrap_or_else(|| panic!("{principal} in {slug}"));
            let verified = principals
                .validate_password(principal, &password)
                .await
                .expect("a password check");
            (found, verified)
        })
    }

    pub fn quota(&self, slug: &str) -> TenantQuota {
        let id = self.tenant_id(slug);
        let store = self.control_plane();
        rt().block_on(async { store.get_quota(&id).await })
            .expect("a quota lookup")
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.stop();
    }
}

/// §3.6's merge for `rsvp_secret`: the tenant's value if it has one, else the
/// global.
///
/// A parse failure falls back to the global rather than to nothing. Returning
/// `None` would silently disable RSVP for a tenant because of a stray comma in
/// a JSON blob, and links already mailed out would stop verifying — the links
/// keep working, which is the safe direction.
#[must_use]
pub fn merge_rsvp_secret(config_json: &str, global: &str) -> String {
    serde_json::from_str::<serde_json::Value>(config_json)
        .ok()
        .and_then(|value| {
            value
                .get("rsvp_secret")
                .and_then(|v| v.as_str())
                .map(ToOwned::to_owned)
        })
        .unwrap_or_else(|| global.to_owned())
}

use rustical_store::{InviteStore, SubscriptionKind, SubscriptionStore};

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Runtime::new().expect("a runtime")
}
