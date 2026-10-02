//! `cli_data_store` — the database a CLI command must use.
//!
//! ## Why this test exists
//!
//! With `[tenancy] enabled`, the server does not read
//! `[data_store.sqlite] db_url`: `tenant_builder` builds a per-tenant
//! `DataStoreConfig` and calls `get_store_bundle` with that. A CLI command
//! passing `config.data_store` therefore mutates a file the server never opens,
//! while reporting success.
//!
//! That was found on a live router, not reasoned about: `app-token create`
//! printed a secret, the token appeared in `app-token list`, no row existed in
//! the tenant database, and the secret 401'd. Worse, `regenerate` left the
//! *previous* secret working and `remove` left the row in place, so a rotation
//! whose gate is "the old token 401s" could not fail.
//!
//! Every case here is cheap; none of them needs a router. What is expensive to
//! get wrong is the database, so that is what is asserted.

use rustical::{config::Config, tenancy::cli_data_store};
use rustical_store::TenantStore;
use rustical_store_sqlite::{SqliteTenantStore, create_control_plane_pool};

/// A `Config` with tenancy off, pointing at `db_url`.
fn config_without_tenancy(db_url: &str) -> Config {
    let mut config = Config::default_config();
    config.data_store =
        rustical::config::DataStoreConfig::Sqlite(rustical::config::SqliteDataStoreConfig {
            db_url: db_url.to_owned(),
            run_repairs: true,
            skip_broken: true,
        });
    config
}

/// A `Config` with tenancy on: a control plane at `control`, tenants under
/// `root`, and `slug` as the default tenant.
fn config_with_tenancy(control: &std::path::Path, root: &std::path::Path, slug: &str) -> Config {
    let mut config = config_without_tenancy("sqlite:///platform/db.sqlite3");
    config.tenancy.enabled = true;
    config.tenancy.control_db_url = format!("sqlite://{}", control.display());
    config.tenancy.data_root = root.display().to_string();
    config.tenancy.default_tenant = slug.to_owned();
    config
}

fn actor() -> rustical_store::Actor {
    rustical_store::Actor::new("test").expect("a valid actor")
}

/// Seed a control plane with one active tenant, returning its id.
async fn seed_tenant(control: &std::path::Path, slug: &str) -> String {
    let url = format!("sqlite://{}", control.display());
    let pool = create_control_plane_pool(&url, true)
        .await
        .expect("the control plane migrates");
    let store = SqliteTenantStore::new(pool);
    let new = rustical_store_sqlite::new_tenant(&slug.parse().expect("a slug"), None);
    store
        .create_tenant(&new, &actor())
        .await
        .unwrap_or_else(|e| panic!("seeding {slug} failed: {e}"));
    let tenant = store
        .get_tenant_by_slug(slug)
        .await
        .expect("a lookup")
        .unwrap_or_else(|| panic!("{slug} was seeded"));
    tenant.id.to_string()
}

/// The whole point: with tenancy on, the CLI must be handed the *tenant's*
/// database, not the platform one.
#[tokio::test]
async fn tenancy_on_redirects_to_the_tenant_database() {
    let tmp = tempdir();
    let control = tmp.path().join("control.sqlite3");
    let root = tmp.path().join("data");
    let id = seed_tenant(&control, "omnical").await;

    let config = config_with_tenancy(&control, &root, "omnical");
    let store = cli_data_store(&config).await.expect("resolves");

    let rustical::config::DataStoreConfig::Sqlite(sqlite) = store;
    let expected = root.join("tenants").join(&id).join("db.sqlite3");
    assert_eq!(
        sqlite.database_file().expect("a file path"),
        expected,
        "the CLI must open the tenant's database, not the platform one"
    );
    assert!(
        !sqlite.db_url.contains("/platform/"),
        "the platform db_url leaked through: {}",
        sqlite.db_url
    );
}

/// A config that **already** names a tenant's database must be left alone.
///
/// This is not a hypothetical shape: `tests/tenant_support` writes one config
/// per tenant pointing straight at that tenant's `db.sqlite3`, with tenancy
/// enabled and no `default_tenant`. Redirecting such a config would resolve the
/// tenant a second time and could hand the command a *different* tenant's
/// database than the config asked for — worse than the bug being fixed.
#[tokio::test]
async fn an_already_tenant_scoped_config_is_not_redirected() {
    let tmp = tempdir();
    let control = tmp.path().join("control.sqlite3");
    let root = tmp.path().join("data");
    let id = seed_tenant(&control, "omnical").await;

    let scoped = root.join("tenants").join(&id).join("db.sqlite3");
    std::fs::create_dir_all(scoped.parent().expect("a parent")).expect("the tenant dir");
    let mut config = config_with_tenancy(&control, &root, "");
    let rustical::config::DataStoreConfig::Sqlite(sqlite) = &mut config.data_store;
    sqlite.db_url = format!("sqlite://{}", scoped.display());

    let store = cli_data_store(&config).await.expect("resolves");
    let rustical::config::DataStoreConfig::Sqlite(sqlite) = store;
    assert_eq!(
        sqlite.database_file().expect("a file path"),
        scoped,
        "an already-scoped config must be used as written"
    );
}

/// Tenancy off is the pre-existing behaviour, byte for byte: a deployment
/// without tenancy has exactly one database and the CLI must keep using it.
#[tokio::test]
async fn tenancy_off_uses_the_configured_database() {
    let config = config_without_tenancy("sqlite:///var/lib/rustical/db.sqlite3");
    let store = cli_data_store(&config).await.expect("resolves");
    let rustical::config::DataStoreConfig::Sqlite(sqlite) = store;
    assert_eq!(sqlite.db_url, "sqlite:///var/lib/rustical/db.sqlite3");
}

/// `run_repairs` and `skip_broken` are operator-chosen and are **not** redirected.
/// `tenant_builder` hard-codes `false` for both; if that were copied here, a
/// CLI command would silently run a repair sweep the server never runs.
#[tokio::test]
async fn repair_flags_come_from_the_global_config() {
    let tmp = tempdir();
    let control = tmp.path().join("control.sqlite3");
    let root = tmp.path().join("data");
    seed_tenant(&control, "omnical").await;

    let mut config = config_with_tenancy(&control, &root, "omnical");
    let rustical::config::DataStoreConfig::Sqlite(sqlite) = &mut config.data_store;
    sqlite.run_repairs = true;
    sqlite.skip_broken = false;

    let store = cli_data_store(&config).await.expect("resolves");
    let rustical::config::DataStoreConfig::Sqlite(sqlite) = store;
    assert!(sqlite.run_repairs, "run_repairs must not be redirected");
    assert!(!sqlite.skip_broken, "skip_broken must not be redirected");
}

/// A tenant the operator has not defined is a refusal naming the slug, not a
/// silent fallback to the platform database — which is the failure this whole
/// change exists to remove.
#[tokio::test]
async fn an_unknown_default_tenant_is_refused_by_name() {
    let tmp = tempdir();
    let control = tmp.path().join("control.sqlite3");
    let root = tmp.path().join("data");
    seed_tenant(&control, "omnical").await;

    let config = config_with_tenancy(&control, &root, "nosuchtenant");
    let err = cli_data_store(&config)
        .await
        .expect_err("an unknown tenant must not resolve to the platform database");
    let msg = err.to_string();
    assert!(msg.contains("nosuchtenant"), "unhelpful error: {msg}");
}

/// A **suspended** tenant is refused, because `get_tenant_by_slug` filters on
/// `status = 'active'`. A CLI command must not become a way to edit the data of
/// a tenant the server has taken away — that is the whole point of suspending.
#[tokio::test]
async fn a_suspended_tenant_is_refused() {
    let tmp = tempdir();
    let control = tmp.path().join("control.sqlite3");
    let root = tmp.path().join("data");
    seed_tenant(&control, "omnical").await;

    let url = format!("sqlite://{}", control.display());
    let pool = create_control_plane_pool(&url, false).await.expect("opens");
    let store = SqliteTenantStore::new(pool);
    let tenant = store
        .get_tenant_by_slug("omnical")
        .await
        .expect("a lookup")
        .expect("seeded");
    store
        .update_tenant_status(
            &tenant.id,
            rustical_store::TenantStatus::Suspended,
            &actor(),
        )
        .await
        .expect("suspending works");

    let config = config_with_tenancy(&control, &root, "omnical");
    let err = cli_data_store(&config)
        .await
        .expect_err("a suspended tenant must not be editable from the CLI");
    assert!(err.to_string().contains("omnical"), "unhelpful: {err}");
}

/// Tenancy on but no default tenant set is a refusal, because there is no
/// tenant to act on — and `TenancyConfig::validate` already refuses to *boot*
/// in that state, so reaching it here means the CLI ran without validation.
#[tokio::test]
async fn an_empty_default_tenant_is_refused() {
    let tmp = tempdir();
    let control = tmp.path().join("control.sqlite3");
    let root = tmp.path().join("data");
    let mut config = config_with_tenancy(&control, &root, "omnical");
    config.tenancy.default_tenant = String::new();
    let err = cli_data_store(&config)
        .await
        .expect_err("an empty default_tenant must not fall through");
    assert!(
        err.to_string().contains("default_tenant"),
        "unhelpful: {err}"
    );
}

/// Minimal scoped temp dir. The repo's other tests each carry their own; this
/// one only needs a path that cleans up, and pulling in a dependency for it
/// would be a larger change than the test.
struct TempDir(std::path::PathBuf);

impl TempDir {
    fn new() -> Self {
        let base = std::env::temp_dir().join(format!(
            "omnical-cli-datastore-{}-{}",
            std::process::id(),
            // Nanoseconds since the epoch, without a date dependency.
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or_default()
        ));
        std::fs::create_dir_all(&base).expect("a temp dir");
        Self(base)
    }

    fn path(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn tempdir() -> TempDir {
    TempDir::new()
}
