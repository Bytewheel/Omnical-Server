//! Which database `backup`, `restore` and `upgrade` act on.
//!
//! ## Why this test exists
//!
//! These three took their path from `config.data_store`, which under tenancy is
//! a file the server never opens. So on a tenancy install they read and wrote a
//! database holding no tenant data — and, because the install *copied* its
//! store into `tenants/<id>/` rather than moving it, that database still had a
//! full set of tables. Nothing failed:
//!
//! - `backup` produced an archive with a healthy-looking database in it and a
//!   plausible row count, taken from nothing.
//! - `restore` would have written a tenant's data somewhere no tenant is served
//!   from, reporting success.
//! - `upgrade` reported "schema is up to date" from the platform copy while the
//!   tenant's own schema was never migrated.
//!
//! That last one is the reason this is worth asserting rather than trusting: an
//! upgrade that reports success and has migrated nothing is indistinguishable
//! from one that had nothing to do.
//!
//! The CLI store resolution itself is covered in `cli_data_store.rs`; this file
//! is about the three commands that were not going through it.

use rustical::commands::backup::resolve_database_path;
use rustical::config::{Config, DataStoreConfig, SqliteDataStoreConfig};
use rustical_store::TenantStore;
use rustical_store_sqlite::{SqliteTenantStore, create_control_plane_pool};
use std::path::{Path, PathBuf};

fn config_without_tenancy(db_url: &str) -> Config {
    let mut config = Config::default_config();
    config.data_store = DataStoreConfig::Sqlite(SqliteDataStoreConfig {
        db_url: db_url.to_owned(),
        run_repairs: true,
        skip_broken: true,
    });
    config
}

fn config_with_tenancy(control: &Path, root: &Path, slug: &str) -> Config {
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

/// Seed a control plane with one active tenant, returning the path of its store.
async fn seed_tenant(control: &Path, root: &Path, slug: &str) -> PathBuf {
    let pool = create_control_plane_pool(&format!("sqlite://{}", control.display()), true)
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

    // `get_store_bundle` creates the store itself; this test only needs to know
    // which path the resolution lands on.
    let path = root
        .join("tenants")
        .join(tenant.id.to_string())
        .join("db.sqlite3");
    std::fs::create_dir_all(path.parent().expect("a parent")).expect("the tenant directory");
    path
}

/// The whole point, for all three commands at once: they share one resolver.
#[tokio::test]
async fn tenancy_on_resolves_the_tenant_database() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let root = dir.path().join("data");
    let control = dir.path().join("control.sqlite3");
    let expected = seed_tenant(&control, &root, "acme").await;
    let config = config_with_tenancy(&control, &root, "acme");

    let resolved = resolve_database_path(&config, None)
        .await
        .expect("resolves");

    assert_eq!(
        resolved, expected,
        "backup/restore/upgrade must land on the tenant's database, not the \
         platform one the server never opens"
    );
}

/// The regression this file exists for, stated as an assertion: the resolved
/// path must not be the configured `db_url`, and the platform file must not
/// have been conjured into existence by resolving it.
#[tokio::test]
async fn resolving_does_not_fall_back_to_the_platform_database() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let root = dir.path().join("data");
    let control = dir.path().join("control.sqlite3");
    seed_tenant(&control, &root, "acme").await;
    let platform = dir.path().join("platform").join("db.sqlite3");
    let mut config = config_with_tenancy(&control, &root, "acme");
    config.data_store = DataStoreConfig::Sqlite(SqliteDataStoreConfig {
        db_url: format!("sqlite://{}", platform.display()),
        run_repairs: true,
        skip_broken: true,
    });

    let resolved = resolve_database_path(&config, None)
        .await
        .expect("resolves");

    assert_ne!(
        resolved, platform,
        "the platform database is not what the server serves from"
    );
    assert!(
        !platform.exists(),
        "resolving a path must not create the platform database: \
         {} came into existence just by being resolved",
        platform.display()
    );
}

/// Tenancy off is untouched: the configured database is the right one.
#[tokio::test]
async fn tenancy_off_resolves_the_configured_database() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let db = dir.path().join("solo.sqlite3");
    let config = config_without_tenancy(&format!("sqlite://{}", db.display()));

    let resolved = resolve_database_path(&config, None)
        .await
        .expect("resolves");

    assert_eq!(resolved, db);
}

/// `--db` still wins, because an operator restoring a specific archive knows
/// which file it came from and that answer should not be second-guessed — even
/// when it points somewhere a tenancy install would never have chosen.
#[tokio::test]
async fn an_explicit_override_wins_over_the_tenant() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let root = dir.path().join("data");
    let control = dir.path().join("control.sqlite3");
    seed_tenant(&control, &root, "acme").await;
    let config = config_with_tenancy(&control, &root, "acme");
    let explicit = dir.path().join("from-an-archive.sqlite3");

    let resolved = resolve_database_path(&config, Some(&explicit))
        .await
        .expect("resolves");

    assert_eq!(resolved, explicit);
}

/// No tenant resolves, so there is no honest answer. This must be a refusal,
/// not a quiet fallback to a database that holds nothing — that fallback is the
/// bug this file documents.
#[tokio::test]
async fn tenancy_on_with_no_tenant_is_refused() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let mut config = config_with_tenancy(
        &dir.path().join("control.sqlite3"),
        &dir.path().join("data"),
        "",
    );
    config.tenancy.control_db_url = format!("sqlite://{}", dir.path().join("c.sqlite3").display());

    let resolved = resolve_database_path(&config, None).await;

    assert!(
        resolved.is_err(),
        "backing up a database with no tenant data must fail loudly, not \
         resolve to the platform one"
    );
}

/// The override path must not need a control plane at all, so that restoring an
/// archive onto a machine whose control plane is not readable yet still works.
#[tokio::test]
async fn an_override_needs_no_control_plane() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let mut config = config_with_tenancy(
        &dir.path().join("nonexistent-control.sqlite3"),
        &dir.path().join("data"),
        "acme",
    );
    config.tenancy.default_tenant = "acme".to_owned();
    let explicit = dir.path().join("restore-me.sqlite3");

    let resolved = resolve_database_path(&config, Some(&explicit))
        .await
        .expect("an override resolves without touching the control plane");

    assert_eq!(resolved, explicit);
}
