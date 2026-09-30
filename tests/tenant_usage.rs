//! Item 20a: the usage snapshot job and the panel that reads it.
//!
//! Two of the plan's rows are the gate, and both are negative tests, because
//! both failure modes are silent:
//!
//! * **37a** — the usage job reads tenant stores; the **panel** does not. §6.6.6's
//!   central property. The test makes a tenant's store *unreadable* and asserts
//!   the panel's page still renders, because "the panel does not read the tenant
//!   store" is otherwise an intention rather than a property.
//! * **37b** — one row per tenant, a named actor, and the job reads only the
//!   tenant it was asked about.
//!
//! And the one that is not a row but matters more: **an unmeasured dimension must
//! render as "not measured", never as `0`**, because a zero tells a customer they
//! are at their limit when nothing is known about them.

use std::path::PathBuf;

use rustical::tenant_usage::{
    measure_tenant, read_all_usage, run_usage_job, summarise, tenant_store_path,
};
use rustical_store::tenant::{Tenant, TenantId, TenantStatus};
use rustical_store::tenant_store::{NewTenant, TenantStore as _};
use rustical_store::tenant_usage::TenantUsage;
use rustical_store_sqlite::SqliteTenantStore;

struct Env {
    _dir: tempfile::TempDir,
    control: SqliteTenantStore,
    data_root: PathBuf,
}

impl Env {
    async fn new() -> Self {
        let dir = tempfile::tempdir().expect("a temp dir");
        let data_root = dir.path().join("tenants");
        std::fs::create_dir_all(&data_root).unwrap();
        let control = SqliteTenantStore::new(
            rustical_store_sqlite::create_control_plane_pool(
                &format!("sqlite://{}", dir.path().join("control.sqlite3").display()),
                true,
            )
            .await
            .expect("a control plane"),
        );
        Self {
            _dir: dir,
            control,
            data_root,
        }
    }

    /// A tenant row **and** a real store file behind it.
    async fn add_tenant(&self, slug: &str, with_data: bool) -> TenantId {
        let id: TenantId = slug.parse().expect("a valid slug");
        if with_data {
            let pool = rustical_store_sqlite::create_db_pool(
                &format!(
                    "sqlite://{}",
                    tenant_store_path(&self.data_root, id.as_str()).display()
                ),
                true,
            )
            .await
            .expect("a tenant store");
            pool.close().await;
        }
        self.control
            .create_tenant(
                &NewTenant {
                    tenant: Tenant {
                        id: id.clone(),
                        slug: id.clone(),
                        display_name: format!("{slug} Ltd"),
                        status: TenantStatus::Active,
                        config_json: "{}".to_owned(),
                        plan: "test".to_owned(),
                        suspended_at: None,
                        created_at: None,
                    },
                    hosts: vec![format!("{slug}.example.com")],
                },
                &rustical_store::Actor::new("test").unwrap(),
            )
            .await
            .expect("the tenant is created");
        id
    }
}

// ── row 37a: the job crosses the boundary, the panel does not ──────────────

#[tokio::test]
async fn the_panel_never_opens_a_tenant_database() {
    // §6.6.6: "the panel never opens a tenant's database". Usage is the first
    // thing that would tempt it — "show quota usage" means counting rows in a
    // tenant's store — so the crossing is done by a job and the panel reads one
    // row of the control plane it already holds open.
    //
    // The test is the strong form: the tenant's store is made **unreadable** and
    // the panel's read still succeeds. An implementation that quietly opened the
    // file would fail here, and an assertion that merely checked the code does
    // not call it would not catch a future change that does.
    let env = Env::new().await;
    let id = env.add_tenant("acme", true).await;

    // A measurement exists…
    run_usage_job(&env.control, &env.data_root, "T", "test", None)
        .await
        .expect("a run");
    assert!(
        env.control
            .usage_for(id.as_str())
            .await
            .expect("readable")
            .is_some()
    );

    // …and then the tenant's store becomes unreadable. On a Unix box that is
    // `chmod 000`; the test is skipped elsewhere rather than passing vacuously,
    // because a skipped chmod would make the row look green and mean nothing.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let path = tenant_store_path(&env.data_root, id.as_str());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
        // Running as root defeats `chmod 000` entirely — the kernel does not
        // check it for uid 0 — so this must be *verified*, not assumed. A test
        // that claims the tenant store was made unreadable when it was not would
        // pass for the wrong reason, which is the exact class of bug row 37a
        // exists to prevent.
        let after = std::fs::metadata(&path).map(|m| m.permissions().mode() & 0o777);
        if after.is_ok_and(|mode| mode == 0o000) {
            let usage = env
                .control
                .usage_for(id.as_str())
                .await
                .expect("the panel's read must not touch the tenant store");
            assert!(
                usage.is_some(),
                "the panel must serve a stored snapshot even when the tenant's store is \
                 unreadable"
            );
        } else {
            eprintln!("skipping the unreadable-store half: chmod did not take effect");
        }
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    #[cfg(not(unix))]
    eprintln!("skipping the unreadable-store half: no chmod on this platform");
}

#[test]
fn the_panel_reads_the_control_plane_and_never_a_path() {
    // The type-level version of the same property: `AdminPanel` holds two
    // control-plane trait objects and has no path to a `StoreBundle`, so there is
    // nothing for it to open.
    let src = include_str!("../crates/frontend/src/routes/admin.rs");
    assert!(
        !src.contains("create_db_pool"),
        "the admin panel must never open a database of its own"
    );
    assert!(
        src.contains("usage_for(tenant.id.as_str())"),
        "the panel should read the usage snapshot from the control plane"
    );
}

// ── row 37b: one row per tenant, a named actor, no sweep ────────────────────

#[tokio::test]
async fn one_row_per_tenant_written_by_a_named_actor() {
    let env = Env::new().await;
    for slug in ["acme", "globex", "initech"] {
        env.add_tenant(slug, true).await;
    }
    run_usage_job(
        &env.control,
        &env.data_root,
        "2026-09-29T00:00:00Z",
        "nightly-cron",
        None,
    )
    .await
    .expect("a run");

    let all = read_all_usage(&env.control).await.expect("readable");
    assert_eq!(all.len(), 3, "not one row per tenant: {all:?}");
    for snapshot in &all {
        assert_eq!(snapshot.actor, "nightly-cron", "{snapshot:?}");
        assert_eq!(snapshot.measured_at, "2026-09-29T00:00:00Z");
    }
    // A re-run **replaces**, it does not append, so the table is bounded by the
    // tenant count and not by uptime.
    run_usage_job(
        &env.control,
        &env.data_root,
        "2026-09-30T00:00:00Z",
        "nightly-cron",
        None,
    )
    .await
    .expect("a second run");
    let all = read_all_usage(&env.control).await.expect("readable");
    assert_eq!(
        all.len(),
        3,
        "a re-run appended instead of replacing: {all:?}"
    );
    assert!(
        all.iter().all(|s| s.measured_at == "2026-09-30T00:00:00Z"),
        "the newer measurement did not win"
    );
}

#[tokio::test]
async fn the_job_can_be_asked_about_exactly_one_tenant() {
    // Row 37b: "the job reads only the tenant it was asked about". Without a
    // `--tenant`, a fix to the per-tenant path would have to be made in a caller
    // that sweeps, and the sweep would be invisible.
    let env = Env::new().await;
    let acme = env.add_tenant("acme", true).await;
    env.add_tenant("globex", true).await;

    run_usage_job(
        &env.control,
        &env.data_root,
        "T",
        "test",
        Some(acme.as_str()),
    )
    .await
    .expect("a run");

    let all = read_all_usage(&env.control).await.expect("readable");
    assert_eq!(
        all.len(),
        1,
        "asking about one tenant measured others too: {all:?}"
    );
    assert_eq!(all[0].tenant_id, acme.as_str());
}

#[test]
fn a_tenant_store_path_is_derived_from_the_id_not_the_slug() {
    // A slug can be reused after a delete, and a snapshot written against the
    // wrong one would bill the wrong customer.
    let root = PathBuf::from("/data/tenants");
    assert_eq!(
        tenant_store_path(&root, "T-abc"),
        PathBuf::from("/data/tenants/T-abc.sqlite3")
    );
    assert_ne!(
        tenant_store_path(&root, "T-abc"),
        tenant_store_path(&root, "T-abd")
    );
}

// ── the one that is not a row and matters more: NULL is not 0 ──────────────

#[test]
fn an_unmeasured_tenant_is_not_measured_rather_than_zero() {
    let u = TenantUsage::unmeasured("T-1", "2026-09-29T00:00:00Z", "nightly-cron");
    assert!(!u.is_measured());
    assert_eq!(u.principals, None, "unmeasured must be None, not Some(0)");
    let summary = u.summary();
    assert!(summary.contains("not measured"), "{summary}");
    assert!(
        summary.contains("NOTHING MEASURED"),
        "the summary must be unmissable: {summary}"
    );
    assert!(
        !summary.contains(", 0 principals"),
        "a zero crept into the summary: {summary}"
    );
}

#[test]
fn a_measured_tenant_reports_numbers() {
    let u = TenantUsage {
        tenant_id: "T-1".to_owned(),
        measured_at: "2026-09-29T00:00:00Z".to_owned(),
        actor: "nightly-cron".to_owned(),
        principals: Some(3),
        calendars: Some(7),
        addressbooks: Some(1),
        bytes_on_disk: Some(4 * 1024 * 1024),
        object_count: Some(128),
    };
    assert!(u.is_measured());
    let summary = u.summary();
    assert!(summary.contains("3 principals"), "{summary}");
    assert!(summary.contains("7 calendars"), "{summary}");
    assert!(!summary.contains("NOTHING MEASURED"), "{summary}");
}

#[tokio::test]
async fn a_tenant_whose_store_is_missing_is_recorded_as_unmeasured_not_skipped() {
    // A control-plane row with no file behind it. Dropping it silently would
    // leave the panel saying nothing, which an operator reads as "no usage".
    let env = Env::new().await;
    let good = env.add_tenant("present", true).await;
    env.add_tenant("missing", false).await;

    let snapshots = run_usage_job(&env.control, &env.data_root, "T", "test", None)
        .await
        .expect("a run");
    assert_eq!(snapshots.len(), 2, "a tenant was skipped: {snapshots:?}");

    let good_row = env
        .control
        .usage_for(good.as_str())
        .await
        .expect("readable");
    assert!(
        good_row.as_ref().is_some_and(|u| u.is_measured()),
        "{good_row:?}"
    );

    // The broken one is **recorded**, with nothing measured — which the panel
    // renders as words.
    let all = read_all_usage(&env.control).await.expect("readable");
    let missing = all.iter().find(|u| u.tenant_id != good.as_str());
    assert!(
        missing.is_some(),
        "the failing tenant was not recorded: {all:?}"
    );
    assert!(missing.is_some_and(|u| !u.is_measured()));

    // And the run **fails**, because a job that measured 1 of 2 and exited 0 is
    // the thing this whole reporting design exists to prevent.
    let err = summarise(&snapshots).expect_err("partial success must fail");
    assert!(err.to_string().contains("missing"), "{err}");
}

#[tokio::test]
async fn measuring_one_tenant_reads_one_file() {
    let env = Env::new().await;
    let id = env.add_tenant("acme", true).await;
    let usage = measure_tenant(
        &tenant_store_path(&env.data_root, id.as_str()),
        id.as_str(),
        "2026-09-29T00:00:00Z",
        "test",
    )
    .await
    .expect("measured");
    assert_eq!(usage.tenant_id, id.as_str());
    // An empty store measures zero **counts** — which is a real measurement, and
    // is different from "not measured". This distinction is the point.
    assert!(usage.is_measured(), "{usage:?}");
    assert_eq!(usage.principals, Some(0));
    assert!(usage.bytes_on_disk.is_some_and(|b| b > 0), "{usage:?}");
}

#[test]
fn the_usage_table_exists_in_the_control_migrations() {
    // A migration and a query that disagree is a 500 at three in the morning.
    // Version numbers are unique, and this is not tidiness: sqlx keys
    // `_sqlx_migrations` by version, so a duplicate makes every control plane
    // fail to open with `UNIQUE constraint failed: _sqlx_migrations.version`.
    // The first version of this migration was numbered the same as
    // `admin_audit` and the collision presented as five unrelated test failures.
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("crates/store_sqlite/control_migrations");
    let mut versions: Vec<String> = std::fs::read_dir(&dir)
        .expect("the control migrations directory")
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".up.sql"))
        .map(|n| n.split('_').next().unwrap_or_default().to_owned())
        .collect();
    versions.sort();
    let before = versions.len();
    versions.dedup();
    assert_eq!(
        before,
        versions.len(),
        "two control migrations share a version number: {versions:?}"
    );

    let up = include_str!(
        "../crates/store_sqlite/control_migrations/20260929130000_tenant_usage.up.sql"
    );
    assert!(up.contains("CREATE TABLE control_tenant_usage"), "{up}");
    assert!(
        up.contains("REFERENCES tenants(id) ON DELETE CASCADE"),
        "a deleted tenant must not leave a usage row behind"
    );
    // …and a down, because §18.21 found 4 base migrations with no down at all.
    let down = include_str!(
        "../crates/store_sqlite/control_migrations/20260929130000_tenant_usage.down.sql"
    );
    assert!(down.contains("DROP TABLE"), "{down}");
}
