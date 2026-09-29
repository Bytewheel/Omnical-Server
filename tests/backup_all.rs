//! `rustical backup --all-tenants` (§7.4, item 18).
//!
//! The command is small. What is worth testing is the **failure mode it exists to
//! prevent**: a backup job that backs up 3 of 200 tenants and exits 0 is a job
//! that will be discovered during an incident, so every test here is about what
//! the report says and what the exit status is.

use std::path::PathBuf;

use rustical::commands::backup_all::{
    AllTenantsReport, TenantOutcome, back_up_all_tenants, summarise, tenant_store_path,
};
use rustical_store::tenant_store::TenantStore;
use rustical_store_sqlite::SqliteTenantStore;

fn report(entries: &[(&str, Option<&str>)]) -> AllTenantsReport {
    AllTenantsReport {
        outcomes: entries
            .iter()
            .map(|(tenant, error)| TenantOutcome {
                tenant: (*tenant).to_owned(),
                archive: error
                    .is_none()
                    .then(|| PathBuf::from(format!("/backups/{tenant}.tar"))),
                error: error.map(ToOwned::to_owned),
            })
            .collect(),
    }
}

// ── the exit status ─────────────────────────────────────────────────────────

#[test]
fn a_full_run_succeeds() {
    let r = report(&[("acme", None), ("globex", None)]);
    assert_eq!(r.succeeded(), 2);
    assert_eq!(r.failed(), 0);
    assert!(summarise(&r).is_ok());
}

#[test]
fn one_failure_of_two_hundred_is_a_failure() {
    // The whole reason this command exists. `succeeded() == 199` must not read as
    // success anywhere, least of all in a cron's exit status.
    let mut entries: Vec<(String, Option<&str>)> =
        (0..199).map(|i| (format!("t{i}"), None)).collect();
    entries.push(("the-broken-one".to_owned(), Some("disk full")));
    let entries: Vec<(&str, Option<&str>)> =
        entries.iter().map(|(t, e)| (t.as_str(), *e)).collect();
    let r = report(&entries);
    assert_eq!(r.succeeded(), 199);
    assert_eq!(r.failed(), 1);
    let err = summarise(&r).expect_err("partial success must be an error");
    let message = err.to_string();
    assert!(message.contains("1 of 200"), "{message}");
    assert!(
        message.contains("the-broken-one"),
        "the error must name the tenant that failed, or nobody knows which restore is missing: \
         {message}"
    );
}

#[test]
fn an_empty_control_plane_is_a_success_with_nothing_in_it() {
    // Zero tenants is a legitimate state for a fresh install, and `Err`ing here
    // would make a fresh deployment's backup job look broken. But it must not
    // claim it backed anything up.
    let r = report(&[]);
    assert_eq!(r.succeeded(), 0);
    assert_eq!(r.failed(), 0);
    assert!(summarise(&r).is_ok());
    assert_eq!(r.outcomes.len(), 0);
}

// ── the paths ───────────────────────────────────────────────────────────────

#[test]
fn a_tenant_store_path_is_the_id_under_the_data_root() {
    // §3.4: the file name is the tenant **id**, not the slug, because the slug
    // can be reused after a delete and a restored archive must not land on top of
    // the wrong tenant's data.
    let root = PathBuf::from("/var/lib/omnical/tenants");
    assert_eq!(
        tenant_store_path(&root, "T-abc123"),
        PathBuf::from("/var/lib/omnical/tenants/T-abc123.sqlite3")
    );
}

#[test]
fn two_tenants_never_share_an_archive_path() {
    // One archive per tenant is C7's payoff: a restore is a one-file operation.
    // If two tenants could land on the same path, that property is gone and a
    // restore would overwrite a customer's data with another's.
    let root = PathBuf::from("/backups/tenants");
    let a = tenant_store_path(&root, "T-1");
    let b = tenant_store_path(&root, "T-2");
    assert_ne!(a, b);
}

// ── end to end, against real tenant files ───────────────────────────────────

#[tokio::test]
async fn every_tenant_gets_its_own_archive() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let data_root = dir.path().join("tenants");
    std::fs::create_dir_all(&data_root).unwrap();
    let control_path = dir.path().join("control.sqlite3");
    let control = SqliteTenantStore::new(
        rustical_store_sqlite::create_control_plane_pool(
            &format!("sqlite://{}", control_path.display()),
            true,
        )
        .await
        .expect("a control plane"),
    );

    let mut config = rustical::config::Config::default_config();
    config.tenancy.enabled = true;
    config.tenancy.control_db_url = format!("file:{}", control_path.display());
    config.tenancy.data_root = data_root.display().to_string();

    let actor = rustical_store::Actor::new("test").unwrap();
    let mut ids = Vec::new();
    for name in ["acme", "globex", "initech"] {
        let id: rustical_store::tenant::TenantId = name.parse().expect("a valid slug");
        let path = tenant_store_path(&data_root, id.as_str());
        let pool =
            rustical_store_sqlite::create_db_pool(&format!("sqlite://{}", path.display()), true)
                .await
                .expect("a tenant store");
        pool.close().await;
        control
            .create_tenant(
                &rustical_store::tenant_store::NewTenant {
                    tenant: rustical_store::tenant::Tenant {
                        id: id.clone(),
                        slug: id,
                        display_name: name.to_owned(),
                        status: rustical_store::tenant::TenantStatus::Active,
                        config_json: "{}".to_owned(),
                        plan: "test".to_owned(),
                        suspended_at: None,
                        created_at: None,
                    },
                    hosts: vec![format!("{name}.example.com")],
                },
                &actor,
            )
            .await
            .expect("the tenant is created");
        ids.push(name);
    }

    let out_dir = dir.path().join("backups");
    let config_file = dir.path().join("config.toml");
    std::fs::write(
        &config_file,
        "this is not a config, and the job must not need to parse it",
    )
    .unwrap();

    let report = back_up_all_tenants(&control, &config, &config_file, &out_dir, true, false)
        .await
        .expect("the job runs");

    assert_eq!(report.outcomes.len(), 3, "{report:?}");
    assert_eq!(report.failed(), 0, "{report:?}");

    // Three distinct archives, each non-empty, and each containing that
    // tenant's database.
    let archives: Vec<PathBuf> = report
        .outcomes
        .iter()
        .filter_map(|o| o.archive.clone())
        .collect();
    assert_eq!(archives.len(), 3, "{archives:?}");
    let mut paths: Vec<String> = archives.iter().map(|p| p.display().to_string()).collect();
    paths.sort();
    paths.dedup();
    assert_eq!(paths.len(), 3, "two tenants shared an archive: {paths:?}");
    // …and each lands in its **own** directory, so one tenant's archives are
    // visibly that tenant's. This is the shape that makes a restore drill
    // obvious, and it is also what stops the one-second timestamp collision.
    let mut dirs: Vec<String> = archives
        .iter()
        .map(|p| {
            p.parent()
                .unwrap()
                .file_name()
                .unwrap()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    dirs.sort();
    assert_eq!(
        dirs,
        vec!["acme", "globex", "initech"],
        "each archive must be in its own tenant's directory: {dirs:?}"
    );

    for archive in &archives {
        let bytes = std::fs::read(archive).expect("the archive is readable");
        assert!(
            bytes.len() > 512,
            "an archive of {} bytes is empty",
            bytes.len()
        );
        // A real tar: `ustar ` is the magic at offset 257 of the first header
        // block. Checking the magic rather than the first entry name keeps the
        // assertion independent of entry order.
        assert_eq!(&bytes[257..263], b"ustar ", "not a POSIX tar archive");
    }

    assert!(summarise(&report).is_ok());
}

#[tokio::test]
async fn a_tenant_whose_file_is_missing_is_reported_not_skipped() {
    // The failure this whole command is about. A control-plane row with no file
    // behind it — a half-finished `tenant create`, a deleted store, a mount that
    // did not come up — must produce a FAIL line and a non-zero exit, not a
    // silently shorter report.
    let dir = tempfile::tempdir().expect("a temp dir");
    let data_root = dir.path().join("tenants");
    std::fs::create_dir_all(&data_root).unwrap();
    let control_path = dir.path().join("control.sqlite3");
    let control = SqliteTenantStore::new(
        rustical_store_sqlite::create_control_plane_pool(
            &format!("sqlite://{}", control_path.display()),
            true,
        )
        .await
        .expect("a control plane"),
    );

    let mut config = rustical::config::Config::default_config();
    config.tenancy.enabled = true;
    config.tenancy.control_db_url = format!("file:{}", control_path.display());
    config.tenancy.data_root = data_root.display().to_string();

    let actor = rustical_store::Actor::new("test").unwrap();
    for name in ["present", "missing"] {
        let id: rustical_store::tenant::TenantId = name.parse().unwrap();
        if name == "present" {
            let path = tenant_store_path(&data_root, id.as_str());
            let pool = rustical_store_sqlite::create_db_pool(
                &format!("sqlite://{}", path.display()),
                true,
            )
            .await
            .expect("a tenant store");
            pool.close().await;
        }
        control
            .create_tenant(
                &rustical_store::tenant_store::NewTenant {
                    tenant: rustical_store::tenant::Tenant {
                        id: id.clone(),
                        slug: id,
                        display_name: name.to_owned(),
                        status: rustical_store::tenant::TenantStatus::Active,
                        config_json: "{}".to_owned(),
                        plan: "test".to_owned(),
                        suspended_at: None,
                        created_at: None,
                    },
                    hosts: vec![format!("{name}.example.com")],
                },
                &actor,
            )
            .await
            .expect("the tenant is created");
    }

    let report = back_up_all_tenants(
        &control,
        &config,
        &dir.path().join("config.toml"),
        &dir.path().join("backups"),
        true,
        false,
    )
    .await
    .expect("the job runs");

    assert_eq!(
        report.outcomes.len(),
        2,
        "a tenant was silently skipped: {report:?}"
    );
    assert_eq!(report.succeeded(), 1, "{report:?}");
    assert_eq!(report.failed(), 1, "{report:?}");

    let err = summarise(&report).expect_err("one failure must fail the run");
    assert!(
        err.to_string().contains("missing"),
        "the error must name the tenant: {err}"
    );

    // …and the failure must carry a **reason**. "FAIL missing: " is a line
    // somebody has to guess at, and a mutation that emptied the message while
    // still recording the failure passed the suite until this was added.
    let failed = report
        .outcomes
        .iter()
        .find(|o| !o.ok())
        .expect("the failing outcome");
    let reason = failed.error.as_deref().expect("a failure has an error");
    assert!(
        !reason.trim().is_empty(),
        "a failure with no reason: {failed:?}"
    );
    assert!(
        reason.len() > 8,
        "the reason is too short to be useful: {reason:?}"
    );
    // The chain, not just the top line: `cmd_backup`'s error is a context chain
    // and the top line alone ("No such file or directory") does not say which
    // file.
    assert!(
        reason.contains(".sqlite3") || reason.contains("database"),
        "the reason does not identify what failed: {reason:?}"
    );
}
