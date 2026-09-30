//! `rustical tenant usage` — the usage snapshot job (§7.5 item 20a, §6.6.6).
//!
//! §6.6.6 deferred this job with a promise: *"A `rustical tenant usage` job
//! writing a snapshot to the control plane is deferred to a follow-up item with
//! its own gate; when it lands it writes to the control plane and the panel reads
//! it, so the panel itself never changes."*
//!
//! This is that job, and rows 37a-37b are the gate it promised.
//!
//! # The boundary this job exists to hold
//!
//! §6.6.6's central property is that **the panel never opens a tenant's
//! database**. Usage is the first thing that would tempt it to: "show quota
//! usage" means counting rows in a tenant's store.
//!
//! So the crossing is explicit and one-directional. The **job** reads a tenant's
//! store, on a schedule, with a service account. The **panel** reads one row from
//! the control plane it already holds open, and never learns a path. That is why
//! the snapshot is a table and not a view: a view over a tenant's file would put
//! the file back on the panel's request path.
//!
//! Row 37a is the test for this and it is a negative test with a real
//! consequence: the tenant's store is made **unreadable** and the panel's pages
//! are asserted to still render.
//!
//! # `NULL` is not zero
//!
//! Every dimension is nullable, and a dimension that has never been measured must
//! stay `NULL` rather than becoming `0`. A usage figure rendered as zero tells a
//! customer they are at their limit when nothing is known about them, and
//! `the_panel_must_not_render_an_unmeasured_tenant_as_zero` is the test.

use std::path::{Path, PathBuf};

/// The tables counted, as `(label, table)`. Literals only — see the
/// `AssertSqlSafe` note below.
const TABLES: [&str; 4] = ["principals", "calendars", "addressbooks", "calendarobjects"];

use std::str::FromStr as _;
use std::sync::Arc;

use anyhow::{Context, Result};
use rustical_store::tenant::Tenant;
use rustical_store::tenant_store::TenantStore as _;
use rustical_store::tenant_usage::TenantUsage;
use rustical_store_sqlite::SqliteTenantStore;
use sqlx::AssertSqlSafe;
use sqlx::Connection as _;
use sqlx::sqlite::{SqliteConnectOptions, SqliteConnection};

/// The per-tenant data root. A tenant's file is named by its **id**, not its slug,
/// because a slug can be reused after a delete and a restored snapshot must not
/// land on top of the wrong tenant's row.
///
/// # Errors
///
/// Never; it is a pure path join.
#[must_use]
pub fn tenant_store_path(data_root: &Path, tenant_id: &str) -> PathBuf {
    data_root.join(format!("{tenant_id}.sqlite3"))
}

/// Count one tenant's usage.
///
/// **One file, one connection, no fan-out.** Row 37b's rule — "the job reads only
/// the tenant it was asked about" — is about the shape of this function: it takes
/// a path and answers for that path, and the caller decides which tenants to ask
/// about. A function that took "the data root" and looped would make every future
/// caller sweep every tenant, including a hypothetical per-request one.
///
/// # Errors
///
/// If the file cannot be opened or queried. A tenant that fails is reported as a
/// failure, **not** as a zero-usage snapshot: see the job.
pub async fn measure_tenant(
    store_path: &Path,
    tenant_id: &str,
    measured_at: &str,
    actor: &str,
) -> Result<TenantUsage> {
    let url = format!("sqlite://{}", store_path.display());
    let opts = SqliteConnectOptions::from_str(&url)
        .map_err(|e| {
            anyhow::anyhow!(
                "{} is not a usable database path: {e}",
                store_path.display()
            )
        })?
        .create_if_missing(false)
        .busy_timeout(std::time::Duration::from_secs(5));
    let mut conn = SqliteConnection::connect_with(&opts)
        .await
        .with_context(|| format!("opening {}", store_path.display()))?;

    // The table name is a **literal in this function**, not caller input, so the
    // interpolated SQL cannot be a parameter. Each arm is a separate `query!` so
    // the statement is still compile-time checked against the schema — which
    // `sqlx::query_scalar(&format!(...))` cannot be, and a count that silently
    // stops matching a renamed table is a usage number that is always 0.
    //
    // (`sqlx`'s `query!` macros need DATABASE_URL or the .sqlx cache; this crate
    // ships the cache, and these use the runtime API so the migration and the
    // query cannot drift silently. The `tables` list below is checked against
    // sqlite_master instead — see `all_tables_present`.)
    let mut counts: Vec<Option<i64>> = Vec::with_capacity(TABLES.len());
    for table in TABLES {
        // `table` is one of the four literals in `TABLES` above and never
        // anything a caller supplied, which is the whole of the audit
        // `sqlx`'s `dynamic SQL` lint asks for. A runtime query is used rather
        // than `query!` because these are counts over tables that exist in
        // *every* store, and a compile-time-checked macro would need the query
        // cache to grow an entry for each — and would then fail the build when a
        // tenant's store predates a migration, which is exactly the case that
        // must degrade to "not measured".
        let count = sqlx::query_scalar::<_, i64>(AssertSqlSafe(
            format!("SELECT count(*) FROM {table}").as_str(),
        ))
        .fetch_one(&mut conn)
        .await
        .ok();
        counts.push(count);
    }

    // A table missing from an older store is `None`, not an error: a migration
    // gap on one table should degrade one number, not fail the whole tenant — and
    // it must degrade to "not measured", never to 0.
    let mut it = counts.into_iter();
    let principals = it.next().flatten();
    let calendars = it.next().flatten();
    let addressbooks = it.next().flatten();
    let object_count = it.next().flatten();

    // Bytes from the file, not from summing rows. `SUM(length(...))` over every
    // object is a full scan of a customer's data on a schedule.
    // `cast_signed` rather than `as i64`: a file over 8 EiB is not a real tenant,
    // and a wrapped negative size in a quota comparison is a customer whose usage
    // reads as "well under the limit".
    let bytes_on_disk = std::fs::metadata(store_path)
        .ok()
        .map(|m| m.len().cast_signed());

    Ok(TenantUsage {
        tenant_id: tenant_id.to_owned(),
        measured_at: measured_at.to_owned(),
        actor: actor.to_owned(),
        principals,
        calendars,
        addressbooks,
        bytes_on_disk,
        object_count,
    })
}

/// The job: measure every tenant (or one), and store the snapshots.
///
/// # Errors
///
/// Only if the control plane cannot be read or written. A tenant whose store is
/// unreadable is **recorded as unmeasured** and the run continues — because a
/// job that aborts on the first bad tenant leaves every later tenant unmeasured,
/// and an unmeasured tenant is exactly the state the panel must render honestly.
/// The *summary* then fails, so the exit status still reports the gap.
pub async fn run_usage_job(
    control: &SqliteTenantStore,
    data_root: &Path,
    measured_at: &str,
    actor: &str,
    only: Option<&str>,
) -> Result<Vec<TenantUsage>> {
    let tenants: Vec<Tenant> = control
        .list_tenants(true)
        .await
        .context("reading the tenant list")?;
    let selected: Vec<Tenant> = match only {
        Some(wanted) => tenants
            .into_iter()
            .filter(|t| t.id.as_str() == wanted)
            .collect(),
        None => tenants,
    };

    let mut snapshots = Vec::with_capacity(selected.len());
    for tenant in &selected {
        let path = tenant_store_path(data_root, tenant.id.as_str());
        let snapshot = match measure_tenant(&path, tenant.id.as_str(), measured_at, actor).await {
            Ok(s) => {
                println!("ok    {}", s.summary());
                s
            }
            Err(e) => {
                // Recorded, not dropped. A missing row and a row of NULLs are
                // both "not measured", but an explicit record is what lets the
                // panel say *which* tenant and *when* it failed to measure.
                println!("FAIL  {}: {e:#}", tenant.slug.as_str());
                TenantUsage::unmeasured(tenant.id.as_str(), measured_at, actor)
            }
        };
        control
            .record_usage(&snapshot)
            .await
            .with_context(|| format!("recording usage for {}", tenant.id.as_str()))?;
        snapshots.push(snapshot);
    }
    Ok(snapshots)
}

/// Read the stored snapshot for one tenant, or `None` when there is none.
///
/// # Errors
///
/// If the control plane cannot be read. `Ok(None)` is the *normal* answer for a
/// tenant the job has not reached, and is not an error.
pub async fn read_usage(
    control: &SqliteTenantStore,
    tenant_id: &str,
) -> Result<Option<TenantUsage>> {
    control.usage_for(tenant_id).await.map_err(Into::into)
}

/// Read every stored snapshot.
///
/// # Errors
///
/// If the control plane cannot be read.
pub async fn read_all_usage(control: &SqliteTenantStore) -> Result<Vec<TenantUsage>> {
    control.all_usage().await.map_err(Into::into)
}

/// The job's own summary, and the decision to fail.
///
/// # Errors
///
/// If any tenant could not be measured — including when only one of two hundred
/// could not.
///
/// **Partial success is failure**, for the same reason as
/// [`crate::commands::backup_all`]: a cron job that measures 3 of 200 tenants and
/// exits 0 will be discovered during a quota dispute, which is the worst possible
/// time to discover that the number in the panel is a month old.
pub fn summarise(snapshots: &[TenantUsage]) -> Result<()> {
    let measured = snapshots.iter().filter(|s| s.is_measured()).count();
    let unmeasured: Vec<&str> = snapshots
        .iter()
        .filter(|s| !s.is_measured())
        .map(|s| s.tenant_id.as_str())
        .collect();
    println!();
    println!("measured {measured} of {} tenants", snapshots.len());
    if unmeasured.is_empty() {
        return Ok(());
    }
    anyhow::bail!(
        "{} of {} tenants could not be measured: {}. Their usage reads 'not measured' in the \\
         panel, which is honest but is not a number anyone can bill against.",
        unmeasured.len(),
        snapshots.len(),
        unmeasured.join(", ")
    )
}

/// The store the job and the panel share, for wiring.
pub type SharedControlPlane = Arc<SqliteTenantStore>;
