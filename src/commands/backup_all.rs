//! `rustical backup --all-tenants` — the per-tenant backup job (§7.4, item 18).
//!
//! §7.4: *"In-binary `rustical backup` (§8.4), invoked per tenant from CI/cron.
//! Back up **each** tenant file separately — that is the payoff of C7."*
//!
//! # Why one archive per tenant, and not one archive of everything
//!
//! C7 is one SQLite file per tenant. That decision is usually argued as a
//! *performance* choice, and it is one — but this is where it pays: restoring a
//! customer is a **one-file operation**. No shared database means no shared
//! failure, no "restore everyone because one table is corrupt", and no restore
//! that has to stop other tenants while it runs.
//!
//! The single-tenant `rustical backup` already exists and is unchanged. This is
//! the tenancy-mode driver around it, and the value is entirely in the
//! **reporting**: a backup job whose failure mode is "it printed nothing" is a
//! backup job nobody notices has been broken for a month.
//!
//! So this command always prints one line per tenant — success *and* failure —
//! and exits non-zero if any tenant failed. Partial success is not success, and
//! a job that exits 0 having backed up 3 of 200 tenants is a job that will be
//! discovered during an incident.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use rustical_store::tenant_store::TenantStore;
use rustical_store_sqlite::SqliteTenantStore;

use crate::commands::backup::{BackupArgs, cmd_backup};
use crate::config::Config;

/// One tenant's outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantOutcome {
    pub tenant: String,
    pub archive: Option<PathBuf>,
    pub error: Option<String>,
}

impl TenantOutcome {
    #[must_use]
    pub const fn ok(&self) -> bool {
        self.error.is_none()
    }
}

/// What the job did, for the summary and for the tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllTenantsReport {
    pub outcomes: Vec<TenantOutcome>,
}

impl AllTenantsReport {
    #[must_use]
    pub fn failed(&self) -> usize {
        self.outcomes.iter().filter(|o| !o.ok()).count()
    }

    #[must_use]
    pub fn succeeded(&self) -> usize {
        self.outcomes.len() - self.failed()
    }
}

/// The per-tenant data root, from the same place `serve_dispatch` gets it.
/// `#[must_use]`: a caller that ignores the path has a backup job that backs up
/// nothing.
///
/// Resolved once and passed in rather than re-derived, so the job and the server
/// cannot disagree about where a tenant's file lives — which is the failure that
/// would produce a backup of the wrong file.
#[must_use]
pub fn tenant_store_path(data_root: &Path, tenant_id: &str) -> PathBuf {
    data_root.join(format!("{tenant_id}.sqlite3"))
}

/// Back up every tenant, one archive each.
///
/// # Errors
///
/// Returns `Err` only when the control plane itself cannot be read — a
/// per-tenant failure is recorded in the report and does not stop the run, because
/// the point of a backup job is that the other 199 tenants get backed up.
pub async fn back_up_all_tenants(
    control: &SqliteTenantStore,
    config: &Config,
    config_file: &Path,
    out_dir: &Path,
    include_suspended: bool,
    gzip: bool,
) -> Result<AllTenantsReport> {
    let tenants = control
        .list_tenants(include_suspended)
        .await
        .context("reading the tenant list — without it there is nothing to back up")?;

    let data_root = config
        .tenancy
        .data_root(&config.data_store)
        .map_err(anyhow::Error::msg)?;

    let mut outcomes = Vec::with_capacity(tenants.len());
    for tenant in &tenants {
        let db_path = tenant_store_path(&data_root, tenant.id.as_str());

        // **A directory per tenant, and not a shared one.**
        //
        // `cmd_backup` names its archive `omnical-backup-<timestamp>.tar`, and a
        // timestamp has one-second resolution — so backing up 200 tenants in a
        // loop writes every one of them to the *same path*, and each overwrites
        // the last. The first version of this command did exactly that, and
        // `every_tenant_gets_its_own_archive` caught it: three tenants, one
        // archive, two customers' data silently gone.
        //
        // That is the exact failure the command exists to prevent, arriving
        // through the command's own naming, which is why the subdirectory is not
        // a tidiness choice. It also makes a restore drill obvious: a tenant's
        // backups are the ones in that tenant's folder.
        let tenant_dir = out_dir.join(tenant.slug.as_str());
        let result = cmd_backup(
            BackupArgs {
                out_dir: Some(tenant_dir.clone()),
                db: Some(db_path.clone()),
                gzip,
                include_config: false,
            },
            config.clone(),
            config_file,
        )
        .await;

        // One line per tenant, always. A silent tenant is a tenant whose data
        // will be lost, discovered during an incident.
        match result {
            Ok(archive) => {
                println!("ok    {} -> {}", tenant.slug.as_str(), archive.display());
                outcomes.push(TenantOutcome {
                    tenant: tenant.slug.as_str().to_owned(),
                    archive: Some(archive),
                    error: None,
                });
            }
            Err(e) => {
                let message = format!("{e:#}");
                println!("FAIL  {}: {message}", tenant.slug.as_str());
                outcomes.push(TenantOutcome {
                    tenant: tenant.slug.as_str().to_owned(),
                    archive: None,
                    error: Some(message),
                });
            }
        }
    }
    Ok(AllTenantsReport { outcomes })
}

/// Summarise, and decide the exit status.
///
/// # Errors
///
/// If any tenant failed — including when only one of two hundred did.
///
/// **Partial success is failure.** A cron job that backs up 3 of 200 tenants and
/// exits 0 is the specific failure this whole command exists to prevent, so the
/// summary is printed with the failing count and the caller gets an `Err`.
pub fn summarise(report: &AllTenantsReport) -> Result<()> {
    println!();
    println!(
        "backed up {} of {} tenants",
        report.succeeded(),
        report.outcomes.len()
    );
    if report.failed() == 0 {
        return Ok(());
    }
    let names: Vec<&str> = report
        .outcomes
        .iter()
        .filter(|o| !o.ok())
        .map(|o| o.tenant.as_str())
        .collect();
    bail!(
        "{} of {} tenants were not backed up: {}",
        report.failed(),
        report.outcomes.len(),
        names.join(", ")
    )
}
