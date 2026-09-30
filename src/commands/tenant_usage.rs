//! `rustical tenant usage` — the CLI face of item 20a.
//!
//! The measurement itself lives in [`crate::tenant_usage`]; this is the argument
//! parsing and the two things the command must decide: *when* to stamp the
//! snapshot, and *what* to print.

use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;

#[derive(Debug, Default, Parser)]
pub struct TenantUsageArgs {
    /// Measure one tenant by id instead of every tenant.
    #[arg(long, value_name = "TENANT_ID")]
    pub tenant: Option<String>,
    /// Print the stored snapshots and take no new measurement.
    #[arg(long)]
    pub show: bool,
    /// Who to record as having run the job. Defaults to the effective user, and
    /// is overridable so a scheduled run can be distinguished from an
    /// operator's: a usage number with no provenance is a number nobody can act
    /// on, which is §6.6.7's audit rule applied to a measurement.
    #[arg(long, value_name = "ACTOR")]
    pub actor: Option<String>,
}

/// The actor recorded on a snapshot, following §6.6.7's rule.
///
/// The CLI's own `resolve_actor` helper is the precedent: a best-effort `$USER`
/// is right for an attended run, and a scheduled one should say so rather than
/// arriving as `root`.
#[must_use]
pub fn resolve_actor(flag: Option<&str>) -> String {
    if let Some(actor) = flag.map(str::trim).filter(|a| !a.is_empty()) {
        return actor.to_owned();
    }
    std::env::var("OMNICAL_ACTOR")
        .ok()
        .filter(|a| !a.trim().is_empty())
        .or_else(|| std::env::var("USER").ok())
        .filter(|u| !u.trim().is_empty())
        .unwrap_or_else(|| "unknown".to_owned())
}

/// A timestamp for `measured_at`.
///
/// Deliberately not "now" from the database's clock: the job writes the value
/// itself so a skew between the job host and the database shows up as a wrong
/// timestamp rather than as a plausible one.
#[must_use]
pub fn now_rfc3339() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    format_rfc3339(secs)
}

/// The same, for a fixed instant, so the tests are deterministic.
#[must_use]
pub fn format_rfc3339(secs: u64) -> String {
    // A saturating cast: a wrapped negative day count produces a date in the
    // distant past, which would sort a tenant's usage snapshot as ancient and
    // make the panel read as "never measured".
    let days = i64::try_from(secs / 86_400).unwrap_or(i64::MAX);
    let tod = secs % 86_400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        tod / 3_600,
        (tod % 3_600) / 60,
        tod % 60
    )
}

/// The command.
///
/// # Errors
///
/// If the control plane is unreadable, or if any tenant could not be measured —
/// the summary deliberately treats a partial run as a failure.
pub async fn cmd_tenant_usage(
    config: crate::config::Config,
    control: &rustical_store_sqlite::SqliteTenantStore,
    args: TenantUsageArgs,
) -> Result<()> {
    let actor = resolve_actor(args.actor.as_deref());
    let measured_at = now_rfc3339();

    if args.show {
        let snapshots = crate::tenant_usage::read_all_usage(control).await?;
        if snapshots.is_empty() {
            println!(
                "no usage has been measured yet — run `rustical tenant usage` (or wait for the \
                 scheduled job). The panel shows this as \"not measured\", not as zero."
            );
            return Ok(());
        }
        for s in &snapshots {
            println!("{}", s.summary());
        }
        return Ok(());
    }

    let data_root: PathBuf = config
        .tenancy
        .data_root(&config.data_store)
        .map_err(anyhow::Error::msg)?;
    let snapshots = crate::tenant_usage::run_usage_job(
        control,
        &data_root,
        &measured_at,
        &actor,
        args.tenant.as_deref(),
    )
    .await?;
    crate::tenant_usage::summarise(&snapshots)
}
