//! `rustical mirror list|sync` — the §18.41 push mirrors on demand.
//!
//! The background loop in `cmd_serve` runs the same engine on a cadence;
//! this surface exists for the first run, for debugging, and for the
//! manual-import discipline it replaces.
use crate::config::{Config, MirrorTargetConfig};
use clap::{Args, Parser, Subcommand};
use rustical_store::auth::AuthenticationProvider as _;
use std::collections::HashSet;

#[derive(Parser, Debug)]
pub struct MirrorArgs {
    #[command(subcommand)]
    pub command: MirrorCommand,
}

#[derive(Subcommand, Debug)]
pub enum MirrorCommand {
    /// List the configured mirror targets
    List,
    /// Run mirror targets once now (the background loop is not required)
    Sync(SyncArgs),
}

#[derive(Args, Debug)]
pub struct SyncArgs {
    /// Only run the target with this name (all targets when omitted)
    #[arg(long)]
    pub name: Option<String>,
}

/// Target names must be unique: the state rows key on the name, and a
/// duplicate would have the second run's state clobber the first's,
/// silently un-deleting nothing and re-putting everything.
fn validate_unique_names(targets: &[MirrorTargetConfig]) -> anyhow::Result<()> {
    let mut seen = HashSet::new();
    for target in targets {
        anyhow::ensure!(
            seen.insert(target.name.clone()),
            "duplicate [mirror.targets] name: {}",
            target.name
        );
    }
    Ok(())
}

#[allow(clippy::missing_errors_doc)]
pub async fn cmd_mirror(args: MirrorArgs, config: Config) -> anyhow::Result<()> {
    // Warnings are the operator's eyes on a sync: a PUT that 403s (an
    // event whose UID is owned by an aphy-native copy elsewhere, §18.41)
    // or a remote that vanished mid-run are only ever `warn!`s, and the
    // CLI initializes no tracing by default. Use the same setup the serve
    // path does so a manual sync says what happened.
    crate::setup_tracing(&config.tracing);

    validate_unique_names(&config.mirror.targets)?;
    if config.mirror.targets.is_empty() {
        anyhow::bail!("no [[mirror.targets]] entries are configured");
    }
    let deployment_timezone = config
        .caldav
        .dailyview_timezone()
        .map_or_else(|| "UTC".to_owned(), str::to_owned);

    match args.command {
        MirrorCommand::List => {
            for target in &config.mirror.targets {
                println!(
                    "{name}: {principal}/{calendar} -> {url} (phone_instances={phone_instances}, horizon_days={horizon_days}, interval_secs={interval_secs})",
                    name = target.name,
                    principal = target.principal,
                    calendar = target.calendar,
                    url = target.url,
                    phone_instances = target.phone_instances,
                    horizon_days = target.horizon_days,
                    interval_secs = target.interval_secs,
                );
            }
            Ok(())
        }
        MirrorCommand::Sync(SyncArgs { name }) => {
            let targets: Vec<&MirrorTargetConfig> = config
                .mirror
                .targets
                .iter()
                .filter(|target| name.as_ref().is_none_or(|want| want == &target.name))
                .collect();
            anyhow::ensure!(
                !targets.is_empty(),
                "no configured mirror target matches {name:?}"
            );

            // The 4th element is the auth provider: needed since §18.42 —
            // each target's sync flattens its phone feed in the calendar
            // **owner's** zone, looked up per run.
            let (_, cal_store, _, auth_provider, _, _, _, _, _, _, _, _, mirror_store) =
                crate::get_data_stores(true, &crate::tenancy::cli_data_store(&config).await?)
                    .await?;
            for target in targets {
                // §18.42 cascade: owner's setting, deployment's, `UTC`.
                // The CLI acts as its own deployment, so the deployment
                // rung is the config's `[caldav] dailyview_timezone`.
                let owner_timezone = auth_provider
                    .get_principal(&target.principal)
                    .await?
                    .map(|owner| owner.timezone)
                    .unwrap_or_default();
                let timezone =
                    crate::mirror::resolve_timezone(&owner_timezone, &deployment_timezone);
                let stats = crate::mirror::sync_target(
                    target,
                    &*cal_store,
                    &*mirror_store,
                    &timezone,
                    chrono::Utc::now(),
                )
                .await?;
                println!(
                    "{name}: {put} put, {deleted} deleted, {unchanged} unchanged",
                    name = target.name,
                    put = stats.put,
                    deleted = stats.deleted,
                    unchanged = stats.unchanged,
                );
            }
            Ok(())
        }
    }
}
