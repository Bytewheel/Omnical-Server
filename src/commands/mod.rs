use crate::config::Config;
use clap::Parser;

pub mod app_token;
pub mod backup;
pub mod guest_shares;
mod health;
pub mod invites;
pub mod membership;
pub mod principals;
pub mod setup;
pub mod subscriptions;
pub mod support_bundle;
pub mod tenants;

pub use backup::{
    ArchiveEntry, BackupArgs, BackupManifest, CONFIG_ENTRY, DB_ENTRY, MANIFEST_ENTRY,
    MANIFEST_FORMAT, RestoreArgs, cmd_backup, cmd_restore,
};
pub use guest_shares::{GuestSharesArgs, cmd_guest_shares};
pub use health::{HealthArgs, cmd_health};
pub use invites::{InvitesArgs, cmd_invites};
pub use principals::{PrincipalsArgs, cmd_principals};
pub use setup::{
    RegistrationChoice, SetupAnswers, SetupArgs, SetupReport, TlsChoice, cmd_setup, run_setup,
    run_setup_with,
};
pub use subscriptions::{SubscriptionsArgs, cmd_subscriptions};

#[derive(Debug, Parser)]
pub struct GenConfigArgs {}

#[allow(clippy::missing_errors_doc, clippy::missing_panics_doc)]
pub fn cmd_gen_config(_args: GenConfigArgs) -> anyhow::Result<()> {
    // The same value `rustical setup` starts from (PLAN_DEPLOYMENTS.md §8.3).
    let generated_config = toml::to_string(&Config::default_config())?;
    println!("{generated_config}");
    Ok(())
}
