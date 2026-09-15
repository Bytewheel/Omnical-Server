//! CLI for the Omnical share-links extension (PLAN.md §17.7):
//! `rustical subscriptions add|list|remove` — server-admin surface, same
//! pattern as `rustical principals` (no HTTP auth involved).
use clap::{Parser, Subcommand};
use rustical_store::{
    AddressbookReadStore, CalendarReadStore, CombinedCalendarStore, SubscriptionKind,
};

use super::app_token::generate_app_token;
use crate::{
    config::Config,
    get_data_stores,
    url_builder::{export_url, public_base_url},
};

/// CLI value enum for `--kind`: clap's `ValueEnum` cannot be derived for the
/// foreign `SubscriptionKind`, so this mirrors it one-to-one.
#[derive(clap::ValueEnum, Clone, Copy, Debug)]
pub enum KindArg {
    Calendar,
    Addressbook,
}

impl From<KindArg> for SubscriptionKind {
    fn from(kind: KindArg) -> Self {
        match kind {
            KindArg::Calendar => Self::Calendar,
            KindArg::Addressbook => Self::Addressbook,
        }
    }
}

#[derive(Debug, Parser)]
pub struct AddArgs {
    pub principal: String,
    pub collection_id: String,
    /// Which kind of collection the feed exports
    #[arg(value_enum, long)]
    pub kind: KindArg,
}

#[derive(Debug, Parser)]
pub struct ListArgs {
    pub principal: String,
}

#[derive(Debug, Parser)]
pub struct RemoveArgs {
    pub principal: String,
    pub id: String,
}

#[derive(Debug, Subcommand)]
pub enum SubscriptionsCommand {
    /// Create a subscription (prints the export URL)
    Add(AddArgs),
    /// List the subscriptions of a principal (re-displays lost URLs)
    List(ListArgs),
    /// Revoke a subscription (the URL stops working immediately)
    Remove(RemoveArgs),
}

#[derive(Parser, Debug)]
pub struct SubscriptionsArgs {
    #[command(subcommand)]
    pub command: SubscriptionsCommand,
}

#[allow(clippy::missing_errors_doc, clippy::missing_panics_doc)]
pub async fn cmd_subscriptions(args: SubscriptionsArgs, config: Config) -> anyhow::Result<()> {
    let (addr_store, cal_store, _, _, _, _, sub_store, _, _, _) =
        get_data_stores(true, &config.data_store).await?;

    let base_url = public_base_url(
        config.subscriptions.public_url.as_deref(),
        config
            .http
            .bind_config()
            .ok()
            .as_ref()
            .and_then(|c| match c {
                crate::config::HttpBindConfig::Tcp(addr) => Some(addr.as_str()),
                _ => None,
            }),
    );

    match args.command {
        SubscriptionsCommand::Add(AddArgs {
            principal,
            collection_id,
            kind,
        }) => {
            if !config.subscriptions.enabled {
                eprintln!(
                    "Note: [subscriptions] enabled = false — the export routes are not mounted, \
                     this URL will not serve until the extension is enabled"
                );
            }
            let kind = SubscriptionKind::from(kind);
            // Fail fast on a wrong collection id instead of creating a URL
            // that 404s forever: validate against the same view the export
            // routes serve (the combined store also covers `_birthdays_*`)
            match kind {
                SubscriptionKind::Calendar => {
                    let combined_cal_store =
                        CombinedCalendarStore::new(cal_store).with_store(addr_store);
                    combined_cal_store
                        .get_calendar(&principal, &collection_id, false)
                        .await?;
                }
                SubscriptionKind::Addressbook => {
                    addr_store
                        .get_addressbook(&principal, &collection_id, false)
                        .await?;
                }
            }

            let token = generate_app_token();
            let id = sub_store
                .add_subscription(&principal, kind, &collection_id, &token)
                .await?;
            println!("Subscription created (id: {id})");
            println!("{}", export_url(&base_url, &token, kind));
        }
        SubscriptionsCommand::List(ListArgs { principal }) => {
            for subscription in sub_store.get_subscriptions(&principal).await? {
                println!(
                    "{} - {} '{}' - {} (created {})",
                    subscription.id,
                    subscription.kind.as_str(),
                    subscription.collection_id,
                    export_url(&base_url, &subscription.token, subscription.kind),
                    subscription.created_at.as_deref().unwrap_or("unknown"),
                );
            }
        }
        SubscriptionsCommand::Remove(RemoveArgs { principal, id }) => {
            sub_store.delete_subscription(&principal, &id).await?;
            println!("Subscription {id} removed");
        }
    }
    Ok(())
}
