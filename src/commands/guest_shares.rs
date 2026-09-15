//! CLI for the Omnical guest-shares extension (PLAN.md §17.10):
//! `rustical guest-share add|list|revoke|credential` — server-admin surface,
//! same pattern as `rustical subscriptions` (no HTTP auth involved).
//!
//! `add` mints a lightweight `guest-{uuid}` principal, an app token and a
//! `collection_shares` row in one step, exactly like the portal "Invite
//! guest" form — the credential it prints is the same one-time token a CalDAV
//! client needs.
use clap::{Parser, Subcommand};
use rustical_store::auth::{AuthenticationProvider, Principal, PrincipalType, Privilege};
use rustical_store::{CalendarReadStore, CollectionShareStore};
use uuid::Uuid;

use super::app_token::generate_app_token;
use crate::{config::Config, get_data_stores};
use rustical_store::CollectionShare;

/// CLI value enum for `--privilege`: mirrors the `Privilege` type used by the
/// share store.
#[derive(clap::ValueEnum, Clone, Copy, Debug)]
pub enum PrivilegeArg {
    View,
    Edit,
    Admin,
}

impl From<PrivilegeArg> for Privilege {
    fn from(p: PrivilegeArg) -> Self {
        match p {
            PrivilegeArg::View => Self::View,
            PrivilegeArg::Edit => Self::Edit,
            PrivilegeArg::Admin => Self::Admin,
        }
    }
}

#[derive(Debug, Parser)]
pub struct AddArgs {
    /// Owner principal of the calendar (a user id or a group the user is
    /// admin over).
    pub owner: String,
    pub collection_id: String,
    /// The privilege granted to the guest (`view` = read-only).
    #[arg(value_enum, default_value = "view")]
    pub privilege: PrivilegeArg,
    /// Optional delivery email (stored for audit; does not send an email
    /// from the CLI).
    #[arg(long)]
    pub email: Option<String>,
}

#[derive(Debug, Parser)]
pub struct ListArgs {
    /// Owner principal whose active guest shares should be listed.
    pub owner: String,
}

#[derive(Debug, Parser)]
pub struct RevokeArgs {
    /// Share id as printed by `add`/`list`.
    pub share_id: String,
}

#[derive(Debug, Parser)]
pub struct CredentialArgs {
    /// Share id as printed by `add`/`list`.
    pub share_id: String,
}

#[derive(Debug, Subcommand)]
pub enum GuestShareCommand {
    /// Mint a guest share and print the one-time credential
    Add(AddArgs),
    /// List the active guest shares of an owner
    List(ListArgs),
    /// Revoke a guest share (access stops immediately)
    Revoke(RevokeArgs),
    /// Print what is recoverable about a share's credential
    Credential(CredentialArgs),
}

#[derive(Parser, Debug)]
pub struct GuestSharesArgs {
    #[command(subcommand)]
    pub command: GuestShareCommand,
}

/// Find an active share by id by scanning every principal's shares. The
/// store has no id-keyed selector; a rare admin CLI op can afford the scan.
async fn find_share(
    principal_store: &dyn AuthenticationProvider,
    share_store: &dyn CollectionShareStore,
    share_id: &str,
) -> anyhow::Result<Option<CollectionShare>> {
    for owner in principal_store.get_principals().await? {
        for share in share_store.list_guest_shares(&owner.id).await? {
            if share.id == share_id {
                return Ok(Some(share));
            }
        }
    }
    Ok(None)
}

#[allow(clippy::missing_errors_doc, clippy::missing_panics_doc)]
pub async fn cmd_guest_shares(args: GuestSharesArgs, config: Config) -> anyhow::Result<()> {
    let (addr_store, cal_store, _, principal_store, _, _, _, _, _, share_store) =
        get_data_stores(true, &config.data_store).await?;

    match args.command {
        GuestShareCommand::Add(AddArgs {
            owner,
            collection_id,
            privilege,
            email,
        }) => {
            let privilege = Privilege::from(privilege);
            // Validates the collection exists through the same combined view
            // the DAV server serves (covers `_birthdays_*`).
            let combined =
                rustical_store::CombinedCalendarStore::new(cal_store).with_store(addr_store);
            combined.get_calendar(&owner, &collection_id, false).await?;

            let guest_id = format!("guest-{}", Uuid::new_v4());
            principal_store
                .insert_principal(
                    Principal {
                        id: guest_id.clone(),
                        displayname: Some(format!("Guest of {collection_id}")),
                        memberships: vec![],
                        password: None,
                        principal_type: PrincipalType::Individual,
                        needs_password_change: false,
                        privileges: Default::default(),
                    },
                    false,
                )
                .await?;

            let token_secret = generate_app_token();
            let mut token_prefix = principal_store
                .add_app_token(
                    &guest_id,
                    format!("{collection_id} guest"),
                    token_secret.clone(),
                )
                .await?;
            token_prefix.truncate(4);
            let credential = format!("{token_prefix}_{token_secret}");

            let share_id = share_store
                .add_share(
                    &owner,
                    &collection_id,
                    "calendar",
                    privilege,
                    &guest_id,
                    &email,
                    "cli",
                )
                .await?;

            println!("Guest share created (id: {share_id})");
            println!("  Username: {guest_id}");
            println!("  App token: {credential}");
            if let Some(email) = email {
                println!("  (bound to {email})");
            }
            println!(
                "Send the username and app token to your guest; they enter them into \
                 any CalDAV client with your server's /caldav URL."
            );
        }
        GuestShareCommand::List(ListArgs { owner }) => {
            for share in share_store.list_guest_shares(&owner).await? {
                let email = share
                    .target_email
                    .as_deref()
                    .map(|e| format!(" <{e}>"))
                    .unwrap_or_default();
                println!(
                    "{} - {} {} '{}/{}' (created {}) - {}{email}",
                    share.id,
                    share.privilege,
                    share.kind,
                    share.owner_principal,
                    share.collection_id,
                    share.created_at.as_deref().unwrap_or("unknown"),
                    share.guest_principal,
                );
            }
        }
        GuestShareCommand::Revoke(RevokeArgs { share_id }) => {
            share_store.revoke_share(&share_id).await?;
            println!("Guest share {share_id} revoked");
        }
        GuestShareCommand::Credential(CredentialArgs { share_id }) => {
            let Some(share) =
                find_share(principal_store.as_ref(), share_store.as_ref(), &share_id).await?
            else {
                anyhow::bail!("no active share with id {share_id}");
            };
            // The app-token secret is stored hashed (pbkdf2) — by design it
            // can never be re-printed. The owner can mint a fresh credential
            // (portal "Invite guest" or `guest-share add`).
            println!("Share {share_id} ({})", share.kind);
            println!("  Guest username: {}", share.guest_principal);
            println!("  Privilege: {}", share.privilege);
            println!(
                "  The app-token secret is only shown once at creation (tokens are stored \
                 hashed). Mint a new credential to reset the guest's access."
            );
        }
    }
    Ok(())
}

/// A tiny validation of the privilege conversion.
#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn privilege_arg_maps() {
        assert_eq!(Privilege::from(PrivilegeArg::View), Privilege::View);
        assert_eq!(Privilege::from(PrivilegeArg::Edit), Privilege::Edit);
        assert_eq!(Privilege::from(PrivilegeArg::Admin), Privilege::Admin);
        assert!(Privilege::from_str("view").is_ok());
    }
}
