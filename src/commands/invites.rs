//! CLI for the Omnical registration extension (PLAN.md §17.8):
//! `rustical invites create|list|revoke` — server-admin surface, same
//! pattern as `rustical subscriptions` (no HTTP auth involved).
use anyhow::{Context, anyhow};
use chrono::Utc;
use clap::{Parser, Subcommand};
use rand::RngExt;

use crate::{config::Config, get_data_stores};

/// Unambiguous URL-safe alphabet for invite codes: no `0/O`, `1/l/I`.
/// 55 chars ^ 12 ≈ 2^70 — brute force is throttled by the registration
/// endpoint's rate limits on top of this entropy.
const CODE_ALPHABET: &[u8] = b"abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";
const CODE_LENGTH: usize = 12;

/// Generate a short human-transcribable invite code (unlike the 64-char
/// app-token shape — these codes get typed or read aloud).
fn generate_invite_code() -> String {
    let mut rng = rand::rng();
    (0..CODE_LENGTH)
        .map(|_| CODE_ALPHABET[rng.random_range(0..CODE_ALPHABET.len())] as char)
        .collect()
}

/// Normalize an `--expires` value to the store's `YYYY-MM-DDTHH:MM:SSZ` form
/// so the expiry comparison in `redeem_invite` is a plain string comparison.
fn normalize_expires(input: &str) -> anyhow::Result<String> {
    if let Ok(date) = chrono::NaiveDate::parse_from_str(input, "%Y-%m-%d") {
        let end_of_day = date
            .and_hms_opt(23, 59, 59)
            .ok_or_else(|| anyhow!("invalid date '{input}'"))?;
        return Ok(end_of_day
            .and_utc()
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string());
    }
    if let Ok(datetime) = chrono::DateTime::parse_from_rfc3339(input) {
        return Ok(datetime
            .with_timezone(&Utc)
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string());
    }
    Err(anyhow!(
        "invalid expiry '{input}' — use YYYY-MM-DD or an ISO 8601 date-time"
    ))
}

#[derive(Debug, Parser)]
pub struct CreateArgs {
    /// Restrict the invite to one email address
    #[arg(long)]
    pub email: Option<String>,
    /// Auto-join this group on registration (grants shared calendar access)
    #[arg(long)]
    pub group: Option<String>,
    /// Expiry as YYYY-MM-DD or ISO 8601 date-time (dates expire at end of day)
    #[arg(long)]
    pub expires: Option<String>,
    /// Who is issuing the invite (audit column)
    #[arg(long, default_value = "admin")]
    pub created_by: String,
}

#[derive(Debug, Parser)]
pub struct ListArgs {
    /// Also show already-redeemed invites (default: unredeemed only)
    #[arg(long)]
    pub all: bool,
}

#[derive(Debug, Parser)]
pub struct RevokeArgs {
    pub code: String,
}

#[derive(Debug, Subcommand)]
pub enum InvitesCommand {
    /// Create an invite and print its code
    Create(CreateArgs),
    /// List invites (unredeemed by default)
    List(ListArgs),
    /// Revoke an invite before it is used
    Revoke(RevokeArgs),
}

#[derive(Parser, Debug)]
pub struct InvitesArgs {
    #[command(subcommand)]
    pub command: InvitesCommand,
}

#[allow(clippy::missing_errors_doc, clippy::missing_panics_doc)]
pub async fn cmd_invites(args: InvitesArgs, config: Config) -> anyhow::Result<()> {
    let (_, _, _, _, _, _, _, invite_store, _) = get_data_stores(true, &config.data_store).await?;

    match args.command {
        InvitesCommand::Create(CreateArgs {
            email,
            group,
            expires,
            created_by,
        }) => {
            let code = generate_invite_code();
            let expires = expires
                .as_deref()
                .map(normalize_expires)
                .transpose()
                .context("invalid --expires value")?;
            let id = invite_store
                .add_invite(&code, &email, &group, &created_by, &expires, &None, &None)
                .await?;
            eprintln!(
                "Invite created (id: {id}, for: {}, group: {}, expiry: {})",
                email.as_deref().unwrap_or("anyone"),
                group.as_deref().unwrap_or("none"),
                expires.as_deref().unwrap_or("none")
            );
            println!("{code}");
        }
        InvitesCommand::List(ListArgs { all }) => {
            for invite in invite_store.list_invites(all).await? {
                let target = invite.target_email.as_deref().unwrap_or("anyone");
                let group = invite.target_group.as_deref().unwrap_or("none");
                let expiry = invite.expires_at.as_deref().unwrap_or("none");
                if let Some(used_by) = invite.used_by.as_deref() {
                    println!(
                        "{}  used by {}  group: {}  (expired {}, created {})",
                        invite.code,
                        used_by,
                        group,
                        expiry,
                        invite.created_at.as_deref().unwrap_or("unknown")
                    );
                } else {
                    println!(
                        "{}  for {}  group: {}  expires {}  created {}",
                        invite.code,
                        target,
                        group,
                        expiry,
                        invite.created_at.as_deref().unwrap_or("unknown")
                    );
                }
            }
        }
        InvitesCommand::Revoke(RevokeArgs { code }) => {
            invite_store.delete_invite(&code).await?;
            println!("Invite {code} revoked");
        }
    }
    Ok(())
}
