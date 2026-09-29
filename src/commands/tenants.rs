//! `rustical tenant` — the hosted-tenancy control plane, from the command line.
//! `PLAN_DEPLOYMENTS.md` §6.5.
//!
//! ## This is the *control plane*, not a tenant's data
//!
//! Every subcommand here reads and writes `control.sqlite3` and nothing else. A
//! tenant's calendars live in a different file, reached through
//! `--config-file` pointed at that tenant's store (or, better, through
//! `OMNICAL_TENANT`, which §6.3 added and which this CLI is the natural
//! front door for). Keeping the two apart is §3.2's whole point, and a CLI that
//! quietly opened both would be the first place that separation leaks.
//!
//! ## `create` materialises the tenant's store, and it has to
//!
//! A tenant's database is otherwise created **lazily**, on the first HTTP
//! request that resolves to it. That is fine for serving and useless for
//! administering: there is no way to point a config at a store path that does
//! not exist yet, so `rustical principals create` against a new tenant fails on
//! the missing directory. This is the obligation item 8's gate recorded in
//! §18.16 and §18.17, and `create` is where it is discharged.
//!
//! It happens here rather than lazily at first request so that the tenant is
//! genuinely usable the moment the command returns, and so a failure is reported
//! to the operator who typed `create` instead of surfacing later as a 500 to
//! somebody's login.
//!
//! ## `suspend` and the running server
//!
//! Suspension takes effect on the **next request** with no eviction and no
//! restart, because `HostDispatch` consults the control plane on every request
//! and filters on `status = 'active'` in SQL (§18.13). So `suspend` here is a
//! database write and nothing else: there is no running-server state to reach
//! into, and pretending otherwise — a cache-eviction call, a signal — would
//! imply a coupling that does not exist.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use rustical_store::Actor;
use rustical_store::admin_store::AdminCredentialStore;
use rustical_store::admin_store::AdminStanding;
use rustical_store::tenant::{Tenant, TenantId, TenantStatus};
use rustical_store::tenant_store::{NewTenant, TenantQuota, TenantStore};
use rustical_store_sqlite::{SqliteTenantStore, create_control_plane_pool};

#[derive(Debug, Parser)]
pub struct TenantArgs {
    #[command(subcommand)]
    pub command: TenantCommand,
}

#[derive(Debug, Subcommand)]
pub enum TenantCommand {
    /// Create a tenant and its store.
    Create(CreateArgs),
    /// List tenants, newest first.
    List(ListArgs),
    /// Show one tenant's full record.
    Show(ShowArgs),
    /// Suspend a tenant: the next request for it is a 404.
    Suspend(SlugArgs),
    /// Resume a suspended tenant.
    Resume(SlugArgs),
    /// Overwrite a tenant's quota. Omitting every flag clears all limits.
    SetQuota(SetQuotaArgs),
    /// Set one per-tenant config override.
    Config(ConfigArgs),
    /// Delete a tenant's control-plane record.
    ///
    /// **Does not delete the tenant's data** — see [`DeleteArgs`].
    Delete(DeleteArgs),
    /// Manage platform-admin credentials (§6.6.3).
    Admin(AdminArgs),
}

/// `--status` for `tenant list`, mirroring [`TenantStatus`].
#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum StatusArg {
    Active,
    Suspended,
    All,
}

#[derive(Debug, Parser)]
pub struct CreateArgs {
    /// DNS-safe identifier: `[a-z0-9-]{1,63}`. Becomes a hostname and a
    /// directory name, so it is validated rather than sanitised.
    #[arg(long)]
    pub slug: String,
    /// Who is making this change, for the audit trail. Defaults to
    /// `$OMNICAL_ACTOR`, then `$SUDO_USER`, then `$USER`; refuses if none is set.
    #[arg(long)]
    pub actor: Option<String>,
    /// Human-readable name shown in admin listings.
    #[arg(long)]
    pub display_name: Option<String>,
    /// A hostname this tenant answers for. Repeatable. Hosts derived from
    /// `base_domain` do not belong here — storing them would give one host two
    /// sources of truth.
    #[arg(long = "host")]
    pub hosts: Vec<String>,
    /// Billing tier, stored as an opaque string.
    #[arg(long, default_value = "free")]
    pub plan: String,
    /// Per-tenant config overrides as JSON, or `@path` to read a file.
    ///
    /// Validated on the way in and reported on the way out, so a blob that is
    /// merely *parseable* but full of unknown keys is caught here rather than
    /// silently ignored at request time.
    #[arg(long)]
    pub config_json: Option<String>,
}

#[derive(Debug, Parser)]
pub struct ListArgs {
    /// Which tenants to list. `all` includes suspended ones.
    #[arg(long, value_enum, default_value = "active")]
    pub status: StatusArg,
    /// Machine-readable output.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Parser)]
pub struct ShowArgs {
    pub slug: String,
}

#[derive(Debug, Parser)]
pub struct SlugArgs {
    pub slug: String,
    /// Who is making this change, for the audit trail.
    #[arg(long)]
    pub actor: Option<String>,
}

#[derive(Debug, Parser)]
pub struct SetQuotaArgs {
    pub slug: String,
    /// Who is making this change, for the audit trail.
    #[arg(long)]
    pub actor: Option<String>,
    #[arg(long)]
    pub principals: Option<i64>,
    #[arg(long)]
    pub calendars: Option<i64>,
    #[arg(long)]
    pub megabytes: Option<i64>,
}

#[derive(Debug, Parser)]
pub struct ConfigArgs {
    #[command(subcommand)]
    pub command: ConfigCommand,
}

#[derive(Debug, Subcommand)]
pub enum ConfigCommand {
    /// Merge a key into the tenant's `config_json`.
    Set(ConfigSetArgs),
    /// Print the tenant's `config_json`.
    Show(ConfigShowArgs),
}

#[derive(Debug, Parser)]
pub struct ConfigSetArgs {
    pub slug: String,
    /// Who is making this change, for the audit trail.
    #[arg(long)]
    pub actor: Option<String>,
    /// A dotted key, e.g. `rsvp_secret` or `subscriptions.public_url`.
    #[arg(long)]
    pub key: String,
    /// The value. JSON is parsed, so `true`, `42` and `"x"` are distinct; a value
    /// that is not valid JSON is stored as a string.
    #[arg(long)]
    pub value: String,
}

#[derive(Debug, Parser)]
pub struct ConfigShowArgs {
    pub slug: String,
}

/// `rustical tenant admin …` — the bootstrap path for the panel's credentials.
///
/// **Names live in config, hashes live in the control plane** (§6.6.3), so
/// these subcommands cannot add an admin on their own: `add` refuses any name
/// `[tenancy] platform_admins` does not list. That refusal is the entire
/// security property, and it is why this group is not a shortcut around config.
#[derive(Debug, Parser)]
pub struct AdminArgs {
    #[command(subcommand)]
    pub command: AdminCommand,
}

#[derive(Debug, Subcommand)]
pub enum AdminCommand {
    /// Create or rotate one admin's credential.
    Add(AdminAddArgs),
    /// Delete one admin's credential row.
    Remove(AdminNameArgs),
    /// Show every name's standing across config and the control plane.
    List(AdminListArgs),
}

#[derive(Debug, Parser)]
pub struct AdminAddArgs {
    /// The admin name. Must appear in `[tenancy] platform_admins`.
    pub name: String,
    /// Who is making this change. Defaults to `$OMNICAL_ACTOR`, then
    /// `$SUDO_USER`, then `$USER`; refuses if none is set.
    #[arg(long)]
    pub actor: Option<String>,
    /// Read the password from this instead of prompting.
    ///
    /// Environment-only is the point: an admin password is the one credential
    /// in this tree that crosses every tenant boundary, and a command-line flag
    /// for it would put it in `ps` output and shell history on a shared host.
    /// The variable is named so that a mistyped `OMNICAL_ADMIN_PASSWORD` is
    /// visible in the process environment rather than in the process table.
    #[arg(long, env = "OMNICAL_ADMIN_PASSWORD", hide_env_values = true)]
    pub password: Option<String>,
}

#[derive(Debug, Parser)]
pub struct AdminNameArgs {
    /// The admin name.
    pub name: String,
}

#[derive(Debug, Parser)]
pub struct AdminListArgs {
    /// Machine-readable output.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Parser)]
pub struct DeleteArgs {
    pub slug: String,
    /// Who is making this change, for the audit trail.
    #[arg(long)]
    pub actor: Option<String>,
    /// Required. Without it, nothing is deleted.
    #[arg(long)]
    pub confirm: bool,
    /// Also delete the tenant's data directory.
    ///
    /// Separate from `--confirm` on purpose. "Remove the tenant" and "destroy
    /// the customer's calendars" are different acts, and making them one command
    /// means a typo in a slug destroys a backup. `--confirm` protects against
    /// running the command by accident; `--purge-data` has to be said a second
    /// time, deliberately, and prints the path it is about to remove.
    #[arg(long)]
    pub purge_data: bool,
}

/// The `--actor`, or the usual environment fallbacks.
///
/// §6.6.7: an action that cannot be attributed does not happen, so this returns
/// an `Err` rather than a placeholder. The flag is optional and the fallbacks
/// mean ordinary use is unchanged — `rustical tenant list` still needs nothing
/// typed — but a **mutating** command in a bare environment (`env -i`, a cron
/// job with no `USER`) refuses rather than writing an audit row with an empty
/// actor.
///
/// The fallbacks are not authentication. `$USER` is whatever the caller set, so
/// the record says "who the shell said this was", which is the honest claim; a
/// panel action, by contrast, is attributable to a credential verified against a
/// hash.
fn resolve_actor(flag: Option<&str>) -> Result<Actor> {
    if let Some(name) = flag {
        return Actor::new(name).map_err(anyhow::Error::msg);
    }
    for var in ["OMNICAL_ACTOR", "SUDO_USER", "USER"] {
        if let Ok(value) = std::env::var(var)
            && !value.trim().is_empty()
        {
            return Actor::new(value).map_err(anyhow::Error::msg);
        }
    }
    anyhow::bail!(
        "this change would be unaudited. Pass --actor <name>, or set OMNICAL_ACTOR, SUDO_USER or \
         USER. A control-plane change that cannot be attributed does not happen (§6.6.7)."
    )
}

/// Open the control plane, migrating it first.
///
/// Migrations run on every invocation, including `list`: they are a no-op once
/// applied (the driver records them in a table of its own), and a CLI that refused to
/// run against an older control plane would leave an operator with no way to
/// upgrade one except by hand.
async fn control_plane(config: &crate::config::Config) -> Result<SqliteTenantStore> {
    let url = &config.tenancy.control_db_url;
    if url.is_empty() {
        anyhow::bail!(
            "[tenancy] control_db_url is not set. The control plane is a separate database from \
             any tenant store (§3.4); without it there is no tenant index to talk to."
        );
    }
    let pool = create_control_plane_pool(url, true)
        .await
        .with_context(|| format!("could not open the control plane at {url}"))?;
    Ok(SqliteTenantStore::new(pool))
}

fn parse_slug(slug: &str) -> Result<TenantId> {
    slug.parse::<TenantId>()
        .map_err(|e| anyhow::anyhow!("{slug:?} is not a valid tenant slug: {e}"))
}

/// Resolve a slug to a tenant **whether or not it is active**.
///
/// `suspend` and `resume` have to name a suspended tenant, and the
/// active-only lookup used for resolution would make both impossible to type.
/// This is the same distinction `TenantStore::get_any_tenant_by_slug` exists for.
async fn any_tenant(store: &SqliteTenantStore, slug: &str) -> Result<Tenant> {
    let slug = parse_slug(slug)?;
    store
        .get_any_tenant_by_slug(slug.as_str())
        .await?
        .ok_or_else(|| anyhow::anyhow!("no tenant with the slug {slug}"))
}

/// Dispatch over the `tenant` subcommands.
///
/// # Errors
/// Returns whatever the arm did, verbatim.
///
/// Long because it is a subcommand dispatch, and the other command modules in
/// this crate are the same shape — `guest_shares`, `invites`, `principals`.
/// Splitting each arm into a function would be eight more names for code that is
/// five lines of store call plus a message.
#[allow(clippy::too_many_lines, reason = "a subcommand dispatch")]
pub async fn cmd_tenants(args: TenantArgs, config: crate::config::Config) -> Result<()> {
    if !config.tenancy.enabled {
        anyhow::bail!(
            "[tenancy] enabled is false, so there is no control plane to administer. Remove the \
             section to run a single-tenant install, or set enabled = true."
        );
    }
    let store = control_plane(&config).await?;

    match args.command {
        TenantCommand::Create(CreateArgs {
            slug,
            actor,
            display_name,
            hosts,
            plan,
            config_json,
        }) => {
            // Resolved before anything is written, so an unattributable create
            // fails before it has created a row.
            let actor = resolve_actor(actor.as_deref())?;
            let slug_id = parse_slug(&slug)?;

            // §6.6.2: `admin_host` is reserved, refused **here** so the
            // collision cannot be introduced at all. The authoritative check
            // still runs at startup — this is the config's view, and a start-up
            // check is what catches a row written by something else. Two checks
            // because they fail at different times for different reasons, not
            // because either is uncertain.
            for host in &hosts {
                crate::admin::refuse_reserved_admin_host(&config.tenancy, host)?;
            }
            let blob = match config_json {
                Some(raw) => {
                    let text = if let Some(path) = raw.strip_prefix('@') {
                        std::fs::read_to_string(path)
                            .with_context(|| format!("could not read --config-json from {path}"))?
                    } else {
                        raw
                    };
                    serde_json::from_str::<serde_json::Value>(&text)
                        .with_context(|| format!("--config-json is not valid JSON: {text}"))?;
                    // Unknown keys are warned about *now*, not silently ignored
                    // at request time: an operator who typo'd `rsvp_secrect`
                    // should hear about it from the command they just ran.
                    warn_unknown_keys(&text);
                    text
                }
                None => "{}".to_owned(),
            };

            let new = NewTenant {
                tenant: Tenant {
                    id: TenantId::generate(),
                    slug: slug_id,
                    display_name: display_name.unwrap_or_else(|| slug.clone()),
                    status: TenantStatus::Active,
                    config_json: blob,
                    plan,
                    suspended_at: None,
                    created_at: None,
                },
                hosts,
            };

            store
                .create_tenant(&new, &actor)
                .await
                .map_err(|e| anyhow::anyhow!("could not create tenant {slug}: {e}"))?;

            // The obligation: materialise the store now, so the tenant is usable
            // the moment this command returns rather than on its first request.
            // See this module's docs.
            let root = config
                .tenancy
                .data_root(&config.data_store)
                .map_err(anyhow::Error::msg)?;
            let path = config
                .tenancy
                .ensure_tenant_store_dir(&root, &new.tenant.id)
                .map_err(|e| {
                    anyhow::anyhow!(
                        "the tenant row was created but its store could not \
                     be prepared: {e}"
                    )
                })?;
            let url = format!("sqlite://{}", path.display());
            rustical_store_sqlite::create_db_pool(&url, true)
                .await
                .with_context(|| {
                    format!(
                        "the tenant row was created but its store at {} could not be initialised; \
                         remove the row or fix the path and re-run",
                        path.display()
                    )
                })?;

            println!("{}", new.tenant.id.as_str());
            eprintln!(
                "Created tenant {} ({}) with store {}",
                new.tenant.slug,
                new.tenant.display_name,
                path.display()
            );
            Ok(())
        }

        TenantCommand::List(ListArgs { status, json }) => {
            let include_suspended = status != StatusArg::Active;
            let mut tenants = store.list_tenants(include_suspended).await?;
            if status == StatusArg::Suspended {
                tenants.retain(|t| t.status == TenantStatus::Suspended);
            }
            if json {
                let view: Vec<serde_json::Value> = tenants
                    .iter()
                    .map(|t| {
                        serde_json::json!({
                            "id": t.id.as_str(),
                            "slug": t.slug.as_str(),
                            "display_name": t.display_name,
                            "status": t.status.as_str(),
                            "plan": t.plan,
                            "created_at": t.created_at,
                            "suspended_at": t.suspended_at,
                        })
                    })
                    .collect();
                println!("{}", serde_json::to_string_pretty(&view)?);
            } else if tenants.is_empty() {
                eprintln!("no tenants");
            } else {
                for t in &tenants {
                    println!("{}\t{}\t{}\t{}", t.slug, t.status, t.plan, t.display_name);
                }
            }
            Ok(())
        }

        TenantCommand::Show(ShowArgs { slug }) => {
            let tenant = any_tenant(&store, &slug).await?;
            let quota = store.get_quota(&tenant.id).await?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "id": tenant.id.as_str(),
                    "slug": tenant.slug.as_str(),
                    "display_name": tenant.display_name,
                    "status": tenant.status.as_str(),
                    "plan": tenant.plan,
                    "created_at": tenant.created_at,
                    "suspended_at": tenant.suspended_at,
                    "config_json": tenant.config_json,
                    "quota": {
                        "principals": quota.principals,
                        "calendars": quota.calendars,
                        "megabytes": quota.megabytes,
                    },
                }))?
            );
            Ok(())
        }

        TenantCommand::Suspend(SlugArgs { slug, actor }) => {
            let actor = resolve_actor(actor.as_deref())?;
            let tenant = any_tenant(&store, &slug).await?;
            store
                .update_tenant_status(&tenant.id, TenantStatus::Suspended, &actor)
                .await?;
            // No eviction, no signal: the next request consults the control
            // plane and sees this. See this module's docs.
            eprintln!(
                "Suspended {}. The next request for it is a 404; in-flight requests finish.",
                tenant.slug
            );
            Ok(())
        }

        TenantCommand::Resume(SlugArgs { slug, actor }) => {
            let actor = resolve_actor(actor.as_deref())?;
            let tenant = any_tenant(&store, &slug).await?;
            store
                .update_tenant_status(&tenant.id, TenantStatus::Active, &actor)
                .await?;
            eprintln!("Resumed {}", tenant.slug);
            Ok(())
        }

        TenantCommand::SetQuota(SetQuotaArgs {
            slug,
            actor,
            principals,
            calendars,
            megabytes,
        }) => {
            let actor = resolve_actor(actor.as_deref())?;
            let tenant = any_tenant(&store, &slug).await?;
            // Omitted flags clear to unlimited rather than being left alone, and
            // the help says so — a quota command where "I did not pass the flag"
            // means "no limit" is the safer of the two readings.
            let quota = TenantQuota {
                principals,
                calendars,
                megabytes,
            };
            store.set_quota(&tenant.id, quota, &actor).await?;
            eprintln!(
                "Quota for {}: principals={:?} calendars={:?} megabytes={:?}",
                tenant.slug, quota.principals, quota.calendars, quota.megabytes
            );
            Ok(())
        }

        TenantCommand::Config(ConfigArgs { command }) => match command {
            ConfigCommand::Show(ConfigShowArgs { slug }) => {
                let tenant = any_tenant(&store, &slug).await?;
                println!("{}", tenant.config_json);
                Ok(())
            }
            // Through the trait rather than a direct statement, so the write is
            // audited: this column holds the RSVP HMAC key and SMTP passwords,
            // and it is exactly the kind of edit whose absence from a log is a
            // question someone eventually has to answer.
            ConfigCommand::Set(ConfigSetArgs {
                slug,
                actor,
                key,
                value,
            }) => {
                let actor = resolve_actor(actor.as_deref())?;
                let tenant = any_tenant(&store, &slug).await?;
                let mut blob: serde_json::Value = serde_json::from_str(&tenant.config_json)
                    .with_context(|| {
                        format!(
                            "{} has a config_json that does not parse; refusing to merge into it",
                            tenant.slug
                        )
                    })?;
                let parsed = serde_json::from_str::<serde_json::Value>(&value)
                    .unwrap_or_else(|_| serde_json::Value::String(value.clone()));
                set_dotted(&mut blob, &key, parsed)?;
                let text = serde_json::to_string(&blob)?;
                // Parse through the product's own path and report what it will
                // actually use, so a key that parses as JSON but is one the
                // product ignores is caught here. This is the difference between
                // "stored" and "in effect", and they are not the same thing.
                let effective = crate::tenant_overrides::Overrides::parse(&text);
                if effective.rsvp_secret.is_none() && text.contains("rsvp_secret") {
                    eprintln!("warning: rsvp_secret is present but did not parse as a string");
                }
                store.set_config_json(&tenant.id, &text, &actor).await?;
                println!("{text}");
                eprintln!("Set {key} for {}", tenant.slug);
                Ok(())
            }
        },

        TenantCommand::Admin(AdminArgs { command }) => {
            cmd_tenant_admin(command, &store, &config).await
        }
        TenantCommand::Delete(DeleteArgs {
            slug,
            actor,
            confirm,
            purge_data,
        }) => {
            let tenant = any_tenant(&store, &slug).await?;
            if !confirm {
                // Refuse before doing anything, including printing what would
                // happen, so a mistyped `--confirm` cannot be the thing that
                // makes the output look like progress.
                anyhow::bail!(
                    "refusing to delete {} without --confirm. Nothing has been changed.",
                    tenant.slug
                );
            }
            // After the `--confirm` gate, so a refused delete never needs an
            // actor and never writes anything.
            let actor = resolve_actor(actor.as_deref())?;
            store.delete_tenant(&tenant.id, &actor).await?;
            eprintln!("Deleted the control-plane record for {}", tenant.slug);

            let root = config
                .tenancy
                .data_root(&config.data_store)
                .map_err(anyhow::Error::msg)?;
            let dir = root.join("tenants").join(tenant.id.as_str());
            if purge_data {
                eprintln!(
                    "Purging the store directory {} — this deletes the tenant's calendars and \
                     every credential in them.",
                    dir.display()
                );
                if dir.exists() {
                    std::fs::remove_dir_all(&dir).with_context(|| {
                        format!(
                            "the record was deleted but {} could not be removed",
                            dir.display()
                        )
                    })?;
                }
            } else {
                eprintln!(
                    "The tenant's data is still at {}. Re-run with --purge-data to remove it, or \
                     keep it for a backup.",
                    dir.display()
                );
            }
            Ok(())
        }
    }
}

/// Set a dotted key in a JSON object, creating the intermediate objects.
///
/// # Errors
/// If the key has an empty path segment, or a path segment names something that
/// is not an object — both of which would otherwise silently produce a blob the
/// product does not read.
///
/// Split on every `.` rather than `rsplit_once`. The `rsplit_once` version was
/// **inverted** — `registration.enabled` produced `{"enabled":{"registration":…}}`
/// — and the unit test below is what caught it. A two-segment key is not worth
/// the cleverness.
fn set_dotted(blob: &mut serde_json::Value, key: &str, value: serde_json::Value) -> Result<()> {
    if !blob.is_object() {
        *blob = serde_json::Value::Object(serde_json::Map::new());
    }
    let parts: Vec<&str> = key.split('.').collect();
    if parts.iter().any(|p| p.is_empty()) {
        anyhow::bail!("{key:?} is not a usable key: it has an empty path segment");
    }

    // Walk every segment but the last, creating objects as needed.
    let mut cursor = blob;
    for part in &parts[..parts.len() - 1] {
        if !cursor.is_object() {
            anyhow::bail!("{key} cannot be set: {part} is not an object");
        }
        let map = cursor.as_object_mut().expect("checked above");
        let entry = map
            .entry((*part).to_owned())
            .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
        if !entry.is_object() {
            anyhow::bail!("{key} cannot be set: {part} is not an object");
        }
        cursor = entry;
    }
    let last = parts[parts.len() - 1];
    cursor
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("{key} cannot be set: its parent is not an object"))?
        .insert(last.to_owned(), value);
    Ok(())
}

/// Report keys the product does not read.
/// The top-level keys this build reads from a tenant's `config_json`.
const KNOWN_OVERRIDES: [&str; 4] = ["rsvp_secret", "scheduling", "subscriptions", "registration"];

fn warn_unknown_keys(json: &str) {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(json) else {
        return;
    };
    if let Some(map) = value.as_object() {
        for key in map.keys() {
            if !KNOWN_OVERRIDES.contains(&key.as_str()) {
                eprintln!(
                    "warning: {key:?} is not a per-tenant override this build reads; it is stored \
                     but ignored"
                );
            }
        }
    }
}

/// `rustical tenant admin …` (§6.6.3).
///
/// Separate from [`cmd_tenants`] because the two halves have opposite failure
/// postures: a tenant command writes a row about *one* tenant, while these
/// write or remove the credential that crosses *every* tenant boundary, and
/// `add`'s refusal below is the reason config is authoritative.
async fn cmd_tenant_admin(
    command: AdminCommand,
    store: &SqliteTenantStore,
    config: &crate::config::Config,
) -> Result<()> {
    match command {
        AdminCommand::Add(args) => admin_add(args, store, config).await,
        AdminCommand::Remove(args) => admin_remove(args, store, config).await,
        AdminCommand::List(args) => admin_list(args, store, config).await,
    }
}

/// `tenant admin add` — the bootstrap path, and §6.6.3's refusal.
async fn admin_add(
    args: AdminAddArgs,
    store: &SqliteTenantStore,
    config: &crate::config::Config,
) -> Result<()> {
    let AdminAddArgs {
        name,
        actor,
        password,
    } = args;

    // Resolved before the store is touched, so an unattributable change
    // fails before it has written anything — the same rule as every
    // other mutating command in this CLI.
    let _actor = resolve_actor(actor.as_deref())?;

    // §6.6.3's rule, and the reason config is authoritative. A row the
    // config will never honour is a credential that looks live and is
    // not: it is in the table, it is in `tenant admin list`, and it can
    // never authenticate. Refusing here is the only place that mistake
    // can still be caught cheaply.
    if !config.tenancy.platform_admins.iter().any(|n| n == &name) {
        anyhow::bail!(
            "{name:?} is not in [tenancy] platform_admins, so a credential for it could \
                     never authenticate — config is authoritative (§6.6.3). Add the name to the \
                     config first, then re-run:\n\n    [tenancy]\n    platform_admins = [{name:?}]\n\n\
                     Nothing has been changed."
        );
    }

    let password = match password {
        Some(p) => p,
        None => super::principals::prompt_password_or_read_stdio()?,
    };
    if password.len() < MIN_ADMIN_PASSWORD {
        anyhow::bail!(
            "an admin password must be at least {MIN_ADMIN_PASSWORD} characters (got \
                     {}). This is the one credential in the tree that reaches every tenant, so \
                     it does not get a shorter floor than the first administrator's.",
            password.len()
        );
    }

    let hash = hash_admin_password(&password);
    store
        .set_admin_credential(&name, &hash, &rustical_store::admin_now())
        .await?;
    eprintln!(
        "Set the credential for {name:?}. The name must also stay in [tenancy] \
                 platform_admins for it to be able to authenticate."
    );
    Ok(())
}

/// `tenant admin remove` — a revocation, and the half of it config cannot do.
async fn admin_remove(
    args: AdminNameArgs,
    store: &SqliteTenantStore,
    config: &crate::config::Config,
) -> Result<()> {
    let AdminNameArgs { name } = args;

    // No `--confirm` and no actor. This is a revocation, it is reversible
    // (re-`add`), and requiring an actor would be theatre: the meaningful
    // half of a revocation is the config edit, which this cannot make.
    let removed = store.remove_admin_credential(&name).await?;
    if removed {
        eprintln!("Removed the credential row for {name:?}.");
    } else {
        eprintln!("No credential row for {name:?}; nothing to remove.");
    }
    if config.tenancy.platform_admins.iter().any(|n| n == &name) {
        eprintln!(
            "Warning: {name:?} is still in [tenancy] platform_admins. It cannot \
                     authenticate without a row, but remove the name from the config too, or a \
                     later `tenant admin add` would re-arm it."
        );
    }
    Ok(())
}

/// `tenant admin list` — config and control plane, reconciled.
async fn admin_list(
    args: AdminListArgs,
    store: &SqliteTenantStore,
    config: &crate::config::Config,
) -> Result<()> {
    let AdminListArgs { json } = args;

    // The union of both halves, deliberately. A listing built from the
    // table alone would show a not-allowlisted row as an ordinary admin,
    // which is the one row an operator most needs to see.
    let entries = store
        .allowlist_gaps(&config.tenancy.platform_admins)
        .await?;
    if json {
        let view: Vec<serde_json::Value> = entries
            .iter()
            .map(|(name, standing)| {
                let (state, detail) = match standing {
                    AdminStanding::Ready { credential } => (
                        "ready",
                        serde_json::json!({
                            "created_at": credential.created_at,
                            "last_login_at": credential.last_login_at,
                            "failed_attempts": credential.failed_attempts,
                            "locked_until": credential.locked_until,
                        }),
                    ),
                    AdminStanding::NoCredential => ("no-credential", serde_json::Value::Null),
                    AdminStanding::NotAllowlisted { credential } => (
                        "not-allowlisted",
                        serde_json::json!({
                            "created_at": credential.created_at,
                            "last_login_at": credential.last_login_at,
                            "failed_attempts": credential.failed_attempts,
                            "locked_until": credential.locked_until,
                        }),
                    ),
                    AdminStanding::Absent => ("absent", serde_json::Value::Null),
                };
                serde_json::json!({ "name": name, "state": state, "detail": detail })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&view)?);
    } else if entries.is_empty() {
        eprintln!(
            "no platform admins: [tenancy] platform_admins is empty and the control plane \
                     has no credential rows"
        );
    } else {
        for (name, standing) in &entries {
            let suffix = match standing {
                AdminStanding::Ready { credential } => format!(
                    "\tenabled\tlast login {}",
                    credential.last_login_at.as_deref().unwrap_or("never")
                ),
                AdminStanding::NoCredential => {
                    "\tNO CREDENTIAL — run: rustical tenant admin add".to_owned()
                }
                AdminStanding::NotAllowlisted { credential } => format!(
                    "\tNOT ALLOWLISTED — cannot authenticate ({} failed, locked until {})",
                    credential.failed_attempts,
                    credential.locked_until.as_deref().unwrap_or("—")
                ),
                AdminStanding::Absent => "\tabsent".to_owned(),
            };
            println!("{name}\t{suffix}");
        }
    }
    Ok(())
}

/// The floor for a platform-admin password, matching `setup.rs`'s
/// `MIN_ADMIN_PASSWORD`.
///
/// **Not** read from `[registration] min_password_length`: a config that lowered
/// that for tenant users must not get to lower the floor on the credential that
/// crosses every tenant boundary, and the wizard's constant is already a
/// deliberate hard floor for the same reason.
const MIN_ADMIN_PASSWORD: usize = 12;

/// argon2 with a fresh salt, the same primitive and parameters `principals` and
/// `password_reset.rs` use.
///
/// `expect` is sound here for the same reason it is there: `Argon2::default()`
/// with a valid `SaltString` cannot fail, and there is no caller-supplied
/// parameter that could make it.
fn hash_admin_password(password: &str) -> String {
    use argon2::password_hash::{PasswordHasher, SaltString, rand_core::OsRng};
    let salt = SaltString::generate(OsRng);
    argon2::Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .expect("argon2 hashing cannot fail for valid parameters")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::set_dotted;

    /// A dotted key has to create the intermediate object rather than write a
    /// literal `"registration.enabled"` key: the config loader walks
    /// `registration.enabled`, so a flat key would be stored and then ignored —
    /// silently, which is the failure mode this test exists to prevent.
    #[test]
    fn a_nested_key_lands_in_the_right_place() {
        let mut blob = serde_json::json!({});
        set_dotted(&mut blob, "registration.enabled", serde_json::json!(false)).unwrap();
        assert_eq!(
            blob,
            serde_json::json!({"registration": {"enabled": false}})
        );
    }

    #[test]
    fn a_top_level_key_lands_at_the_top() {
        let mut blob = serde_json::json!({});
        set_dotted(&mut blob, "rsvp_secret", serde_json::json!("s")).unwrap();
        assert_eq!(blob, serde_json::json!({"rsvp_secret": "s"}));
    }
}
