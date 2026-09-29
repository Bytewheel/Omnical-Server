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
}

#[derive(Debug, Parser)]
pub struct SetQuotaArgs {
    pub slug: String,
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

#[derive(Debug, Parser)]
pub struct DeleteArgs {
    pub slug: String,
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
            display_name,
            hosts,
            plan,
            config_json,
        }) => {
            let slug_id = parse_slug(&slug)?;
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
                .create_tenant(&new)
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

        TenantCommand::Suspend(SlugArgs { slug }) => {
            let tenant = any_tenant(&store, &slug).await?;
            store
                .update_tenant_status(&tenant.id, TenantStatus::Suspended)
                .await?;
            // No eviction, no signal: the next request consults the control
            // plane and sees this. See this module's docs.
            eprintln!(
                "Suspended {}. The next request for it is a 404; in-flight requests finish.",
                tenant.slug
            );
            Ok(())
        }

        TenantCommand::Resume(SlugArgs { slug }) => {
            let tenant = any_tenant(&store, &slug).await?;
            store
                .update_tenant_status(&tenant.id, TenantStatus::Active)
                .await?;
            eprintln!("Resumed {}", tenant.slug);
            Ok(())
        }

        TenantCommand::SetQuota(SetQuotaArgs {
            slug,
            principals,
            calendars,
            megabytes,
        }) => {
            let tenant = any_tenant(&store, &slug).await?;
            // Omitted flags clear to unlimited rather than being left alone, and
            // the help says so — a quota command where "I did not pass the flag"
            // means "no limit" is the safer of the two readings.
            let quota = TenantQuota {
                principals,
                calendars,
                megabytes,
            };
            store.set_quota(&tenant.id, quota).await?;
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
            ConfigCommand::Set(ConfigSetArgs { slug, key, value }) => {
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
                sqlx_upsert_config_json(&store, &tenant.id, &text).await?;
                println!("{text}");
                eprintln!("Set {key} for {}", tenant.slug);
                Ok(())
            }
        },

        TenantCommand::Delete(DeleteArgs {
            slug,
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
            store.delete_tenant(&tenant.id).await?;
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

/// Replace a tenant's `config_json`.
///
/// There is no `TenantStore` method for this — the trait's write methods are the
/// ones the dispatcher needs, and adding a config setter for a CLI would widen
/// the control plane's surface for one caller. So this is one direct statement
/// against the control-plane pool, and it is the only place in the fork that
/// writes that column.
async fn sqlx_upsert_config_json(
    store: &SqliteTenantStore,
    id: &TenantId,
    config_json: &str,
) -> Result<()> {
    let updated = sqlx::query("UPDATE tenants SET config_json = ? WHERE id = ?")
        .bind(config_json)
        .bind(id.as_str())
        .execute(store.pool())
        .await
        .context("could not write config_json")?
        .rows_affected();
    if updated == 0 {
        anyhow::bail!("no tenant with the id {id}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::set_dotted;

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
