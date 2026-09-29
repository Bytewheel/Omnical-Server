#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
use anyhow::Result;
use clap::Parser;
use figment::Figment;
use figment::providers::{Env, Format, Toml};
use rustical::config::Config;
use rustical::{Args, Command, commands::tenants::cmd_tenants};
use rustical::{
    cmd_backup, cmd_gen_config, cmd_guest_shares, cmd_health, cmd_invites, cmd_principals,
    cmd_restore, cmd_serve, cmd_setup, cmd_subscriptions,
};
use rustical_store::tenant_store::TenantStore;
use std::path::PathBuf;
use tracing::warn;

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    let args = Args::parse();

    // One loader, so every command gets the same treatment — including the
    // tenant selection, which is *not* something a command should have to
    // remember to do.
    let parse_config = || load_config(&args.config_file);

    // Copied out before the match because `--include-config` needs the path and
    // the closure above borrows `args`.
    let config_file = PathBuf::from(&args.config_file);

    match args.command {
        Command::GenConfig(gen_config_args) => cmd_gen_config(gen_config_args),
        Command::Principals(principals_args) => {
            cmd_principals(principals_args, parse_config().await?).await
        }
        Command::Subscriptions(subscriptions_args) => {
            cmd_subscriptions(subscriptions_args, parse_config().await?).await
        }
        Command::Invites(invites_args) => cmd_invites(invites_args, parse_config().await?).await,
        Command::GuestShare(guest_share_args) => {
            cmd_guest_shares(guest_share_args, parse_config().await?).await
        }
        Command::Tenant(tenant_args) => cmd_tenants(tenant_args, parse_config().await?).await,
        Command::Backup(backup_args) => {
            cmd_backup(backup_args, parse_config().await?, &config_file)
                .await
                .map(|_| ())
        }
        Command::Restore(restore_args) => cmd_restore(restore_args, parse_config().await?).await,
        // The wizard builds the config itself, so it is not parsed here — that
        // is the point: an operator without a config file is the normal case.
        Command::Setup(setup_args) => cmd_setup(setup_args, &config_file).await,
        Command::Health(health_args) => {
            let config = parse_config().await?;
            cmd_health(config.http, health_args).await
        }
        Command::Serve => {
            let config = parse_config().await?;
            cmd_serve(args, config, None, true).await
        }
    }
}

/// The environment variable that names the tenant an operator is acting as.
///
/// **Not** `RUSTICAL_TENANT`. Config is loaded through
/// `Env::prefixed("RUSTICAL_").split("__")`, so any `RUSTICAL_*` variable is read
/// as a *config key* — and `Config` is `deny_unknown_fields`, so
/// `RUSTICAL_TENANT` does not get ignored, it makes every single command fail
/// with `unknown field: found 'tenant'`. The first version of this used that name
/// and failed exactly that way, on every command, which is how it was found.
///
/// A separate prefix is also the honest shape: this is not a configuration value,
/// it is a selection, and it should not be settable in `config.toml` next to
/// `[tenancy]`.
const TENANT_ENV: &str = "OMNICAL_TENANT";

/// The tenant an operator is acting as, if one is named.
///
/// §6.3 rows 30-31 are about what a *command* does, not only what the server
/// does: `rustical invites create --send` picks its SMTP identity and its
/// register link out of the config, so without this an admin operating on tenant
/// A's data would send A's invitation from the **global** identity with a link to
/// the **global** host. The per-tenant overrides live in the control plane, and
/// this is what brings them into a command's view of the config.
///
/// Deliberately an **environment variable** rather than a flag: it has to reach
/// every command, and adding it to each subcommand's `Args` is 8 copies of the
/// same thing. `rustical tenant` (item 11) will make this explicit.
fn tenant_selection() -> Option<String> {
    std::env::var(TENANT_ENV)
        .ok()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
}

/// Apply the selected tenant's `config_json` over the global config.
///
/// A no-op when tenancy is disabled, when no tenant is selected, or when the
/// tenant does not resolve — the last one **fails** rather than falling back to
/// the global config, because silently operating on global settings while the
/// operator believes they are acting for a tenant is how an invitation goes out
/// with the wrong `From:`.
///
/// # Errors
/// If a tenant is named but cannot be read. The message names the control plane.
async fn apply_tenant_selection_to(config: Config) -> Result<Config> {
    let Some(slug) = tenant_selection() else {
        return Ok(config);
    };
    if !config.tenancy.enabled {
        return Ok(config);
    }
    let url = &config.tenancy.control_db_url;
    let pool = rustical_store_sqlite::create_control_plane_pool(url, false)
        .await
        .map_err(|e| anyhow::anyhow!("RUSTICAL_TENANT={slug} is set but the control plane at {url} could not be opened: {e}"))?;
    let store = rustical_store_sqlite::SqliteTenantStore::new(pool);
    let tenant = store
        .get_tenant_by_slug(&slug)
        .await
        .map_err(|e| anyhow::anyhow!("{TENANT_ENV}={slug} could not be looked up: {e}"))?
        .ok_or_else(|| {
            anyhow::anyhow!(
                "{TENANT_ENV}={slug} does not resolve to an active tenant in {url}. Refusing to \
                 fall back to the global configuration: that would send mail and print links as \
                 the wrong tenant."
            )
        })?;
    Ok(config.with_tenant_overrides(&tenant))
}

/// Parse the config file, then apply the tenant selection.
///
/// `async` because the selection reads the control plane, and `main` is already
/// async. An earlier version built its own runtime to do the blocking call,
/// which panics with "cannot start a runtime from within a runtime" on every
/// command — so it failed loudly rather than quietly, but it failed on *every*
/// invocation rather than only the ones that select a tenant.
async fn load_config(config_file: &str) -> Result<Config> {
    let config: Config = Figment::new()
        .merge(Toml::file(config_file))
        .merge(Env::prefixed("RUSTICAL_").split("__"))
        .extract()
        // Clippy appeasement clippy::result_large_err
        .map_err(anyhow::Error::from)?;
    apply_tenant_selection_to(config).await
}

#[cfg(test)]
mod test_config {
    use figment::{
        Figment, Jail,
        providers::{Env, Format, Toml},
    };
    use rustical::config::{Config, HttpBindConfig};

    #[test]
    fn test_config_toml_subscriptions() {
        let config = r#"
[data_store.sqlite]
db_url = "/var/lib/rustical/db.sqlite3"

[http]
bind = "0.0.0.0:4000"

[subscriptions]
enabled = true
public_url = "https://0115d8cf.duckdns.org:8443"
"#;

        let config: Config = Figment::new()
            .merge(Toml::string(config))
            .extract()
            .unwrap();
        assert!(config.subscriptions.enabled);
        assert_eq!(
            config.subscriptions.public_url.as_deref(),
            Some("https://0115d8cf.duckdns.org:8443")
        );
        // A config without the section must keep the disabled default
        let config = r#"
[data_store.sqlite]
db_url = "/var/lib/rustical/db.sqlite3"
"#;
        let config: Config = Figment::new()
            .merge(Toml::string(config))
            .extract()
            .unwrap();
        assert!(!config.subscriptions.enabled);
        assert_eq!(config.subscriptions.public_url, None);
        assert_eq!(
            config.http.bind_config().unwrap(),
            HttpBindConfig::Tcp("[::]:4000".to_string())
        );
    }

    #[test]
    fn test_config_toml_http_host() {
        let config = r#"
[data_store.sqlite]
db_url = "/var/lib/rustical/db.sqlite3"

[http]
host = "0.0.0.0"
port = 4000

[oidc]
name = "Authelia"
issuer = "https://auth.rustical.dev"
client_id = "rustical"
client_secret = "secret"
claim_userid = "email"
scopes = ["openid", "email", "profile", "groups"]
require_group = "app:rustical"
allow_sign_up = true
"#;

        let config: Config = Figment::new()
            .merge(Toml::string(config))
            .extract()
            .unwrap();
        assert_eq!(
            config.http.bind_config().unwrap(),
            HttpBindConfig::Tcp("0.0.0.0:4000".to_string())
        );
    }

    #[test]
    fn test_config_env_http_host() {
        Jail::expect_with(|jail| {
            jail.set_env(
                "RUSTICAL_DATA_STORE__SQLITE__DB_URL",
                "/var/lib/rustical/db.sqlite3",
            );
            jail.set_env("RUSTICAL_HTTP__HOST", "localhost");
            jail.set_env("RUSTICAL_HTTP__PORT", "4000");

            let config: Config = Figment::new()
                .merge(Env::prefixed("RUSTICAL_").split("__"))
                .extract()
                .unwrap();
            assert_eq!(
                config.http.bind_config().unwrap(),
                HttpBindConfig::Tcp("localhost:4000".to_string())
            );
            Ok(())
        });
    }

    #[test]
    fn test_config_toml_http_bind() {
        let config = r#"
[data_store.sqlite]
db_url = "/var/lib/rustical/db.sqlite3"

[http]
bind = "0.0.0.0:4000"

[oidc]
name = "Authelia"
issuer = "https://auth.rustical.dev"
client_id = "rustical"
client_secret = "secret"
claim_userid = "email"
scopes = ["openid", "email", "profile", "groups"]
require_group = "app:rustical"
allow_sign_up = true
"#;

        let config: Config = Figment::new()
            .merge(Toml::string(config))
            .extract()
            .unwrap();
        assert_eq!(
            config.http.bind_config().unwrap(),
            HttpBindConfig::Tcp("0.0.0.0:4000".to_string())
        );
    }

    #[test]
    fn test_config_env_http_bind() {
        Jail::expect_with(|jail| {
            jail.set_env(
                "RUSTICAL_DATA_STORE__SQLITE__DB_URL",
                "/var/lib/rustical/db.sqlite3",
            );
            jail.set_env("RUSTICAL_HTTP__BIND", "localhost:4000");

            let config: Config = Figment::new()
                .merge(Env::prefixed("RUSTICAL_").split("__"))
                .extract()
                .unwrap();
            assert_eq!(
                config.http.bind_config().unwrap(),
                HttpBindConfig::Tcp("localhost:4000".to_string())
            );
            Ok(())
        });
    }

    #[test]
    fn test_config_env_http_unix() {
        Jail::expect_with(|jail| {
            jail.set_env(
                "RUSTICAL_DATA_STORE__SQLITE__DB_URL",
                "/var/lib/rustical/db.sqlite3",
            );
            jail.set_env("RUSTICAL_HTTP__BIND", "unix:/run/rustical/socket");

            let config: Config = Figment::new()
                .merge(Env::prefixed("RUSTICAL_").split("__"))
                .extract()
                .unwrap();
            assert_eq!(
                config.http.bind_config().unwrap(),
                HttpBindConfig::Unix("/run/rustical/socket".parse().unwrap())
            );
            Ok(())
        });
    }
}
