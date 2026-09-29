#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::missing_errors_doc)]
pub use error::Error;
use serde::Serialize;
use sqlx::pool::PoolOptions;
use sqlx::{Pool, Sqlite, SqlitePool, sqlite::SqliteConnectOptions};
use tracing::info;
mod addressbook_store;
pub use addressbook_store::SqliteAddressbookStore;
mod calendar_store;
pub use calendar_store::SqliteCalendarStore;
mod calendar_source_store;
pub use calendar_source_store::SqliteCalendarSourceStore;
mod collection_share_store;
pub use collection_share_store::SqliteCollectionShareStore;
mod dav_push_store;
pub use dav_push_store::SqliteDavPushStore;
pub mod error;
mod invite_store;
pub use invite_store::SqliteInviteStore;
mod password_reset_store;
pub use password_reset_store::SqlitePasswordResetStore;
mod principal_store;
pub use principal_store::SqlitePrincipalStore;
mod scheduling_store;
pub use scheduling_store::SqliteSchedulingStore;
mod subscription_store;
pub use subscription_store::SqliteSubscriptionStore;
mod tenant_store;
pub use tenant_store::{SqliteTenantStore, new_tenant, new_tenant_id};

// Begin statement for write transactions
pub const BEGIN_IMMEDIATE: &str = "BEGIN IMMEDIATE";

#[cfg(any(test, feature = "test"))]
pub mod tests;

#[derive(Debug, Clone, Serialize, sqlx::Type)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum ChangeOperation {
    // There's no distinction between Add and Modify
    Add,
    Delete,
}

/// Open the **control plane** database — `PLAN_DEPLOYMENTS.md` §3.4.
///
/// A separate function from [`create_db_pool`] for a reason that is easy to get
/// wrong and expensive to notice: it runs `./control_migrations`, not
/// `./migrations`. The control plane is the cross-tenant index and is specified
/// to hold no calendar, contact or credential data, and pointing it at the
/// tenant migration set would quietly create thirteen tables of that data in
/// the one database whose whole property is that it cannot hold any.
///
/// The control plane is a single small file touched by every request, so it gets
/// one connection rather than a pool sized like a tenant's: a pool of
/// connections that exist only to serve one indexed lookup is memory that a
/// 256 MiB appliance budget should not be paying for. WAL is still on, so the
/// CLI reading a tenant list while the server resolves hosts does not block.
pub async fn create_control_plane_pool(
    db_url: &str,
    migrate: bool,
) -> Result<Pool<Sqlite>, sqlx::Error> {
    let options: SqliteConnectOptions = db_url.parse()?;

    // The control plane file holds SMTP passwords: §3.6 puts per-tenant
    // `scheduling.smtp` identities in `tenants.config_json`, and §6.3 calls that
    // out as "critical" for exactly this reason. A SQLite file is created 0644
    // by default, i.e. world-readable, so a self-hoster's tenant passwords would
    // be readable by every account on the machine — on a shared host, by every
    // other tenant of the host.
    //
    // Created here with `mode(0o600)` before SQLx opens it. The alternative,
    // `set_permissions` after the fact, has a window in which the file exists
    // world-readable; `OpenOptions` with a mode has none.
    //
    // `O_CREAT` without `O_TRUNC`: an existing control plane keeps its contents
    // and its mode, so restarting does not reset an operator's deliberate
    // `0o640` for a group-readable service account.
    if let Some(path) = sqlite_path(db_url)
        && !std::path::Path::new(&path).exists()
    {
        if let Some(parent) = std::path::Path::new(&path).parent()
            && !parent.as_os_str().is_empty()
            && !parent.exists()
        {
            std::fs::create_dir_all(parent).map_err(|e| {
                sqlx::Error::Configuration(
                    format!(
                        "could not create {}/ for the control plane: {e}",
                        parent.display()
                    )
                    .into(),
                )
            })?;
        }
        let mut options = std::fs::OpenOptions::new();
        options.create(true).write(true);
        // `mode` applies only to a file *this* call creates, which is
        // exactly the case being handled. Unix-only: this file is a
        // credential whose protection class is a POSIX mode, and the
        // appliance target is aarch64-linux.
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        options.open(&path).map_err(|e| {
            sqlx::Error::Io(std::io::Error::other(format!(
                "could not create the control plane at {path}: {e}"
            )))
        })?;
    }

    let db = PoolOptions::<Sqlite>::new()
        .max_connections(2)
        .connect_with(
            options
                .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
                .create_if_missing(true),
        )
        .await?;
    if migrate {
        info!("Running control-plane database migrations");
        sqlx::migrate!("./control_migrations").run(&db).await?;
    }
    Ok(db)
}

/// The filesystem path a sqlite URL points at, or `None` for an in-memory
/// database.
///
/// The `SQLx` driver accepts the sqlite scheme with or without slashes, the file
/// scheme, and bare paths, all for the same thing — and the in-memory form is not a
/// path at all. Getting this wrong would mean creating a stray file named after it
/// in the working directory, so every
/// form is enumerated rather than pattern-matched.
fn sqlite_path(db_url: &str) -> Option<String> {
    let rest = db_url
        .strip_prefix("sqlite://")
        .or_else(|| db_url.strip_prefix("sqlite:"))
        .or_else(|| db_url.strip_prefix("file:"))
        .unwrap_or(db_url);
    // Drop any `?mode=rwc`-style query; it is not part of the path.
    let rest = rest.split('?').next().unwrap_or(rest);
    if rest.is_empty() || rest == ":memory:" {
        return None;
    }
    Some(rest.to_owned())
}

pub async fn create_db_pool(db_url: &str, migrate: bool) -> Result<Pool<Sqlite>, sqlx::Error> {
    let options: SqliteConnectOptions = db_url.parse()?;

    let db = SqlitePool::connect_with(
        options
            .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
            .create_if_missing(true),
    )
    .await?;
    if migrate {
        info!("Running database migrations");
        sqlx::migrate!("./migrations").run(&db).await?;
    }
    Ok(db)
}
