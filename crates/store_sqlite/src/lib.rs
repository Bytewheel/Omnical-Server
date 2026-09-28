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
