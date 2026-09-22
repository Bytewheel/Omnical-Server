#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::missing_errors_doc)]
pub use error::Error;
use serde::Serialize;
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
