//! SQLite implementation of the [`SubscriptionStore`] (Omnical share-links
//! extension).
//!
//! All queries use the runtime query API (`sqlx::query`) deliberately: the
//! sqlx offline metadata in `.sqlx/` only covers upstream's macro queries and
//! keeping our queries out of it avoids `cargo sqlx prepare` churn.
use async_trait::async_trait;
use rustical_store::error::Error;
use rustical_store::{Subscription, SubscriptionKind, SubscriptionStore};
use sqlx::Row;
use tracing::instrument;

use super::calendar_store::SqliteCalendarStore;

#[derive(Debug, Clone)]
pub struct SqliteSubscriptionStore {
    pub(crate) cal_store: SqliteCalendarStore,
}

impl SqliteSubscriptionStore {
    #[must_use]
    pub fn new(cal_store: SqliteCalendarStore) -> Self {
        Self { cal_store }
    }
}

fn row_to_subscription(row: &sqlx::sqlite::SqliteRow) -> Result<Subscription, Error> {
    let kind: String = row.get("kind");
    Ok(Subscription {
        id: row.get("id"),
        principal: row.get("principal"),
        kind: SubscriptionKind::try_from(kind.as_str())?,
        collection_id: row.get("collection_id"),
        token: row.get("token"),
        created_at: row.try_get("created_at").ok(),
    })
}

#[async_trait]
impl SubscriptionStore for SqliteSubscriptionStore {
    #[instrument(skip(token))]
    async fn add_subscription(
        &self,
        principal: &str,
        kind: SubscriptionKind,
        collection_id: &str,
        token: &str,
    ) -> Result<String, Error> {
        let id = uuid::Uuid::new_v4().to_string();
        // A duplicated token surfaces as `Error::AlreadyExists` through the
        // `From<sqlx::Error>` conversion (unique-violation mapping).
        sqlx::query(
            "INSERT INTO subscriptions (id, principal, kind, collection_id, token) \
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(&id)
        .bind(principal)
        .bind(kind.as_str())
        .bind(collection_id)
        .bind(token)
        .execute(self.cal_store.db_pool())
        .await
        .map_err(crate::Error::from)?;
        Ok(id)
    }

    #[instrument]
    async fn get_subscription_by_token(&self, token: &str) -> Result<Subscription, Error> {
        let row = sqlx::query(
            "SELECT id, principal, kind, collection_id, token, created_at \
             FROM subscriptions WHERE token = ?",
        )
        .bind(token)
        .fetch_optional(self.cal_store.db_pool())
        .await
        .map_err(crate::Error::from)?
        .ok_or(Error::NotFound)?;
        row_to_subscription(&row)
    }

    #[instrument]
    async fn get_subscriptions(&self, principal: &str) -> Result<Vec<Subscription>, Error> {
        let rows = sqlx::query(
            "SELECT id, principal, kind, collection_id, token, created_at \
             FROM subscriptions WHERE principal = ? ORDER BY created_at, id",
        )
        .bind(principal)
        .fetch_all(self.cal_store.db_pool())
        .await
        .map_err(crate::Error::from)?;
        rows.iter().map(row_to_subscription).collect()
    }

    #[instrument]
    async fn delete_subscription(&self, principal: &str, id: &str) -> Result<(), Error> {
        let result = sqlx::query("DELETE FROM subscriptions WHERE (principal, id) = (?, ?)")
            .bind(principal)
            .bind(id)
            .execute(self.cal_store.db_pool())
            .await
            .map_err(crate::Error::from)?;
        if result.rows_affected() == 0 {
            return Err(Error::NotFound);
        }
        Ok(())
    }
}
