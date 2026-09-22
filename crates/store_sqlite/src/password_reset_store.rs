//! SQLite implementation of the [`PasswordResetStore`] (Omnical
//! password-reset extension).
//!
//! All queries use the runtime query API (`sqlx::query`) deliberately: the
//! sqlx offline metadata in `.sqlx/` only covers upstream's macro queries and
//! keeping our queries out of it avoids `cargo sqlx prepare` churn.
use async_trait::async_trait;
use rustical_store::error::Error;
use rustical_store::{PasswordReset, PasswordResetStore};
use sqlx::Row;
use tracing::instrument;

use super::calendar_store::SqliteCalendarStore;

#[derive(Debug, Clone)]
pub struct SqlitePasswordResetStore {
    pub(crate) cal_store: SqliteCalendarStore,
}

impl SqlitePasswordResetStore {
    #[must_use]
    pub const fn new(cal_store: SqliteCalendarStore) -> Self {
        Self { cal_store }
    }
}

fn row_to_reset(row: &sqlx::sqlite::SqliteRow) -> PasswordReset {
    // NOTE: `try_get(col)` without an explicit type infers `String`, which
    // decodes a NULL column as `""`. Decoding as `Option<String>` yields the
    // true SQL NULL, then `.flatten()` collapses the nested Option.
    PasswordReset {
        id: row.get("id"),
        principal_id: row.get("principal_id"),
        token_hash: row.get("token_hash"),
        created_at: row
            .try_get::<Option<String>, _>("created_at")
            .ok()
            .flatten(),
        expires_at: row.get("expires_at"),
        used_at: row.try_get::<Option<String>, _>("used_at").ok().flatten(),
    }
}

#[async_trait]
impl PasswordResetStore for SqlitePasswordResetStore {
    #[instrument(skip(token_hash))]
    async fn add_reset(
        &self,
        token_hash: &str,
        principal_id: &str,
        expires_at: &str,
        now: &str,
    ) -> Result<String, Error> {
        let id = uuid::Uuid::new_v4().to_string();
        let mut tx = self
            .cal_store
            .db_pool()
            .begin()
            .await
            .map_err(crate::Error::from)?;
        // A fresh request supersedes the account's older links: at most one
        // reset link per principal is ever outstanding.
        sqlx::query(
            "UPDATE password_resets SET used_at = ? \
             WHERE principal_id = ? AND used_at IS NULL",
        )
        .bind(now)
        .bind(principal_id)
        .execute(&mut *tx)
        .await
        .map_err(crate::Error::from)?;
        // A duplicated digest surfaces as `Error::AlreadyExists` through
        // the `From<sqlx::Error>` conversion (unique-violation mapping).
        sqlx::query(
            "INSERT INTO password_resets (id, principal_id, token_hash, expires_at) \
             VALUES (?, ?, ?, ?)",
        )
        .bind(&id)
        .bind(principal_id)
        .bind(token_hash)
        .bind(expires_at)
        .execute(&mut *tx)
        .await
        .map_err(crate::Error::from)?;
        tx.commit().await.map_err(crate::Error::from)?;
        Ok(id)
    }

    #[instrument]
    async fn get_reset(&self, token_hash: &str) -> Result<Option<PasswordReset>, Error> {
        let row = sqlx::query(
            "SELECT id, principal_id, token_hash, created_at, expires_at, used_at \
             FROM password_resets WHERE token_hash = ?",
        )
        .bind(token_hash)
        .fetch_optional(self.cal_store.db_pool())
        .await
        .map_err(crate::Error::from)?;
        Ok(row.map(|r| row_to_reset(&r)))
    }

    #[instrument]
    async fn redeem_reset(&self, token_hash: &str, now: &str) -> Result<PasswordReset, Error> {
        let mut tx = self
            .cal_store
            .db_pool()
            .begin()
            .await
            .map_err(crate::Error::from)?;
        // Expiry is checked here (and in the pre-check get_reset) so the
        // redemption is fully atomic: an expired or used token can never be
        // redeemed, even in the window between checking and updating.
        let result = sqlx::query(
            "UPDATE password_resets SET used_at = ? \
             WHERE token_hash = ? AND used_at IS NULL AND expires_at > ?",
        )
        .bind(now)
        .bind(token_hash)
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(crate::Error::from)?;
        if result.rows_affected() == 0 {
            return Err(Error::NotFound);
        }
        let row = sqlx::query(
            "SELECT id, principal_id, token_hash, created_at, expires_at, used_at \
             FROM password_resets WHERE token_hash = ?",
        )
        .bind(token_hash)
        .fetch_one(&mut *tx)
        .await
        .map_err(crate::Error::from)?;
        let reset = row_to_reset(&row);
        // Completing a reset invalidates the account's other outstanding
        // links (e.g. one requested earlier that has not expired yet).
        sqlx::query(
            "UPDATE password_resets SET used_at = ? \
             WHERE principal_id = ? AND used_at IS NULL",
        )
        .bind(now)
        .bind(&reset.principal_id)
        .execute(&mut *tx)
        .await
        .map_err(crate::Error::from)?;
        tx.commit().await.map_err(crate::Error::from)?;
        Ok(reset)
    }
}
