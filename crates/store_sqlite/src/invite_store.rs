//! SQLite implementation of the [`InviteStore`] (Omnical registration
//! extension).
//!
//! All queries use the runtime query API (`sqlx::query`) deliberately: the
//! sqlx offline metadata in `.sqlx/` only covers upstream's macro queries and
//! keeping our queries out of it avoids `cargo sqlx prepare` churn.
use async_trait::async_trait;
use rustical_store::error::Error;
use rustical_store::{Invite, InviteStore};
use sqlx::Row;
use tracing::instrument;

use super::calendar_store::SqliteCalendarStore;

#[derive(Debug, Clone)]
pub struct SqliteInviteStore {
    pub(crate) cal_store: SqliteCalendarStore,
}

impl SqliteInviteStore {
    #[must_use]
    pub const fn new(cal_store: SqliteCalendarStore) -> Self {
        Self { cal_store }
    }
}

fn row_to_invite(row: &sqlx::sqlite::SqliteRow) -> Invite {
    // NOTE: `try_get(col)` without an explicit type infers `String`, which
    // decodes a NULL column as `""`. Decoding as `Option<String>` yields the
    // true SQL NULL, then `.flatten()` collapses the nested Option.
    Invite {
        id: row.get("id"),
        code: row.get("code"),
        target_email: row
            .try_get::<Option<String>, _>("target_email")
            .ok()
            .flatten(),
        target_group: row
            .try_get::<Option<String>, _>("target_group")
            .ok()
            .flatten(),
        created_by: row.get("created_by"),
        created_at: row
            .try_get::<Option<String>, _>("created_at")
            .ok()
            .flatten(),
        expires_at: row
            .try_get::<Option<String>, _>("expires_at")
            .ok()
            .flatten(),
        used_by: row.try_get::<Option<String>, _>("used_by").ok().flatten(),
        used_at: row.try_get::<Option<String>, _>("used_at").ok().flatten(),
    }
}

#[async_trait]
impl InviteStore for SqliteInviteStore {
    #[instrument(skip(code))]
    async fn add_invite(
        &self,
        code: &str,
        target_email: &Option<String>,
        target_group: &Option<String>,
        created_by: &str,
        expires_at: &Option<String>,
    ) -> Result<String, Error> {
        let id = uuid::Uuid::new_v4().to_string();
        // A duplicated code surfaces as `Error::AlreadyExists` through the
        // `From<sqlx::Error>` conversion (unique-violation mapping).
        sqlx::query(
            "INSERT INTO invites (id, code, target_email, target_group, created_by, expires_at) \
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(&id)
        .bind(code)
        .bind(target_email)
        .bind(target_group)
        .bind(created_by)
        .bind(expires_at)
        .execute(self.cal_store.db_pool())
        .await
        .map_err(crate::Error::from)?;
        Ok(id)
    }

    #[instrument]
    async fn get_invite(&self, code: &str) -> Result<Option<Invite>, Error> {
        let row = sqlx::query(
            "SELECT id, code, target_email, target_group, created_by, created_at, expires_at, \
                    used_by, used_at \
             FROM invites WHERE code = ?",
        )
        .bind(code)
        .fetch_optional(self.cal_store.db_pool())
        .await
        .map_err(crate::Error::from)?;
        Ok(row.map(|r| row_to_invite(&r)))
    }

    #[instrument]
    async fn redeem_invite(&self, code: &str, used_by: &str, now: &str) -> Result<(), Error> {
        // Expiry is checked here (and in the pre-check get_invite) so the
        // redemption is fully atomic: an expired invite can never be redeemed,
        // even in the window between checking and updating.
        let result = sqlx::query(
            "UPDATE invites SET used_by = ?, used_at = CURRENT_TIMESTAMP \
             WHERE code = ? AND used_by IS NULL \
               AND (expires_at IS NULL OR expires_at > ?)",
        )
        .bind(used_by)
        .bind(code)
        .bind(now)
        .execute(self.cal_store.db_pool())
        .await
        .map_err(crate::Error::from)?;
        if result.rows_affected() == 0 {
            return Err(Error::NotFound);
        }
        Ok(())
    }

    #[instrument]
    async fn list_invites(&self, include_used: bool) -> Result<Vec<Invite>, Error> {
        let rows = if include_used {
            sqlx::query(
                "SELECT id, code, target_email, target_group, created_by, created_at, expires_at, \
                        used_by, used_at \
                 FROM invites ORDER BY created_at, id",
            )
            .fetch_all(self.cal_store.db_pool())
        } else {
            sqlx::query(
                "SELECT id, code, target_email, target_group, created_by, created_at, expires_at, \
                        used_by, used_at \
                 FROM invites WHERE used_by IS NULL ORDER BY created_at, id",
            )
            .fetch_all(self.cal_store.db_pool())
        }
        .await
        .map_err(crate::Error::from)?;
        Ok(rows.iter().map(row_to_invite).collect())
    }

    #[instrument]
    async fn delete_invite(&self, code: &str) -> Result<(), Error> {
        let result = sqlx::query("DELETE FROM invites WHERE code = ?")
            .bind(code)
            .execute(self.cal_store.db_pool())
            .await
            .map_err(crate::Error::from)?;
        if result.rows_affected() == 0 {
            return Err(Error::NotFound);
        }
        Ok(())
    }
}
