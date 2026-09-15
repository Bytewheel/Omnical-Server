//! SQLite implementation of the [`CollectionShareStore`] (Omnical §17.10
//! guest-invites extension).
//!
//! All queries use the runtime query API (`sqlx::query`) deliberately: the
//! sqlx offline metadata in `.sqlx/` only covers upstream's macro queries and
//! keeping our queries out of it avoids `cargo sqlx prepare` churn.
use async_trait::async_trait;
use rustical_store::auth::Privilege;
use rustical_store::error::Error;
use rustical_store::{CollectionShare, CollectionShareStore};
use sqlx::Row;
use tracing::instrument;

use super::calendar_store::SqliteCalendarStore;

#[derive(Debug, Clone)]
pub struct SqliteCollectionShareStore {
    pub(crate) cal_store: SqliteCalendarStore,
}

impl SqliteCollectionShareStore {
    #[must_use]
    pub const fn new(cal_store: SqliteCalendarStore) -> Self {
        Self { cal_store }
    }
}

fn row_to_share(row: &sqlx::sqlite::SqliteRow) -> CollectionShare {
    // NOTE: `try_get(col)` without an explicit type infers `String`, which
    // decodes a NULL column as `""`. Decoding as `Option<String>` yields the
    // true SQL NULL, then `.flatten()` collapses the nested Option.
    CollectionShare {
        id: row.get("id"),
        owner_principal: row.get("owner_principal"),
        collection_id: row.get("collection_id"),
        kind: row.get("kind"),
        // The column CHECK constraint guarantees one of the three values; the
        // fallback (`View`) is the read-only default and never grants writes.
        privilege: row
            .try_get::<String, _>("privilege")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(Privilege::View),
        guest_principal: row.get("guest_principal"),
        target_email: row
            .try_get::<Option<String>, _>("target_email")
            .ok()
            .flatten(),
        created_by: row.get("created_by"),
        created_at: row
            .try_get::<Option<String>, _>("created_at")
            .ok()
            .flatten(),
        revoked_at: row
            .try_get::<Option<String>, _>("revoked_at")
            .ok()
            .flatten(),
    }
}

#[async_trait]
impl CollectionShareStore for SqliteCollectionShareStore {
    #[instrument(skip(self))]
    async fn add_share(
        &self,
        owner_principal: &str,
        collection_id: &str,
        kind: &str,
        privilege: Privilege,
        guest_principal: &str,
        target_email: &Option<String>,
        created_by: &str,
    ) -> Result<String, Error> {
        let id = uuid::Uuid::new_v4().to_string();
        // A duplicate `guest_principal` surfaces as `Error::AlreadyExists`
        // through the `From<sqlx::Error>` conversion (unique-violation
        // mapping).
        sqlx::query(
            "INSERT INTO collection_shares \
                (id, owner_principal, collection_id, kind, privilege, guest_principal, \
                 target_email, created_by) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&id)
        .bind(owner_principal)
        .bind(collection_id)
        .bind(kind)
        .bind(privilege.as_str())
        .bind(guest_principal)
        .bind(target_email)
        .bind(created_by)
        .execute(self.cal_store.db_pool())
        .await
        .map_err(crate::Error::from)?;
        Ok(id)
    }

    #[instrument]
    async fn get_share_by_guest(&self, guest_id: &str) -> Result<Option<CollectionShare>, Error> {
        let row = sqlx::query(
            "SELECT id, owner_principal, collection_id, kind, privilege, guest_principal, \
                    target_email, created_by, created_at, revoked_at \
             FROM collection_shares WHERE guest_principal = ? AND revoked_at IS NULL",
        )
        .bind(guest_id)
        .fetch_optional(self.cal_store.db_pool())
        .await
        .map_err(crate::Error::from)?;
        Ok(row.map(|r| row_to_share(&r)))
    }

    #[instrument]
    async fn get_shares_for_collection(
        &self,
        owner_principal: &str,
        collection_id: &str,
    ) -> Result<Vec<CollectionShare>, Error> {
        let rows = sqlx::query(
            "SELECT id, owner_principal, collection_id, kind, privilege, guest_principal, \
                    target_email, created_by, created_at, revoked_at \
             FROM collection_shares \
             WHERE owner_principal = ? AND collection_id = ? AND revoked_at IS NULL \
             ORDER BY created_at, id",
        )
        .bind(owner_principal)
        .bind(collection_id)
        .fetch_all(self.cal_store.db_pool())
        .await
        .map_err(crate::Error::from)?;
        Ok(rows.iter().map(row_to_share).collect())
    }

    #[instrument]
    async fn revoke_share(&self, share_id: &str) -> Result<(), Error> {
        let result = sqlx::query(
            "UPDATE collection_shares SET revoked_at = CURRENT_TIMESTAMP \
             WHERE id = ? AND revoked_at IS NULL",
        )
        .bind(share_id)
        .execute(self.cal_store.db_pool())
        .await
        .map_err(crate::Error::from)?;
        if result.rows_affected() == 0 {
            return Err(Error::NotFound);
        }
        Ok(())
    }

    #[instrument]
    async fn list_guest_shares(
        &self,
        owner_principal: &str,
    ) -> Result<Vec<CollectionShare>, Error> {
        let rows = sqlx::query(
            "SELECT id, owner_principal, collection_id, kind, privilege, guest_principal, \
                    target_email, created_by, created_at, revoked_at \
             FROM collection_shares \
             WHERE owner_principal = ? AND revoked_at IS NULL \
             ORDER BY created_at, id",
        )
        .bind(owner_principal)
        .fetch_all(self.cal_store.db_pool())
        .await
        .map_err(crate::Error::from)?;
        Ok(rows.iter().map(row_to_share).collect())
    }
}
