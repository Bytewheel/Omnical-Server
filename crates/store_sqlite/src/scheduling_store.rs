//! SQLite implementation of the [`SchedulingStore`] (Omnical RFC 6638 extension).
//!
//! All queries use the runtime query API (`sqlx::query`) deliberately: the
//! sqlx offline metadata in `.sqlx/` only covers upstream's macro queries and
//! keeping our queries out of it avoids `cargo sqlx prepare` churn.
use crate::{BEGIN_IMMEDIATE, ChangeOperation};
use async_trait::async_trait;
use rustical_ical::CalendarObject;
use rustical_store::CollectionOperationInfo;
use rustical_store::calendar_store::CalendarReadStore;
use rustical_store::error::Error;
use rustical_store::{InboxObject, SchedulingStore};
use sqlx::{Row, Sqlite, Transaction};
use tracing::instrument;

use super::calendar_store::SqliteCalendarStore;

#[derive(Debug)]
pub struct SqliteSchedulingStore {
    pub(crate) cal_store: SqliteCalendarStore,
}

impl SqliteSchedulingStore {
    #[must_use]
    pub fn new(cal_store: SqliteCalendarStore) -> Self {
        Self { cal_store }
    }
}

async fn bump_synctoken_and_notify(
    cal_store: &SqliteCalendarStore,
    mut tx: Transaction<'_, Sqlite>,
    principal: &str,
    cal_id: &str,
    object_id: &str,
) -> Result<(), Error> {
    let sync_token = SqliteCalendarStore::log_object_operation(
        &mut tx,
        principal,
        cal_id,
        object_id,
        ChangeOperation::Add,
    )
    .await?;
    tx.commit().await.map_err(crate::Error::from)?;
    cal_store.send_push_notification(
        CollectionOperationInfo::Content { sync_token },
        cal_store
            .get_calendar(principal, cal_id, true)
            .await?
            .push_topic,
    );
    Ok(())
}

#[async_trait]
impl SchedulingStore for SqliteSchedulingStore {
    #[instrument]
    async fn principal_exists(&self, principal: &str) -> Result<bool, Error> {
        let row: Option<(i64,)> = sqlx::query_as("SELECT COUNT(*) FROM principals WHERE id = ?")
            .bind(principal)
            .fetch_optional(self.cal_store.db_pool())
            .await
            .map_err(crate::Error::from)?;
        Ok(row.is_some_and(|(count,)| count > 0))
    }

    #[instrument]
    async fn principal_memberships(&self, principal: &str) -> Result<Vec<String>, Error> {
        let rows: Vec<(String,)> =
            sqlx::query_as("SELECT member_of FROM memberships WHERE principal = ?")
                .bind(principal)
                .fetch_all(self.cal_store.db_pool())
                .await
                .map_err(crate::Error::from)?;
        Ok(rows.into_iter().map(|(member_of,)| member_of).collect())
    }

    #[instrument]
    async fn put_inbox_object(
        &self,
        principal: &str,
        object_id: &str,
        ics: &str,
    ) -> Result<(), Error> {
        sqlx::query(
            "INSERT INTO scheduling_inbox_objects (principal, id, ics) VALUES (?, ?, ?) \
             ON CONFLICT (principal, id) DO UPDATE SET ics = excluded.ics, created_at = CURRENT_TIMESTAMP",
        )
        .bind(principal)
        .bind(object_id)
        .bind(ics)
        .execute(self.cal_store.db_pool())
        .await
        .map_err(crate::Error::from)?;
        Ok(())
    }

    #[instrument]
    async fn get_inbox_object(
        &self,
        principal: &str,
        object_id: &str,
    ) -> Result<InboxObject, Error> {
        let row = sqlx::query(
            "SELECT id, ics FROM scheduling_inbox_objects WHERE (principal, id) = (?, ?)",
        )
        .bind(principal)
        .bind(object_id)
        .fetch_optional(self.cal_store.db_pool())
        .await
        .map_err(crate::Error::from)?
        .ok_or(Error::NotFound)?;
        Ok(InboxObject {
            object_id: row.get("id"),
            ics: row.get("ics"),
        })
    }

    #[instrument]
    async fn get_inbox_objects(&self, principal: &str) -> Result<Vec<InboxObject>, Error> {
        let rows = sqlx::query(
            "SELECT id, ics FROM scheduling_inbox_objects WHERE principal = ? ORDER BY created_at, id",
        )
        .bind(principal)
        .fetch_all(self.cal_store.db_pool())
        .await
        .map_err(crate::Error::from)?;
        Ok(rows
            .into_iter()
            .map(|row| InboxObject {
                object_id: row.get("id"),
                ics: row.get("ics"),
            })
            .collect())
    }

    #[instrument]
    async fn delete_inbox_object(&self, principal: &str, object_id: &str) -> Result<(), Error> {
        let result =
            sqlx::query("DELETE FROM scheduling_inbox_objects WHERE (principal, id) = (?, ?)")
                .bind(principal)
                .bind(object_id)
                .execute(self.cal_store.db_pool())
                .await
                .map_err(crate::Error::from)?;
        if result.rows_affected() == 0 {
            return Err(Error::NotFound);
        }
        Ok(())
    }

    #[instrument]
    async fn find_calendar_objects_by_uid(
        &self,
        principal: &str,
        uid: &str,
    ) -> Result<Vec<(String, String, String)>, Error> {
        let rows = sqlx::query(
            "SELECT cal_id, id, ics FROM calendarobjects \
             WHERE principal = ? AND deleted_at IS NULL AND uid = ?",
        )
        .bind(principal)
        .bind(uid)
        .fetch_all(self.cal_store.db_pool())
        .await
        .map_err(crate::Error::from)?;
        Ok(rows
            .into_iter()
            .map(|row| (row.get("cal_id"), row.get("id"), row.get("ics")))
            .collect())
    }

    #[instrument]
    async fn update_calendar_object_ics(
        &self,
        principal: &str,
        calendar_id: &str,
        object_id: &str,
        ics: &str,
    ) -> Result<(), Error> {
        // Parse first so we only ever store valid data and get the new etag
        let object = CalendarObject::from_ics(ics.to_owned())?;
        let etag = object.get_etag();

        let mut tx = self
            .cal_store
            .db_pool()
            .begin_with(BEGIN_IMMEDIATE)
            .await
            .map_err(crate::Error::from)?;
        let result =
            sqlx::query("UPDATE calendarobjects SET ics = ?, etag = ?, updated_at = CURRENT_TIMESTAMP WHERE (principal, cal_id, id) = (?, ?, ?)")
                .bind(ics)
                .bind(etag)
                .bind(principal)
                .bind(calendar_id)
                .bind(object_id)
                .execute(&mut *tx)
                .await
                .map_err(crate::Error::from)?;
        if result.rows_affected() == 0 {
            return Err(Error::NotFound);
        }
        bump_synctoken_and_notify(&self.cal_store, tx, principal, calendar_id, object_id).await?;
        // Invalidate the push topic? No: the notification above already covers it.
        Ok(())
    }
}
