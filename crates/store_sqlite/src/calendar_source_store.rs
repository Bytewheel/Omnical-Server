//! SQLite implementation of the [`CalendarSourceStore`] (Omnical registration
//! extension / "linked platforms").
//!
//! All queries use the runtime query API (`sqlx::query`) deliberately: the
//! sqlx offline metadata in `.sqlx/` only covers upstream's macro queries and
//! keeping our queries out of it avoids `cargo sqlx prepare` churn.
use async_trait::async_trait;
use rustical_store::error::Error;
use rustical_store::{CalendarSource, CalendarSourceStore};
use sqlx::Row;
use tracing::instrument;

use super::calendar_store::SqliteCalendarStore;

#[derive(Debug, Clone)]
pub struct SqliteCalendarSourceStore {
    pub(crate) cal_store: SqliteCalendarStore,
}

impl SqliteCalendarSourceStore {
    #[must_use]
    pub const fn new(cal_store: SqliteCalendarStore) -> Self {
        Self { cal_store }
    }
}

fn row_to_calendar_source(row: &sqlx::sqlite::SqliteRow) -> CalendarSource {
    // NOTE: `try_get(col)` without an explicit type infers `String`, which
    // decodes a NULL column as `""`. Decoding as `Option<String>` yields the
    // true SQL NULL, then `.flatten()` collapses the nested Option.
    CalendarSource {
        id: row.get("id"),
        principal: row.get("principal"),
        calendar_id: row.get("calendar_id"),
        source_url: row.get("source_url"),
        provider_host: row.get("provider_host"),
        last_fetch_at: row
            .try_get::<Option<String>, _>("last_fetch_at")
            .ok()
            .flatten(),
        last_fetch_success: row.get::<i64, _>("last_fetch_success") != 0,
        created_at: row
            .try_get::<Option<String>, _>("created_at")
            .ok()
            .flatten(),
    }
}

#[async_trait]
impl CalendarSourceStore for SqliteCalendarSourceStore {
    #[instrument(skip(source_url))]
    async fn add_calendar_source(
        &self,
        principal: &str,
        calendar_id: &str,
        source_url: &str,
        provider_host: &str,
    ) -> Result<String, Error> {
        let id = uuid::Uuid::new_v4().to_string();
        // A duplicated (principal, calendar_id, source_url) triple surfaces as
        // `Error::AlreadyExists` through the sqlx unique-violation mapping.
        sqlx::query(
            "INSERT INTO calendar_sources (id, principal, calendar_id, source_url, provider_host) \
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(&id)
        .bind(principal)
        .bind(calendar_id)
        .bind(source_url)
        .bind(provider_host)
        .execute(self.cal_store.db_pool())
        .await
        .map_err(crate::Error::from)?;
        Ok(id)
    }

    #[instrument]
    async fn get_calendar_sources(&self, principal: &str) -> Result<Vec<CalendarSource>, Error> {
        let rows = sqlx::query(
            "SELECT id, principal, calendar_id, source_url, provider_host, \
                    last_fetch_at, last_fetch_success, created_at \
             FROM calendar_sources WHERE principal = ? ORDER BY created_at, id",
        )
        .bind(principal)
        .fetch_all(self.cal_store.db_pool())
        .await
        .map_err(crate::Error::from)?;
        Ok(rows.iter().map(row_to_calendar_source).collect())
    }

    #[instrument]
    async fn get_calendar_source(
        &self,
        principal: &str,
        id: &str,
    ) -> Result<CalendarSource, Error> {
        let row = sqlx::query(
            "SELECT id, principal, calendar_id, source_url, provider_host, \
                    last_fetch_at, last_fetch_success, created_at \
             FROM calendar_sources WHERE (principal, id) = (?, ?)",
        )
        .bind(principal)
        .bind(id)
        .fetch_optional(self.cal_store.db_pool())
        .await
        .map_err(crate::Error::from)?
        .ok_or(Error::NotFound)?;
        Ok(row_to_calendar_source(&row))
    }

    #[instrument]
    async fn update_calendar_source_fetch(
        &self,
        principal: &str,
        id: &str,
        last_fetch_at: &str,
        success: bool,
    ) -> Result<(), Error> {
        let result = sqlx::query(
            "UPDATE calendar_sources SET last_fetch_at = ?, last_fetch_success = ? \
             WHERE (principal, id) = (?, ?)",
        )
        .bind(last_fetch_at)
        .bind(i32::from(success))
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

    #[instrument]
    async fn delete_calendar_source(&self, principal: &str, id: &str) -> Result<(), Error> {
        let result = sqlx::query("DELETE FROM calendar_sources WHERE (principal, id) = (?, ?)")
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
