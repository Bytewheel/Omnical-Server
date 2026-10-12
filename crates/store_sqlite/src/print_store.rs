//! `SQLite` implementation of the [`PrintStore`] (the portal print pages'
//! new-vs-all tracking, ``PLAN_NEXT_AGENT_PRINTING.md`` §3.3).
//!
//! All queries use the runtime query API (`sqlx::query`) deliberately: the
//! sqlx offline metadata in `.sqlx/` only covers upstream's macro queries and
//! keeping our queries out of it avoids `cargo sqlx prepare` churn.
use async_trait::async_trait;
use rustical_store::error::Error;
use rustical_store::{PrintCollectionKind, PrintMark, PrintStore};
use sqlx::Row;
use std::collections::HashSet;
use tracing::instrument;

use super::calendar_store::SqliteCalendarStore;

#[derive(Debug, Clone)]
pub struct SqlitePrintStore {
    pub(crate) cal_store: SqliteCalendarStore,
}

impl SqlitePrintStore {
    #[must_use]
    pub const fn new(cal_store: SqliteCalendarStore) -> Self {
        Self { cal_store }
    }
}

#[async_trait]
impl PrintStore for SqlitePrintStore {
    #[instrument(skip(self, marks))]
    async fn mark_printed(&self, marks: &[PrintMark]) -> Result<(), Error> {
        for mark in marks {
            // Upsert: re-printing the same sticker refreshes printed_at/printed_by
            // instead of failing on the unique key (plan D5 — marking is
            // idempotent, the page can be POSTed twice).
            sqlx::query(
                "INSERT INTO print_state \
                 (principal, collection_id, kind, object_id, instance_key, printed_by) \
                 VALUES (?, ?, ?, ?, ?, ?) \
                 ON CONFLICT (principal, collection_id, kind, object_id, instance_key) \
                 DO UPDATE SET printed_at = CURRENT_TIMESTAMP, printed_by = excluded.printed_by",
            )
            .bind(&mark.principal)
            .bind(&mark.collection_id)
            .bind(mark.kind.as_str())
            .bind(&mark.object_id)
            .bind(&mark.instance_key)
            .bind(&mark.printed_by)
            .execute(self.cal_store.db_pool())
            .await
            .map_err(crate::Error::from)?;
        }
        Ok(())
    }

    #[instrument(skip(self))]
    async fn printed_keys(
        &self,
        principal: &str,
        kind: PrintCollectionKind,
        collection_id: &str,
    ) -> Result<HashSet<(String, String)>, Error> {
        let rows = sqlx::query(
            "SELECT object_id, instance_key FROM print_state \
             WHERE principal = ? AND kind = ? AND collection_id = ?",
        )
        .bind(principal)
        .bind(kind.as_str())
        .bind(collection_id)
        .fetch_all(self.cal_store.db_pool())
        .await
        .map_err(crate::Error::from)?;
        Ok(rows
            .into_iter()
            .map(|row| {
                (
                    row.get::<String, _>("object_id"),
                    row.get::<String, _>("instance_key"),
                )
            })
            .collect())
    }
}
