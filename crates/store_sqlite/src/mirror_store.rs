//! `SQLite` implementation of the [`MirrorStore`] (Omnical §18.41).
//!
//! All queries use the runtime query API (`sqlx::query`) deliberately: the
//! sqlx offline metadata in `.sqlx/` only covers upstream's macro queries and
//! keeping our queries out of it avoids `cargo sqlx prepare` churn.
use async_trait::async_trait;
use rustical_store::error::Error;
use rustical_store::{MirrorObject, MirrorStore};
use sqlx::Row;
use tracing::instrument;

use super::calendar_store::SqliteCalendarStore;

#[derive(Debug, Clone)]
pub struct SqliteMirrorStore {
    pub(crate) cal_store: SqliteCalendarStore,
}

impl SqliteMirrorStore {
    #[must_use]
    pub const fn new(cal_store: SqliteCalendarStore) -> Self {
        Self { cal_store }
    }
}

#[async_trait]
impl MirrorStore for SqliteMirrorStore {
    #[instrument(skip(self))]
    async fn get_mirror_objects(&self, mirror: &str) -> Result<Vec<MirrorObject>, Error> {
        let pool = self.cal_store.db_pool();
        let rows =
            sqlx::query("SELECT uid, href, hash FROM mirror_objects WHERE mirror = ? ORDER BY uid")
                .bind(mirror)
                .fetch_all(pool)
                .await
                .map_err(crate::Error::from)?;
        Ok(rows
            .iter()
            .map(|row| MirrorObject {
                uid: row.get("uid"),
                href: row.get("href"),
                hash: row.get("hash"),
            })
            .collect())
    }

    #[instrument(skip(self, objects))]
    async fn replace_mirror_objects(
        &self,
        mirror: &str,
        objects: &[MirrorObject],
    ) -> Result<(), Error> {
        let pool = self.cal_store.db_pool();
        let mut tx = pool.begin().await.map_err(crate::Error::from)?;
        sqlx::query("DELETE FROM mirror_objects WHERE mirror = ?")
            .bind(mirror)
            .execute(&mut *tx)
            .await
            .map_err(crate::Error::from)?;
        for object in objects {
            sqlx::query("INSERT INTO mirror_objects (mirror, uid, href, hash) VALUES (?, ?, ?, ?)")
                .bind(mirror)
                .bind(&object.uid)
                .bind(&object.href)
                .bind(&object.hash)
                .execute(&mut *tx)
                .await
                .map_err(crate::Error::from)?;
        }
        tx.commit().await.map_err(crate::Error::from)?;
        Ok(())
    }
}
