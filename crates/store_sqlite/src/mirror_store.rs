//! `SQLite` implementation of the [`MirrorStore`] (Omnical §18.41).
//!
//! All queries use the runtime query API (`sqlx::query`) deliberately: the
//! sqlx offline metadata in `.sqlx/` only covers upstream's macro queries and
//! keeping our queries out of it avoids `cargo sqlx prepare` churn.
use async_trait::async_trait;
use rustical_store::error::Error;
use rustical_store::{MirrorObject, MirrorRun, MirrorStore};
use sqlx::Row;
use tracing::instrument;

use super::calendar_store::SqliteCalendarStore;

/// How many recent runs per target the store keeps (§18.42). The UI reads
/// the newest one; the rest is operator-facing history for "did the 15:30
/// cron run fail?" — bounded, because a 30-minute cadence would otherwise
/// grow the table by 48 rows a day per target forever.
const KEEP_RUNS_PER_TARGET: i64 = 20;

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

    #[instrument(skip(self, run))]
    async fn record_mirror_run(&self, mirror: &str, run: &MirrorRun) -> Result<(), Error> {
        let pool = self.cal_store.db_pool();
        let mut tx = pool.begin().await.map_err(crate::Error::from)?;
        // usize counters over SQLite are i64 by nature; a run that pushed
        // more than i64::MAX objects is not a state this table can reach,
        // and a silent wrap would be worse than the loud error.
        let put = i64::try_from(run.put)
            .map_err(|_| Error::Other(anyhow::anyhow!("mirror run put counter overflow")))?;
        let deleted = i64::try_from(run.deleted)
            .map_err(|_| Error::Other(anyhow::anyhow!("mirror run deleted counter overflow")))?;
        let unchanged = i64::try_from(run.unchanged)
            .map_err(|_| Error::Other(anyhow::anyhow!("mirror run unchanged counter overflow")))?;
        sqlx::query(
            "INSERT INTO mirror_runs (mirror, ran_at, put, deleted, unchanged, error) \
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(mirror)
        .bind(&run.ran_at)
        .bind(put)
        .bind(deleted)
        .bind(unchanged)
        .bind(&run.error)
        .execute(&mut *tx)
        .await
        .map_err(crate::Error::from)?;
        // Keep only the newest history for this target, inside the same
        // transaction: a prune that could land on a different connection
        // than the insert could drop the very row it exists to keep.
        sqlx::query(
            "DELETE FROM mirror_runs WHERE mirror = ? AND ran_at NOT IN \
             (SELECT ran_at FROM mirror_runs WHERE mirror = ? ORDER BY ran_at DESC LIMIT ?)",
        )
        .bind(mirror)
        .bind(mirror)
        .bind(KEEP_RUNS_PER_TARGET)
        .execute(&mut *tx)
        .await
        .map_err(crate::Error::from)?;
        tx.commit().await.map_err(crate::Error::from)?;
        Ok(())
    }

    #[instrument(skip(self))]
    async fn last_mirror_run(&self, mirror: &str) -> Result<Option<MirrorRun>, Error> {
        let pool = self.cal_store.db_pool();
        let row = sqlx::query(
            "SELECT ran_at, put, deleted, unchanged, error FROM mirror_runs \
             WHERE mirror = ? ORDER BY ran_at DESC LIMIT 1",
        )
        .bind(mirror)
        .fetch_optional(pool)
        .await
        .map_err(crate::Error::from)?;
        // A free fn (not a closure) so the counter conversions can use `?` —
        // the same shape as `principal_from_row`.
        row.map(|row| run_from_row(&row)).transpose()
    }
}

/// Map a `mirror_runs` row into a [`MirrorRun`]. The counters round-trip
/// through `i64` (SQLite's native integer): they were written from `usize`
/// counters of objects this very code pushed, so a value that no longer
/// fits is a database this table never produced — the loud error, not a
/// silent wrap.
fn run_from_row(row: &sqlx::sqlite::SqliteRow) -> Result<MirrorRun, Error> {
    let counter = |name: &str| -> Result<usize, Error> {
        usize::try_from(row.get::<i64, _>(name))
            .map_err(|_| Error::Other(anyhow::anyhow!("mirror_runs.{name} does not fit usize")))
    };
    Ok(MirrorRun {
        ran_at: row.get("ran_at"),
        put: counter("put")?,
        deleted: counter("deleted")?,
        unchanged: counter("unchanged")?,
        error: row.get("error"),
    })
}
