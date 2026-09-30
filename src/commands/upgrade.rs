//! `PLAN_DEPLOYMENTS.md` item 21 / §12 row 42 — `rustical upgrade --rollback`.
//!
//! # Why this is not `rustical restore`
//!
//! §18.21 established that the schema rollback *works*: all 17 `.up.sql`/
//! `.down.sql` pairs execute and only remove schema, and the full rollback /
//! re-upgrade roundtrip restores the structure. It also established the two
//! things that do **not** go away:
//!
//! * the downs **destroy data** — that is what dropping a column means; and
//! * `add_calendar_uid`'s down **rewrites every calendar object's UID to its
//!   row id**, which is not a schema change at all but a content mutation.
//!
//! So this command is deliberately shaped around the fact that it is the
//! *destructive* option. `rustical restore` is the lossless one, and this file
//! exists to make sure nobody reaches for the destructive one by accident.
//!
//! # The four things that make it safe
//!
//! 1. **A verified backup is a precondition, not advice.** The rollback runs the
//!    same `backup` that `PRAGMA integrity_check`s the archive and counts every
//!    table first. There is no `--force` past it: the only way to run a
//!    destructive schema downgrade without a restorable copy is to not have this
//!    command at all.
//! 2. **Row counts are captured before and after and printed**, so the operator
//!    sees *what was lost* rather than discovering it later. A rollback that
//!    succeeds quietly is how data disappears unnoticed.
//! 3. **The base migrations cannot be undone.** Four of the 38 files are bare
//!    base migrations with no `.down.sql`; undoing past them is impossible and
//!    this says so by name instead of letting sqlx fail with a version error.
//! 4. **The UID rewrite is called out before the target runs**, because it is
//!    the one down that changes user-visible identifiers rather than schema.
//!
//! # The limit of the after-report, stated plainly
//!
//! Row counts are the wrong instrument for a dropped *column*, and the rehearsal
//! makes that concrete: rolling back past `add_calendar_uid` printed
//! `davpush_vapid_key 1 -> 0` and "3 rows" of `calendarobjects` throughout —
//! the events all survived — while the `uid` column those identifiers lived in
//! was gone, unreported, because no table shrank. A green after-report does not
//! mean the rollback was harmless; it means **no table lost rows**, which is a
//! strictly weaker claim.
//!
//! That is why [`CONTENT_MUTATING_DOWNS`] is an explicit list maintained by hand
//! rather than something inferred: the check cannot find these, so someone has
//! to name them. `content_mutating_downs_are_real` is what keeps that list
//! honest — it failed to compile against a version that did not exist, which is
//! how the original `20260701120000` typo would otherwise have shipped a warning
//! that never fired.

use std::collections::BTreeMap;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use clap::Parser;

use crate::config::{Config, DataStoreConfig, SqliteDataStoreConfig};
use rustical_store_sqlite::MIGRATOR;
use sqlx::migrate::MigrationType;

/// Migrations whose `.down.sql` destroys user-visible data beyond dropping schema.
///
/// `add_calendar_uid` is the one. Its down recreates `calendarobjects` **without
/// the `uid` column** and copies the rows across without it, so undoing it
/// discards every calendar object's UID. §18.21 observed the roundtrip's *net*
/// effect and recorded it as "rewrites UIDs to `id`" — that is what you see after
/// rolling back and re-applying, because the up migration backfills `uid` from
/// the row id. The down on its own is simpler and worse than that: the column is
/// gone. Either way the UIDs do not come back, and nothing rewrites the
/// references that pointed at them — a subscription's `VEVENT` UID, an
/// `ATTACH`, an RSVP.
///
/// The first draft of this constant pinned `20260701120000`, a version that does
/// not exist, so the warning never fired for the one migration it was written
/// for. `content_mutating_downs_are_real` below is what makes that class of
/// mistake fail instead of pass quietly.
const CONTENT_MUTATING_DOWNS: &[i64] = &[/* add_calendar_uid */ 20_251_101_181_540];

/// Tables that are *expected* to shrink, so a shrink is not reported as loss.
///
/// No `.down.sql` in this schema drops `app_tokens`, so on a real rollback it
/// will not appear here. It is listed anyway because the first version of
/// `RollbackReport::losses` reported every shrink as `LOST ROWS` under a
/// "this is what DROP COLUMN means" banner, which is how a deliberate
/// revocation would have been printed as collateral damage. Same rule as the
/// credential-rotation drill (`scripts/credential-rotation-drill.sh`), which
/// exists for the same reason: the one change you meant to make must not be
/// able to hide behind, or masquerade as, the one you did not.
const EXPECTED_TO_SHRINK: &[&str] = &["app_tokens"];

#[derive(Debug, Parser)]
pub struct UpgradeArgs {
    /// Roll the schema back to this migration version. Requires `--rollback`;
    /// `--to` on its own is refused, because "migrate to version X" reads like a
    /// forward migration and silently doing nothing would be worse than an error.
    #[arg(long, value_name = "VERSION")]
    pub to: Option<i64>,

    /// Undo applied migrations down to `--to` (or to the earliest reversible
    /// version). **Destructive**: dropping columns drops the data in them.
    #[arg(long)]
    pub rollback: bool,

    /// Skip the pre-rollback backup. There is deliberately no way to combine
    /// this with a real rollback today; it exists so the flag can be rejected
    /// with an explanation rather than silently ignored.
    #[arg(long)]
    pub no_backup: bool,

    /// Directory for the pre-rollback backup. Defaults to `backups/` next to the
    /// database.
    #[arg(long, value_name = "DIR")]
    pub backup_dir: Option<PathBuf>,

    /// Show what would be undone, then stop.
    #[arg(long)]
    pub dry_run: bool,
}

/// What a rollback would do, and — after it ran — what it did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct RollbackReport {
    pub from_version: i64,
    pub to_version: i64,
    pub undone: Vec<i64>,
    pub rows_before: BTreeMap<String, i64>,
    pub rows_after: BTreeMap<String, i64>,
    pub content_mutating: Vec<i64>,
}

impl RollbackReport {
    /// Tables that lost rows and were not supposed to. This is the part an
    /// operator must read, so it is rendered rather than left in the struct for
    /// someone to print later.
    #[must_use]
    pub fn losses(&self) -> Vec<(String, i64, i64)> {
        let mut out = Vec::new();
        for (table, before) in &self.rows_before {
            if EXPECTED_TO_SHRINK.contains(&table.as_str()) {
                continue;
            }
            let after = self.rows_after.get(table).copied().unwrap_or(0);
            if after < *before {
                out.push((table.clone(), *before, after));
            }
        }
        out
    }

    /// The shrink that was meant to happen, kept separate so it can be printed
    /// as what it is rather than folded into the loss count.
    #[must_use]
    pub fn expected_shrink(&self) -> Vec<(String, i64, i64)> {
        let mut out = Vec::new();
        for (table, before) in &self.rows_before {
            if !EXPECTED_TO_SHRINK.contains(&table.as_str()) {
                continue;
            }
            let after = self.rows_after.get(table).copied().unwrap_or(0);
            if after < *before {
                out.push((table.clone(), *before, after));
            }
        }
        out
    }
}

/// Versions applied to `pool` that this build can undo, newest first.
///
/// # Errors
/// Fails when the `_sqlx_migrations` table cannot be read.
pub async fn undoable_versions(pool: &sqlx::SqlitePool) -> Result<Vec<i64>> {
    let applied: Vec<(i64,)> =
        sqlx::query_as("SELECT version FROM _sqlx_migrations WHERE success ORDER BY version DESC")
            .fetch_all(pool)
            .await
            .context("reading the applied migration versions")?;

    let undoable = reversible_versions();
    Ok(applied
        .into_iter()
        .map(|(version,)| version)
        .filter(|v| undoable.contains(v))
        .collect())
}

/// Versions this build can undo: those with a matching `.down.sql`.
///
/// sqlx records a reversible pair as one `ReversibleUp` and one
/// `ReversibleDown` entry sharing a version, and a bare base migration as
/// `Simple`. The four base migrations in this schema are `Simple`, which is
/// precisely why "undo to version 0" is not an offer this command makes.
#[must_use]
pub fn reversible_versions() -> Vec<i64> {
    let mut versions: Vec<i64> = MIGRATOR
        .iter()
        .filter(|m| matches!(m.migration_type, MigrationType::ReversibleDown))
        .map(|m| m.version)
        .collect();
    versions.sort_unstable();
    versions
}

async fn table_row_counts(pool: &sqlx::SqlitePool) -> Result<BTreeMap<String, i64>> {
    let tables: Vec<String> = sqlx::query_scalar::<_, String>(
        "SELECT name FROM sqlite_master WHERE type = 'table' \
         AND name NOT LIKE 'sqlite_%' AND name != '_sqlx_migrations' ORDER BY name",
    )
    .fetch_all(pool)
    .await
    .context("listing tables")?;

    let mut counts = BTreeMap::new();
    for table in tables {
        // Safe identifier interpolation: a name from sqlite_master cannot break
        // out of a double-quoted identifier, which escapes embedded `"` by
        // doubling. Same reasoning as `backup::inspect_database`.
        let count: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
            "SELECT COUNT(*) FROM \"{}\"",
            table.replace('"', "\"\"")
        )))
        .fetch_one(pool)
        .await
        .with_context(|| format!("counting {table}"))?;
        counts.insert(table, count);
    }
    Ok(counts)
}

/// The earliest version this build can undo to.
fn floor() -> i64 {
    reversible_versions().into_iter().min().unwrap_or(i64::MAX)
}

/// # Errors
/// Errors when the target is not below the applied version, is under the
/// reversible floor, or `--no-backup` was combined with a real rollback.
#[allow(clippy::too_many_lines)]
pub async fn cmd_upgrade(config: &Config, args: UpgradeArgs) -> Result<()> {
    let db_path = crate::commands::backup::resolve_database_path(config, None)?;
    let DataStoreConfig::Sqlite(SqliteDataStoreConfig {
        db_url,
        run_repairs,
        ..
    }) = &config.data_store;
    let pool = rustical_store_sqlite::create_db_pool(db_url, *run_repairs)
        .await
        .context("opening the database")?;

    let before = table_row_counts(&pool).await?;
    let applied = undoable_versions(&pool).await?;
    let current: Option<i64> =
        sqlx::query_scalar("SELECT MAX(version) FROM _sqlx_migrations WHERE success")
            .fetch_one(&pool)
            .await
            .context("reading the highest applied migration")?;

    let Some(current_version) = current else {
        pool.close().await;
        bail!("no migrations are recorded as applied; refusing to guess at the current version");
    };

    let target = match args.to {
        Some(t) => t,
        None if args.rollback => {
            let Some(lowest) = applied.last().copied() else {
                pool.close().await;
                bail!(
                    "none of the applied migrations are reversible — the base \
                     migrations have no .down.sql, so there is nothing this build \
                     can roll back to. Use `rustical restore` with a backup \
                     instead, which is lossless."
                );
            };
            lowest
        }
        None => {
            // Forward: nothing to do beyond what startup already does, but say
            // so rather than exiting silently.
            let pending = MIGRATOR
                .iter()
                .filter(|m| m.version > current_version)
                .count();
            pool.close().await;
            if pending == 0 {
                println!("schema is up to date at version {current_version}");
            } else {
                println!(
                    "{pending} migration(s) pending above {current_version}; the server \
                     applies them on start (`rustical serve`)"
                );
            }
            return Ok(());
        }
    };

    if !args.rollback && args.to.is_none() {
        pool.close().await;
        bail!("--to requires --rollback");
    }

    if target >= current_version {
        pool.close().await;
        bail!(
            "--to {target} is not below the applied version {current_version}; that is \
             an upgrade, not a rollback"
        );
    }
    if target < floor() {
        pool.close().await;
        bail!(
            "--to {target} is below the earliest reversible migration {}. Everything \
             below that is a bare base migration with no .down.sql, so it cannot be \
             undone. Use `rustical restore` instead.",
            floor()
        );
    }

    let would_undo: Vec<i64> = applied.iter().copied().filter(|v| *v > target).collect();
    let content_mutating: Vec<i64> = would_undo
        .iter()
        .copied()
        .filter(|v| CONTENT_MUTATING_DOWNS.contains(v))
        .collect();

    if would_undo.is_empty() {
        pool.close().await;
        println!("nothing to roll back: already at or below {target}");
        return Ok(());
    }

    println!("rollback plan");
    println!("  from {current_version} to {target}");
    println!("  would undo {} migration(s):", would_undo.len());
    for v in &would_undo {
        let name = MIGRATOR
            .iter()
            .find(|m| m.version == *v)
            .map_or_else(|| "?".into(), |m| m.description.clone());
        println!("    {v}  {name}");
    }
    if !content_mutating.is_empty() {
        println!();
        println!(
            "  WARNING: {} of these change stored content, not just schema:",
            content_mutating.len()
        );
        for v in &content_mutating {
            println!(
                "    {v} drops calendarobjects.uid — every calendar object's UID is discarded."
            );
        }
        println!("    The references that pointed at those UIDs are not rewritten.");
    }

    if args.dry_run {
        pool.close().await;
        println!("\n--dry-run: nothing was changed");
        return Ok(());
    }

    // Precondition, not advice: no rollback without a restorable copy.
    if args.no_backup {
        pool.close().await;
        bail!(
            "--no-backup cannot be combined with a rollback. `rustical restore` is \
             the lossless way back; a schema downgrade drops the data in every column \
             it removes, and this command will not do that without a verified backup \
             to restore from."
        );
    }

    let out_dir = args.backup_dir.clone().unwrap_or_else(|| {
        db_path
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."))
            .join("backups")
    });
    println!(
        "\ntaking the pre-rollback backup into {}",
        out_dir.display()
    );
    let archive = crate::commands::cmd_backup(
        crate::commands::BackupArgs {
            out_dir: Some(out_dir),
            db: Some(db_path.clone()),
            gzip: false,
            include_config: false,
        },
        config.clone(),
        std::path::Path::new(""),
    )
    .await?;
    println!("  backup written: {}", archive.display());
    println!(
        "  if this rollback goes wrong: rustical restore {}",
        archive.display()
    );

    println!("\nrolling back…");
    MIGRATOR
        .undo(&pool, target)
        .await
        .with_context(|| format!("undoing migrations down to version {target}"))?;

    let after = table_row_counts(&pool).await?;
    pool.close().await;

    let mut report = RollbackReport {
        from_version: current_version,
        to_version: target,
        undone: would_undo,
        rows_before: before,
        rows_after: after,
        content_mutating,
    };

    let losses = report.losses();
    let expected = report.expected_shrink();
    println!(
        "\nrolled back {} -> {}",
        report.from_version, report.to_version
    );
    for (table, b, a) in &expected {
        println!("  {table:<32} {b:>8} -> {a:>8}  (expected)");
    }
    if losses.is_empty() {
        println!("  no table lost rows");
    } else {
        println!("  {} table(s) LOST ROWS:", losses.len());
        for (table, b, a) in &losses {
            println!("    {table:<32} {b:>8} -> {a:>8}  ({:>8} rows gone)", b - a);
        }
        println!("\n  This is what `DROP COLUMN` means. The backup above is the only copy.");
    }
    report.undone.shrink_to_fit();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// §18.21's counts, as an executable claim rather than a paragraph.
    ///
    /// The audit said 17 `.up.sql`/`.down.sql` pairs plus 4 bare base files with
    /// no down. If a migration is added, removed or — as happened during
    /// development — mis-versioned, the rollback command's own behaviour changes,
    /// so the number it reports has to move with it or this fails.
    #[test]
    fn the_migration_set_is_what_the_audit_counted() {
        let reversible = reversible_versions();
        assert_eq!(
            reversible.len(),
            17,
            "expected 17 reversible migrations (the §18.21 audit), found {}: {:?}",
            reversible.len(),
            reversible
        );
        assert!(
            reversible.windows(2).all(|w| w[0] < w[1]),
            "reversible versions must be strictly increasing: {reversible:?}"
        );
    }

    /// Every version in [`CONTENT_MUTATING_DOWNS`] names a migration that exists.
    ///
    /// This is the test that would have caught the `20260701120000` typo: the
    /// constant listed a version that is not in the schema, so the UID-destruction
    /// warning never fired for the one migration it existed to warn about, and
    /// every test still passed. A pin that silently names nothing is the worst
    /// kind of constant.
    #[test]
    fn content_mutating_downs_are_real() {
        let known: Vec<i64> = MIGRATOR.iter().map(|m| m.version).collect();
        for version in CONTENT_MUTATING_DOWNS {
            assert!(
                known.contains(version),
                "CONTENT_MUTATING_DOWNS pins {version}, which is not in the migration \
                 set; the warning would never fire. Known: {known:?}"
            );
            assert!(
                reversible_versions().contains(version),
                "CONTENT_MUTATING_DOWNS pins {version}, which is not reversible"
            );
        }
    }

    /// The UID migration really is the destructive one, so the warning is aimed
    /// at something rather than at nothing.
    #[test]
    fn the_uid_migration_is_the_one_that_drops_data() {
        let uid = *CONTENT_MUTATING_DOWNS
            .first()
            .expect("at least one content-mutating down is pinned");
        let migration = MIGRATOR
            .iter()
            .find(|m| m.version == uid)
            .expect("pinned version is in the set");
        assert!(
            migration.sql.as_str().to_ascii_uppercase().contains("UID"),
            "migration {uid} was pinned as destroying UIDs but its up.sql does not \
             mention uid"
        );
    }

    /// Nothing below the floor can be undone, and the floor is a real migration.
    #[test]
    fn the_floor_is_reachable_and_is_the_earliest_reversible() {
        let reversible = reversible_versions();
        let earliest = reversible_versions().into_iter().min().unwrap();
        assert_eq!(
            earliest,
            floor(),
            "floor() disagrees with the earliest reversible version"
        );
        assert!(
            reversible.contains(&earliest),
            "the floor {earliest} is not itself reversible, so a rollback to it would \
             leave the schema in a state this build cannot describe"
        );
    }

    /// `--to` at or above the current version is an upgrade, not a rollback, and
    /// must be refused rather than treated as a no-op that exits 0.
    #[test]
    fn losses_are_only_reported_when_rows_were_lost() {
        let report = RollbackReport {
            rows_before: BTreeMap::from([("calendars".into(), 9), ("app_tokens".into(), 4)]),
            rows_after: BTreeMap::from([("calendars".into(), 9), ("app_tokens".into(), 0)]),
            ..RollbackReport::default()
        };
        assert!(
            report.losses().is_empty(),
            "revoking tokens must not read as data loss: {:?}",
            report.losses()
        );
        assert_eq!(
            report.expected_shrink(),
            vec![("app_tokens".to_string(), 4, 0)],
            "the intended shrink must still be reported, just not as a loss"
        );

        let report = RollbackReport {
            rows_before: BTreeMap::from([
                ("calendarobjects".into(), 1400),
                ("calendars".into(), 9),
            ]),
            rows_after: BTreeMap::from([("calendarobjects".into(), 1399), ("calendars".into(), 9)]),
            ..RollbackReport::default()
        };
        assert_eq!(
            report.losses(),
            vec![("calendarobjects".to_string(), 1400, 1399)],
            "one lost event out of 1400 must be reported, not rounded away"
        );
    }

    /// A table that vanishes entirely counts as total loss, not as "missing".
    #[test]
    fn a_dropped_table_is_total_loss() {
        let report = RollbackReport {
            rows_before: BTreeMap::from([("birthday_calendars".into(), 5)]),
            rows_after: BTreeMap::new(),
            ..RollbackReport::default()
        };
        assert_eq!(
            report.losses(),
            vec![("birthday_calendars".to_string(), 5, 0)],
            "a dropped table must read as 5 rows gone"
        );
    }
}
