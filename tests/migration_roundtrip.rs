//! The `.down.sql` audit, as an executable gate — `PLAN_DEPLOYMENTS.md` §13,
//! §14, row 42.
//!
//! ## Why a test and not a document
//!
//! §14's mitigation for "downgrade past a migration is impossible" read *"audit
//! all 19 pairs in W0"*, and a one-time audit is a snapshot that rots on the
//! next migration. So the audit is a **gate**: it applies every migration, rolls
//! every one back, applies them all again, and asserts the schema came back.
//!
//! That is what a rollback looks like in production — `upgrade --rollback` swaps
//! the binary, the migrations are reverted, the old binary serves, and a later
//! upgrade re-applies them. Nobody has built that command, so **nothing in the
//! product runs these files**; they are documentation until an item makes them
//! executable, and this test is what says whether they would work if one did.
//!
//! ## What the audit found, and what it corrected in the plan
//!
//! - The plan said "19 `.up.sql`, 19 `.down.sql`". The truth is **38 files**:
//!   **17** pairs, **4** bare upstream base migrations with **no down at all**,
//!   and 21 files applied going up. An audit that counted 19 pairs would have
//!   looked complete while the base schema was unreversible.
//! - All 17 pairs are **individually** reversible and a **full** rollback plus
//!   re-upgrade restores the schema. The plan's risk entry was more pessimistic
//!   than reality for the pairs, and more accurate than it knew about the base.
//! - A rollback is **not lossless**, and thirteen of the downs drop a table or a
//!   column. No test pretends otherwise.
//! - **A rollback followed by a re-upgrade silently rewrites every calendar
//!   object's UID** — see
//!   [`a_rollback_then_re_upgrade_rewrites_every_uid`].
//! - A down/up cycle **moves a column** within its table's stored definition.
//!   Cosmetic, and proven so rather than assumed.

use std::collections::BTreeMap;
use std::path::PathBuf;

use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::{Row, SqlitePool};

/// The migration directory, found from this package's manifest.
///
/// A path and not a `sqlx::migrate!` literal, because the *down* files cannot be
/// fed to the macro — only the ups are compiled in, and reading the downs as
/// text is the whole point of the exercise.
fn migrations_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("crates/store_sqlite/migrations")
}

/// Every `.sql` file, in the order `sqlx` applies them (by filename).
fn migrations() -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = std::fs::read_dir(migrations_dir())
        .expect("the migrations directory")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|p| p.extension().is_some_and(|ext| ext == "sql"))
        .collect();
    out.sort();
    out
}

/// Everything applied going **up**: the `.up.sql` files and the bare upstream
/// ones. Only `.down.sql` is excluded.
///
/// One predicate with a single negation, rather than two globs: an earlier
/// draft of this audit used `*.sql` and swept the downs in with the ups, which
/// produced a confident "this down is broken" finding that was entirely the
/// script's fault. This comment is the guard against rediscovering that.
fn ups() -> Vec<PathBuf> {
    migrations()
        .into_iter()
        .filter(|p| !p.to_string_lossy().ends_with(".down.sql"))
        .collect()
}

/// The `.down.sql` files, **newest first** — the order a rollback runs them in.
fn downs_newest_first() -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = migrations()
        .into_iter()
        .filter(|p| p.to_string_lossy().ends_with(".down.sql"))
        .collect();
    out.sort();
    out.reverse();
    out
}

/// The bare base migrations: applied going up, never reverted, and so not
/// re-applied on the way back up either.
fn bare_base_migrations() -> Vec<PathBuf> {
    ups()
        .into_iter()
        .filter(|p| !p.to_string_lossy().ends_with(".up.sql"))
        .collect()
}

async fn pool(name: &str) -> SqlitePool {
    let dir = tempfile::tempdir().expect("a temp dir");
    let path = dir.path().join(name);
    // The pool outlives the temp dir, so the directory is deliberately leaked: a
    // test that deletes the database out from under an open pool fails on some
    // platforms only. One leaked temp dir per test is cheaper than that.
    let options = SqliteConnectOptions::new()
        .filename(&path)
        .create_if_missing(true);
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .expect("a database");
    std::mem::forget(dir);
    pool
}

/// Apply one `.sql` file.
///
/// `raw_sql` rather than a hand-rolled `;` split: a migration may contain a
/// semicolon inside a string literal or a trigger body, and splitting on `;`
/// would corrupt it.
async fn apply(pool: &SqlitePool, path: &PathBuf) {
    let sql = std::fs::read_to_string(path).expect("a readable migration");
    // `AssertSqlSafe`: the SQL comes off disk, so it is dynamic by construction.
    // It is a *migration file in this repository* — the same input
    // `sqlx::migrate!` compiles in, on the boot path — and reading it is the
    // entire purpose of the file. Refusing to run it would make the audit
    // untestable while adding nothing.
    sqlx::raw_sql(sqlx::AssertSqlSafe(sql))
        .execute(pool)
        .await
        .unwrap_or_else(|e| panic!("{}: {e}", path.display()));
}

/// The schema, compared **structurally** rather than textually.
///
/// A table's `sqlite_master.sql` text is not used, because SQLite's
/// `ALTER TABLE ... ADD COLUMN` *appends* to that text and `DROP COLUMN` removes
/// the entry, so a down/up cycle can leave a column in a different position — see
/// [`a_down_up_cycle_moves_a_column_without_moving_its_meaning`]. Comparing the
/// text would fail on a difference no caller can observe.
///
/// What *is* compared: every table and index by name, every column by name,
/// type, nullability, default and primary-key flag, and every index's exact
/// definition (an index's order is semantic; a table's column order is not).
async fn schema(pool: &SqlitePool) -> BTreeMap<String, String> {
    let objects = sqlx::query(
        "SELECT type, name, COALESCE(sql, '') AS sql FROM sqlite_master \
         WHERE name NOT LIKE 'sqlite_%' AND name != 'sqlx_migrations' \
         ORDER BY type, name",
    )
    .fetch_all(pool)
    .await
    .expect("a schema read");

    let mut out: BTreeMap<String, String> = BTreeMap::new();
    for object in objects {
        let kind: String = object.get("type");
        let name: String = object.get("name");
        if kind == "index" {
            out.insert(format!("index:{name}"), object.get::<String, _>("sql"));
        } else if kind == "table" {
            // `PRAGMA` takes no bound parameters, and `name` here comes from
            // this database's own `sqlite_master` — not from a request — so
            // there is nothing to inject. The assertion is the point: a schema
            // name that could contain a quote would fail loudly below rather
            // than silently query something else.
            let columns = sqlx::query(sqlx::AssertSqlSafe(format!(
                "PRAGMA table_info(\"{name}\")"
            )))
            .fetch_all(pool)
            .await
            .expect("a column read");
            let mut described: Vec<String> = columns
                .iter()
                .map(|c| {
                    format!(
                        "{}:{}:{}:{}:{}",
                        c.get::<String, _>("name"),
                        c.get::<String, _>("type"),
                        c.get::<i64, _>("notnull"),
                        c.get::<Option<String>, _>("dflt_value").unwrap_or_default(),
                        c.get::<i64, _>("pk"),
                    )
                })
                .collect();
            described.sort();
            out.insert(format!("table:{name}"), described.join("; "));
        }
    }
    out
}

/// Assert two schemas are equal, naming only what differs.
///
/// A `BTreeMap` of table definitions is megabytes, so an `assert_eq!` prints both
/// in full and leaves the reader to find the one line that matters. Every failure
/// during this audit was a wall of SQL, which is how one wrong assertion survived
/// as long as it did.
fn assert_same_schema(
    head: &BTreeMap<String, String>,
    other: &BTreeMap<String, String>,
    what: &str,
) {
    let changed: Vec<&String> = head
        .keys()
        .filter(|k| other.get(*k) != head.get(*k))
        .collect();
    let unexpected: Vec<&String> = other.keys().filter(|k| !head.contains_key(*k)).collect();
    assert!(
        changed.is_empty() && unexpected.is_empty(),
        "{what}\n  missing or changed: {changed:?}\n  unexpectedly present: {unexpected:?}"
    );
}

// ────────────────────────────────── the audit ───────────────────────────────

/// A full rollback followed by a re-upgrade restores the schema.
///
/// This is the claim §14's risk entry said could not be made. For the 17 pairs
/// it holds.
#[tokio::test]
async fn a_full_rollback_and_re_upgrade_restores_the_schema() {
    let pool = pool("roundtrip.sqlite3").await;

    for path in ups() {
        apply(&pool, &path).await;
    }
    let head = schema(&pool).await;
    assert!(
        head.len() > 20,
        "the ups should have built a real schema, got {} objects",
        head.len()
    );

    for path in downs_newest_first() {
        apply(&pool, &path).await;
    }
    let rolled_back = schema(&pool).await;
    assert!(
        rolled_back.len() < head.len(),
        "a full rollback should have removed something: {} -> {}",
        head.len(),
        rolled_back.len()
    );

    // Forward again, skipping the bare base migrations: they were never
    // reverted, so re-applying them is the harness being naive rather than the
    // tree being wrong. `sqlx` skips them for exactly this reason — it has them
    // recorded as applied.
    for path in ups() {
        if path.to_string_lossy().ends_with(".up.sql") {
            apply(&pool, &path).await;
        }
    }

    assert_same_schema(
        &head,
        &schema(&pool).await,
        "a full rollback followed by a re-upgrade did not restore the schema:",
    );
}

/// Every `down.sql` **executes cleanly**, and every one is reversible.
///
/// This started as "up → down → up returns to HEAD" and that was wrong in a way
/// worth recording, because the wrong version looked like it was finding bugs.
/// A `down.sql` is often destructive of work a *later* migration built on: rolling
/// back `20260907120000_invites` drops the `invites` table, and re-applying only
/// that up recreates the table without the three columns `20260912` and
/// `20260914` added — so the schema legitimately does not come back. The
/// per-pair property that is actually true, and the one a real rollback depends
/// on, is:
///
///  1. **the down runs without error** — a statement that fails aborts the
///     rollback mid-way, leaving a half-reverted database, which is the failure
///     mode that matters; and
///  2. **the down does not grow the schema**, which would mean it is not a
///     reversal at all.
///
/// The stronger claim — that a full rollback and re-upgrade restores everything
/// — is [`a_full_rollback_and_re_upgrade_restores_the_schema`], and it is
/// checked there, where it is true.
#[tokio::test]
async fn every_down_migration_executes_and_only_removes() {
    for (i, down) in downs_newest_first().iter().enumerate() {
        let pool = pool(&format!("down{i}.sqlite3")).await;
        for path in ups() {
            apply(&pool, &path).await;
        }
        let head = schema(&pool).await;

        // (1) and (2). A failure here is the panic inside `apply`, naming the
        // file — which is the finding, not an error in the harness.
        apply(&pool, down).await;
        let rolled_back = schema(&pool).await;
        assert!(
            rolled_back.len() <= head.len(),
            "{}: the down grew the schema from {} to {} objects, which is not a reversal",
            down.file_name().expect("a name").to_string_lossy(),
            head.len(),
            rolled_back.len()
        );
    }
}

/// The single seeded object's UID.
async fn uid_of(pool: &SqlitePool) -> String {
    sqlx::query("SELECT \"uid\" FROM calendarobjects LIMIT 1")
        .fetch_one(pool)
        .await
        .expect("a uid")
        .get::<String, _>(0)
}

/// The one rollback consequence that is **silent** rather than an expected loss.
///
/// Rolling back `add_calendar_uid` rebuilds `calendarobjects` without the `uid`
/// column, and re-applying the up sets `uid = id`. So an operator who rolls back
/// and later upgrades forward finds every calendar object's global UID silently
/// changed — and for CalDAV a UID is the object's identity, so a client holding
/// the old one treats the re-created object as new.
///
/// This pins the behaviour rather than endorsing it. The day someone writes a
/// `down.sql` that preserves `uid`, this fails and the plan's rollback section
/// needs the same care this audit got.
#[tokio::test]
async fn a_rollback_then_re_upgrade_rewrites_every_uid() {
    let pool = pool("uid.sqlite3").await;
    for path in ups() {
        apply(&pool, &path).await;
    }
    // `principals` has no email column in this fork: id, displayname,
    // principal_type, password_hash, needs_password_change.
    sqlx::raw_sql(
        "INSERT INTO principals (id, displayname, principal_type) VALUES ('p1','A','individual');
         INSERT INTO calendars (principal, id, displayname, push_topic, comp_event, comp_todo, comp_journal)
           VALUES ('p1','c1','Cal','t1',1,1,1);
         INSERT INTO calendarobjects (principal, cal_id, id, \"uid\", ics, object_type)
           VALUES ('p1','c1','o1.ics','a-real-uid','BEGIN:VCALENDAR',0);",
    )
    .execute(&pool)
    .await
    .expect("a seeded object");

    assert_eq!(uid_of(&pool).await, "a-real-uid");

    for path in downs_newest_first() {
        apply(&pool, &path).await;
    }
    for path in ups() {
        if path.to_string_lossy().ends_with(".up.sql") {
            apply(&pool, &path).await;
        }
    }

    assert_eq!(
        uid_of(&pool).await,
        "o1.ics",
        "the up migration derives uid from id, so a rollback/re-upgrade cycle changes it. \
         If this now fails, a down that preserves uid has been written and the plan's \
         rollback section needs updating."
    );
}

/// A down/up cycle moves a column within its table's stored definition.
///
/// SQLite's `ALTER TABLE ... ADD COLUMN` appends to the stored `CREATE TABLE`
/// text, so `invites.target_group` — added by `20260912120000`, after
/// `collection_id` and `kind` had themselves been added by `20260914120000` —
/// comes back at the end rather than in the middle. The table is identical in
/// every way that matters: same columns, types, constraints, and row layout
/// (SQLite stores rows by `rowid`, not by column position).
///
/// Unobservable here, and **checked rather than assumed**: the tree's only
/// `SELECT *` sites are on `calendars` — which round-trips exactly, because its
/// dropped column was the last one — and inside a
/// `FROM (SELECT * FROM principals …)` sub-select, and `sqlx::query_as!` binds by
/// column *name* regardless of position.
#[tokio::test]
async fn a_down_up_cycle_moves_a_column_without_moving_its_meaning() {
    let pool = pool("colorder.sqlite3").await;
    for path in ups() {
        apply(&pool, &path).await;
    }
    let head = schema(&pool).await;

    let pair = migrations_dir().join("20260912120000_invites_target_group");
    apply(
        &pool,
        &PathBuf::from(format!("{}.down.sql", pair.display())),
    )
    .await;
    apply(&pool, &PathBuf::from(format!("{}.up.sql", pair.display()))).await;

    // Structurally identical, which is what `schema()` compares.
    assert_same_schema(
        &head,
        &schema(&pool).await,
        "invites: a down/up cycle changed the table's shape:",
    );
}

/// The counts, asserted so the plan's numbers and the directory cannot drift.
///
/// §14 said "audit all 19 pairs". There are **38** files: **17** pairs, **4** bare
/// base migrations with no down at all, and **21** files applied going up.
#[test]
fn the_migration_counts_are_what_the_plan_says() {
    let files_total = migrations().len();
    let pairs = downs_newest_first().len();
    let applied_ups = ups().len();
    let bare = bare_base_migrations().len();

    assert_eq!(
        files_total, 38,
        "migration file count changed; update the plan"
    );
    assert_eq!(pairs, 17, "pair count changed; update the plan");
    assert_eq!(applied_ups, 21, "applied-up count changed; update the plan");
    assert_eq!(
        bare, 4,
        "base migrations without a down changed; update the plan"
    );
    assert_eq!(applied_ups, pairs + bare, "arithmetic");

    let bare_names: Vec<String> = bare_base_migrations()
        .iter()
        .map(|p| {
            p.file_name()
                .expect("a name")
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    assert_eq!(
        bare_names,
        vec![
            "20250426122310_principals.sql",
            "20250426122338_calendars.sql",
            "20250426122343_addressbooks.sql",
            "20250426122350_davpush.sql",
        ],
        "the set of base migrations with no .down.sql changed; update the plan"
    );
}
