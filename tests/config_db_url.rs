//! `db_url` → filesystem path: one definition, pinned to sqlx (bug 1).
//!
//! ## Why this file exists at all
//!
//! `db_url` was turned into a path in **two** places, and both were wrong for
//! the `file:` scheme the deployed appliance actually uses:
//!
//! - `resolve_database_path` parsed with sqlx and then refused any filename
//!   containing a `:`, so `file:/usr/local/share/rustical/db.sqlite3` tripped
//!   the guard and `backup`, `restore` and `upgrade` all refused a perfectly
//!   good database;
//! - `Config::sqlite_db_path` made the same `get_filename()` call with **no**
//!   colon check, so it returned `"file:/usr/local/share/rustical/db.sqlite3"`
//!   *as if that were a path* — and a caller would then try to open a file with
//!   a colon in its name, somewhere much less obvious.
//!
//! One loud refusal and one silent wrong answer, for the same string. The
//! appliance therefore had **no working backup path at all**. Both call sites
//! now go through `SqliteDataStoreConfig::database_file`, and this file is what
//! keeps that one definition honest.
//!
//! ## The interesting property: agreement with what SQLite actually opens
//!
//! The value that matters is not "what does sqlx say the filename is" but "what
//! file does the server have open". Those differ: sqlx leaves a `file:` scheme
//! in the filename because it is not a scheme sqlx knows, and SQLite then
//! consumes it, because sqlx hands the filename to `sqlite3_open_v2` with URI
//! handling on. So `database_file` parses with sqlx — inheriting its query
//! splitting and percent-decoding, which a hand-rolled prefix chop would get
//! wrong — and then strips the `file:` that sqlx left behind.
//!
//! `the_path_is_the_file_sqlite_opens` checks that end to end against real
//! SQLite, in a real temporary directory, by opening a database through sqlx
//! and then finding it at the path `database_file` names. That is the assertion
//! that would have caught the original bug; the table tests below would not
//! have.

use rustical::config::{Config, DataStoreConfig, SqliteDataStoreConfig};
use sqlx::sqlite::SqliteConnectOptions as Options;
use sqlx::{Connection, Executor, Row};

fn db_url(url: &str) -> SqliteDataStoreConfig {
    SqliteDataStoreConfig {
        db_url: url.to_owned(),
        run_repairs: true,
        skip_broken: true,
    }
}

fn config_with(url: &str) -> Config {
    let mut config = Config::default_config();
    config.data_store = DataStoreConfig::Sqlite(db_url(url));
    config
}

/// The two spellings the appliance and every test config use, plus the ones that
/// must stay refused. Kept as one table so a case cannot be quietly dropped.
const FILE_URLS: &[(&str, &str)] = &[
    // what the deployed router has, and what broke `backup`
    (
        "file:/usr/local/share/rustical/db.sqlite3",
        "/usr/local/share/rustical/db.sqlite3",
    ),
    // the empty-authority form of the same thing
    (
        "file:///usr/local/share/rustical/db.sqlite3",
        "/usr/local/share/rustical/db.sqlite3",
    ),
    // a relative `file:` URL, which SQLite resolves against the cwd
    ("file:db.sqlite3", "db.sqlite3"),
    // `sqlite:` — sqlx already strips this one
    (
        "sqlite:///var/lib/rustical/db.sqlite3",
        "/var/lib/rustical/db.sqlite3",
    ),
    ("sqlite://db.sqlite3", "db.sqlite3"),
    // a bare path, no scheme at all
    (
        "/var/lib/rustical/db.sqlite3",
        "/var/lib/rustical/db.sqlite3",
    ),
];

#[test]
fn every_file_url_resolves_to_its_path() {
    for (url, want) in FILE_URLS {
        let got = db_url(url)
            .database_file()
            .unwrap_or_else(|reason| panic!("{url} should be a file, got: {reason}"));
        assert_eq!(got.to_string_lossy(), *want, "db_url = {url}");
    }
}

#[test]
fn a_query_string_is_not_part_of_the_path() {
    assert_eq!(
        db_url("file:/srv/db.sqlite3?mode=rwc")
            .database_file()
            .unwrap()
            .to_string_lossy(),
        "/srv/db.sqlite3"
    );
}

#[test]
fn a_percent_escape_is_decoded_like_sqlite_decodes_it() {
    // `a b.db`, not `a%20b.db`. sqlx percent-decodes, and so must we, or the
    // backup names a file that does not exist.
    assert_eq!(
        db_url("file:/srv/a%20b.db")
            .database_file()
            .unwrap()
            .to_string_lossy(),
        "/srv/a b.db"
    );
}

#[test]
fn the_scheme_is_matched_case_insensitively() {
    // URI schemes are case-insensitive. sqlx's own `trim_start_matches` is
    // not, which is one more reason the `file:` strip lives here.
    for url in ["FILE:/srv/db.sqlite3", "File:/srv/db.sqlite3"] {
        assert_eq!(
            db_url(url).database_file().unwrap().to_string_lossy(),
            "/srv/db.sqlite3",
            "db_url = {url}"
        );
    }
}

/// **The assertion the bug needed.** For each URL *shape*, open a real database
/// through sqlx exactly as the server does, then require that the one file the
/// connection created is the one `database_file` names.
///
/// If sqlx and `database_file` ever disagree, this fails — which is the whole
/// point of putting the strip after the parse rather than before it.
#[tokio::test]
async fn the_path_is_the_file_sqlite_opens() {
    // (URL shape, how to point it at a fresh directory)
    let shapes: [fn(&std::path::Path) -> String; 5] = [
        |dir| format!("file:{}/db.sqlite3", dir.display()),
        |dir| format!("file://{}/db.sqlite3", dir.display()),
        |dir| format!("sqlite:{}/db.sqlite3", dir.display()),
        |dir| format!("sqlite:///{}/db.sqlite3", dir.display()),
        |dir| format!("{}/db.sqlite3", dir.display()),
    ];

    for shape in shapes {
        let dir = tempfile::tempdir().unwrap();
        let url = shape(dir.path());
        let expected = db_url(&url)
            .database_file()
            .unwrap_or_else(|reason| panic!("{url} should be a file, got: {reason}"));

        let mut options: Options = url.parse().expect("the URL must parse");
        options = options.create_if_missing(true);
        let mut conn = <sqlx::SqliteConnection as Connection>::connect_with(&options)
            .await
            .unwrap();
        conn.execute("CREATE TABLE marker(x)").await.unwrap();
        conn.execute("INSERT INTO marker VALUES (1)").await.unwrap();
        conn.close().await.unwrap();

        assert!(
            expected.is_file(),
            "database_file said {expected:?} for db_url = {url}, but no such file exists"
        );

        // One URL, one database: nothing else was created alongside it.
        let siblings: Vec<_> = std::fs::read_dir(expected.parent().unwrap())
            .unwrap()
            .flatten()
            .map(|e| e.file_name())
            .collect();
        assert_eq!(
            siblings,
            vec![std::ffi::OsString::from("db.sqlite3")],
            "db_url = {url} created something other than the file database_file named"
        );
    }
}

/// The guard the original `resolve_database_path` was trying to write, still
/// here and now firing for the right reason: another backend's URL is not a
/// file. sqlx parses both of these happily and hands the whole string back,
/// which is exactly how the old colon check earned its keep.
#[test]
fn another_backends_url_is_refused_rather_than_turned_into_a_path() {
    for url in ["postgres://host/db", "mysql://host/db"] {
        let reason = db_url(url)
            .database_file()
            .expect_err("a postgres URL is not a file");
        assert!(
            reason.contains("not a file path"),
            "db_url = {url} was refused, but not for the stated reason: {reason}"
        );
    }
}

#[test]
fn an_in_memory_database_is_refused_by_name_rather_than_by_a_path_sqlx_invented() {
    // sqlx has no public getter for `in_memory` and reports one of these as
    // `file:sqlx-in-memory-N`. Stripping that prefix "successfully" would hand
    // back `sqlx-in-memory-0` — a relative path that does not exist, named after
    // a sqlx implementation detail. Refuse instead.
    for url in [
        ":memory:",
        "sqlite::memory:",
        "sqlite://:memory:",
        "sqlite://?mode=memory",
    ] {
        let reason = db_url(url)
            .database_file()
            .expect_err("an in-memory database is not a file");
        assert!(
            reason.contains("in-memory"),
            "db_url = {url} was refused, but not for the stated reason: {reason}"
        );
    }
}

#[test]
fn a_file_url_with_a_host_is_refused_because_sqlite_rejects_it() {
    // `file://host/path` is "invalid uri authority" at `sqlite3_open_v2`. The
    // tempting wrong answer is to chop `//` and return `host/path`, a relative
    // path that looks fine and is not the file the server has open.
    for url in ["file://localhost/srv/db.sqlite3", "file://host/db.sqlite3"] {
        let reason = db_url(url)
            .database_file()
            .expect_err("a file:// host is not a usable path");
        assert!(
            reason.contains("file:// host"),
            "db_url = {url} was refused, but not for the stated reason: {reason}"
        );
    }
}

/// Pins the in-memory mirror to sqlx rather than to a reading of its source.
///
/// `names_an_in_memory_database` re-implements two rules from
/// `sqlx_sqlite::options::parse` (`:memory:`, `mode=memory`) because sqlx
/// exposes no getter for `in_memory`. A mirror can drift, and it would drift
/// silently — a database mistaken for a file is a backup of nothing.
///
/// So the oracle is behavioural: open the URL and ask SQLite, via
/// `PRAGMA database_list`, whether the connection has a file behind it.
///
/// The property asserted is deliberately **one-directional**, because the
/// oracle is coarser than the mirror. `database_list` reports an empty `file`
/// column for *both* a purely in-memory database and an unnamed temporary one —
/// `sqlite://?mode=rwc` has an empty database part, so SQLite hands it a private
/// temp database and reports no file. (An earlier version of this test tried to
/// use sqlx's synthetic `file:sqlx-in-memory-N` filename as the oracle and
/// failed: `sqlite://?mode=memory` is in-memory with an *empty* filename.) What
/// is sound, and what actually matters, is:
///
/// 1. a URL SQLite gives a file to is never refused as in-memory — this is the
///    one that would send `backup` looking at a path that is not the database;
/// 2. a URL SQLite gives no file to never yields a path — this is the one that
///    would send `backup` after a file sqlx invented.
///
/// Which of the several refusal reasons is attached to (2) is a message, not a
/// safety property, and `an_in_memory_database_is_refused_by_name…` covers it.
#[tokio::test]
async fn the_in_memory_rules_agree_with_sqlx() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("db.sqlite3").display().to_string();

    let cases: Vec<String> = vec![
        ":memory:".to_owned(),
        "sqlite::memory:".to_owned(),
        "sqlite://:memory:".to_owned(),
        "sqlite://?mode=memory".to_owned(),
        // an empty database part: an unnamed temporary database, no file either
        "sqlite://?mode=rwc".to_owned(),
        // and the negatives, which do name files
        format!("sqlite://{file}"),
        format!("sqlite:{file}"),
        format!("file:{file}"),
        format!("file://{file}"),
        file,
    ];

    for url in cases {
        let options: Options = url.parse().expect("must parse");
        let mut conn =
            <sqlx::SqliteConnection as Connection>::connect_with(&options.create_if_missing(true))
                .await
                .unwrap_or_else(|e| panic!("db_url = {url}: {e}"));
        let rows = sqlx::query("PRAGMA database_list")
            .fetch_all(&mut conn)
            .await
            .unwrap();
        let sqlite_has_a_file = rows.iter().any(|row| {
            row.try_get::<Option<String>, _>("file")
                .expect("database_list has a file column")
                .is_some_and(|file| !file.is_empty())
        });

        let resolved = db_url(&url).database_file();
        let called_in_memory = resolved
            .as_ref()
            .is_err_and(|reason| reason.contains("in-memory"));

        // (1) never refuse a database that has a file…
        assert!(
            !(sqlite_has_a_file && called_in_memory),
            "db_url = {url}: SQLite has a file, but database_file called it in-memory"
        );
        // (2) …and never invent a path for one that does not.
        assert_eq!(
            resolved.is_ok(),
            sqlite_has_a_file,
            "db_url = {url}: SQLite has a file={sqlite_has_a_file}, \
             database_file gave a path={}",
            resolved.is_ok()
        );
    }
}

#[test]
fn a_url_sqlx_cannot_parse_is_refused() {
    // `mode=bogus` — sqlx rejects an unknown mode, so we never reach the strip.
    let reason = db_url("file:/srv/db.sqlite3?mode=bogus")
        .database_file()
        .expect_err("an unknown mode is not usable");
    assert!(
        reason.contains("not a usable SQLite URL"),
        "refused, but not for the stated reason: {reason}"
    );
}

/// The two former copies of this question, now one. `sqlite_db_path` is what the
/// setup wizard asks for a default data directory and what the setup tests
/// compare against the database the wizard opened; it used to be the copy that
/// failed silently.
#[test]
fn config_sqlite_db_path_agrees_with_the_single_definition() {
    for (url, want) in FILE_URLS {
        assert_eq!(
            config_with(url)
                .sqlite_db_path()
                .map(|p| p.to_string_lossy().into_owned()),
            Some((*want).to_owned()),
            "db_url = {url}"
        );
    }
    for url in ["postgres://host/db", ":memory:"] {
        assert_eq!(
            config_with(url).sqlite_db_path(),
            None,
            "db_url = {url} names no file"
        );
    }
}

/// What the deployed appliance has, spelled exactly as `render-router-config.sh`
/// writes it. If this one changes shape the guard test above is not enough —
/// this is the config that had no working backup path.
#[test]
fn the_deployed_appliances_db_url_has_a_working_backup_path() {
    let config = config_with("file:/usr/local/share/rustical/db.sqlite3");
    let path = config
        .sqlite_db_path()
        .expect("the deployed db_url must resolve to a file");
    assert_eq!(
        path,
        std::path::Path::new("/usr/local/share/rustical/db.sqlite3")
    );
    assert!(
        !path.to_string_lossy().contains(':'),
        "a path with a colon in it is what the setup wizard would try to open"
    );
}
