//! `rustical backup` / `rustical restore` round-trip tests
//! (PLAN_DEPLOYMENTS.md §8.4, verification-matrix row 43).
//!
//! Row 43 is the §14 row-18 restore drill, promoted to a per-release CI job:
//! a backup taken here restores into a scratch database on its own machine,
//! opens, and shows the expected row counts. The negative cases matter as much
//! as the happy one — a backup tool that restores a corrupt archive quietly
//! is worse than no backup tool — so tamper detection, the running-server
//! guard, tar-slip rejection and the refusal to clobber a database are all
//! asserted here rather than assumed.
use rustical::config::{Config, DataStoreConfig, HttpConfig, SqliteDataStoreConfig, TenancyConfig};
use rustical::{
    ArchiveEntry, BackupArgs, BackupManifest, CONFIG_ENTRY, DB_ENTRY, MANIFEST_ENTRY,
    MANIFEST_FORMAT, RestoreArgs, cmd_backup, cmd_restore,
};
use rustical_store::Secret;
use rustical_store::auth::{AuthenticationProvider, Principal, PrincipalType};
use rustical_store::{Calendar, CalendarMetadata, CalendarReadStore, CalendarWriteStore};
use rustical_store_sqlite::{SqliteCalendarStore, SqlitePrincipalStore, create_db_pool};
use std::path::{Path, PathBuf};

fn test_config(db_path: &Path) -> Config {
    Config {
        tenancy: TenancyConfig::default(),
        data_store: DataStoreConfig::Sqlite(SqliteDataStoreConfig {
            db_url: db_path.to_string_lossy().into_owned(),
            run_repairs: false,
            skip_broken: false,
        }),
        http: Default::default(),
        frontend: Default::default(),
        oidc: None,
        tracing: Default::default(),
        dav_push: Default::default(),
        nextcloud_login: Default::default(),
        caldav: Default::default(),
        scheduling: Default::default(),
        subscriptions: Default::default(),
        registration: Default::default(),
        maintenance: Default::default(),
    }
}

fn backup_args(out_dir: &Path, db: &Path, gzip: bool) -> BackupArgs {
    BackupArgs {
        out_dir: Some(out_dir.to_path_buf()),
        db: Some(db.to_path_buf()),
        gzip,
        include_config: false,
    }
}

fn restore_args(archive: &Path, db: &Path) -> RestoreArgs {
    RestoreArgs {
        archive: archive.to_path_buf(),
        db: Some(db.to_path_buf()),
        force: true,
        dry_run: false,
        config_out: None,
        ignore_row_count_changes: false,
    }
}

const NO_CONFIG: &str = "/nonexistent/config.toml";

/// Two principals and two calendars, so a restore that "works" but restores
/// an empty or the wrong database shows up in the assertions below.
async fn seed(db_path: &Path) {
    let pool = create_db_pool(&db_path.to_string_lossy(), true)
        .await
        .unwrap();
    let principal_store = SqlitePrincipalStore::new(pool.clone());
    let (send_cal, _recv) = tokio::sync::mpsc::channel(1);
    let cal_store = SqliteCalendarStore::new(pool.clone(), send_cal, false);

    for id in ["alice@example.com", "bob@example.com"] {
        principal_store
            .insert_principal(
                Principal {
                    id: id.to_owned(),
                    displayname: Some(id.to_owned()),
                    memberships: vec![],
                    password: Some(Secret("$argon2id$v=19$m=1,t=1,p=1$c2FsdA$aaaa".to_owned())),
                    principal_type: PrincipalType::Individual,
                    needs_password_change: false,
                    privileges: Default::default(),
                },
                false,
            )
            .await
            .unwrap();
    }
    for (principal, id) in [
        ("alice@example.com", "personal"),
        ("bob@example.com", "work"),
    ] {
        cal_store
            .insert_calendar(Calendar {
                id: id.to_owned(),
                principal: principal.to_owned(),
                meta: CalendarMetadata {
                    displayname: Some(id.to_owned()),
                    order: 0,
                    description: None,
                    color: None,
                },
                timezone_id: None,
                deleted_at: None,
                synctoken: 0,
                subscription_url: None,
                push_topic: format!("backup-test-{id}"),
                components: vec![rustical_ical::CalendarObjectType::Event],
            })
            .await
            .unwrap();
    }
    pool.close().await;
}

async fn principal_ids(db_path: &Path) -> Vec<String> {
    let pool = create_db_pool(&db_path.to_string_lossy(), false)
        .await
        .unwrap();
    let store = SqlitePrincipalStore::new(pool.clone());
    let mut ids: Vec<String> = store
        .get_principals()
        .await
        .unwrap()
        .into_iter()
        .map(|principal| principal.id)
        .collect();
    ids.sort();
    pool.close().await;
    ids
}

async fn calendar_ids(db_path: &Path, principal: &str) -> Vec<String> {
    let pool = create_db_pool(&db_path.to_string_lossy(), false)
        .await
        .unwrap();
    let (send_cal, _recv) = tokio::sync::mpsc::channel(1);
    let store = SqliteCalendarStore::new(pool.clone(), send_cal, false);
    let mut ids: Vec<String> = store
        .get_calendars(principal)
        .await
        .unwrap()
        .into_iter()
        .map(|calendar| calendar.id)
        .collect();
    ids.sort();
    pool.close().await;
    ids
}

async fn backup(db_path: &Path, out_dir: &Path, gzip: bool) -> PathBuf {
    cmd_backup(
        backup_args(out_dir, db_path, gzip),
        test_config(db_path),
        Path::new(NO_CONFIG),
    )
    .await
    .unwrap()
}

// --- the drill ------------------------------------------------------------

/// Row 43: back up, take the database away, restore into a scratch path (a
/// different machine as far as this can tell), check the data came back.
#[tokio::test]
async fn test_backup_restore_drill() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("db.sqlite3");
    let out_dir = dir.path().join("backups");
    seed(&db_path).await;

    let archive = backup(&db_path, &out_dir, false).await;
    assert!(archive.is_file(), "{}", archive.display());
    assert!(archive.starts_with(&out_dir));
    let archive_name = archive.file_name().unwrap().to_string_lossy().into_owned();
    assert!(
        archive_name.starts_with("omnical-backup-") && archive_name.ends_with(".tar"),
        "{archive_name}"
    );

    // Take the database away entirely, the way a lost disk would.
    std::fs::remove_file(&db_path).unwrap();
    assert!(!db_path.exists());

    cmd_restore(restore_args(&archive, &db_path), test_config(&db_path))
        .await
        .unwrap();

    assert_eq!(
        principal_ids(&db_path).await,
        vec!["alice@example.com", "bob@example.com"]
    );
    assert_eq!(
        calendar_ids(&db_path, "alice@example.com").await,
        ["personal"]
    );
    assert_eq!(calendar_ids(&db_path, "bob@example.com").await, ["work"]);
}

/// The archive describes itself, and the manifest is what `restore` checks
/// the restored database against.
#[tokio::test]
async fn test_archive_manifest_describes_the_database() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("db.sqlite3");
    let out_dir = dir.path().join("backups");
    seed(&db_path).await;
    let archive = backup(&db_path, &out_dir, false).await;

    let manifest = read_manifest(&archive);
    assert_eq!(manifest.format, MANIFEST_FORMAT);
    assert_eq!(manifest.integrity_check, "ok");
    assert_eq!(manifest.database.name, DB_ENTRY);
    assert_eq!(manifest.database.sha256.len(), 64);
    assert!(manifest.database.size > 0);
    assert_eq!(manifest.row_counts.get("principals"), Some(&2));
    assert_eq!(manifest.row_counts.get("calendars"), Some(&2));
    assert!(
        manifest.config.is_none(),
        "--include-config was not given, so the manifest must not claim a config"
    );

    // A dry run verifies the archive and writes nothing at all.
    std::fs::remove_file(&db_path).unwrap();
    let mut args = restore_args(&archive, &db_path);
    args.dry_run = true;
    cmd_restore(args, test_config(&db_path)).await.unwrap();
    assert!(!db_path.exists(), "a dry run must not create the database");
}

// --- transport ------------------------------------------------------------

/// A gzip archive restores exactly like a plain one, and the reader decides
/// by magic bytes so a mislabelled file still works.
#[tokio::test]
async fn test_gzip_archive_round_trips() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("db.sqlite3");
    let out_dir = dir.path().join("backups");
    seed(&db_path).await;

    let archive = backup(&db_path, &out_dir, true).await;
    assert!(archive.to_string_lossy().ends_with(".tar.gz"));
    let bytes = std::fs::read(&archive).unwrap();
    assert_eq!(&bytes[..2], &[0x1f, 0x8b], "not a gzip stream");

    // Rename it so the extension no longer says gzip.
    let mislabelled = dir.path().join("mislabelled.tar");
    std::fs::rename(&archive, &mislabelled).unwrap();

    std::fs::remove_file(&db_path).unwrap();
    cmd_restore(restore_args(&mislabelled, &db_path), test_config(&db_path))
        .await
        .unwrap();
    assert_eq!(
        principal_ids(&db_path).await,
        vec!["alice@example.com", "bob@example.com"]
    );
}

// --- refusing to restore something bad ------------------------------------

/// A corrupt archive is refused, and refused *before* the target is touched —
/// that is the entire point of the manifest.
#[tokio::test]
async fn test_restore_rejects_a_tampered_archive() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("db.sqlite3");
    let out_dir = dir.path().join("backups");
    seed(&db_path).await;
    let before = principal_ids(&db_path).await;
    let archive = backup(&db_path, &out_dir, false).await;

    // Rebuild the tar with one byte of the database flipped, leaving the
    // 100-byte SQLite header intact so the file still looks like a database.
    let tampered = dir.path().join("tampered.tar");
    let mut entries = entries_of(&archive);
    let database = entry_mut(&mut entries, DB_ENTRY);
    let offset = database.len() / 2;
    database[offset] ^= 0xff;
    write_tar(&tampered, &entries);

    let error = cmd_restore(restore_args(&tampered, &db_path), test_config(&db_path))
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("sha256 mismatch"), "{error}");
    assert_eq!(
        principal_ids(&db_path).await,
        before,
        "a rejected archive must leave the live database alone"
    );
    assert!(
        !sibling_names(dir.path())
            .iter()
            .any(|name| name.contains("pre-restore") || name.contains(".restore-")),
        "a rejected archive must not even leave a safety copy behind: {:?}",
        sibling_names(dir.path())
    );
}

/// A database entry replaced with a different file fails on size or digest —
/// it must never be accepted.
#[tokio::test]
async fn test_restore_rejects_a_replaced_database_entry() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("db.sqlite3");
    let out_dir = dir.path().join("backups");
    seed(&db_path).await;
    let archive = backup(&db_path, &out_dir, false).await;

    // A different database, same entry name.
    let other = dir.path().join("other.sqlite3");
    let pool = create_db_pool(&other.to_string_lossy(), true)
        .await
        .unwrap();
    let principal_store = SqlitePrincipalStore::new(pool.clone());
    principal_store
        .insert_principal(
            Principal {
                id: "mallory@example.com".to_owned(),
                displayname: None,
                memberships: vec![],
                password: None,
                principal_type: PrincipalType::Individual,
                needs_password_change: false,
                privileges: Default::default(),
            },
            false,
        )
        .await
        .unwrap();
    pool.close().await;

    let mut entries = entries_of(&archive);
    *entry_mut(&mut entries, DB_ENTRY) = std::fs::read(&other).unwrap();
    let swapped = dir.path().join("swapped.tar");
    write_tar(&swapped, &entries);

    let error = cmd_restore(restore_args(&swapped, &db_path), test_config(&db_path))
        .await
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("sha256 mismatch") || error.contains("extracted"),
        "{error}"
    );
    assert_eq!(
        principal_ids(&db_path).await,
        vec!["alice@example.com", "bob@example.com"]
    );
}

/// An entry this build does not know about is refused rather than extracted.
#[tokio::test]
async fn test_restore_rejects_an_unexpected_entry() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("db.sqlite3");
    seed(&db_path).await;
    let before = principal_ids(&db_path).await;
    let archive = backup(&db_path, &dir.path().join("backups"), false).await;

    let mut entries = entries_of(&archive);
    entries.push(Entry {
        name: "surprise.txt".to_owned(),
        bytes: b"payload".to_vec(),
    });
    let extra = dir.path().join("extra.tar");
    write_tar(&extra, &entries);

    let error = cmd_restore(restore_args(&extra, &db_path), test_config(&db_path))
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("unexpected entry"), "{error}");
    assert_eq!(principal_ids(&db_path).await, before);
}

/// A tar-slip attempt. Two flavours, because they are stopped by two
/// different layers: an absolute name is caught by this command's own guard,
/// while a `..` name is refused by the tar reader before the guard ever sees
/// it. Either way nothing is extracted and the database is untouched.
///
/// The headers are built byte by byte because `tar::Header::set_path` refuses
/// to write these names at all.
#[tokio::test]
async fn test_restore_rejects_path_traversal_entries() {
    for hostile in ["/etc/passwd", "../../etc/passwd"] {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("db.sqlite3");
        seed(&db_path).await;
        let before = principal_ids(&db_path).await;
        let archive = backup(&db_path, &dir.path().join("backups"), false).await;

        let evil = dir.path().join("evil.tar");
        std::fs::copy(&archive, &evil).unwrap();
        append_raw_entry(&evil, hostile, b"root:x:0:0");

        let error = cmd_restore(restore_args(&evil, &db_path), test_config(&db_path))
            .await
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("unexpected path")
                || error.contains("reading an archive entry")
                || error.contains("passwd"),
            "hostile name {hostile} produced: {error}"
        );
        assert_eq!(principal_ids(&db_path).await, before);
        assert!(!Path::new("/tmp/etc/passwd").exists());
    }
}

/// A manifest from a future format is refused rather than guessed at.
#[tokio::test]
async fn test_restore_rejects_an_unknown_manifest_format() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("db.sqlite3");
    seed(&db_path).await;
    let archive = backup(&db_path, &dir.path().join("backups"), false).await;

    let mut entries = entries_of(&archive);
    let manifest_index = entries
        .iter()
        .position(|entry| entry.name == MANIFEST_ENTRY)
        .unwrap();
    let mut manifest: BackupManifest = serde_json::from_slice(&entries[manifest_index].bytes)
        .expect("the manifest this build wrote must parse");
    manifest.format = MANIFEST_FORMAT + 7;
    entries[manifest_index].bytes = serde_json::to_vec_pretty(&manifest).unwrap();
    let future = dir.path().join("future.tar");
    write_tar(&future, &entries);

    let error = cmd_restore(restore_args(&future, &db_path), test_config(&db_path))
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("not supported by this build"), "{error}");
}

// --- refusing to overwrite something live ---------------------------------

/// Restoring onto a running server is how a deploy ends up serving a
/// half-written database, so it takes an explicit `--force`.
#[tokio::test]
async fn test_restore_refuses_while_the_server_is_listening() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("db.sqlite3");
    let out_dir = dir.path().join("backups");
    seed(&db_path).await;
    let archive = backup(&db_path, &out_dir, false).await;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    // Hold the listener open for the length of the check.
    let accept = tokio::spawn(async move {
        let _ = listener.accept().await;
    });

    let mut config = test_config(&db_path);
    config.http = HttpConfig {
        bind: Some(format!("127.0.0.1:{port}")),
        ..Default::default()
    };

    let mut args = restore_args(&archive, &db_path);
    args.force = false;
    let error = cmd_restore(args, config.clone())
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("still reachable"), "{error}");

    // Same situation, but the operator said so.
    cmd_restore(restore_args(&archive, &db_path), config)
        .await
        .expect("--force must allow the restore");
    accept.abort();
    assert_eq!(
        principal_ids(&db_path).await,
        vec!["alice@example.com", "bob@example.com"]
    );
}

/// Restoring onto an existing database keeps a copy of it, and leaves no
/// staging file behind.
#[tokio::test]
async fn test_restore_keeps_the_replaced_database() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("db.sqlite3");
    let out_dir = dir.path().join("backups");
    seed(&db_path).await;
    let archive = backup(&db_path, &out_dir, false).await;

    cmd_restore(restore_args(&archive, &db_path), test_config(&db_path))
        .await
        .unwrap();

    let names = sibling_names(dir.path());
    let safety: Vec<&String> = names
        .iter()
        .filter(|name| name.starts_with("db.sqlite3.pre-restore-"))
        .collect();
    assert_eq!(
        safety.len(),
        1,
        "expected one pre-restore copy in {names:?}"
    );
    assert_eq!(
        principal_ids(&dir.path().join(safety[0])).await.len(),
        2,
        "the pre-restore copy must itself be a working database"
    );

    let staging: Vec<&String> = names
        .iter()
        .filter(|name| name.starts_with(".db.sqlite3.restore-"))
        .collect();
    assert!(staging.is_empty(), "staging file left behind: {staging:?}");
}

/// A stale `-wal`/`-shm` next to the target is what turns a correct restore
/// into a corrupt database, so a restore over one has to still work. The WAL
/// is copied out while its database is still open, because a clean close
/// checkpoints and deletes it — and a checkpointed WAL is not the hazard.
#[tokio::test]
async fn test_restore_over_a_stale_wal() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("db.sqlite3");
    let out_dir = dir.path().join("backups");
    seed(&db_path).await;
    let archive = backup(&db_path, &out_dir, false).await;

    // A second database with a hot WAL, as a crashed server leaves behind.
    let other = dir.path().join("other.sqlite3");
    let pool = create_db_pool(&other.to_string_lossy(), true)
        .await
        .unwrap();
    let principal_store = SqlitePrincipalStore::new(pool.clone());
    principal_store
        .insert_principal(
            Principal {
                id: "mallory@example.com".to_owned(),
                displayname: None,
                memberships: vec![],
                password: None,
                principal_type: PrincipalType::Individual,
                needs_password_change: false,
                privileges: Default::default(),
            },
            false,
        )
        .await
        .unwrap();
    let source_wal = PathBuf::from(format!("{}-wal", other.display()));
    let stale_wal = PathBuf::from(format!("{}-wal", db_path.display()));
    let wal_bytes = std::fs::read(&source_wal).expect("a live WAL to exist");
    assert!(!wal_bytes.is_empty(), "the fixture needs a non-empty WAL");
    std::fs::write(&stale_wal, &wal_bytes).unwrap();
    let stale_shm = PathBuf::from(format!("{}-shm", db_path.display()));
    std::fs::write(&stale_shm, vec![0_u8; 32 * 1024]).unwrap();
    pool.close().await;

    cmd_restore(restore_args(&archive, &db_path), test_config(&db_path))
        .await
        .expect("a stale WAL must not stop the restore");

    assert_eq!(
        principal_ids(&db_path).await,
        vec!["alice@example.com", "bob@example.com"],
        "the restored database must be the archived one, not the stale WAL \
         replayed into it"
    );
    assert!(
        !sibling_names(dir.path())
            .iter()
            .any(|name| name.starts_with(".db.sqlite3.restore-")),
        "the staging file must not survive"
    );
}

// --- the config, and the permissions --------------------------------------

/// `--include-config` puts the config in the archive, and restore writes it
/// out only where it is told to.
#[tokio::test]
async fn test_config_is_archived_only_on_request() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("db.sqlite3");
    let out_dir = dir.path().join("backups");
    let config_path = dir.path().join("config.toml");
    let config_body = "[data_store.sqlite]\ndb_url = \"/var/lib/omnical/db.sqlite3\"\n";
    std::fs::write(&config_path, config_body).unwrap();
    seed(&db_path).await;

    let mut args = backup_args(&out_dir, &db_path, false);
    args.include_config = true;
    let archive = cmd_backup(args, test_config(&db_path), &config_path)
        .await
        .unwrap();

    let manifest = read_manifest(&archive);
    let config_entry: ArchiveEntry = manifest
        .config
        .clone()
        .expect("the manifest must describe the config");
    assert_eq!(config_entry.name, CONFIG_ENTRY);
    assert_eq!(config_entry.sha256.len(), 64);
    assert!(entries_of(&archive).iter().any(|e| e.name == CONFIG_ENTRY));

    // Without --config-out the config is announced, not written anywhere, and
    // the file that is already on disk is left exactly as it was.
    std::fs::remove_file(&db_path).unwrap();
    cmd_restore(restore_args(&archive, &db_path), test_config(&db_path))
        .await
        .unwrap();
    assert!(!dir.path().join("restored-config.toml").exists());
    assert_eq!(
        std::fs::read_to_string(&config_path).unwrap(),
        config_body,
        "restore must not touch the live config"
    );

    let config_out = dir.path().join("recovered.toml");
    let mut args = restore_args(&archive, &db_path);
    args.config_out = Some(config_out.clone());
    cmd_restore(args, test_config(&db_path)).await.unwrap();
    assert_eq!(std::fs::read_to_string(&config_out).unwrap(), config_body);
}

/// The archive and the directory holding it stay private: they carry password
/// hashes, app tokens and (opt-in) cleartext secrets.
#[tokio::test]
async fn test_backup_artifacts_are_private() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("db.sqlite3");
    let out_dir = dir.path().join("backups");
    seed(&db_path).await;
    let archive = backup(&db_path, &out_dir, false).await;

    let mode = std::fs::metadata(&archive).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "archive mode was {mode:o}");
    let dir_mode = std::fs::metadata(&out_dir).unwrap().permissions().mode() & 0o777;
    assert_eq!(dir_mode, 0o700, "backup directory mode was {dir_mode:o}");

    // No snapshot or `.part` file survives a successful run.
    let strays: Vec<String> = std::fs::read_dir(&out_dir)
        .unwrap()
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| *name != archive.file_name().unwrap().to_string_lossy().as_ref())
        .collect();
    assert!(strays.is_empty(), "{strays:?}");
}

// --- error paths ----------------------------------------------------------

/// Missing inputs fail with a message that says what to do about it.
#[tokio::test]
async fn test_error_paths_are_explicit() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("db.sqlite3");
    seed(&db_path).await;

    let error = cmd_restore(
        restore_args(&dir.path().join("nope.tar"), &db_path),
        test_config(&db_path),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(error.contains("not a readable file"), "{error}");

    let error = cmd_backup(
        BackupArgs {
            out_dir: Some(dir.path().join("backups")),
            db: Some(dir.path().join("absent.sqlite3")),
            gzip: false,
            include_config: false,
        },
        test_config(&db_path),
        Path::new(NO_CONFIG),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(error.contains("no database at"), "{error}");

    // An in-memory database has nothing to back up, and saying so beats
    // writing an archive that restores to nothing.
    let mut memory_config = test_config(&db_path);
    memory_config.data_store = DataStoreConfig::Sqlite(SqliteDataStoreConfig {
        db_url: "sqlite::memory:".to_owned(),
        run_repairs: false,
        skip_broken: false,
    });
    let error = cmd_backup(
        BackupArgs {
            out_dir: Some(dir.path().join("backups")),
            db: None,
            gzip: false,
            include_config: false,
        },
        memory_config,
        Path::new(NO_CONFIG),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(error.contains("nothing to back up"), "{error}");

    // --include-config with no config file is an error, not a silent skip.
    let error = cmd_backup(
        BackupArgs {
            out_dir: Some(dir.path().join("backups")),
            db: Some(db_path.clone()),
            gzip: false,
            include_config: true,
        },
        test_config(&db_path),
        Path::new(NO_CONFIG),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(error.contains("--include-config"), "{error}");
}

/// `db_url` may be a `sqlite://` URL; the command still finds the file.
#[tokio::test]
async fn test_database_path_is_resolved_from_a_sqlite_url() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("db.sqlite3");
    seed(&db_path).await;
    let mut config = test_config(&db_path);
    config.data_store = DataStoreConfig::Sqlite(SqliteDataStoreConfig {
        db_url: format!("sqlite://{}?mode=rw", db_path.display()),
        run_repairs: false,
        skip_broken: false,
    });
    let archive = cmd_backup(
        BackupArgs {
            out_dir: Some(dir.path().join("backups")),
            db: None,
            gzip: false,
            include_config: false,
        },
        config.clone(),
        Path::new(NO_CONFIG),
    )
    .await
    .unwrap();
    assert!(archive.is_file());

    std::fs::remove_file(&db_path).unwrap();
    cmd_restore(
        RestoreArgs {
            archive,
            db: None,
            force: true,
            dry_run: false,
            config_out: None,
            ignore_row_count_changes: false,
        },
        config,
    )
    .await
    .unwrap();
    assert_eq!(principal_ids(&db_path).await.len(), 2);
}

// --- archive surgery helpers ---------------------------------------------
//
// These rebuild an archive by hand, so the tests can feed `restore` archives
// that `rustical backup` would never write.

use std::io::Read;

#[derive(Clone)]
struct Entry {
    name: String,
    bytes: Vec<u8>,
}

fn read_manifest(archive: &Path) -> BackupManifest {
    let bytes = entries_of(archive)
        .into_iter()
        .find(|entry| entry.name == MANIFEST_ENTRY)
        .expect("the archive has no manifest")
        .bytes;
    serde_json::from_slice(&bytes).expect("the manifest must parse")
}

fn entries_of(archive: &Path) -> Vec<Entry> {
    let file = std::fs::File::open(archive).unwrap();
    let mut tar = tar::Archive::new(file);
    let mut entries = Vec::new();
    for entry in tar.entries().unwrap() {
        let mut entry = entry.unwrap();
        let name = entry.path().unwrap().to_string_lossy().into_owned();
        let mut bytes = Vec::new();
        entry.read_to_end(&mut bytes).unwrap();
        entries.push(Entry { name, bytes });
    }
    entries
}

fn sibling_names(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

fn entry_mut<'a>(entries: &'a mut [Entry], name: &str) -> &'a mut Vec<u8> {
    entries
        .iter_mut()
        .find(|entry| entry.name == name)
        .unwrap_or_else(|| panic!("the archive has no {name}"))
        .bytes
        .as_mut()
}

/// Write a tar with the entry names written straight into the header's name
/// field. `tar::Header::set_path` refuses names containing `..`, which is
/// exactly why the tar-slip fixture has to be assembled at the byte level.
fn write_tar(path: &Path, entries: &[Entry]) {
    let file = std::fs::File::create(path).unwrap();
    let mut builder = tar::Builder::new(file);
    for entry in entries {
        let header = raw_header(&entry.name, entry.bytes.len() as u64);
        builder.append(&header, entry.bytes.as_slice()).unwrap();
    }
    builder.finish().unwrap();
}

fn raw_header(name: &str, size: u64) -> tar::Header {
    let mut header = tar::Header::new_gnu();
    header.set_size(size);
    header.set_mode(0o600);
    header.set_mtime(0);
    header.set_entry_type(tar::EntryType::Regular);
    let raw = header.as_old_mut();
    raw.name.fill(0);
    raw.name[..name.len()].copy_from_slice(name.as_bytes());
    header.set_cksum();
    header
}

/// Append an entry to an existing archive, before its end-of-archive marker —
/// a tar reader stops at the first zero block, so an entry appended after it
/// would never be seen.
fn append_raw_entry(path: &Path, name: &str, bytes: &[u8]) {
    let mut existing = std::fs::read(path).unwrap();
    // Drop the trailing end-of-archive blocks, append, then put them back.
    while existing.len() >= 512 && existing[existing.len() - 512..].iter().all(|b| *b == 0) {
        existing.truncate(existing.len() - 512);
    }
    let header = raw_header(name, bytes.len() as u64);
    existing.extend_from_slice(header.as_bytes());
    existing.extend_from_slice(bytes);
    existing.resize(existing.len() + (512 - bytes.len() % 512) % 512, 0);
    existing.extend_from_slice(&[0_u8; 1024]);
    std::fs::write(path, existing).unwrap();
}
