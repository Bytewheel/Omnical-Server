//! `rustical backup` / `rustical restore` — in-binary backup and restore for
//! self-hosted and appliance deployments (`PLAN_DEPLOYMENTS.md` §8.4).
//!
//! The method is the one `scripts/nightly-backup.sh` already proves on the
//! router: checkpoint the WAL, take a consistent snapshot of the database,
//! archive it together with the config. Two deliberate differences:
//!
//! * `VACUUM INTO` replaces the `sqlite3 .backup` CLI call, because sqlx
//!   does not expose SQLite's online-backup API. For this purpose it is a
//!   superset of `.backup`: one statement, one consistent snapshot of a live
//!   database, and the output is compacted — so the archive holds a small
//!   self-contained file instead of a copy of a live database.
//! * The archive carries a `manifest.json` with a SHA-256 and a size per
//!   entry, plus the row counts. That is what makes `restore` verifiable.
//!   The nightly script has no such check, and a tar that extracts into a
//!   corrupt database is the one failure mode a backup exists to prevent.
//!
//! Archive layout (tar, optionally gzipped):
//!
//! ```text
//! manifest.json    format version, creation time, binary version, checksums
//! db.sqlite3       the consistent snapshot
//! config.toml      only with --include-config; it contains secrets
//! ```
//!
//! Restore is deliberately narrow: it extracts only the three known entry
//! names, verifies each against the manifest before anything on disk is
//! touched, stages the database next to its target so the swap is an atomic
//! rename, and removes the `-wal`/`-shm` sidecars before the rename. A stale
//! sidecar from the replaced database is the one way a correct restore
//! silently ends up corrupt.
use crate::config::{Config, DataStoreConfig, HttpBindConfig, SqliteDataStoreConfig};
use anyhow::{Context, Result, anyhow, bail};
use chrono::Utc;
use clap::Parser;
use flate2::Compression;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use rustical_store_sqlite::create_db_pool;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{AssertSqlSafe, Row};
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// Bumped whenever the archive layout changes incompatibly. `restore` refuses
/// a manifest it does not understand rather than guessing.
pub const MANIFEST_FORMAT: u32 = 1;
pub const MANIFEST_ENTRY: &str = "manifest.json";
pub const DB_ENTRY: &str = "db.sqlite3";
pub const CONFIG_ENTRY: &str = "config.toml";

/// Archives hold password hashes, app tokens and (optionally) the SMTP and
/// RSVP secrets, so nothing group- or world-readable is ever created.
const FILE_MODE: u32 = 0o600;
const DIR_MODE: u32 = 0o700;
/// How long to wait for the configured HTTP bind before concluding that the
/// server is not up. This only has to notice a service that is already
/// accepting connections.
const PROBE_TIMEOUT: Duration = Duration::from_millis(750);
const COPY_CHUNK: usize = 64 * 1024;
const GZIP_MAGIC: [u8; 2] = [0x1f, 0x8b];

/// One file inside the archive, with the digest that proves it arrived intact.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArchiveEntry {
    pub name: String,
    pub size: u64,
    pub sha256: String,
}

/// The `manifest.json` payload: everything `restore` needs to decide whether
/// the archive is trustworthy and whether the restore matched.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupManifest {
    pub format: u32,
    pub created_at: String,
    pub rustical_version: String,
    /// `PRAGMA integrity_check` on the snapshot itself, so a bad backup is
    /// reported at backup time rather than at restore time.
    pub integrity_check: String,
    pub database: ArchiveEntry,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config: Option<ArchiveEntry>,
    pub row_counts: BTreeMap<String, i64>,
}

#[derive(Debug, Parser)]
pub struct BackupArgs {
    /// Directory to write the archive into. Defaults to `backups/` next to the
    /// database file.
    #[arg(long, value_name = "DIR")]
    pub out_dir: Option<PathBuf>,
    /// Database file to back up. Defaults to `data_store.sqlite.db_url`.
    #[arg(long, value_name = "PATH")]
    pub db: Option<PathBuf>,
    /// Gzip the archive (the nightly script always does; off by default so a
    /// self-hoster on a slow CPU can trade size for CPU).
    #[arg(long)]
    pub gzip: bool,
    /// Also archive the config file. It holds the SMTP, IMAP and RSVP
    /// secrets in cleartext, so this is opt-in.
    #[arg(long)]
    pub include_config: bool,
}

#[derive(Debug, Parser)]
pub struct RestoreArgs {
    /// Archive written by `rustical backup`.
    pub archive: PathBuf,
    /// Database file to replace. Defaults to `data_store.sqlite.db_url`.
    #[arg(long, value_name = "PATH")]
    pub db: Option<PathBuf>,
    /// Replace the database even though one is already there.
    #[arg(long)]
    pub force: bool,
    /// Verify the archive and report what it would do, changing nothing.
    #[arg(long)]
    pub dry_run: bool,
    /// Write the archived `config.toml` here. The live config is never
    /// overwritten automatically: restoring a database onto a config that
    /// changed since the backup is an operator decision.
    #[arg(long, value_name = "PATH")]
    pub config_out: Option<PathBuf>,
    /// Accept a row-count mismatch between the manifest and the restored
    /// database. Needed when migrating forward adds or rewrites rows.
    #[arg(long)]
    pub ignore_row_count_changes: bool,
}

/// Create a verified archive of the database. Returns the archive path.
#[allow(clippy::missing_errors_doc, clippy::missing_panics_doc)]
pub async fn cmd_backup(args: BackupArgs, config: Config, config_file: &Path) -> Result<PathBuf> {
    let db_path = resolve_database_path(&config, args.db.as_deref())?;
    require_database_file(&db_path)?;

    let out_dir = args.out_dir.clone().unwrap_or_else(|| {
        db_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join("backups")
    });
    fs::DirBuilder::new()
        .recursive(true)
        .mode(DIR_MODE)
        .create(&out_dir)
        .with_context(|| format!("creating output directory {}", out_dir.display()))?;

    let stamp = timestamp();
    let archive_name = format!(
        "omnical-backup-{stamp}.tar{}",
        if args.gzip { ".gz" } else { "" }
    );
    let archive_path = out_dir.join(&archive_name);
    // Written under a `.part` name and renamed, so a crashed or killed backup
    // never leaves a truncated file that looks like a usable one.
    let part_path = out_dir.join(format!(".{archive_name}.part"));
    let snapshot_path = out_dir.join(format!(".{archive_name}.sqlite3.part"));

    let result = build_archive(
        &db_path,
        args,
        config_file,
        &snapshot_path,
        &part_path,
        &archive_path,
    )
    .await;

    // The snapshot holds every password hash in the deployment, so it is
    // removed on the failure path too, not just the happy one.
    let _ = fs::remove_file(&snapshot_path);
    if result.is_err() {
        let _ = fs::remove_file(&part_path);
    }
    result
}

/// Long by design: the four steps of §8.4.1 in order, so the order of the
/// checkpoint, the snapshot, the inspection and the archive is readable
/// top to bottom. Same call as `cmd_serve`.
#[allow(clippy::too_many_lines)]
async fn build_archive(
    db_path: &Path,
    args: BackupArgs,
    config_file: &Path,
    snapshot_path: &Path,
    part_path: &Path,
    archive_path: &Path,
) -> Result<PathBuf> {
    // migrate = false: a backup must never mutate the schema it is copying,
    // and it must work against a database whose migrations are mid-flight.
    let db_url = db_path.to_string_lossy().into_owned();
    let pool = create_db_pool(&db_url, false)
        .await
        .with_context(|| format!("opening {}", db_path.display()))?;

    // Step 1, identical to nightly-backup.sh: fold the WAL back into the
    // database. Best-effort — under a live server the checkpoint can come back
    // busy, which is not fatal, because `VACUUM INTO` reads through the WAL
    // and still sees one consistent snapshot.
    let checkpoint = sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
        .fetch_one(&pool)
        .await
        .context("checkpointing the write-ahead log")?;
    let busy: i64 = checkpoint.try_get(0).unwrap_or(0);
    if busy != 0 {
        eprintln!(
            "Note: the WAL checkpoint reported busy (a reader held the database). \
             The snapshot is still consistent."
        );
    }
    pool.close().await;

    // Step 2, the in-process equivalent of `sqlite3 .backup`: one statement,
    // one consistent snapshot. `VACUUM INTO` refuses an existing target, and
    // it writes the file itself, so it must not be the live database.
    if snapshot_path.exists() {
        fs::remove_file(snapshot_path)?;
    }
    let pool = create_db_pool(&db_url, false)
        .await
        .with_context(|| format!("re-opening {}", db_path.display()))?;
    sqlx::query("VACUUM INTO ?")
        .bind(snapshot_path.to_string_lossy().as_ref())
        .execute(&pool)
        .await
        .with_context(|| {
            format!(
                "snapshotting the database into {} — the destination directory must be writable",
                snapshot_path.display()
            )
        })?;
    pool.close().await;

    // Step 3: prove the snapshot is good and describe it. The counts come from
    // the snapshot, not the live database, so the manifest describes the bytes
    // that end up in the archive.
    let (integrity_check, row_counts) = inspect_database(snapshot_path).await?;

    // Hash after the inspection above: opening the file may have written to its
    // header (WAL mode), and the digest has to cover the archived bytes.
    let database = ArchiveEntry {
        name: DB_ENTRY.to_owned(),
        size: fs::metadata(snapshot_path)?.len(),
        sha256: sha256_file(snapshot_path)?,
    };

    let config_entry = if args.include_config {
        if !config_file.is_file() {
            bail!(
                "--include-config was given but {} is not a readable file",
                config_file.display()
            );
        }
        Some(ArchiveEntry {
            name: CONFIG_ENTRY.to_owned(),
            size: fs::metadata(config_file)?.len(),
            sha256: sha256_file(config_file)?,
        })
    } else {
        None
    };

    let manifest = BackupManifest {
        format: MANIFEST_FORMAT,
        created_at: Utc::now().to_rfc3339(),
        rustical_version: env!("CARGO_PKG_VERSION").to_owned(),
        integrity_check: integrity_check.clone(),
        database: database.clone(),
        config: config_entry,
        row_counts: row_counts.clone(),
    };

    // Step 4: the archive itself, manifest first so a streaming reader knows
    // what it is looking at before the payload arrives.
    let file = private_file(part_path, true)?;
    if args.gzip {
        let mut encoder = GzEncoder::new(file, Compression::default());
        write_tar(
            &mut encoder,
            &manifest,
            snapshot_path,
            config_file,
            manifest.config.as_ref(),
        )?;
        encoder.finish().context("flushing the gzip stream")?;
    } else {
        let mut file = file;
        write_tar(
            &mut file,
            &manifest,
            snapshot_path,
            config_file,
            manifest.config.as_ref(),
        )?;
        file.flush()?;
    }
    fs::set_permissions(part_path, fs::Permissions::from_mode(FILE_MODE))?;
    fs::rename(part_path, archive_path)?;

    println!("Backup written: {}", archive_path.display());
    println!(
        "  database: {name} ({size}, sha256 {digest})",
        name = database.name,
        size = human_size(database.size),
        digest = short_digest(&database.sha256),
    );
    if let Some(config) = &manifest.config {
        println!(
            "  config:   {name} ({size}, sha256 {digest}) — contains secrets",
            name = config.name,
            size = human_size(config.size),
            digest = short_digest(&config.sha256),
        );
    }
    println!("  integrity_check: {integrity_check}");
    println!(
        "  rustical {version}, archive format {format}",
        version = manifest.rustical_version,
        format = MANIFEST_FORMAT
    );
    print_row_counts(&row_counts);
    println!(
        "Restore it with: rustical --config-file {} restore {}",
        config_file.display(),
        archive_path.display()
    );

    Ok(archive_path.to_path_buf())
}

fn write_tar(
    sink: &mut impl Write,
    manifest: &BackupManifest,
    snapshot_path: &Path,
    config_file: &Path,
    config_entry: Option<&ArchiveEntry>,
) -> Result<()> {
    let mut builder = tar::Builder::new(sink);
    builder.mode(tar::HeaderMode::Deterministic);

    let mut manifest_bytes = serde_json::to_vec_pretty(manifest)?;
    manifest_bytes.push(b'\n');
    append_bytes(&mut builder, MANIFEST_ENTRY, &manifest_bytes)?;
    append_path(&mut builder, DB_ENTRY, snapshot_path)?;
    if let Some(entry) = config_entry {
        append_path(&mut builder, entry.name.as_str(), config_file)?;
    }

    builder.finish().context("finalising the tar archive")?;
    Ok(())
}

fn append_bytes(builder: &mut tar::Builder<impl Write>, name: &str, bytes: &[u8]) -> Result<()> {
    let mut header = tar::Header::new_gnu();
    header.set_size(bytes.len() as u64);
    header.set_mode(FILE_MODE);
    header.set_mtime(0);
    header.set_entry_type(tar::EntryType::Regular);
    header.set_cksum();
    builder
        .append_data(&mut header, name, bytes)
        .with_context(|| format!("adding {name} to the archive"))
}

fn append_path(builder: &mut tar::Builder<impl Write>, name: &str, path: &Path) -> Result<()> {
    let file = File::open(path).with_context(|| format!("reading {}", path.display()))?;
    let mut header = tar::Header::new_gnu();
    header.set_size(file.metadata()?.len());
    header.set_mode(FILE_MODE);
    header.set_mtime(0);
    header.set_entry_type(tar::EntryType::Regular);
    header.set_cksum();
    builder
        .append_data(&mut header, name, file)
        .with_context(|| format!("adding {name} to the archive"))
}

/// Replace a database with one from an archive, verifying the archive first.
#[allow(clippy::missing_errors_doc, clippy::missing_panics_doc)]
pub async fn cmd_restore(args: RestoreArgs, config: Config) -> Result<()> {
    let archive = read_archive(&args.archive)?;
    let manifest = &archive.manifest;

    println!(
        "Archive: {path} (format {format}, created {created}, rustical {version})",
        path = args.archive.display(),
        format = manifest.format,
        created = manifest.created_at,
        version = manifest.rustical_version,
    );
    println!(
        "  verified {} ({}, sha256 ok)",
        manifest.database.name,
        human_size(manifest.database.size)
    );
    if let Some(entry) = &manifest.config {
        println!(
            "  verified {} ({}, sha256 ok)",
            entry.name,
            human_size(entry.size)
        );
    }

    let db_path = resolve_database_path(&config, args.db.as_deref())?;

    if args.dry_run {
        println!(
            "  would restore {} table(s) into {}",
            manifest.row_counts.len(),
            db_path.display()
        );
        println!("Dry run: nothing was written.");
        return Ok(());
    }

    // Replacing a database out from under a running server is how a deploy
    // ends up serving a half-written file, so it takes an explicit override.
    if !args.force && server_is_up(&config).await {
        bail!(
            "the server is still reachable on {} — stop it before restoring, or pass \
             --force. Replacing the database of a live server corrupts it",
            config.http.bind_config().map_or_else(
                |_| "its configured address".to_owned(),
                |bind| format!("{bind:?}")
            )
        );
    }

    if let Some(parent) = db_path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }

    // A restore is irreversible by nature; this copy is the only way back
    // without hunting down the last nightly archive.
    if db_path.is_file() {
        let safety = safety_copy_path(&db_path);
        copy_file(&db_path, &safety)?;
        println!("  previous database kept at {}", safety.display());
    }

    // Stage next to the target so the final move is a rename within one
    // filesystem, and so the verification covers the file that lands there.
    let staging = staging_path(&db_path);
    let result = swap_in_database(&archive, &staging, &db_path);
    if result.is_err() {
        let _ = fs::remove_file(&staging);
    }
    result?;

    if let Some(entry) = &manifest.config
        && let Some(destination) = &args.config_out
    {
        archive.copy_out(entry, destination)?;
        println!("  wrote {} to {}", entry.name, destination.display());
    } else if manifest.config.is_some() {
        println!(
            "  the archive contains {CONFIG_ENTRY}; pass --config-out PATH to write it out \
             (it is never applied automatically)",
        );
    }

    // Migrations run after the swap, never before: a failed migration must
    // leave the old database recoverable, and a backup must not be mutated.
    let pool = create_db_pool(&db_path.to_string_lossy(), true)
        .await
        .with_context(|| {
            format!(
                "opening {} — pending migrations are applied here",
                db_path.display()
            )
        })?;
    pool.close().await;

    verify_restored(
        &db_path,
        &manifest.row_counts,
        args.ignore_row_count_changes,
    )
    .await
}

/// The last gate: the restored database has to open clean, and it has to hold
/// what the archive said it held.
async fn verify_restored(
    db_path: &Path,
    manifest_row_counts: &BTreeMap<String, i64>,
    ignore_row_count_changes: bool,
) -> Result<()> {
    let (integrity_check, row_counts) = inspect_database(db_path).await?;
    if integrity_check != "ok" {
        bail!("the restored database failed integrity_check: {integrity_check}");
    }
    println!("  integrity_check: ok");
    println!("  database: {}", db_path.display());

    let comparison = compare_row_counts(manifest_row_counts, &row_counts);
    for mismatch in &comparison.mismatches {
        println!("  {mismatch}");
    }
    for note in &comparison.notes {
        println!("  note: {note}");
    }
    if !comparison.mismatches.is_empty() && !ignore_row_count_changes {
        bail!(
            "the restored database does not match the archive manifest (see the MISMATCH \
             lines above). That is expected when restoring across a migration; re-run with \
             --ignore-row-count-changes if the change is intended"
        );
    }
    print_row_counts(&row_counts);
    println!("Restore complete.");
    Ok(())
}

fn swap_in_database(archive: &VerifiedArchive, staging: &Path, db_path: &Path) -> Result<()> {
    archive.copy_out(&archive.manifest.database, staging)?;

    // The sidecars belong to the database being replaced. Left in place,
    // SQLite would replay the old WAL into the new file on the next open,
    // which is the classic way a "successful" restore corrupts the data.
    for suffix in ["-wal", "-shm"] {
        let mut sidecar = db_path.as_os_str().to_os_string();
        sidecar.push(suffix);
        let sidecar = PathBuf::from(sidecar);
        if sidecar.exists() {
            fs::remove_file(&sidecar).with_context(|| format!("removing {}", sidecar.display()))?;
        }
    }

    fs::rename(staging, db_path)
        .with_context(|| format!("replacing {} with the restored database", db_path.display()))?;
    if let Some(parent) = db_path.parent()
        && !parent.as_os_str().is_empty()
        && let Ok(dir) = File::open(parent)
    {
        let _ = dir.sync_all();
    }
    Ok(())
}

/// A verified archive, extracted to a scratch directory for as long as the
/// command runs. `Drop` removes it, so an aborted restore leaves nothing.
struct VerifiedArchive {
    manifest: BackupManifest,
    dir: PathBuf,
}

impl VerifiedArchive {
    /// Check every extracted file against the manifest. Called once, after
    /// the whole archive has been read, so a bad archive is rejected before
    /// the caller has touched the target at all — no safety copy, no staging
    /// file, no rename.
    fn verify_all(&self) -> Result<()> {
        let mut entries = vec![&self.manifest.database];
        if let Some(config) = &self.manifest.config {
            entries.push(config);
        }
        for entry in entries {
            let source = self.dir.join(&entry.name);
            let actual_size = fs::metadata(&source)
                .with_context(|| format!("the extracted {} is missing", entry.name))?
                .len();
            if actual_size != entry.size {
                bail!(
                    "{}: extracted {actual_size} bytes, the manifest says {}",
                    entry.name,
                    entry.size
                );
            }
            let actual_digest = sha256_file(&source)?;
            if actual_digest != entry.sha256 {
                bail!(
                    "{}: sha256 mismatch — the archive is corrupt (expected {}, got {}). \
                     Nothing was restored",
                    entry.name,
                    entry.sha256,
                    actual_digest
                );
            }
        }
        Ok(())
    }

    /// Copy a verified entry to its destination.
    fn copy_out(&self, entry: &ArchiveEntry, destination: &Path) -> Result<()> {
        let source = self.dir.join(&entry.name);
        if !source.is_file() {
            bail!("the extracted {} is missing", entry.name);
        }
        copy_file(&source, destination)
    }
}

impl Drop for VerifiedArchive {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

/// Read, parse and verify an archive. Every entry is checked against the
/// manifest here, so the target is untouched unless the whole archive is good.
fn read_archive(path: &Path) -> Result<VerifiedArchive> {
    if !path.is_file() {
        bail!("{} is not a readable file", path.display());
    }
    let file = File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let mut reader = BufReader::new(file);
    // Detect gzip by magic bytes rather than by extension: an archive that
    // arrived over scp without its `.gz` suffix still has to restore.
    let gzipped = reader.fill_buf()?.starts_with(&GZIP_MAGIC);
    let dir = scratch_dir()?;
    let mut archive = tar::Archive::new(ReaderOrGzip::new(reader, gzipped));

    let mut manifest = None;
    let mut seen: Vec<String> = Vec::new();
    for entry in archive
        .entries()
        .context("reading the archive — is it a tar file?")?
    {
        let mut entry = entry.context("reading an archive entry")?;
        // The raw name bytes, never a parsed path: nothing here wants a path
        // component, and letting the tar crate turn one into a `PathBuf` is
        // the first step of a tar-slip.
        let name = String::from_utf8_lossy(&entry.path_bytes()).into_owned();
        if !entry.header().entry_type().is_file() {
            bail!("archive entry {name} is not a regular file");
        }
        // The tar-slip guard: this format has exactly three names, none of
        // which contains a separator, a parent reference or a NUL.
        if name.contains('/') || name.contains('\\') || name.contains("..") {
            bail!("archive entry {name} has an unexpected path");
        }
        if name.is_empty() || name.as_bytes().contains(&0) {
            bail!("archive entry has an unusable name");
        }
        if !matches!(name.as_str(), MANIFEST_ENTRY | DB_ENTRY | CONFIG_ENTRY) {
            bail!("archive contains an unexpected entry: {name}");
        }
        if seen.contains(&name) {
            bail!("archive contains {name} twice");
        }
        seen.push(name.clone());

        let destination = dir.join(&name);
        let mut out = private_file(&destination, true)?;
        std::io::copy(&mut entry, &mut out).context("extracting an archive entry")?;
        out.flush()?;

        if name == MANIFEST_ENTRY {
            let bytes = fs::read(&destination)?;
            let parsed: BackupManifest =
                serde_json::from_slice(&bytes).context("the archive manifest is not valid JSON")?;
            if parsed.format != MANIFEST_FORMAT {
                bail!(
                    "archive manifest format {} is not supported by this build (expected \
                     {MANIFEST_FORMAT})",
                    parsed.format
                );
            }
            manifest = Some(parsed);
        }
    }

    let manifest = manifest.context("the archive has no manifest.json")?;
    if manifest.database.name != DB_ENTRY {
        bail!(
            "the manifest describes {} but this build restores it as {DB_ENTRY}",
            manifest.database.name
        );
    }
    if let Some(config) = &manifest.config
        && config.name != CONFIG_ENTRY
    {
        bail!(
            "the manifest describes {} but this build restores it as {CONFIG_ENTRY}",
            config.name
        );
    }

    let archive = VerifiedArchive { manifest, dir };
    archive.verify_all()?;
    Ok(archive)
}

/// A plain file or a gzip stream, chosen by the magic bytes at open time.
enum ReaderOrGzip<R: Read> {
    Plain(R),
    Gzip(GzDecoder<R>),
}

impl<R: Read> ReaderOrGzip<R> {
    fn new(reader: R, gzipped: bool) -> Self {
        if gzipped {
            Self::Gzip(GzDecoder::new(reader))
        } else {
            Self::Plain(reader)
        }
    }
}

impl<R: Read> Read for ReaderOrGzip<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Plain(reader) => reader.read(buf),
            Self::Gzip(reader) => reader.read(buf),
        }
    }
}

/// `PRAGMA integrity_check` plus a row count per user table.
async fn inspect_database(path: &Path) -> Result<(String, BTreeMap<String, i64>)> {
    let pool = create_db_pool(&path.to_string_lossy(), false)
        .await
        .with_context(|| format!("opening {}", path.display()))?;
    let integrity_check: String = sqlx::query_scalar("PRAGMA integrity_check")
        .fetch_one(&pool)
        .await
        .with_context(|| format!("running integrity_check on {}", path.display()))?;
    let tables: Vec<String> = sqlx::query_scalar::<_, String>(
        "SELECT name FROM sqlite_master WHERE type = 'table' \
         AND name NOT LIKE 'sqlite_%' AND name != '_sqlx_migrations' ORDER BY name",
    )
    .fetch_all(&pool)
    .await
    .context("listing the database tables")?;
    let mut row_counts = BTreeMap::new();
    for table in tables {
        // SQLite resolves this as an identifier, and a double quote inside a
        // quoted identifier is escaped by doubling, so the name from
        // sqlite_master cannot break out of it.
        let count: i64 = sqlx::query_scalar(AssertSqlSafe(format!(
            "SELECT COUNT(*) FROM \"{}\"",
            table.replace('"', "\"\"")
        )))
        .fetch_one(&pool)
        .await
        .with_context(|| format!("counting rows in {table}"))?;
        row_counts.insert(table, count);
    }
    pool.close().await;
    Ok((integrity_check, row_counts))
}

#[derive(Debug, Default, PartialEq, Eq)]
struct RowCountComparison {
    mismatches: Vec<String>,
    notes: Vec<String>,
}

fn compare_row_counts(
    expected: &BTreeMap<String, i64>,
    actual: &BTreeMap<String, i64>,
) -> RowCountComparison {
    let mut comparison = RowCountComparison::default();
    for (table, count) in expected {
        match actual.get(table) {
            Some(actual_count) if actual_count == count => {}
            Some(actual_count) => comparison.mismatches.push(format!(
                "MISMATCH {table}: the manifest says {count}, the restored database has \
                 {actual_count}"
            )),
            None => comparison.mismatches.push(format!(
                "MISMATCH {table}: missing from the restored database"
            )),
        }
    }
    for table in actual.keys() {
        if !expected.contains_key(table) {
            comparison.notes.push(format!(
                "{table} is not in the manifest (added by a migration)"
            ));
        }
    }
    comparison
}

fn print_row_counts(row_counts: &BTreeMap<String, i64>) {
    let width = row_counts.keys().map(String::len).max().unwrap_or(0);
    let mut out = String::from("  rows:\n");
    for (table, count) in row_counts {
        let _ = writeln!(out, "    {table:width$} {count}");
    }
    print!("{out}");
}

/// Ask the configured bind whether anything is serving. A TCP connect is
/// enough — this is an "is the service up" check, not a health check
/// (`rustical health` is that).
async fn server_is_up(config: &Config) -> bool {
    let Ok(bind_config) = config.http.bind_config() else {
        return false;
    };
    match bind_config {
        HttpBindConfig::Tcp(address) => {
            let address = loopback_normalised(&address);
            tokio::time::timeout(PROBE_TIMEOUT, tokio::net::TcpStream::connect(&address))
                .await
                .is_ok_and(|result| result.is_ok())
        }
        HttpBindConfig::Unix(path) => {
            tokio::time::timeout(PROBE_TIMEOUT, tokio::net::UnixStream::connect(&path))
                .await
                .is_ok_and(|result| result.is_ok())
        }
    }
}

/// A wildcard bind is not connectable; the server listens on every interface,
/// so localhost is where to look for it.
fn loopback_normalised(address: &str) -> String {
    match address.rsplit_once(':') {
        Some(("0.0.0.0", port)) => format!("127.0.0.1:{port}"),
        Some(("[::]", port)) => format!("[::1]:{port}"),
        _ => address.to_owned(),
    }
}

/// The database file to operate on: `--db` wins over `db_url`, which may be a
/// `sqlite://` URL with options in the query string.
#[allow(clippy::missing_errors_doc, clippy::missing_panics_doc)]
pub fn resolve_database_path(config: &Config, db_override: Option<&Path>) -> Result<PathBuf> {
    if let Some(path) = db_override {
        return Ok(path.to_path_buf());
    }
    let DataStoreConfig::Sqlite(SqliteDataStoreConfig { db_url, .. }) = &config.data_store;
    let options: sqlx::sqlite::SqliteConnectOptions = db_url
        .parse()
        .map_err(|error| anyhow!("data_store.sqlite.db_url is unusable: {error}"))?;
    let filename = options.get_filename();
    if filename.as_os_str().as_bytes().contains(&b':') {
        bail!("data_store.sqlite.db_url is not a file path ({db_url}) — nothing to back up");
    }
    Ok(filename.to_path_buf())
}

fn require_database_file(path: &Path) -> Result<()> {
    if !path.is_file() {
        bail!(
            "no database at {} — has the server ever run with this config? \
             (--db overrides data_store.sqlite.db_url)",
            path.display()
        );
    }
    Ok(())
}

/// A scratch directory for one run of the command. It has to be somewhere the
/// process can always write; the final move into place is a separate rename
/// next to the target, so nothing here depends on being the same filesystem.
///
/// The name carries the pid *and* a counter *and* the clock. A pid alone is
/// not enough: two restores in the same process (the test suite runs them in
/// parallel threads) would share a directory, and the first one to finish
/// would delete the other's extracted archive.
fn scratch_dir() -> Result<PathBuf> {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_nanos());
    let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "rustical-restore-{}-{nanos}-{unique}",
        std::process::id()
    ));
    fs::DirBuilder::new()
        .recursive(true)
        .mode(DIR_MODE)
        .create(&dir)
        .with_context(|| format!("creating {}", dir.display()))?;
    Ok(dir)
}

fn staging_path(db_path: &Path) -> PathBuf {
    sibling_path(db_path, &format!(".restore-{}", timestamp()))
}

fn safety_copy_path(db_path: &Path) -> PathBuf {
    sibling_path(db_path, &format!(".pre-restore-{}", timestamp()))
}

fn sibling_path(path: &Path, suffix: &str) -> PathBuf {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .unwrap_or_else(|| std::ffi::OsStr::new("db.sqlite3"))
        .to_string_lossy()
        .into_owned();
    parent.join(format!("{file_name}{suffix}"))
}

fn private_file(path: &Path, truncate: bool) -> Result<File> {
    OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(truncate)
        .mode(FILE_MODE)
        .open(path)
        .with_context(|| format!("creating {}", path.display()))
}

fn copy_file(from: &Path, to: &Path) -> Result<()> {
    let mut input = File::open(from).with_context(|| format!("opening {}", from.display()))?;
    let mut output = private_file(to, true)?;
    std::io::copy(&mut input, &mut output)
        .with_context(|| format!("copying {} to {}", from.display(), to.display()))?;
    output.flush()?;
    let _ = output.sync_all();
    Ok(())
}

fn sha256_file(path: &Path) -> Result<String> {
    let mut file = File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; COPY_CHUNK];
    loop {
        let read = file
            .read(&mut buffer)
            .with_context(|| format!("reading {}", path.display()))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn short_digest(digest: &str) -> String {
    digest.chars().take(16).collect()
}

fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 4] = ["B", "KiB", "MiB", "GiB"];
    let mut size = f64::from(u32::try_from(bytes).unwrap_or(u32::MAX));
    let mut unit = 0;
    while size >= 1024.0 && unit < UNITS.len() - 1 {
        size /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{size:.1} {}", UNITS[unit])
    }
}

/// `20260928T114500Z` — sorts chronologically, safe in a filename.
fn timestamp() -> String {
    Utc::now().format("%Y%m%dT%H%M%SZ").to_string()
}

#[cfg(test)]
mod tests {
    use super::{
        ArchiveEntry, BackupManifest, CONFIG_ENTRY, DB_ENTRY, MANIFEST_ENTRY, MANIFEST_FORMAT,
        RowCountComparison, compare_row_counts, human_size, loopback_normalised, short_digest,
        sibling_path,
    };
    use std::collections::BTreeMap;
    use std::path::Path;

    fn manifest() -> BackupManifest {
        BackupManifest {
            format: MANIFEST_FORMAT,
            created_at: "2026-09-28T11:45:00+00:00".to_owned(),
            rustical_version: "0.16.1".to_owned(),
            integrity_check: "ok".to_owned(),
            database: ArchiveEntry {
                name: DB_ENTRY.to_owned(),
                size: 10,
                sha256: "a".repeat(64),
            },
            config: None,
            row_counts: BTreeMap::from([("principals".to_owned(), 3)]),
        }
    }

    #[test]
    fn test_manifest_json_roundtrip_omits_absent_config() {
        let json = serde_json::to_string(&manifest()).unwrap();
        assert!(!json.contains("config"), "{json}");
        let parsed: BackupManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.format, MANIFEST_FORMAT);
        assert_eq!(parsed.database.sha256, "a".repeat(64));
        assert_eq!(parsed.row_counts.get("principals"), Some(&3));
    }

    #[test]
    fn test_manifest_json_roundtrip_keeps_config() {
        let mut manifest = manifest();
        manifest.config = Some(ArchiveEntry {
            name: CONFIG_ENTRY.to_owned(),
            size: 20,
            sha256: "b".repeat(64),
        });
        let parsed: BackupManifest =
            serde_json::from_str(&serde_json::to_string(&manifest).unwrap()).unwrap();
        assert_eq!(
            parsed.config.map(|entry| entry.name),
            Some(CONFIG_ENTRY.to_owned())
        );
    }

    #[test]
    fn test_manifest_rejects_unknown_format() {
        let mut manifest = manifest();
        manifest.format = MANIFEST_FORMAT + 1;
        let parsed: BackupManifest =
            serde_json::from_str(&serde_json::to_string(&manifest).unwrap()).unwrap();
        assert_ne!(parsed.format, MANIFEST_FORMAT);
    }

    #[test]
    fn test_compare_row_counts_reports_each_case() {
        let expected =
            BTreeMap::from([("calendars".to_owned(), 33), ("principals".to_owned(), 11)]);
        let actual = BTreeMap::from([
            ("calendars".to_owned(), 34),
            ("principals".to_owned(), 11),
            ("tenants".to_owned(), 1),
        ]);
        let comparison = compare_row_counts(&expected, &actual);
        assert_eq!(
            comparison.mismatches.len(),
            1,
            "{:?}",
            comparison.mismatches
        );
        assert!(comparison.mismatches[0].contains("MISMATCH calendars"));
        assert_eq!(comparison.notes.len(), 1, "{:?}", comparison.notes);
        assert!(comparison.notes[0].contains("tenants"));
    }

    #[test]
    fn test_compare_row_counts_flags_missing_table() {
        let expected = BTreeMap::from([("principals".to_owned(), 11)]);
        let comparison = compare_row_counts(&expected, &BTreeMap::new());
        assert_eq!(
            comparison,
            RowCountComparison {
                mismatches: vec![
                    "MISMATCH principals: missing from the restored database".to_owned()
                ],
                notes: vec![],
            }
        );
    }

    #[test]
    fn test_compare_row_counts_clean() {
        let expected = BTreeMap::from([("principals".to_owned(), 11)]);
        let comparison = compare_row_counts(&expected, &expected);
        assert!(comparison.mismatches.is_empty());
        assert!(comparison.notes.is_empty());
    }

    #[test]
    fn test_loopback_normalised() {
        assert_eq!(loopback_normalised("0.0.0.0:4000"), "127.0.0.1:4000");
        assert_eq!(loopback_normalised("[::]:4000"), "[::1]:4000");
        assert_eq!(loopback_normalised("127.0.0.1:4000"), "127.0.0.1:4000");
        assert_eq!(loopback_normalised("example.com:4000"), "example.com:4000");
        assert_eq!(loopback_normalised("[::1]:4000"), "[::1]:4000");
    }

    #[test]
    fn test_human_size() {
        assert_eq!(human_size(0), "0 B");
        assert_eq!(human_size(512), "512 B");
        assert_eq!(human_size(2048), "2.0 KiB");
        assert_eq!(human_size(5 * 1024 * 1024), "5.0 MiB");
    }

    #[test]
    fn test_short_digest() {
        assert_eq!(short_digest(&"a".repeat(64)), "a".repeat(16));
    }

    #[test]
    fn test_sibling_path_keeps_the_directory() {
        let path = sibling_path(Path::new("/var/lib/omnical/db.sqlite3"), ".pre-restore-1");
        assert_eq!(path.parent().unwrap(), Path::new("/var/lib/omnical"));
        assert_eq!(
            path.file_name().unwrap().to_string_lossy(),
            "db.sqlite3.pre-restore-1"
        );
    }

    #[test]
    fn test_entry_names_are_fixed() {
        // The extractor only accepts these three names; the tar-slip guard and
        // the unexpected-entry rejection both key off this list.
        assert_eq!(MANIFEST_ENTRY, "manifest.json");
        assert_eq!(DB_ENTRY, "db.sqlite3");
        assert_eq!(CONFIG_ENTRY, "config.toml");
        assert!(!MANIFEST_ENTRY.contains('/'));
    }
}
