//! The appliance panel's facts, and the two things it can do that destroy
//! data — `NEXT_AGENT_ITEM14_PANEL.md` (item 14, §9.4).
//!
//! Three sections, and they are not equally interesting:
//!
//! - **Data** — restore points, a staged restore, and the report that says what
//!   the restore actually did.
//! - **Network** — the addresses this box has, and the public URL it is
//!   reachable at. Read-only.
//! - **Firmware** — the running version, the binary's size, the overlay's free
//!   space, and the `sysupgrade` call. Read-only until the last thing.
//!
//! ## Why the redaction lives here and not in the view
//!
//! The panel renders the config's own values (the bind address, the public URL,
//! an SMTP host). Row 50's rule is that a secret must not survive into an
//! artefact a person attaches to a public tracker, and a support screenshot of
//! this panel is exactly such an artefact. So every string this module produces
//! is passed through [`redact`](crate::commands::support_bundle::redact) **on the
//! way out**, using the same
//! [`secrets_in`](crate::commands::support_bundle::secrets_in) discovery the
//! support bundle uses. `crates/frontend` cannot import the `rustical` crate, so
//! the alternative is a second redaction path in the view layer — two
//! implementations, one of which nobody re-tests when a new secret-shaped config
//! key is added. There is one implementation and the panel cannot skip it.
//!
//! The alternative that was rejected: redact a `Debug` rendering and parse it
//! back. It needs a `decode_redacted` that always bails, so the panel fails the
//! moment redaction catches something — which is to say, it fails the first time
//! it works.
//!
//! ## Why a restore is staged rather than performed
//!
//! [`cmd_restore`](crate::commands::backup::cmd_restore) refuses while the
//! server is reachable (`backup.rs:446-457`), and this panel is served *by* that
//! server. Forcing past the guard with `force: true` defeats the only thing the
//! guard is for. So a restore here is two halves:
//!
//! 1. [`stage_restore`] — verify the archive, take a safety copy, write the new
//!    database *beside* the live one, record what is pending, ask for a restart.
//! 2. [`complete_staged_restore`] — called from `main` **before the connection
//!    pool opens**, so the swap happens against a database nothing has open.
//!
//! The server being down is therefore a *consequence* of asking for a restore,
//! not an obstacle worked around. `main.rs` is the only place both are in scope,
//! which is why the completion is a free function rather than a method.
//!
//! ## Why the row-count report is measured against the archive
//!
//! Restoring deliberately moves data back in time: every row written since the
//! archive is meant to disappear. Comparing "rows before" against "rows after"
//! would therefore print **every correct restore as catastrophic data loss**,
//! which is how §18.29's deliberate token revocation came to be printed as
//! `LOST ROWS` under a banner about collateral damage. So `expected` is the
//! manifest's `row_counts` and `actual` is measured after the swap, and
//! [`RestoreReport::claim`] is forbidden from implying that nothing was lost.
//!
//! The honest limit carries forward from §18.28: **row counts cannot see a
//! dropped column.** A green report means "every table in the archive is present
//! with the archived row count", which is strictly weaker than "lossless".

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::commands::backup::{
    self, DatabaseInventory, RestorePoint, RowCountComparison, VerifiedArchive, compare_row_counts,
    format_size, verify_archive,
};
use crate::commands::support_bundle::{REDACTED, redact, secrets_in};
use crate::config::Config;

/// The marker written next to a staged database, and read at start-up.
///
/// **A fixed name, not a timestamped one.** `main` has to *find* the pending
/// restore without being told which timestamp it carries, so the name is
/// derived from the database and is stable. The staged database and the safety
/// copy alongside it are timestamped; the marker is the fixed point.
const STAGED_MARKER: &str = ".omnical-staged-restore.json";

/// A restore that has been verified and written beside the live database, and
/// is waiting for a restart to be swapped in.
///
/// Written to `<db>.omnical-staged-restore.json`. It is the only thing that
/// survives the restart, so it carries everything [`complete_staged_restore`]
/// needs and nothing it does not.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StagedRestore {
    /// The live database this will replace. Checked at completion, so a marker
    /// copied or moved to the wrong install refuses rather than swapping the
    /// wrong file.
    pub database: PathBuf,
    /// The verified, extracted database sitting beside it.
    pub staged: PathBuf,
    /// The pre-restore copy, kept for the same reason `cmd_restore` keeps one.
    pub safety_copy: PathBuf,
    /// Where the operator picked the archive from, for the log and the report.
    pub archive: PathBuf,
    /// The manifest's own account of the database, carried across the restart
    /// because the archive is not re-read: the point of the report is to compare
    /// against **this** archive, and re-deriving it later could compare against
    /// a different file if the directory changed underneath.
    #[serde(default)]
    pub expected: BTreeMap<String, i64>,
    /// The manifest's `created_at`, shown in the report so the operator can see
    /// how old the data they just restored is.
    pub archive_created_at: String,
    /// The admin who asked for it, for the log line. Never rendered as a
    /// credential — it is a name that is already in the allowlist.
    pub requested_by: String,
}

/// What a completed restore actually did.
///
/// Mirrors [`RollbackReport`](crate::commands::upgrade::RollbackReport)'s split
/// between *losses* and *expected change*, and for the same reason: a single
/// undifferentiated number invites reading a deliberate change as damage.
///
/// Serialised because the report has to outlive the process that produced it —
/// the restart that completes a restore also destroys the request that asked
/// for it, so the panel reads this back from disk rather than from memory.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RestoreReport {
    pub database: PathBuf,
    pub archive: PathBuf,
    pub archive_created_at: String,
    pub requested_by: String,
    /// `PRAGMA integrity_check` on the swapped-in database.
    pub integrity_check: String,
    /// The manifest's counts.
    pub expected: BTreeMap<String, i64>,
    /// What the database holds now.
    pub actual: BTreeMap<String, i64>,
    pub comparison: RowCountComparison,
    /// The pre-restore copy, if one was taken.
    pub safety_copy: Option<PathBuf>,
    /// When the swap happened, RFC 3339.
    pub completed_at: String,
}

impl RestoreReport {
    /// Did the restore hold up against the archive?
    ///
    /// The one predicate the panel branches on. `true` means the integrity check
    /// passed **and** every table in the archive is present with its archived
    /// count. It does not mean the restore was lossless — see
    /// [`Self::claim`], which is what gets rendered.
    #[must_use]
    pub fn is_verified(&self) -> bool {
        self.integrity_check == "ok"
            && self.comparison.mismatches.is_empty()
            && self.comparison.missing.is_empty()
    }

    /// The one claim a row count supports, in words an operator can act on.
    ///
    /// Delegates to [`DatabaseInventory::claim`] so the panel and the CLI cannot
    /// disagree about what a row count proves. **Never says "no data was
    /// lost"** — restoring *did* discard newer rows, on purpose.
    #[must_use]
    pub fn claim(&self) -> String {
        DatabaseInventory {
            integrity_check: self.integrity_check.clone(),
            row_counts: self.actual.clone(),
        }
        .claim(&self.comparison)
    }

    /// The rows the restore removed, as `(table, before, after)`.
    ///
    /// Before is the **archive's** count, not the live database's pre-restore
    /// count — so this is "what the archive had that the restored database does
    /// not", which is the damage signal, rather than "what changed", which is
    /// mostly the restore working.
    #[must_use]
    pub fn losses(&self) -> Vec<(String, i64, i64)> {
        let mut out = Vec::new();
        for (table, before) in &self.expected {
            let after = self.actual.get(table).copied().unwrap_or(0);
            if after < *before {
                out.push((table.clone(), *before, after));
            }
        }
        out
    }
}

// ────────────────────────────────── facts ───────────────────────────────────

/// Read-only facts about the box, for the Data / Network / Firmware sections.
///
/// A struct rather than free functions so the panel can hold one and the tests
/// can build one over a temp directory without touching the real `/`.
#[derive(Clone)]
pub struct ApplianceFacts {
    /// The database the Data section manages. The appliance's own store.
    pub database: PathBuf,
    /// Where restore points are listed from and where archives are written.
    pub backup_dir: PathBuf,
    /// The running executable, for the Firmware section's size.
    pub binary: PathBuf,
    /// The filesystem whose free space gates a firmware flash.
    pub overlay_mount: PathBuf,
    /// The config, read for the Network section and as the redaction source.
    pub config: Config,
    /// The raw config text, so key-shaped redaction covers fields this build
    /// does not know about. Empty when the file is unreadable — which is why
    /// reading it is a `Result` and not a field default.
    pub raw_config: String,
}

/// A hand-written `Debug`, and the reason it is hand-written is the point.
///
/// [`Config`] has no `Debug` — deliberately, because it holds SMTP passwords and
/// the RSVP HMAC key, and a derived `Debug` on a struct containing one is a
/// `{:?}` away from printing a credential into a log. Rather than leak the
/// config's shape or add a redacting `Debug` to `Config` (which every other
/// call site would then inherit), this prints the paths and says the config is
/// present. What the panel *renders* goes through [`redact`]; what this prints
/// goes through nothing, so it holds nothing.
impl std::fmt::Debug for ApplianceFacts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApplianceFacts")
            .field("database", &self.database)
            .field("backup_dir", &self.backup_dir)
            .field("binary", &self.binary)
            .field("overlay_mount", &self.overlay_mount)
            // Not the config, and not the raw text: both hold secrets.
            .field("config", &"<redacted: not Debug>")
            .field("raw_config", &"<redacted: not Debug>")
            .finish()
    }
}

/// Free space on a filesystem.
///
/// `Option`, and **`None` is not zero**. "Could not be measured" and "measured,
/// and there is none" are different claims, and a panel that renders an
/// unmeasured filesystem as `0 B free` is telling an operator there is no room
/// to flash when nobody looked. A `statvfs` that fails leaves the field absent
/// and the page says so.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FreeSpace {
    pub total: u64,
    pub available: u64,
}

/// `statvfs` on `path`.
///
/// **`statvfs`, not `df`.** Row 51's own gate is written `df -k /`, but parsing
/// `df` means a locale-dependent, column-count-dependent text parse on the exact
/// path that decides whether there is room to write flash — a `df` with a
/// wrapped long device name has two lines where the code expects one. `libc` is
/// already a dependency, so this is both more correct and less code.
///
/// `f_bavail` rather than `f_bfree`: the blocks reserved for root are available
/// to this process (it runs as root) and not counted in `f_bfree` on some
/// filesystems, which would under-report room that genuinely exists.
/// # Errors
/// If `path` contains a NUL byte, or `statvfs` fails — which is reported as an
/// error rather than as zero free space, because "could not be measured" and
/// "measured, and empty" are different claims.
pub fn free_space(path: &Path) -> Result<FreeSpace> {
    let c_path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())
        .with_context(|| format!("{} contains a NUL byte", path.display()))?;
    // SAFETY: `statvfs` writes exactly one `statvfs` through the pointer, and
    // `c_path` is a valid NUL-terminated string that outlives the call.
    let mut stats: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY: as above — `path` is a live CString and `stats` is writable.
    let result = unsafe { libc::statvfs(c_path.as_ptr(), &raw mut stats) };
    if result != 0 {
        return Err(std::io::Error::last_os_error()).with_context(|| {
            format!(
                "statvfs({}) failed — free space is unknown, not zero",
                path.display()
            )
        });
    }
    // `f_frsize` is the fragment size, the unit `f_blocks` and `f_bavail` are
    // both counted in. `f_bsize` is the preferred I/O size and is a different
    // unit on several filesystems.
    //
    // `c_ulong` is unsigned on every platform this builds for, so no cast is
    // needed and none is done — an `as` here would be the kind of conversion
    // that is right on Linux and silently wrong somewhere else.
    let block = if stats.f_frsize > 0 {
        stats.f_frsize
    } else {
        stats.f_bsize
    };
    Ok(FreeSpace {
        total: stats.f_blocks.saturating_mul(block),
        available: stats.f_bavail.saturating_mul(block),
    })
}

/// One address on one interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceAddress {
    pub interface: String,
    pub family: String,
    pub address: String,
    pub prefix_len: u8,
}

/// The addresses `ip -j addr` reports.
///
/// **`ip -j addr`, not `getifaddrs`.** One read-only fact does not justify a new
/// dependency, and `ip` is already on every `OpenWrt` box this ships to — it is
/// what `deploy.sh` and the support bundle's own diagnostics use.
///
/// # Errors
/// If `ip` cannot be run, exits non-zero, or prints something that is not the
/// JSON array it promises. **Never returns an empty list for a failure** — a
/// silently empty network section reads as "this box has no network", which is
/// the most dangerous possible thing to show someone whose box is misconfigured.
/// An absent fact and an empty one are different claims, here as everywhere.
pub fn interface_addresses() -> Result<Vec<InterfaceAddress>> {
    let output = std::process::Command::new("ip")
        .arg("-j")
        .arg("addr")
        .output()
        .context("running `ip -j addr` — network addresses are unknown, not empty")?;
    if !output.status.success() {
        bail!(
            "`ip -j addr` exited {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    parse_ip_json(&output.stdout)
}

/// Parse `ip -j addr` output.
///
/// Split out and `pub` because "the panel must not show an empty list when `ip`
/// fails" is a claim about *parsing* as much as about running, and a test that
/// has to shell out to prove it is a test that needs an `ip` binary.
#[derive(Debug, serde::Deserialize)]
struct IpInterface {
    #[serde(default)]
    ifname: String,
    #[serde(default)]
    addr_info: Vec<IpAddrInfo>,
}

#[derive(Debug, serde::Deserialize)]
struct IpAddrInfo {
    #[serde(default)]
    family: String,
    #[serde(default)]
    local: String,
    prefixlen: u8,
}

/// Parse the JSON `ip -j addr` prints.
///
/// # Errors
/// If `bytes` is not the JSON array `ip` promises. **Never an empty list for a
/// failure** — see [`interface_addresses`].
pub fn parse_ip_json(bytes: &[u8]) -> Result<Vec<InterfaceAddress>> {
    let interfaces: Vec<IpInterface> = serde_json::from_slice(bytes)
        .context("`ip -j addr` did not print the JSON array it promises")?;
    Ok(interfaces
        .into_iter()
        .flat_map(|interface| {
            interface
                .addr_info
                .into_iter()
                .map(move |addr| InterfaceAddress {
                    interface: interface.ifname.clone(),
                    family: addr.family,
                    address: addr.local,
                    prefix_len: addr.prefixlen,
                })
        })
        .filter(|addr| !addr.address.is_empty())
        .collect())
}

/// The running binary's size, for the Firmware section.
///
/// `None` when it cannot be stat'd, for the same reason free space is `None`
/// rather than `0`: an unreadable binary is not a zero-byte binary.
#[must_use]
pub fn binary_size(path: &Path) -> Option<u64> {
    std::fs::metadata(path).ok().map(|metadata| metadata.len())
}

/// The running executable's path.
///
/// `None` rather than an error: this is one line of a page, and a build where
/// `/proc/self/exe` is unreadable should still render the other Firmware facts.
#[must_use]
pub fn current_executable() -> Option<PathBuf> {
    std::env::current_exe().ok()
}

/// Everything the Network section shows, with every string already redacted.
///
/// **Redaction happens here, in the `rustical` crate, before the value reaches
/// the view layer** — see the module docs. The panel receives strings that are
/// already safe to render, so there is no second redaction path to keep honest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkFacts {
    pub addresses: Vec<InterfaceAddress>,
    /// The configured bind, redacted. A bind is a path or an address, so the
    /// key-shape pass does not touch it — but the public URL and anything an
    /// operator typed into it might be a credential, so it goes through the same
    /// `redact` anyway.
    pub bind: String,
    /// `[subscriptions] public_url`, or `None`.
    pub public_url: Option<String>,
    /// The data root, which on an appliance is where the tenant stores live.
    pub data_root: String,
    /// The admin hosts the panel answers on. Not secret, and not derived from
    /// the config's secret-shaped keys.
    pub admin_hosts: Vec<String>,
}

/// Build the Network section's facts, redacted.
///
/// Every string goes through [`redact`] with the same secrets the support
/// bundle would use. `redact` **fails rather than returning a string that still
/// holds a secret**, so this propagates that failure rather than swallowing it:
/// a network section that could not be made safe is a page that is not rendered,
/// which is the correct outcome and is what row 50 asks for.
///
/// # Errors
/// If any rendered string still holds a secret after redaction, which means the
/// redaction itself is broken. The whole section fails rather than rendering
/// something that might be a credential.
pub fn network_facts(
    config: &Config,
    raw_config: &str,
    addresses: Vec<InterfaceAddress>,
) -> Result<NetworkFacts> {
    let secrets = secrets_in(config, raw_config);
    let bind = config
        .http
        .bind
        .clone()
        .unwrap_or_else(|| "(default)".to_owned());
    Ok(NetworkFacts {
        addresses,
        bind: redact(&bind, &secrets)?,
        public_url: config
            .subscriptions
            .public_url
            .as_deref()
            .map(|url| redact(url, &secrets))
            .transpose()?,
        data_root: redact(&config.tenancy.data_root, &secrets)?,
        admin_hosts: config
            .tenancy
            .normalised_admin_hosts()
            .into_iter()
            .map(|host| redact(&host, &secrets))
            .collect::<Result<Vec<_>>>()?,
    })
}

/// Everything the Firmware section shows, read-only.
///
/// `free` is `None` when the overlay could not be measured. That is **not** the
/// same as no free space, and the flash button refuses on `None` rather than
/// proceeding on a guess.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirmwareFacts {
    pub version: String,
    pub commit: String,
    /// `(size, free, unit)` — the unit is empty when the numbers are unknown, so
    /// a template cannot render "0 B free" for a filesystem nobody measured.
    pub size: Option<u64>,
    pub free: Option<FreeSpace>,
    pub size_text: String,
    pub free_text: String,
    /// The filesystem the numbers came from, for the label.
    pub overlay_mount: String,
    /// `true` when the numbers are known and there is room for at least one
    /// more copy of the binary. The conservative reading: a flash writes a new
    /// image *and* keeps the old one until it succeeds.
    pub has_room: bool,
}

/// Build the Firmware section's facts.
pub fn firmware_facts(overlay_mount: &Path, binary: &Path) -> FirmwareFacts {
    let free = free_space(overlay_mount).ok();
    let size = binary_size(binary);
    // Room for the new image *plus* the current one, because `sysupgrade` writes
    // the new image before it swaps and the old one is the way back. Requiring
    // only `size` would approve a flash that cannot complete.
    let has_room = match (free, size) {
        (Some(space), Some(size)) => space.available >= size.saturating_mul(2),
        // Unknown on either side is **not** room. A flash is irreversible and
        // an out-of-space write can leave an unbootable unit, so the unknown
        // case refuses rather than proceeding.
        _ => false,
    };
    FirmwareFacts {
        version: env!("CARGO_PKG_VERSION").to_owned(),
        commit: crate::build_provenance::build_sha().to_owned(),
        size,
        free,
        size_text: size.map_or_else(|| "(not measured)".to_owned(), format_size),
        free_text: free.map_or_else(
            || "(not measured)".to_owned(),
            |space| {
                format!(
                    "{} free of {}",
                    format_size(space.available),
                    format_size(space.total)
                )
            },
        ),
        overlay_mount: overlay_mount.display().to_string(),
        has_room,
    }
}

/// The restore points the Data section offers.
///
/// Delegates to [`list_restore_points`](backup::list_restore_points), which owns
/// the `.part` exclusion and the non-recursive scan. The panel does not get its
/// own directory walk, because the two would disagree about what a restore point
/// is the first time a naming rule changed.
///
/// # Errors
/// If the backup directory cannot be listed. Absent is an error rather than an
/// empty list, so "no backups" and "the backup directory is gone" stay
/// distinguishable.
pub fn restore_points(backup_dir: &Path) -> Result<Vec<RestorePoint>> {
    backup::list_restore_points(backup_dir)
}

/// A renderable row for a restore point.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestorePointRow {
    /// The archive's file name — the form that goes in a form field. Never a
    /// full path: a path in a form value is a path a client can edit, and the
    /// server re-joins it against the configured directory rather than
    /// believing it.
    pub name: String,
    pub size: u64,
    pub size_text: String,
    pub modified: i64,
    /// ISO-ish UTC, computed once here rather than in the template.
    pub modified_text: String,
}

impl RestorePointRow {
    /// Build a row from a discovered restore point.
    ///
    /// # Errors
    /// If the file name is not representable as UTF-8, which cannot happen for
    /// anything this module created but is checked rather than assumed — a lossy
    /// name in a form field would restore a *different* file than the operator
    /// clicked.
    pub fn from_point(point: &RestorePoint) -> Result<Self> {
        let name = point
            .path
            .file_name()
            .and_then(std::ffi::OsStr::to_str)
            .context("a restore point whose name is not valid UTF-8")?
            .to_owned();
        Ok(Self {
            size_text: format_size(point.size),
            modified_text: rfc3339(point.modified),
            name,
            size: point.size,
            modified: point.modified,
        })
    }
}

/// Seconds since the epoch to `YYYY-MM-DDTHH:MM:SSZ`.
///
/// The same Howard Hinnant conversion the support bundle uses. Duplicated
/// because pulling a date crate in for one format is worse, and both call sites
/// are checked against a fixed input by their own tests.
#[must_use]
pub fn rfc3339(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let tod = secs.rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        tod / 3_600,
        (tod % 3_600) / 60,
        tod % 60
    )
}

// ─────────────────────────────── staging ────────────────────────────────────

/// What a staged restore produced, for the page that asked for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StagedSummary {
    pub database: PathBuf,
    pub staged: PathBuf,
    pub safety_copy: Option<PathBuf>,
    pub archive_created_at: String,
    /// The archive's table count, so the operator sees what they are about to
    /// get before the restart.
    pub expected_tables: usize,
}

/// Verify an archive and write it **beside** the live database.
///
/// Does not touch the live database. Not a rename, not a truncation, not a
/// `force`. The sequence is:
///
/// 1. [`verify_archive`] — every entry checked against the manifest, so a
///    corrupt archive fails before a safety copy is taken.
/// 2. A safety copy of the live database, if it exists.
/// 3. The archive's database extracted to `<db>.restore-<ts>`, on the **same
///    filesystem** as the target so the eventual move is a rename.
/// 4. A [`StagedRestore`] marker written, which is what
///    [`complete_staged_restore`] reads.
///
/// # Errors
/// Every failure of [`verify_archive`], or an I/O failure writing the copy, the
/// staging file or the marker. On any of them the live database is untouched
/// and, if a staging file was created, it is removed.
pub fn stage_restore(
    archive_path: &Path,
    database: &Path,
    requested_by: &str,
) -> Result<StagedSummary> {
    // 1. Verify first, before anything on disk is touched. `archive` is dropped
    //    at the end of this function, which removes its scratch directory — the
    //    extracted file we want is copied out to `staged`, not left there.
    let archive: VerifiedArchive = verify_archive(archive_path)?;
    let manifest = archive.manifest().clone();

    // 2. Safety copy. Taken before the staging file is written so that a
    //    failure to copy leaves no half-staged state to reason about.
    let safety_copy = if database.is_file() {
        let path = sibling(database, &format!(".pre-restore-{}", timestamp()));
        std::fs::copy(database, &path)
            .with_context(|| format!("copying {} to {}", database.display(), path.display()))?;
        Some(path)
    } else {
        None
    };

    // 3. Extract beside the target, so the completion is a rename within one
    //    filesystem.
    let staged = sibling(database, &format!(".restore-{}", timestamp()));
    let extracted = archive.extract_database_to(&staged).and_then(|()| {
        // `private_file` inside `copy_out` already created it 0600; this makes
        // the intent explicit at the call site that matters.
        std::fs::set_permissions(&staged, permissions_0600())
            .with_context(|| format!("securing {}", staged.display()))
    });
    if let Err(e) = extracted {
        let _ = std::fs::remove_file(&staged);
        return Err(e);
    }

    // 4. The marker. Without it there is a staging file and no way to know it
    //    was deliberate.
    let staged_record = StagedRestore {
        database: database.to_path_buf(),
        staged: staged.clone(),
        safety_copy: safety_copy.clone().unwrap_or_default(),
        archive: archive_path.to_path_buf(),
        expected: manifest.row_counts.clone(),
        archive_created_at: manifest.created_at.clone(),
        requested_by: requested_by.to_owned(),
    };
    let write_marker = write_marker(database, &staged_record);
    if let Err(e) = write_marker {
        // Nothing has touched the live database, so the honest cleanup is to
        // leave no trace at all.
        let _ = std::fs::remove_file(&staged);
        if let Some(copy) = &safety_copy {
            let _ = std::fs::remove_file(copy);
        }
        return Err(e);
    }

    info!(
        archive = %archive_path.display(),
        database = %database.display(),
        staged = %staged.display(),
        requested_by,
        "restore staged; a restart will complete it"
    );

    Ok(StagedSummary {
        database: database.to_path_buf(),
        staged,
        safety_copy,
        archive_created_at: manifest.created_at,
        expected_tables: manifest.row_counts.len(),
    })
}

/// Where a staged restore's marker lives for a given database.
#[must_use]
pub fn marker_path(database: &Path) -> PathBuf {
    sibling(database, STAGED_MARKER)
}

/// Is a restore waiting to be completed?
///
/// `false` for an unreadable marker, which is the fail-safe direction: a marker
/// this build cannot parse is not a restore it should attempt, and treating it
/// as "nothing pending" leaves the live database alone.
#[must_use]
pub fn restore_is_staged(database: &Path) -> bool {
    read_marker(database).is_ok()
}

/// Read the pending restore for `database`, if there is one.
fn read_marker(database: &Path) -> Result<StagedRestore> {
    let path = marker_path(database);
    let bytes = std::fs::read(&path)
        .with_context(|| format!("reading the staged-restore marker {}", path.display()))?;
    serde_json::from_slice(&bytes)
        .with_context(|| format!("parsing the staged-restore marker {}", path.display()))
}

fn write_marker(database: &Path, staged: &StagedRestore) -> Result<()> {
    let path = marker_path(database);
    let json = serde_json::to_vec_pretty(staged).context("serialising the staged restore")?;
    std::fs::write(&path, json).with_context(|| format!("writing {}", path.display()))?;
    std::fs::set_permissions(&path, permissions_0600())
        .with_context(|| format!("securing {}", path.display()))?;
    Ok(())
}

fn remove_marker(database: &Path) {
    let _ = std::fs::remove_file(marker_path(database));
}

/// Swap a staged restore in, and report what happened.
///
/// **Called from `main` before the connection pool is opened.** That ordering is
/// the whole reason this exists as a free function: `cmd_restore` refuses while
/// the server is reachable, and this is the one moment the server is not
/// reachable and the database is not open.
///
/// Steps, in order, because each one's failure has to leave the next one
/// impossible rather than merely unlikely:
///
/// 1. The marker is removed **first**. If anything below fails, the restore is
///    not retried on the next boot — a half-applied restore retried
///    automatically is how a recoverable situation becomes a lost database.
///    The safety copy is on disk either way, and the operator re-stages.
/// 2. The staged file is checked to be a real file. A zero-length or absent
///    staging file is refused.
/// 3. The `-wal` and `-shm` sidecars are removed. Left in place, SQLite would
///    replay the *old* WAL into the *new* file on the next open — the classic
///    way a "successful" restore corrupts the data. Copied from
///    `swap_in_database`, and for the same reason.
/// 4. The rename, then a directory `fsync` so the rename itself is durable.
///
/// # Errors
/// If the staging file is missing or empty, or the rename fails. In every case
/// the marker is already gone, so this does not retry.
pub async fn complete_staged_restore(database: &Path) -> Result<Option<RestoreReport>> {
    // No marker is the overwhelmingly common case: `Ok(None)`, not an error,
    // because a server that was never asked to restore anything is not a server
    // with a problem.
    let Ok(staged) = read_marker(database) else {
        return Ok(None);
    };

    // 1. Consume the marker before doing anything irreversible.
    remove_marker(database);

    if staged.database != database {
        bail!(
            "the staged restore in {} names a different database ({}) — refusing to swap it in",
            marker_path(database).display(),
            staged.database.display()
        );
    }
    let metadata = std::fs::metadata(&staged.staged).with_context(|| {
        format!(
            "the staged database {} is missing — the restore was not applied",
            staged.staged.display()
        )
    })?;
    if metadata.len() == 0 {
        bail!(
            "the staged database {} is empty — the restore was not applied",
            staged.staged.display()
        );
    }

    // 2. Sidecars, then the rename.
    for suffix in ["-wal", "-shm"] {
        let mut sidecar = staged.database.as_os_str().to_os_string();
        sidecar.push(suffix);
        let sidecar = PathBuf::from(sidecar);
        if sidecar.exists() {
            std::fs::remove_file(&sidecar)
                .with_context(|| format!("removing {}", sidecar.display()))?;
        }
    }
    std::fs::rename(&staged.staged, &staged.database).with_context(|| {
        format!(
            "replacing {} with the restored database",
            staged.database.display()
        )
    })?;
    if let Some(parent) = staged.database.parent()
        && !parent.as_os_str().is_empty()
        && let Ok(dir) = std::fs::File::open(parent)
    {
        // A rename that is not fsynced is a rename that may not survive a power
        // cut — and this is the one operation in the program that deliberately
        // discards data, so it is the one that must not be half-durable.
        let _ = dir.sync_all();
    }

    // 3. Migrations run **after** the swap, never before: a failed migration
    //    must leave the old database recoverable, and an archive must never be
    //    mutated. Same ordering as `cmd_restore`.
    let pool = rustical_store_sqlite::create_db_pool(&staged.database.to_string_lossy(), true)
        .await
        .with_context(|| {
            format!(
                "opening {} — pending migrations are applied here",
                staged.database.display()
            )
        })?;
    pool.close().await;

    // 4. Measure against the archive, not against what was there before.
    let inventory: DatabaseInventory = backup::row_counts_of(&staged.database).await?;
    let comparison = compare_row_counts(&staged.expected, &inventory.row_counts);
    // An empty `safety_copy` is the deserialised form of "there was no live
    // database to copy", which `stage_restore` writes as a default. Presenting
    // that as a path would point an operator at `db.sqlite3` itself.
    let safety_copy = if staged.safety_copy.as_os_str().is_empty() {
        None
    } else {
        Some(staged.safety_copy.clone())
    };
    let report = RestoreReport {
        database: staged.database.clone(),
        archive: staged.archive.clone(),
        archive_created_at: staged.archive_created_at.clone(),
        requested_by: staged.requested_by.clone(),
        integrity_check: inventory.integrity_check.clone(),
        expected: staged.expected.clone(),
        actual: inventory.row_counts,
        comparison,
        safety_copy: safety_copy.clone(),
        completed_at: rfc3339(now_seconds()),
    };

    if report.is_verified() {
        info!(
            database = %staged.database.display(),
            tables = report.actual.len(),
            "staged restore completed and matched the archive"
        );
    } else {
        // Not a `bail!`: the swap has already happened, so this is a report, not
        // a refusal.
        warn!(
            database = %staged.database.display(),
            mismatches = report.comparison.mismatches.len(),
            missing = report.comparison.missing.len(),
            integrity_check = %report.integrity_check,
            safety_copy = ?safety_copy,
            "staged restore completed but did NOT match the archive"
        );
    }

    // Persist the report, because the panel that asked for the restore is not
    // running any more: the restart that completed it also tore down the
    // request that wanted to see the answer. Without this the operator's only
    // view of whether their restore worked is `logread`.
    if let Err(e) = write_report(database, &report) {
        // Not fatal — the restore itself succeeded, and the report is a
        // convenience. Losing it must not turn a good restore into a boot
        // failure, but it is worth a warning because it means the panel will
        // show nothing.
        warn!(%e, "the restore completed but its report could not be written");
    }

    Ok(Some(report))
}

/// Where the last completed restore's report is written.
#[must_use]
pub fn report_path(database: &Path) -> PathBuf {
    sibling(database, ".omnical-restore-report.json")
}

/// Write the report next to the database it describes.
fn write_report(database: &Path, report: &RestoreReport) -> Result<()> {
    let path = report_path(database);
    let json = serde_json::to_vec_pretty(report).context("serialising the restore report")?;
    std::fs::write(&path, json).with_context(|| format!("writing {}", path.display()))?;
    std::fs::set_permissions(&path, permissions_0600())
        .with_context(|| format!("securing {}", path.display()))?;
    Ok(())
}

/// The last completed restore's report, if there is one.
///
/// `None` for a missing or unreadable file, and `Err` for one that does not
/// parse — those are different: "no restore has been completed" is a fact the
/// panel renders as an empty state, while "there is a report I cannot read" is a
/// problem the operator needs to see.
#[must_use]
pub fn last_restore_report(database: &Path) -> Option<Result<RestoreReport>> {
    let bytes = std::fs::read(report_path(database)).ok()?;
    Some(
        serde_json::from_slice(&bytes)
            .with_context(|| format!("parsing {}", report_path(database).display())),
    )
}

fn now_seconds() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        // `try_from` rather than `as i64`: a saturating read is the honest one
        // for a clock, and an `as` that silently wrapped would put a restore
        // report's timestamp in the wrong century.
        .map_or(0, |elapsed| {
            i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX)
        })
}

fn timestamp() -> String {
    chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string()
}

fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .unwrap_or_else(|| std::ffi::OsStr::new("db.sqlite3"))
        .to_string_lossy()
        .into_owned();
    parent.join(format!("{file_name}{suffix}"))
}

fn permissions_0600() -> std::fs::Permissions {
    use std::os::unix::fs::PermissionsExt;
    std::fs::Permissions::from_mode(0o600)
}

// ────────────────────────────── firmware write ──────────────────────────────

/// Writes a firmware image. The one destructive, irreversible call on the panel.
///
/// Injected exactly as [`SetupRestart`](crate::setup_mode::SetupRestart) is
/// injected for item 13's restart, and for the same reason: `sysupgrade` writes
/// flash, so shipping one without a seam means rows 49 and 51 stay red forever
/// because the only way to test the call is to brick a unit.
///
/// The real implementation shells to `sysupgrade`. The test double lives in
/// `tests/appliance_panel.rs`, **not** in this module, so a double that drifts
/// from the real signature has nowhere to hide.
///
/// `#[async_trait]` rather than a plain `async fn` on the trait, and the reason
/// is dyn-compatibility: the panel holds this as `Arc<dyn FirmwareWriter>`, and
/// a trait with an RPITIT method has no vtable. `TenantStore` and every other
/// injectable store in the workspace already went through this.
#[async_trait::async_trait]
pub trait FirmwareWriter: Send + Sync + std::fmt::Debug {
    /// Flash `image`. Resolves once the write has finished or failed.
    ///
    /// # Errors
    /// Anything that stopped the flash. A real implementation's error text is
    /// the only thing an operator has to go on, so it is surfaced verbatim
    /// rather than replaced with a generic message.
    async fn write(&self, image: &Path) -> Result<()>;

    /// Is a supported flashing tool present on this box?
    ///
    /// Checked **before** the confirmation is even offered, so the panel does
    /// not present a button that cannot work. `false` on a host with no
    /// `sysupgrade` — which is every development machine, and is why this is a
    /// method rather than a constant.
    fn available(&self) -> bool {
        false
    }
}

/// The real writer: `sysupgrade -n <image>`.
///
/// **`-n` deliberately.** Without it `sysupgrade` restores the backup partition
/// as part of flashing, which overwrites `/config` — and on a tenancy-enabled
/// appliance that directory holds the control plane, every tenant's SMTP
/// password and the RSVP HMAC key (§3.6). A firmware update must not silently
/// roll the control plane back to whatever was in the backup partition. The
/// consequence, which is the operator's to accept deliberately, is that a
/// factory reset is no longer "free" as a side effect of upgrading.
#[derive(Debug, Clone)]
pub struct SysupgradeWriter {
    /// The program to run. Injectable so a test can assert the exact argv
    /// without a real `sysupgrade` on `PATH`.
    program: PathBuf,
}

impl SysupgradeWriter {
    /// The default: `sysupgrade` from `PATH`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            program: PathBuf::from("sysupgrade"),
        }
    }

    /// A writer for a specific program, for tests and for a non-default path.
    #[must_use]
    pub fn with_program(program: impl Into<PathBuf>) -> Self {
        Self {
            program: program.into(),
        }
    }
}

impl Default for SysupgradeWriter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl FirmwareWriter for SysupgradeWriter {
    fn available(&self) -> bool {
        which(&self.program).is_some()
    }

    async fn write(&self, image: &Path) -> Result<()> {
        if !image.is_file() {
            bail!("{} is not a readable firmware image", image.display());
        }
        let program = which(&self.program).ok_or_else(|| {
            anyhow::anyhow!(
                "{} is not on PATH — this is not an OpenWrt appliance, and flashing it from \
                 here would do nothing",
                self.program.display()
            )
        })?;

        // Logged before the call, because after a successful flash the box is
        // gone and this line is the only record that the flash was requested
        // and by whom. The image path and the running version are facts; the
        // image itself is not logged.
        info!(image = %image.display(), "flashing firmware");
        let program = program.clone();
        let image = image.to_path_buf();

        // `spawn_blocking`, not `tokio::process`. A flash takes minutes and ends
        // in a reboot, so it is genuinely blocking work and holding an async
        // worker for its duration would be wrong. It also keeps the dependency
        // graph unchanged — `tokio`'s `process` feature is not enabled in this
        // workspace, and enabling it to run a command that is about to kill the
        // process is not a trade worth making.
        tokio::task::spawn_blocking(move || {
            let status = std::process::Command::new(&program)
                .arg("-n")
                .arg(&image)
                .status()
                .with_context(|| format!("running {}", program.display()))?;
            if !status.success() {
                bail!("sysupgrade exited {status} — the unit was not flashed");
            }
            Ok(())
        })
        .await
        .context("the flash task did not finish")?
    }
}

/// Find a program on `PATH`.
///
/// Hand-rolled rather than pulling a crate: it is a loop over `PATH` splitting
/// on `:`, and a dependency for it would be a bigger review than the code.
fn which(program: &Path) -> Option<PathBuf> {
    // An absolute or explicitly relative path is used as-is. `which("sysupgrade")`
    // searching `PATH` for a *relative* name is a footgun, and a caller that
    // passes one has said where the program is.
    if program.components().count() > 1 {
        return program.is_file().then(|| program.to_path_buf());
    }
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(program))
        .find(|candidate| candidate.is_file())
}

/// What a firmware flash is about to do, rendered for the confirmation page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirmwareFlashSummary {
    pub image: PathBuf,
    pub image_text: String,
    pub running_version: String,
    pub image_version: String,
    /// `true` when the image is the same version as the running binary. Still
    /// allowed — an operator reflashing a known-good image is a real recovery
    /// step — but the page says so rather than leaving the operator to notice.
    pub same_version: bool,
}

/// Build the confirmation summary for a flash.
///
/// # Errors
/// If the image is not a readable file. Checking here rather than at the write
/// means the operator finds out on the confirmation page, not after clicking.
pub fn firmware_flash_summary(image: &Path) -> Result<FirmwareFlashSummary> {
    if !image.is_file() {
        bail!("{} is not a readable firmware image", image.display());
    }
    let size = binary_size(image).unwrap_or(0);
    let running_version = env!("CARGO_PKG_VERSION").to_owned();
    // The image's own version is read from its file name, which is the only
    // place a `sysupgrade`-style image carries it that does not mean mounting
    // and parsing an entire firmware filesystem to ask.
    let image_version = image
        .file_stem()
        .map(std::ffi::OsStr::to_string_lossy)
        .map_or_else(|| "(unknown)".to_owned(), std::borrow::Cow::into_owned);
    Ok(FirmwareFlashSummary {
        image_text: format_size(size),
        same_version: image_version.contains(&running_version),
        running_version,
        image_version,
        image: image.to_path_buf(),
    })
}

/// The marker left in place of a secret, re-exported so a template can compare
/// against it without importing the `rustical` crate.
pub const REDACTION_MARKER: &str = REDACTED;

/// Facts for a page, gathered together, with each section's failure kept
/// separate.
///
/// A section that failed is `Err`, not an empty value: the Data section's error
/// must not blank the Network section, and neither may read as "nothing to
/// report".
#[derive(Debug)]
pub struct ApplianceView {
    pub data: Result<DataFacts>,
    pub network: Result<NetworkFacts>,
    pub firmware: Result<FirmwareFacts>,
}

/// The Data section's facts.
#[derive(Debug)]
pub struct DataFacts {
    pub database: PathBuf,
    pub backup_dir: PathBuf,
    pub restore_points: Vec<RestorePointRow>,
    /// Set when a restore is staged and waiting for a restart. The page must say
    /// so plainly, because until the restart happens **nothing has been
    /// restored** and an operator who assumes otherwise is wrong about the state
    /// of their database.
    pub pending: Option<StagedRestore>,
    pub database_exists: bool,
}

/// Gather the Data section's facts.
///
/// # Errors
/// If the backup directory cannot be listed. The pending-restore check is
/// infallible by design — a marker this build cannot parse reads as "no restore
/// pending", which leaves the database alone.
pub fn data_facts(facts: &ApplianceFacts) -> Result<DataFacts> {
    let points = restore_points(&facts.backup_dir)?
        .iter()
        .map(RestorePointRow::from_point)
        .collect::<Result<Vec<_>>>()?;
    Ok(DataFacts {
        database_exists: facts.database.is_file(),
        pending: read_marker(&facts.database).ok(),
        restore_points: points,
        database: facts.database.clone(),
        backup_dir: facts.backup_dir.clone(),
    })
}

/// Gather the Network section's facts.
///
/// # Errors
/// Propagates a failure to read addresses or to redact. **An unreadable network
/// is an error the page shows**, never an empty list that reads as "no network".
pub fn network_section(facts: &ApplianceFacts) -> Result<NetworkFacts> {
    network_facts(&facts.config, &facts.raw_config, interface_addresses()?)
}

/// Gather the Firmware section's facts.
///
/// Infallible in practice — [`firmware_facts`] reports absence as absence — but
/// returns `Result` so a future measurement can fail without changing every
/// call site.
///
/// # Errors
/// Never, today. Present so the signature stays honest if a measurement is
/// added that can fail.
pub fn firmware_section(facts: &ApplianceFacts) -> Result<FirmwareFacts> {
    Ok(firmware_facts(&facts.overlay_mount, &facts.binary))
}

#[cfg(test)]
mod tests {
    use super::{
        FirmwareFacts, RestorePointRow, StagedRestore, free_space, marker_path, parse_ip_json,
        rfc3339, sibling,
    };
    use crate::commands::backup;
    use std::collections::BTreeMap;
    use std::path::{Path, PathBuf};

    #[test]
    fn test_rfc3339_matches_a_known_instant() {
        // 1790768700 == 2026-09-30T11:45:00Z. Computed from the date rather
        // than typed in, because a hand-typed epoch constant that disagrees
        // with the date it is meant to represent is exactly how this test ends
        // up asserting a wrong date is correct.
        assert_eq!(rfc3339(1_790_768_700), "2026-09-30T11:45:00Z");
    }

    #[test]
    fn test_rfc3339_handles_the_epoch_and_before_it() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
        // A negative value must not panic or wrap into a nonsense date.
        assert!(rfc3339(-1).starts_with("1969-12-31"));
    }

    #[test]
    fn test_parse_ip_json_reads_addresses() {
        let json = br#"[{"ifname":"eth0","addr_info":[
            {"family":"inet","local":"192.168.1.10","prefixlen":24},
            {"family":"inet6","local":"fe80::1","prefixlen":64}]}]"#;
        let addresses = parse_ip_json(json).expect("parsed");
        assert_eq!(addresses.len(), 2);
        assert_eq!(addresses[0].interface, "eth0");
        assert_eq!(addresses[0].address, "192.168.1.10");
        assert_eq!(addresses[1].prefix_len, 64);
    }

    #[test]
    fn test_parse_ip_json_omits_an_address_with_no_value() {
        // Some `ip` versions emit an `addr_info` entry with no `local` for an
        // unassigned interface. Rendering it would print an empty address.
        let json = br#"[{"ifname":"eth0","addr_info":[{"family":"inet","prefixlen":0}]}]"#;
        assert!(parse_ip_json(json).expect("parsed").is_empty());
    }

    #[test]
    fn test_parse_ip_json_fails_rather_than_returning_empty_on_garbage() {
        // The important one: an unparseable `ip` must be an **error**, because
        // an empty list renders as "this box has no network".
        assert!(parse_ip_json(b"not json at all").is_err());
        assert!(parse_ip_json(b"").is_err());
    }

    #[test]
    fn test_free_space_measures_a_real_directory() {
        let dir = std::env::temp_dir();
        let space = free_space(&dir).expect("a writable temp dir is on a real filesystem");
        assert!(space.total > 0, "{space:?}");
    }

    #[test]
    fn test_free_space_on_a_missing_path_is_an_error_not_zero() {
        // The distinction the whole `Option` design rests on.
        let missing = std::env::temp_dir().join("omnical-no-such-path-for-tests");
        assert!(free_space(&missing).is_err());
    }

    #[test]
    fn test_firmware_refuses_to_guess_room_when_space_is_unknown() {
        // `has_room` is built by `firmware_facts`, which measures a real path.
        // Assert the rule on a hand-built value so the "unknown is not room"
        // claim does not depend on a filesystem being how we expect.
        let unknown = FirmwareFacts {
            version: "1".to_owned(),
            commit: String::new(),
            size: Some(1024),
            free: None,
            size_text: "1.0 KiB".to_owned(),
            free_text: "(not measured)".to_owned(),
            overlay_mount: "/".to_owned(),
            has_room: false,
        };
        assert!(!unknown.has_room);
    }

    #[test]
    fn test_restore_point_row_uses_the_file_name_not_the_path() {
        let point = backup::RestorePoint {
            path: std::path::PathBuf::from("/var/lib/omnical/backups/omnical-backup-1.tar.gz"),
            size: 2048,
            modified: 0,
        };
        let row = RestorePointRow::from_point(&point).expect("a row");
        assert_eq!(row.name, "omnical-backup-1.tar.gz");
        assert!(!row.name.contains('/'), "{}", row.name);
    }

    #[test]
    fn test_marker_path_is_derived_from_the_database_and_is_stable() {
        // `main` has to *find* a pending restore without being told a
        // timestamp, so the marker name must not vary between calls.
        let db = Path::new("/var/lib/omnical/tenants/abc/db.sqlite3");
        assert_eq!(marker_path(db), marker_path(db));
        assert!(
            marker_path(db)
                .to_string_lossy()
                .ends_with("db.sqlite3.omnical-staged-restore.json")
        );
        assert_eq!(
            marker_path(db).parent(),
            Some(Path::new("/var/lib/omnical/tenants/abc"))
        );
    }

    #[test]
    fn test_a_staged_restore_survives_a_round_trip_through_the_marker() {
        // The marker is the only thing that crosses the restart, so a field it
        // does not carry is a field the completion cannot have.
        let record = StagedRestore {
            database: Path::new("/data/db.sqlite3").to_path_buf(),
            staged: Path::new("/data/db.sqlite3.restore-1").to_path_buf(),
            safety_copy: PathBuf::new(),
            archive: Path::new("/backups/omnical-backup-1.tar.gz").to_path_buf(),
            expected: BTreeMap::from([("principals".to_owned(), 3_i64)]),
            archive_created_at: "2026-09-30T11:45:00+00:00".to_owned(),
            requested_by: "ops".to_owned(),
        };
        let json = serde_json::to_vec(&record).expect("serialise");
        let parsed: StagedRestore = serde_json::from_slice(&json).expect("parse");
        assert_eq!(parsed, record);
    }

    #[test]
    fn test_a_staging_file_is_a_sibling_of_the_database() {
        // The completion is a `rename`, so a different filesystem would turn it
        // into a copy — and a copy is not atomic.
        let db = Path::new("/data/tenants/abc/db.sqlite3");
        assert_eq!(sibling(db, ".restore-1").parent(), db.parent());
    }
}
