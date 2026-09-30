//! The `rustical` side of the appliance panel: an [`ApplianceService`]
//! implementation, and the two things it is allowed to do.
//!
//! Everything the panel renders is produced here, **after**
//! [`redact`](crate::commands::support_bundle::redact) has run. `crates/frontend`
//! declares the trait and holds no secret; this file is the only place that can
//! read the config, run `ip`, or call `statvfs`.
//!
//! ## The one thing this must not become
//!
//! **A second way to reach a tenant's database.** The admin panel beside it is
//! forbidden from opening one, and that is a property of its types. This service
//! *is* allowed to touch the appliance's own database — a restore replaces it —
//! so the discipline has to be explicit rather than structural:
//!
//! - It touches **one configured path**, resolved from `[appliance] database`.
//!   It is not a "pick a tenant and get its store" function, because that would
//!   be a tenant-database API wearing a panel's clothes.
//! - A request handler **never opens** it. `stage_restore` verifies a tar and
//!   copies files. The row counts are measured in `main`, before the pool opens,
//!   by [`appliance::complete_staged_restore`].
//! - The archive name a client sends is **re-joined against the configured
//!   backup directory** and rejected if it escapes. It is never used as a path.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use rustical_frontend::{
    AddressView, ApplianceService, DataView, FirmwareView, ImageView, NetworkView, PendingView,
    ReportView, RestorePointView, StagedView,
};
use rustical_store::tenant_store::TenantStore;
use tracing::{info, warn};

use crate::appliance::{self, ApplianceFacts, FirmwareFacts, RestoreReport, SysupgradeWriter};

/// The service, over one appliance's own database.
///
/// `Debug` is hand-written for the same reason `ApplianceFacts`'s is: the fields
/// include a store and a firmware writer that are not `Debug`, and there is
/// nothing here worth printing anyway.
pub struct RusticalApplianceService {
    facts: ApplianceFacts,
    firmware: Arc<dyn appliance::FirmwareWriter>,
    /// The control plane, for the audit trail only. A separate field from
    /// `facts` so it is obvious this is the *only* store here and it is not a
    /// tenant's.
    audit: Arc<dyn TenantStore>,
    restart: Arc<dyn crate::setup_mode::SetupRestart>,
    /// Where firmware images are listed from and flashed from.
    firmware_dir: PathBuf,
}

impl std::fmt::Debug for RusticalApplianceService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RusticalApplianceService")
            .field("facts", &self.facts)
            .field("firmware_dir", &self.firmware_dir)
            .finish_non_exhaustive()
    }
}

/// Everything the service needs, gathered once at start-up.
///
/// # Errors
/// If the config names a database inside the backup directory, or the backup
/// directory cannot be resolved. Both are refused rather than corrected: a
/// service that silently fixes a nonsensical path is a service whose operator
/// cannot predict what it will touch.
pub fn service_for(
    facts: ApplianceFacts,
    firmware: Arc<dyn appliance::FirmwareWriter>,
    audit: Arc<dyn TenantStore>,
    restart: Arc<dyn crate::setup_mode::SetupRestart>,
    firmware_dir: PathBuf,
) -> Result<Arc<dyn ApplianceService>> {
    if facts.backup_dir.as_path() == facts.database.parent().unwrap_or_else(|| Path::new("/")) {
        bail!(
            "[appliance] backup_dir and the database's directory are the same ({}). Restore \
             points and the live database would be listed as each other",
            facts.backup_dir.display()
        );
    }
    Ok(Arc::new(RusticalApplianceService {
        facts,
        firmware,
        audit,
        restart,
        firmware_dir,
    }))
}

impl RusticalApplianceService {
    /// Resolve a client-supplied archive **name** against the configured backup
    /// directory.
    ///
    /// The name is untrusted. Three things are checked, and all three are
    /// needed:
    ///
    /// 1. **No separator.** `/` or `\` means the client is trying to name a
    ///    path, not a file in one directory.
    /// 2. **No parent reference.** `..` is the same attack with more steps.
    /// 3. **It must actually be in the listing.** Not a path check — a
    ///    membership check against [`list_restore_points`], so the set of
    ///    restorable files is exactly the set the operator was shown, including
    ///    its `.part` exclusion. A name that passes 1 and 2 but is not a
    ///    restore point is refused.
    ///
    /// The final `canonicalize` + `starts_with` is belt and braces: if a symlink
    /// in the backup directory points somewhere else, this is what catches it.
    fn resolve_archive(&self, name: &str) -> Result<PathBuf> {
        let trimmed = name.trim();
        if trimmed.is_empty() {
            bail!("no archive was named");
        }
        if trimmed.contains(['/', '\\']) || trimmed.contains("..") || trimmed.starts_with('.') {
            bail!(
                "{trimmed:?} is not a file name. The panel restores archives that are already in \
                 the configured backup directory, and this does not name one"
            );
        }
        let candidate = self.facts.backup_dir.join(trimmed);
        let listed = appliance::restore_points(&self.facts.backup_dir)
            .with_context(|| format!("listing {}", self.facts.backup_dir.display()))?;
        if !listed
            .iter()
            .any(|point| point.path.file_name().is_some_and(|n| n == trimmed))
        {
            bail!(
                "{trimmed:?} is not one of the restore points in {}. It may have been removed, or \
                 it may still be a .part file from a backup that has not finished",
                self.facts.backup_dir.display()
            );
        }
        // Symlink escape. `canonicalize` on both sides, then a prefix check on
        // the *directory*, not the file, so a directory named `backups-evil`
        // beside `backups` cannot pass.
        let real_dir = self
            .facts
            .backup_dir
            .canonicalize()
            .with_context(|| format!("resolving {}", self.facts.backup_dir.display()))?;
        let real_file = candidate
            .canonicalize()
            .with_context(|| format!("resolving {}", candidate.display()))?;
        if !real_file.starts_with(&real_dir) {
            bail!(
                "{} resolves outside the backup directory — refusing to restore it",
                candidate.display()
            );
        }
        Ok(candidate)
    }

    /// The firmware images in the configured directory.
    ///
    /// `*.bin` and `*.img`, which is what a `sysupgrade` accepts. A `sysupgrade`
    /// image can be either depending on the platform, and offering only one
    /// would hide half the images on half the hardware.
    fn images(&self) -> Result<Vec<ImageView>, String> {
        let entries = std::fs::read_dir(&self.firmware_dir)
            .map_err(|e| format!("listing {}: {e}", self.firmware_dir.display()))?;
        let mut out = Vec::new();
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let Some(name) = path.file_name().and_then(std::ffi::OsStr::to_str) else {
                continue;
            };
            if !is_firmware_image(Path::new(name)) {
                continue;
            }
            // Skipped for the same reason `.part` is: a half-copied image is
            // not something to flash, and `sysupgrade` would fail on it anyway.
            if name.starts_with('.') || name.contains(".part") {
                continue;
            }
            let size = std::fs::metadata(&path).map_or(0, |m| m.len());
            out.push(ImageView {
                name: name.to_owned(),
                size_text: crate::commands::backup::format_size(size),
            });
        }
        out.sort_by(|a, b| b.name.cmp(&a.name));
        Ok(out)
    }

    /// Resolve a client-supplied image **name** against the firmware directory.
    ///
    /// The same three checks as [`Self::resolve_archive`], plus a suffix check:
    /// only `*.bin` and `*.img` are flashable, and a panel that will pass
    /// anything the client names is a panel that will eventually be talked into
    /// running `sysupgrade` against `/etc/config`.
    fn resolve_image(&self, name: &str) -> Result<PathBuf> {
        let trimmed = name.trim();
        if trimmed.is_empty() {
            bail!("no firmware image was named");
        }
        if trimmed.contains(['/', '\\']) || trimmed.contains("..") || trimmed.starts_with('.') {
            bail!("{trimmed:?} is not a file name");
        }
        if !is_firmware_image(Path::new(trimmed)) {
            bail!("{trimmed:?} is not a firmware image (.bin or .img)");
        }
        let candidate = self.firmware_dir.join(trimmed);
        if !candidate.is_file() {
            bail!(
                "{} is not in {}",
                candidate.display(),
                self.firmware_dir.display()
            );
        }
        Ok(candidate)
    }
}

fn to_report_view(report: &RestoreReport) -> ReportView {
    // One row per table, expected-vs-actual, with the tables that disagree
    // marked. Computing the marker here rather than in the template keeps the
    // template free of comparisons it would have to get right.
    let rows = report
        .expected
        .iter()
        .map(|(table, expected)| {
            let actual = report.actual.get(table);
            let text = match actual {
                Some(actual) if actual == expected => format!("{expected}"),
                Some(actual) => format!("{expected} &rarr; **{actual}**"),
                None => format!("{expected} &rarr; **missing**"),
            };
            (table.clone(), expected.to_string(), text)
        })
        .collect();
    ReportView {
        archive: report.archive.display().to_string(),
        archive_created_at: report.archive_created_at.clone(),
        completed_at: report.completed_at.clone(),
        requested_by: report.requested_by.clone(),
        verified: report.is_verified(),
        integrity_check: report.integrity_check.clone(),
        claim: report.claim(),
        rows,
        mismatches: report.comparison.mismatches.clone(),
        missing: report.comparison.missing.clone(),
        added_by_migration: report.comparison.added_by_migration.clone(),
        losses: report
            .losses()
            .into_iter()
            .map(|(table, before, after)| (table, before.to_string(), after.to_string()))
            .collect(),
        safety_copy: report
            .safety_copy
            .as_ref()
            .map(|path| path.display().to_string()),
    }
}

fn to_firmware_view(
    facts: &FirmwareFacts,
    can_flash: bool,
    images: Vec<ImageView>,
    firmware_dir: &std::path::Path,
) -> FirmwareView {
    FirmwareView {
        version: facts.version.clone(),
        commit: facts.commit.clone(),
        size_text: facts.size_text.clone(),
        free_text: facts.free_text.clone(),
        overlay_mount: facts.overlay_mount.clone(),
        firmware_dir: firmware_dir.display().to_string(),
        has_room: facts.has_room,
        space_known: facts.free.is_some(),
        can_flash,
        images,
    }
}

/// Is this name a flashable firmware image?
///
/// **`.bin` or `.img`, compared case-insensitively.** Both, because a
/// `sysupgrade` image's extension depends on the platform and offering only one
/// would hide half the images on half the hardware. Case-insensitively, because
/// `IMAGE.BIN` is the same file to `sysupgrade` and an operator who copied an
/// image onto a case-preserving filesystem should not be told it is not an
/// image.
///
/// The extension is taken with [`Path::extension`] rather than by scanning the
/// string, so a directory called `firmware.bin` is not mistaken for an image
/// and `image.tar.gz` is not either.
fn is_firmware_image(name: &Path) -> bool {
    name.extension()
        .and_then(std::ffi::OsStr::to_str)
        .is_some_and(|extension| {
            extension.eq_ignore_ascii_case("bin") || extension.eq_ignore_ascii_case("img")
        })
}

#[async_trait::async_trait]
impl ApplianceService for RusticalApplianceService {
    async fn data(&self) -> Result<DataView, String> {
        let facts = appliance::data_facts(&self.facts).map_err(|e| e.to_string())?;
        let restore_points = facts
            .restore_points
            .iter()
            .map(|point| RestorePointView {
                name: point.name.clone(),
                size_text: point.size_text.clone(),
                modified_text: point.modified_text.clone(),
            })
            .collect();
        // The report is read on **every** request rather than memoised.
        //
        // The first draft cached it in a `Mutex<Option<...>>` on the theory that
        // it only changes when a restore completes, which is true in production
        // — the completion is in `main`, and `main` is a new process. It is
        // **not** true of a test that completes a restore in-process, and the
        // test caught it: the panel kept reporting "no restore has been run"
        // after one had. A cache whose invalidation depends on a fact outside the
        // process is a cache that can be wrong, and reading one small JSON file
        // per page view is not a cost worth that. `data()` is not a hot path —
        // it is an operator opening a page because something is wrong.
        let (last_report, report_error) = match appliance::last_restore_report(&self.facts.database)
        {
            None => (None, None),
            Some(Ok(report)) => (Some(to_report_view(&report)), None),
            Some(Err(e)) => (None, Some(e.to_string())),
        };
        Ok(DataView {
            database: facts.database.display().to_string(),
            backup_dir: facts.backup_dir.display().to_string(),
            database_exists: facts.database_exists,
            restore_points,
            pending: facts.pending.as_ref().map(|pending| PendingView {
                archive: pending.archive.display().to_string(),
                archive_created_at: pending.archive_created_at.clone(),
                staged: pending.staged.display().to_string(),
                // `None`, not an empty path, when there was no live database to
                // copy — the template renders "there was no database to copy"
                // rather than a path pointing at the live file itself.
                safety_copy: if pending.safety_copy.as_os_str().is_empty() {
                    None
                } else {
                    Some(pending.safety_copy.display().to_string())
                },
                requested_by: pending.requested_by.clone(),
            }),
            last_report,
            report_error,
        })
    }

    async fn network(&self) -> Result<NetworkView, String> {
        let facts = appliance::network_section(&self.facts).map_err(|e| e.to_string())?;
        Ok(NetworkView {
            addresses: facts
                .addresses
                .into_iter()
                .map(|address| AddressView {
                    interface: address.interface,
                    family: address.family,
                    address: address.address,
                    prefix_len: address.prefix_len,
                })
                .collect(),
            bind: facts.bind,
            public_url: facts.public_url,
            data_root: facts.data_root,
            admin_hosts: facts.admin_hosts,
        })
    }

    async fn firmware(&self) -> Result<FirmwareView, String> {
        let facts = appliance::firmware_section(&self.facts).map_err(|e| e.to_string())?;
        // An unlistable firmware directory is not fatal: the version, the sizes
        // and the free space are still true, and an operator debugging a box
        // needs those more than they need a flash button.
        let images = self.images().unwrap_or_else(|e| {
            warn!(%e, "appliance panel: the firmware directory could not be listed");
            Vec::new()
        });
        Ok(to_firmware_view(
            &facts,
            self.firmware.available(),
            images,
            &self.firmware_dir,
        ))
    }

    async fn stage_restore(&self, archive_name: &str, admin: &str) -> Result<StagedView, String> {
        let archive = self
            .resolve_archive(archive_name)
            .map_err(|e| e.to_string())?;
        let staged = appliance::stage_restore(&archive, &self.facts.database, admin)
            .map_err(|e| e.to_string())?;
        Ok(StagedView {
            archive: archive.display().to_string(),
            archive_created_at: staged.archive_created_at,
            staged: staged.staged.display().to_string(),
            safety_copy: staged
                .safety_copy
                .as_ref()
                .map(|path| path.display().to_string()),
            expected_tables: staged.expected_tables,
            requested_by: admin.to_owned(),
        })
    }

    async fn restore_pending(&self) -> bool {
        appliance::restore_is_staged(&self.facts.database)
    }

    async fn last_report(&self) -> Option<Result<ReportView, String>> {
        match appliance::last_restore_report(&self.facts.database) {
            None => None,
            Some(Ok(report)) => Some(Ok(to_report_view(&report))),
            Some(Err(e)) => Some(Err(e.to_string())),
        }
    }

    async fn flash(&self, image_name: &str, admin: &str) -> Result<(), String> {
        let image = self.resolve_image(image_name).map_err(|e| e.to_string())?;
        info!(image = %image.display(), %admin, "appliance panel: flashing firmware");
        self.firmware.write(&image).await.map_err(|e| e.to_string())
    }

    async fn firmware_images(&self) -> Result<Vec<ImageView>, String> {
        self.images()
    }

    async fn can_flash(&self) -> bool {
        self.firmware.available()
    }

    async fn audit(&self, admin: &str, action: &str, detail: &str) -> Result<(), String> {
        // The audit trail is a control-plane table and this action is not
        // tenant-scoped, so the tenant column is `None` — the same shape a
        // tenant creation uses. `AdminPanel`'s mutations audit through the
        // store methods themselves; there is no free-standing audit write on the
        // trait, so this is the one place that has to be honest about the
        // difference rather than pretend it is the same door.
        let actor = rustical_store::Actor::new(admin)
            .map_err(|e| format!("{admin:?} cannot be recorded as an audit actor: {e}"))?;
        self.audit
            .record_appliance_action(&actor, action, detail)
            .await
            .map_err(|e| e.to_string())
    }

    fn request_restart(&self) {
        self.restart.request_restart();
    }
}

/// The real writer, for production wiring.
#[must_use]
pub fn sysupgrade_writer() -> Arc<dyn appliance::FirmwareWriter> {
    Arc::new(SysupgradeWriter::new())
}
