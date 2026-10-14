//! Push-mirror state (Omnical §18.41, `PLAN_DEPLOYMENTS.md`): what a
//! `[mirror]` target last wrote to its remote `CalDAV` collection.
//!
//! A mirror is a one-way push from one local calendar to one remote
//! `CalDAV` collection (aphy in the reference deployment). Each run PUTs
//! the desired object set and must also DELETE objects it previously
//! wrote that have since vanished from the source — which requires
//! remembering exactly that set. The rows are keyed on the mirror's
//! config `name`, so removing a target from the config orphans its rows
//! harmlessly (nothing reads them; they are replaced, never diffed,
//! when the name returns).
//!
//! Implemented by the `SQLite` store. The default implementations are
//! no-ops/errors so other (test) stores keep compiling unchanged.

use crate::error::Error;
use async_trait::async_trait;

/// One object a mirror target wrote to its remote: the (remote) href it
/// lives at, and the body hash the mirror last pushed.
///
/// The hash drives change detection; the href is remembered so deletes can
/// be issued without re-listing the remote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MirrorObject {
    pub uid: String,
    pub href: String,
    pub hash: String,
}

/// One completed (or failed) sync run of one mirror target — the record the
/// profile page's "last sync" line reads (§18.42).
///
/// Written by the engine itself, so every sync surface — the background
/// loop, the cron'd CLI, the profile page's button — leaves the same
/// receipt. A `None` `error` is a run that finished; `Some` is a run that
/// aborted before its first write (store failure), which is exactly the
/// distinction the UI needs to draw.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MirrorRun {
    /// When the run finished, `%Y-%m-%dT%H:%M:%SZ` (UTC, plain-string
    /// comparable like the password-reset rows).
    pub ran_at: String,
    pub put: usize,
    pub deleted: usize,
    pub unchanged: usize,
    pub error: Option<String>,
}

#[async_trait]
pub trait MirrorStore: Send + Sync + 'static {
    /// All objects one mirror target last wrote.
    ///
    /// # Errors
    /// Any store error (no rows is an empty list, not an error).
    async fn get_mirror_objects(&self, _mirror: &str) -> Result<Vec<MirrorObject>, Error> {
        Ok(vec![])
    }

    /// Replace the recorded state of one mirror target wholesale: the caller
    /// has just made the remote match `objects`, so the rows simply say what
    /// exists now. Delete detection on the *next* run diffs against this.
    ///
    /// # Errors
    /// - [`Error::ReadOnly`] if the store does not implement mirror state
    async fn replace_mirror_objects(
        &self,
        _mirror: &str,
        _objects: &[MirrorObject],
    ) -> Result<(), Error> {
        Err(Error::ReadOnly)
    }

    /// Record one completed/failed run of one target (§18.42): the profile
    /// page's "last sync" line, written by the engine after every attempt.
    ///
    /// # Errors
    /// - [`Error::ReadOnly`] if the store does not implement mirror state
    async fn record_mirror_run(&self, _mirror: &str, _run: &MirrorRun) -> Result<(), Error> {
        Err(Error::ReadOnly)
    }

    /// The newest recorded run of one target, when it has ever run.
    ///
    /// # Errors
    /// Any store error (never run is `Ok(None)`, not an error).
    async fn last_mirror_run(&self, _mirror: &str) -> Result<Option<MirrorRun>, Error> {
        Ok(None)
    }
}
