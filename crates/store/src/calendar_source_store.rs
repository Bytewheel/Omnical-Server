use crate::error::Error;
use async_trait::async_trait;

/// A linked external subscribe URL materialized into one calendar (Omnical
/// registration extension / "linked platforms").
///
/// The server fetches the `source_url` (a public read-only `.ics` feed),
/// inserts the events into `calendar_id`, and stores the mapping here so a
/// later explicit refresh can diff by UID. Removing the mapping leaves the
/// materialized calendar data behind — a linked source is a copy by design.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CalendarSource {
    pub id: String,
    pub principal: String,
    pub calendar_id: String,
    pub source_url: String,
    /// Hostname of `source_url` (used by the importer's SSRF reporting).
    pub provider_host: String,
    pub last_fetch_at: Option<String>,
    pub last_fetch_success: bool,
    pub created_at: Option<String>,
}

/// Data access for linked external calendar sources (Omnical extension).
///
/// This is implemented by the `SQLite` store. The default implementations are
/// no-ops/errors so other (test) stores keep compiling unchanged.
#[async_trait]
pub trait CalendarSourceStore: Send + Sync + 'static {
    /// Store a linked source (caller generates the id via the store's
    /// implementation). A duplicate `(principal, calendar_id, source_url)` is
    /// rejected so the importer cannot create double mappings.
    ///
    /// # Errors
    /// - [`Error::ReadOnly`] if the store does not implement calendar sources
    /// - [`Error::AlreadyExists`] if the triple already exists
    async fn add_calendar_source(
        &self,
        _principal: &str,
        _calendar_id: &str,
        _source_url: &str,
        _provider_host: &str,
    ) -> Result<String, Error> {
        Err(Error::ReadOnly)
    }

    /// List all linked sources of a principal.
    ///
    /// # Errors
    /// Any store error (no sources is an empty list, not an error).
    async fn get_calendar_sources(&self, _principal: &str) -> Result<Vec<CalendarSource>, Error> {
        Ok(vec![])
    }

    /// Look up one linked source, scoped to the owning principal.
    ///
    /// # Errors
    /// - [`Error::NotFound`] if the principal has no source with this id or
    ///   the store does not implement calendar sources
    async fn get_calendar_source(
        &self,
        _principal: &str,
        _id: &str,
    ) -> Result<CalendarSource, Error> {
        Err(Error::NotFound)
    }

    /// Record the outcome of a refresh (fetch time + success flag).
    ///
    /// # Errors
    /// - [`Error::NotFound`] if the principal has no source with this id
    async fn update_calendar_source_fetch(
        &self,
        _principal: &str,
        _id: &str,
        _last_fetch_at: &str,
        _success: bool,
    ) -> Result<(), Error> {
        Err(Error::NotFound)
    }

    /// Unlink a source. Leaves the materialized calendar data intact.
    ///
    /// # Errors
    /// - [`Error::NotFound`] if the principal has no source with this id or
    ///   the store does not implement calendar sources
    async fn delete_calendar_source(&self, _principal: &str, _id: &str) -> Result<(), Error> {
        Err(Error::NotFound)
    }

    /// Record which materialized objects a source owns after an import or
    /// refresh — the recorded set scopes the next refresh's by-UID diff to
    /// this source's own events. A calendar can carry several sources at
    /// once (the create-calendar modal merges several holiday sets into one
    /// calendar; the linked-platforms form can point several URLs at one),
    /// so a refresh must not treat every other set's events as "vanished
    /// from the feed". Replaces the source's set atomically.
    ///
    /// # Errors
    /// - [`Error::ReadOnly`] if the store does not implement calendar sources
    /// - [`Error::NotFound`] if the source is not the principal's
    async fn record_source_objects(
        &self,
        _principal: &str,
        _source_id: &str,
        _object_ids: &[String],
    ) -> Result<(), Error> {
        Err(Error::ReadOnly)
    }

    /// The object ids a source owns (recorded by the last import/refresh).
    /// An empty list means a source predates the ownership rows (or holds a
    /// legitimately empty feed) — the refresh engine falls back to the
    /// pre-ownership whole-calendar diff in that case, which the
    /// mass-delete abort still guards.
    ///
    /// # Errors
    /// Any store error (no recorded ids is an empty list, not an error).
    async fn get_source_object_ids(
        &self,
        _principal: &str,
        _source_id: &str,
    ) -> Result<Vec<String>, Error> {
        Ok(Vec::new())
    }
}
