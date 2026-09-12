use crate::error::Error;
use async_trait::async_trait;

/// An object stored in a principal's scheduling inbox
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboxObject {
    pub object_id: String,
    pub ics: String,
}

/// Data access for RFC 6638 style scheduling (Omnical extension).
///
/// This is implemented by the SQLite store. The default implementations are
/// no-ops so other (test) stores keep compiling unchanged.
#[async_trait]
pub trait SchedulingStore: Send + Sync + 'static {
    /// Whether `principal` is a local principal id (used to decide if an
    /// attendee/organizer is served by this server).
    async fn principal_exists(&self, _principal: &str) -> Result<bool, Error> {
        Ok(false)
    }

    /// The group principals `principal` is a member of (used to locate an
    /// organizer's copies of an event in group calendars).
    async fn principal_memberships(&self, _principal: &str) -> Result<Vec<String>, Error> {
        Ok(vec![])
    }

    /// Insert or replace an object in a principal's scheduling inbox.
    async fn put_inbox_object(
        &self,
        _principal: &str,
        _object_id: &str,
        _ics: &str,
    ) -> Result<(), Error> {
        Ok(())
    }

    async fn get_inbox_object(
        &self,
        _principal: &str,
        _object_id: &str,
    ) -> Result<InboxObject, Error> {
        Err(Error::NotFound)
    }

    async fn get_inbox_objects(&self, _principal: &str) -> Result<Vec<InboxObject>, Error> {
        Ok(vec![])
    }

    async fn delete_inbox_object(&self, _principal: &str, _object_id: &str) -> Result<(), Error> {
        Err(Error::NotFound)
    }

    /// Find all calendar objects with the given UID owned by `principal`.
    /// Returns (calendar_id, object_id, ics) triples.
    async fn find_calendar_objects_by_uid(
        &self,
        _principal: &str,
        _uid: &str,
    ) -> Result<Vec<(String, String, String)>, Error> {
        Ok(vec![])
    }

    /// Replace the raw ICS of a stored calendar object (used to apply
    /// attendee PARTSTAT updates to an organizer's copy).
    async fn update_calendar_object_ics(
        &self,
        _principal: &str,
        _calendar_id: &str,
        _object_id: &str,
        _ics: &str,
    ) -> Result<(), Error> {
        Err(Error::NotFound)
    }
}
