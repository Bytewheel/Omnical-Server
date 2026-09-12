//! CalDAV layer of the Omnical RFC 6638 scheduling extension.
//!
//! When a [`rustical_scheduling::Scheduler`] is enabled, this module serves
//! the per-principal schedule-inbox (a real, DB-backed collection) and
//! schedule-outbox (accepts iTIP POSTs) and fills the RFC 6638 principal
//! properties (`schedule-inbox-URL`, `schedule-outbox-URL`,
//! `schedule-default-calendar-URL`).

pub mod inbox;
pub mod outbox;

pub use inbox::{
    InboxObjectResource, InboxObjectResourceService, InboxResource, InboxResourceService,
};
pub use outbox::{OutboxResource, OutboxResourceService, ScheduleResponse};

use rustical_ical::CalendarObjectType;
use rustical_scheduling::{DAV_TOKENS, Scheduler};
use rustical_store::Calendar;
use std::borrow::Cow;

/// Principal-level scheduling information, present when the scheduling
/// extension is enabled.
#[derive(Debug, Clone)]
pub struct SchedulingProps {
    pub(crate) default_calendar_id: Option<String>,
}

/// `DAV` header advertised by the CalDAV services: the scheduling feature
/// tokens are appended only while the extension is enabled.
pub(crate) fn dav_header_with_scheduling(
    base: &'static str,
    scheduler: Option<&Scheduler>,
) -> Cow<'static, str> {
    if scheduler.is_some_and(Scheduler::enabled) {
        Cow::Owned(format!("{base}, {DAV_TOKENS}"))
    } else {
        Cow::Borrowed(base)
    }
}

/// Pick the calendar a client should store newly scheduled events in:
/// the first user-writable VEVENT calendar (internal `_`-prefixed and
/// subscribed calendars are skipped).
pub(crate) fn select_default_calendar_id(calendars: &[Calendar]) -> Option<String> {
    calendars
        .iter()
        .filter(|cal| {
            cal.subscription_url.is_none()
                && !cal.id.starts_with('_')
                && cal.components.contains(&CalendarObjectType::Event)
        })
        .min_by(|a, b| (a.meta.order, &a.id).cmp(&(b.meta.order, &b.id)))
        .map(|cal| cal.id.clone())
}

#[cfg(test)]
mod tests;
