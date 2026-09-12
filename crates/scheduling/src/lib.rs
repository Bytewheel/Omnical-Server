#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::module_name_repetitions,
    clippy::too_many_lines
)]
//! Omnical scheduling extension for RustiCal: a pragmatic subset of RFC 6638
//! (CalDAV scheduling) that enables Apple Calendar (iOS/macOS) to show its
//! invitees UI and delivers invitations either server-side (internal
//! attendees, via the schedule-inbox) or via iMIP email (external attendees,
//! through the organizer's SMTP account). Inbound replies from external
//! attendees are ingested by polling the organizer's IMAP mailbox
//! (RFC 6047).

pub mod config;
pub mod error;
pub mod ics;
pub mod imap;
pub mod ingest;
pub mod mime;
pub mod mime_parse;
pub mod rsvp;
pub mod scheduler;
pub mod smtp;
mod tls;

pub use config::{ImapAccount, SchedulingConfig, SmtpAccount};
pub use error::SchedulingError;
pub use rsvp::RsvpClaims;
pub use scheduler::{DAV_TOKENS, OutboxStatus, RsvpError, RsvpEvent, Scheduler};
