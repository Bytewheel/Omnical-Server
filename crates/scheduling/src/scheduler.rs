//! The Omnical scheduling engine (RFC 6638 "implicit scheduling" subset).
//!
//! Wire-up lives in `rustical_caldav` (PUT/DELETE hooks, inbox/outbox
//! resources); this module decides *what* must be delivered when an event
//! changes and performs the deliveries:
//!
//! * Internal attendees/organizers (principals of this server) are served
//!   through their schedule-inbox, fully server-side.
//! * External attendees/organizers are served via iMIP email through the
//!   organizer/attendee's own SMTP account.
//!
//! Everything is deliberately conservative: unknown or ambiguous situations
//! log a warning and do nothing rather than spam invitations.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use tracing::{info, instrument, warn};

use rustical_store::SchedulingStore;

use crate::config::{ImapAccount, SchedulingConfig, SmtpAccount};
use crate::ics;
use crate::mime;
use crate::rsvp;
use crate::smtp;

pub struct Scheduler {
    store: Arc<dyn SchedulingStore>,
    config: SchedulingConfig,
}

// Manual impl: the config carries SMTP passwords which must never leak
// into Debug output (e.g. through PrincipalResourceService's derive).
impl fmt::Debug for Scheduler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Scheduler")
            .field("enabled", &self.config.enabled)
            .finish_non_exhaustive()
    }
}

/// DAV feature tokens to advertise when scheduling is enabled.
pub const DAV_TOKENS: &str = "calendar-scheduling, calendar-auto-schedule";

/// Result of one outbox POST delivery.
pub struct OutboxStatus {
    pub recipient: String,
    pub code: u16,
    pub message: String,
}

/// What the public RSVP page shows about an invitation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RsvpEvent {
    pub summary: String,
    /// Humanized DTSTART (see [`ics::humanize_dtstart`]).
    pub when: String,
    pub recurring: bool,
    pub organizer: String,
    pub attendee: String,
    /// The attendee's current PARTSTAT (`NEEDS-ACTION` before the first
    /// response; the freshly applied one after [`Scheduler::rsvp_apply`]).
    pub partstat: String,
}

/// Failure modes of the public RSVP routes; the router maps each to a
/// status + page.
#[derive(Debug, PartialEq, Eq)]
pub enum RsvpError {
    /// Unknown/expired token, or the organizer is no longer served by
    /// this server → 404 (indistinguishable from a bogus path).
    Invalid,
    /// Valid token, but the event or the attendee's invitation is gone
    /// (cancelled/deleted/uninvited) → 410.
    Gone,
    /// Unknown response word → 400.
    BadResponse,
    /// Operational failure → 500.
    Store(String),
}

impl OutboxStatus {
    fn success(recipient: String, message: &str) -> Self {
        Self {
            recipient,
            code: 2_00,
            message: message.to_owned(),
        }
    }

    fn failure(recipient: String, message: String) -> Self {
        Self {
            recipient,
            code: 5_00,
            message,
        }
    }
}

#[derive(Debug)]
enum DeliveryKind {
    /// Organizer notifying attendees about an event (REQUEST/CANCEL)
    OrganizerPush { method: &'static str },
}

impl Scheduler {
    #[must_use]
    pub fn new(config: SchedulingConfig, store: Arc<dyn SchedulingStore>) -> Self {
        Self { store, config }
    }

    #[must_use]
    pub fn enabled(&self) -> bool {
        self.config.enabled
    }

    /// The backing store handle (used by the CalDAV layer to serve the
    /// schedule-inbox collections).
    #[must_use]
    pub fn store(&self) -> Arc<dyn SchedulingStore> {
        self.store.clone()
    }

    /// The IMAP mailboxes polled for inbound iMIP replies.
    #[must_use]
    pub fn imap_accounts(&self) -> &[ImapAccount] {
        &self.config.imap
    }

    /// Poll cadence of the IMAP ingestion loop (floored to protect mail
    /// providers from aggressive configurations).
    #[must_use]
    pub fn imap_poll_interval(&self) -> Duration {
        Duration::from_secs(self.config.imap_poll_secs.max(30))
    }

    /// Called by the CalDAV PUT handler after an object was stored.
    ///
    /// `acting_user` is the *authenticated* principal (email id), `current`
    /// the (principal, calendar, object) location the PUT targeted — the
    /// copy just written is excluded from the move-guard lookup — and
    /// `old_ics` the previous object at the same href (if any).
    #[instrument(skip(self, new_ics))]
    pub async fn handle_put(
        &self,
        acting_user: &str,
        current: (&str, &str, &str),
        old_ics: Option<&str>,
        new_ics: &str,
        ua: Option<&str>,
    ) {
        if self.run_guard() {
            return;
        }
        let Some(event) = ics::parse_event(new_ics) else {
            return;
        };

        if event.method.is_some() {
            // Stored objects must not carry METHOD; iTIP messages are not
            // scheduling triggers.
            return;
        }

        let Some(organizer) = event.organizer.clone() else {
            // No ORGANIZER on the event (e.g. khal-created events):
            // the acting user acts as the organizer if they are an
            // attendee or own the calendar being written to.
            let is_attendee = event.attendees.iter().any(|a| a.email.eq_ignore_ascii_case(acting_user));
            let owns_calendar = current.0.eq_ignore_ascii_case(acting_user);
            if is_attendee || owns_calendar {
                self.organizer_put(acting_user, current, &event, old_ics, new_ics, acting_user)
                    .await;
            }
            return;
        };

        if organizer.eq_ignore_ascii_case(acting_user) {
            self.organizer_put(acting_user, current, &event, old_ics, new_ics, &organizer)
                .await;
        } else {
            self.attendee_put(acting_user, &event, old_ics).await;
        }
    }

    /// Called by the CalDAV DELETE handler after an object was removed.
    #[instrument(skip(self, deleted_ics))]
    pub async fn handle_delete(&self, acting_user: &str, deleted_ics: &str, ua: Option<&str>) {
        if self.run_guard() {
            return;
        }
        let Some(event) = ics::parse_event(deleted_ics) else {
            return;
        };
        if event.method.is_some() || event.attendees.is_empty() {
            return;
        }
        let Some(organizer) = event.organizer.clone() else {
            // No ORGANIZER on the event: the acting user acts as the
            // organizer for the CANCEL. The CalDAV layer already
            // authenticated and authorised the delete.
            self.deliver(
                &DeliveryKind::OrganizerPush { method: "CANCEL" },
                &event,
                deleted_ics,
                acting_user,
            )
            .await;
            return;
        };
        if !organizer.eq_ignore_ascii_case(acting_user) {
            // Attendees deleting their copy do not cancel the event.
            return;
        }
        if event.status.as_deref().is_some_and(|s| s == "CANCELLED") {
            // Already cancelled before; do not re-cancel.
            return;
        }

        // Move guard: if the UID still exists anywhere under this user (or
        // their groups), this was a move between calendars, not a deletion.
        let mut principals = vec![acting_user.to_owned()];
        if let Ok(memberships) = self.store.principal_memberships(acting_user).await {
            principals.extend(memberships);
        }
        for principal in principals {
            match self
                .store
                .find_calendar_objects_by_uid(&principal, &event.uid)
                .await
            {
                Ok(copies) if !copies.is_empty() => {
                    info!(
                        uid = event.uid,
                        remaining_in = principal,
                        "skipping CANCEL: event was moved, not deleted"
                    );
                    return;
                }
                Ok(_) => {}
                Err(err) => {
                    warn!("scheduling CANCEL: UID lookup failed: {err}");
                    return;
                }
            }
        }

        self.deliver(
            &DeliveryKind::OrganizerPush { method: "CANCEL" },
            &event,
            deleted_ics,
            &organizer,
        )
        .await;
    }

    /// POST to the schedule-outbox (explicit scheduling, RFC 6638 section 8).
    /// Returns per-recipient statuses for the schedule-response.
    #[instrument(skip(self, body))]
    pub async fn handle_outbox_post(
        &self,
        acting_user: &str,
        body: &str,
    ) -> Result<Vec<OutboxStatus>, String> {
        let Some(event) = ics::parse_event(body) else {
            return Err("could not parse iTIP message".to_owned());
        };
        let Some(organizer) = event.organizer.clone() else {
            return Err("iTIP message has no ORGANIZER".to_owned());
        };
        let Some(method) = event.method.clone() else {
            return Err("iTIP message has no METHOD".to_owned());
        };

        match method.as_str() {
            "REQUEST" | "PUBLISH" | "CANCEL" => {
                if !organizer.eq_ignore_ascii_case(acting_user) {
                    return Err(format!(
                        "only the organizer ({organizer}) may post {method} messages"
                    ));
                }
                let kind = if method == "CANCEL" {
                    DeliveryKind::OrganizerPush { method: "CANCEL" }
                } else {
                    DeliveryKind::OrganizerPush { method: "REQUEST" }
                };
                let body = ics::add_method(body, &method);
                let statuses = self.deliver_status(&kind, &event, &body, &organizer).await;
                Ok(statuses)
            }
            "REPLY" => {
                // An attendee posts their REPLY; the replying attendee is
                // determined by which ATTENDEE in the message matches the
                // authenticated principal.
                let Some(attendee) = event
                    .attendees
                    .iter()
                    .find(|a| a.email.eq_ignore_ascii_case(acting_user))
                else {
                    return Err(
                        "authenticated principal is not an attendee of this REPLY".to_owned()
                    );
                };
                let Some(partstat) = attendee.partstat.clone() else {
                    return Err("REPLY carries no PARTSTAT".to_owned());
                };
                let Some(first_attendee) = event.attendees.first() else {
                    return Err("REPLY has no attendees".to_owned());
                };
                // A client-posted REPLY contains exactly one attendee entry
                let statuses = if self
                    .deliver_reply(
                        &event,
                        &first_attendee.email,
                        first_attendee.cn.as_deref(),
                        &partstat,
                    )
                    .await
                {
                    vec![OutboxStatus::success(
                        first_attendee.email.clone(),
                        "delivered",
                    )]
                } else {
                    vec![OutboxStatus::failure(
                        first_attendee.email.clone(),
                        "delivery failed (see server log)".to_owned(),
                    )]
                };
                Ok(statuses)
            }
            other => Err(format!("METHOD:{other} is not supported")),
        }
    }

    fn run_guard(&self) -> bool {
        !self.enabled()
    }

    // --- Organizers -----------------------------------------------------------

    async fn organizer_put(
        &self,
        acting_user: &str,
        current: (&str, &str, &str),
        event: &ics::EventInfo,
        old_ics: Option<&str>,
        new_ics: &str,
        organizer: &str,
    ) {
        if event.attendees.is_empty() {
            return;
        }

        // Skip no-op re-uploads (client save with only DTSTAMP etc. changes)
        if let Some(old_ics) = old_ics {
            if let Some(old_event) = ics::parse_event(old_ics) {
                if old_event.attendees.is_empty() {
                    // Attendees were added by this PUT: schedule below.
                } else if !ics::scheduling_relevant_change(old_ics, new_ics) {
                    info!(
                        uid = event.uid,
                        "scheduling: no relevant change, skipping REQUEST"
                    );
                    return;
                }
            }
        } else {
            // Copy/move guard: a brand-new PUT whose UID already exists under
            // another calendar of this user is a move, not a new invitation.
            // The copy this PUT just wrote is always present (the hook runs
            // after the store-write) and is excluded via `current`.
            let mut principals = vec![acting_user.to_owned()];
            if let Ok(memberships) = self.store.principal_memberships(acting_user).await {
                principals.extend(memberships);
            }
            for principal in principals {
                let copies = match self
                    .store
                    .find_calendar_objects_by_uid(&principal, &event.uid)
                    .await
                {
                    Ok(copies) => copies,
                    Err(err) => {
                        warn!("scheduling: UID lookup failed: {err}");
                        return;
                    }
                };
                let copies: Vec<_> = copies
                    .into_iter()
                    .filter(|(cal_id, object_id, _)| {
                        !(principal == current.0 && cal_id == current.1 && object_id == current.2)
                    })
                    .collect();
                if !copies.is_empty() {
                    info!(
                        uid = event.uid,
                        existing_in = principal,
                        "scheduling: UID exists in another calendar, assuming move"
                    );
                    return;
                }
            }
        }

        self.deliver(
            &DeliveryKind::OrganizerPush { method: "REQUEST" },
            event,
            new_ics,
            organizer,
        )
        .await;
    }

    // --- Attendees ------------------------------------------------------------

    async fn attendee_put(&self, acting_user: &str, event: &ics::EventInfo, old_ics: Option<&str>) {
        let Some(attendee) = event
            .attendees
            .iter()
            .find(|a| a.email.eq_ignore_ascii_case(acting_user))
        else {
            // The acting user stores an event they are not participating in
            // (e.g. someone else's event mirrored by a sync client): nothing to do.
            return;
        };
        let Some(partstat) = attendee.partstat.clone() else {
            return;
        };
        // Only act when the PARTSTAT actually changed (edits to other fields
        // of an invited event must not re-deliver replies).
        if let Some(old_ics) = old_ics {
            if let Some(old_event) = ics::parse_event(old_ics) {
                if let Some(old_attendee) = old_event
                    .attendees
                    .iter()
                    .find(|a| a.email.eq_ignore_ascii_case(acting_user))
                {
                    if old_attendee.partstat.as_deref() == Some(partstat.as_str()) {
                        return;
                    }
                }
            }
        }

        if !self
            .deliver_reply(event, &attendee.email, attendee.cn.as_deref(), &partstat)
            .await
        {
            warn!(uid = event.uid, "scheduling: REPLY delivery failed");
        }
    }

    /// Deliver an attendee's PARTSTAT update: update the organizer's local
    /// copies + inbox, or email the remote organizer.
    #[instrument(skip(self))]
    async fn deliver_reply(
        &self,
        event: &ics::EventInfo,
        attendee_email: &str,
        attendee_cn: Option<&str>,
        partstat: &str,
    ) -> bool {
        let Some(organizer) = event.organizer.as_deref() else {
            return false;
        };
        let organizer_is_local = self
            .store
            .principal_exists(organizer)
            .await
            .unwrap_or(false);

        let reply_ics = ics::build_reply(
            organizer,
            attendee_email,
            attendee_cn,
            partstat,
            &event.uid,
            event.sequence,
        );

        if organizer_is_local {
            let mut success = true;

            // Update the organizer's stored copies of this event
            let mut principals = vec![organizer.to_owned()];
            match self.store.principal_memberships(organizer).await {
                Ok(memberships) => principals.extend(memberships),
                Err(err) => warn!("scheduling: memberships lookup failed: {err}"),
            }
            for principal in principals {
                let Ok(copies) = self
                    .store
                    .find_calendar_objects_by_uid(&principal, &event.uid)
                    .await
                else {
                    success = false;
                    continue;
                };
                for (cal_id, object_id, stored_ics) in copies {
                    // Only touch copies organised by this organizer
                    if let Some(parsed) = ics::parse_event(&stored_ics) {
                        if parsed
                            .organizer
                            .as_deref()
                            .is_none_or(|o| !o.eq_ignore_ascii_case(organizer))
                        {
                            continue;
                        }
                    }
                    let updated = ics::set_attendee_partstat(&stored_ics, attendee_email, partstat);
                    if updated == stored_ics {
                        continue; // nothing changed (attendee not in that copy)
                    }
                    if let Err(err) = self
                        .store
                        .update_calendar_object_ics(&principal, &cal_id, &object_id, &updated)
                        .await
                    {
                        warn!(
                            "scheduling: could not update organizer copy {principal}/{cal_id}/{object_id}: {err}"
                        );
                        success = false;
                    }
                }
            }

            // File a REPLY in the organizer's inbox
            let object_id = ics::sanitize_id("reply", &event.uid, &format!("-{}", attendee_email));
            if let Err(err) = self
                .store
                .put_inbox_object(organizer, &object_id, &reply_ics)
                .await
            {
                warn!("scheduling: could not put REPLY into inbox of {organizer}: {err}");
                success = false;
            }

            // Update the attendee's stored copies so their CalDAV client
            // picks up the new PARTSTAT on next sync.
            let attendee_local = self
                .store
                .principal_exists(attendee_email)
                .await
                .unwrap_or(false);
            if attendee_local {
                let mut principals = vec![attendee_email.to_owned()];
                match self.store.principal_memberships(attendee_email).await {
                    Ok(memberships) => principals.extend(memberships),
                    Err(err) => warn!("scheduling: memberships lookup failed for {attendee_email}: {err}"),
                }
                for principal in principals {
                    let Ok(copies) = self.store.find_calendar_objects_by_uid(&principal, &event.uid).await else {
                        success = false;
                        continue;
                    };
                    for (cal_id, object_id, stored_ics) in copies {
                        if let Some(parsed) = ics::parse_event(&stored_ics) {
                            if parsed.organizer.as_deref().is_none_or(|o| !o.eq_ignore_ascii_case(organizer)) {
                                continue;
                            }
                        }
                        let updated = ics::set_attendee_partstat(&stored_ics, attendee_email, partstat);
                        if updated == stored_ics {
                            continue;
                        }
                        if let Err(err) = self.store.update_calendar_object_ics(&principal, &cal_id, &object_id, &updated).await {
                            warn!("scheduling: could not update attendee copy {principal}/{cal_id}/{object_id}: {err}");
                            success = false;
                        }
                    }
                }
            }

            success
        } else {
            // Remote organizer: email the REPLY from the attendee's identity
            let Some(account) = self.config.smtp_account(attendee_email).cloned() else {
                warn!(
                    "scheduling: no SMTP account for {attendee_email}, cannot email REPLY to {organizer}"
                );
                return false;
            };
            self.spawn_email(
                account,
                attendee_email,
                organizer,
                &reply_ics,
                "REPLY",
                mime::reply_body(attendee_email, partstat, event),
                format!(
                    "Response: {}",
                    event
                        .summary
                        .clone()
                        .unwrap_or_else(|| "Calendar event".into())
                ),
            );
            true
        }
    }

    /// Ingest one inbound iMIP REPLY (RFC 6047) found in the mailbox of
    /// `mailbox_identity` — the missing inbound leg of email scheduling:
    /// external attendees (or local users without a principal yet) answer
    /// by email, and those replies must update the organizer's stored
    /// copies and scheduling inbox exactly like internal replies do.
    ///
    /// Returns `Ok(Some((attendee, partstat)))` when the reply was applied,
    /// `Ok(None)` when the message was deterministically ignored (reason
    /// logged), and `Err` on operational failure (the poll loop retries).
    ///
    /// Validation: the iTIP object must carry `METHOD:REPLY` and be
    /// organized by `mailbox_identity`; the mailbox identity must be a
    /// local principal (otherwise [`deliver_reply`]'s remote branch would
    /// email the very mailbox being polled and re-ingest forever — a mail
    /// loop). The replying attendee is disambiguated against the email's
    /// From address when the REPLY lists several attendees (Outlook does).
    #[instrument(skip(self, reply_ics))]
    pub async fn ingest_imip_reply(
        &self,
        mailbox_identity: &str,
        reply_ics: &str,
        from: Option<&str>,
    ) -> Result<Option<(String, String)>, String> {
        let Some(event) = ics::parse_event(reply_ics) else {
            warn!("iMIP ingest: could not parse text/calendar part");
            return Ok(None);
        };

        if event.method.as_deref() != Some("REPLY") {
            // REQUEST/CANCEL addressed *to* this mailbox are invitations for
            // the user, not replies — left to the mail client (out of scope).
            tracing::debug!(
                method = event.method,
                uid = event.uid,
                "iMIP ingest: not a REPLY, ignoring"
            );
            return Ok(None);
        }

        let Some(organizer) = event.organizer.as_deref() else {
            warn!(uid = event.uid, "iMIP ingest: REPLY without ORGANIZER");
            return Ok(None);
        };
        if !organizer.eq_ignore_ascii_case(mailbox_identity) {
            warn!(
                organizer,
                uid = event.uid,
                "iMIP ingest: REPLY for a different organizer, ignoring"
            );
            return Ok(None);
        }

        // Mail-loop guard: without a local principal, deliver_reply would
        // email the "remote" organizer — this very mailbox — and the reply
        // would be ingested (and re-sent) on every poll.
        let organizer_local = self
            .store
            .principal_exists(organizer)
            .await
            .unwrap_or(false);
        if !organizer_local {
            warn!(
                organizer,
                uid = event.uid,
                "iMIP ingest: mailbox identity is not a local principal, ignoring"
            );
            return Ok(None);
        }

        let Some(attendee) = pick_reply_attendee(&event, from) else {
            warn!(
                uid = event.uid,
                "iMIP ingest: REPLY has no attendee with a PARTSTAT"
            );
            return Ok(None);
        };
        let Some(partstat) = attendee.partstat.clone() else {
            return Ok(None);
        };

        if !self
            .deliver_reply(&event, &attendee.email, attendee.cn.as_deref(), &partstat)
            .await
        {
            return Err(format!(
                "REPLY delivery for {} (uid {}) failed",
                attendee.email, event.uid
            ));
        }

        info!(
            uid = event.uid,
            attendee = attendee.email,
            partstat,
            "iMIP ingest: attendee reply applied"
        );
        Ok(Some((attendee.email.clone(), partstat)))
    }

    // --- One-click RSVP links -------------------------------------------------

    /// Whether invitation emails carry one-click RSVP links (both the
    /// signing secret and a public base URL configured) and the public
    /// response route is mounted.
    #[must_use]
    pub fn rsvp_links_enabled(&self) -> bool {
        self.config.rsvp_links_enabled()
    }

    /// The public response-page URL for one invited attendee, or `None`
    /// while the RSVP link extension is not fully configured.
    ///
    /// Only ever called on paths where the organizer is the acting local
    /// principal (`handle_put` / `handle_outbox_post` enforce
    /// organizer == acting user); the endpoint re-validates organizer
    /// locality before applying anything anyway.
    fn rsvp_link_url(
        &self,
        event: &ics::EventInfo,
        organizer: &str,
        attendee: &str,
    ) -> Option<String> {
        let secret = self.config.rsvp_secret.as_deref()?;
        let base = self.config.rsvp_base_url.as_deref()?;
        let token = rsvp::mint_token(
            secret,
            &event.uid,
            organizer,
            attendee,
            chrono::Utc::now().timestamp(),
        );
        Some(format!("{}/rsvp/{token}", base.trim_end_matches('/')))
    }

    /// Resolve a valid RSVP link token to the current state of the
    /// invited event, for rendering the response page.
    ///
    /// `Err(RsvpError::Invalid)` for unknown/expired tokens (and while
    /// the extension is not configured), `Err(RsvpError::Gone)` when the
    /// event or the attendee's invitation no longer exists.
    pub async fn rsvp_page_data(&self, token: &str) -> Result<RsvpEvent, RsvpError> {
        let claims = self.verify_rsvp_token(token)?;
        let (event, attendee) = self.resolve_rsvp_event(&claims).await?;
        Ok(rsvp_page_event(&event, &attendee))
    }

    /// Record the attendee's chosen response (`accept`/`maybe`/`decline`)
    /// exactly like an emailed iMIP REPLY would: the organizer's stored
    /// copies get the new PARTSTAT and a REPLY is filed into their
    /// scheduling inbox. Returns the page data for the confirmation view.
    pub async fn rsvp_apply(&self, token: &str, response: &str) -> Result<RsvpEvent, RsvpError> {
        let Some(partstat) = rsvp::partstat_for_response(response) else {
            return Err(RsvpError::BadResponse);
        };
        let claims = self.verify_rsvp_token(token)?;
        let (event, mut attendee) = self.resolve_rsvp_event(&claims).await?;
        if !self
            .deliver_reply(&event, &claims.attendee, attendee.cn.as_deref(), partstat)
            .await
        {
            return Err(RsvpError::Store(
                "could not update the organizer's copy".to_owned(),
            ));
        }
        info!(
            uid = claims.uid,
            attendee = claims.attendee,
            partstat,
            "rsvp link: attendee reply applied"
        );
        attendee.partstat = Some(partstat.to_owned());
        Ok(rsvp_page_event(&event, &attendee))
    }

    fn verify_rsvp_token(&self, token: &str) -> Result<rsvp::RsvpClaims, RsvpError> {
        let Some(secret) = self.config.rsvp_secret.as_deref() else {
            return Err(RsvpError::Invalid);
        };
        rsvp::verify_token(secret, token, chrono::Utc::now().timestamp()).ok_or(RsvpError::Invalid)
    }

    /// Shared endpoint resolution: the organizer must be a local
    /// principal (mirror of the iMIP ingest guard), their current stored
    /// copy of the event must still exist and still invite the token's
    /// attendee. Returns that copy plus the attendee's entry (CN,
    /// current PARTSTAT) for the page / reply.
    async fn resolve_rsvp_event(
        &self,
        claims: &rsvp::RsvpClaims,
    ) -> Result<(ics::EventInfo, ics::Attendee), RsvpError> {
        let organizer_local = self
            .store
            .principal_exists(&claims.organizer)
            .await
            .map_err(|err| RsvpError::Store(err.to_string()))?;
        if !organizer_local {
            return Err(RsvpError::Invalid);
        }

        let mut principals = vec![claims.organizer.clone()];
        match self.store.principal_memberships(&claims.organizer).await {
            Ok(memberships) => principals.extend(memberships),
            Err(err) => return Err(RsvpError::Store(err.to_string())),
        }
        for principal in principals {
            let copies = self
                .store
                .find_calendar_objects_by_uid(&principal, &claims.uid)
                .await
                .map_err(|err| RsvpError::Store(err.to_string()))?;
            for (_cal_id, _object_id, stored_ics) in copies {
                let Some(parsed) = ics::parse_event(&stored_ics) else {
                    continue;
                };
                // Only copies organised by the token's organizer
                if parsed
                    .organizer
                    .as_deref()
                    .is_none_or(|o| !o.eq_ignore_ascii_case(&claims.organizer))
                {
                    continue;
                }
                if parsed.status.as_deref() == Some("CANCELLED") {
                    // Deliberately Gone, not Invalid: the token is fine
                    return Err(RsvpError::Gone);
                }
                let Some(attendee) = parsed
                    .attendees
                    .iter()
                    .find(|a| a.email.eq_ignore_ascii_case(&claims.attendee))
                    .cloned()
                else {
                    continue; // attendee removed from this copy
                };
                return Ok((parsed, attendee));
            }
        }
        Err(RsvpError::Gone)
    }

    // --- Shared delivery -------------------------------------------------------

    #[instrument(skip(self))]
    async fn deliver(
        &self,
        kind: &DeliveryKind,
        event: &ics::EventInfo,
        base_ics: &str,
        organizer: &str,
    ) {
        let statuses = self.deliver_status(kind, event, base_ics, organizer).await;
        for status in &statuses {
            if status.code >= 3_00 {
                warn!(
                    "scheduling: delivery to {} failed: {}",
                    status.recipient, status.message
                );
            }
        }
    }

    #[instrument(skip(self, base_ics))]
    async fn deliver_status(
        &self,
        kind: &DeliveryKind,
        event: &ics::EventInfo,
        base_ics: &str,
        organizer: &str,
    ) -> Vec<OutboxStatus> {
        let &DeliveryKind::OrganizerPush { method } = kind;
        let target_attendees: Vec<&str> =
            event.attendees.iter().map(|a| a.email.as_str()).collect();

        // Outgoing iTIP must not carry principal-URL CAL-ADDRESSes (the form
        // iOS uses for the account owner): internal inbox copies and iMIP
        // attachments alike get `mailto:` addresses remote and local clients
        // can work with.
        let ics_with_method = ics::add_method(&ics::normalize_caladdresses(base_ics), method);
        // Strip Apple-specific properties that cause Android Google Calendar
        // to reject the .ics attachment ("cannot launch event").
        let ics_for_email = ics::strip_apple_properties(&ics_with_method);
        let mut statuses = vec![];
        for email in target_attendees {
            let internal = self.store.principal_exists(email).await.unwrap_or(false);
            if internal {
                let object_id = match method {
                    "CANCEL" => ics::sanitize_id("cancel", &event.uid, ""),
                    _ => ics::sanitize_id("req", &event.uid, ""),
                };
                let mut ics_to_store = ics_with_method.clone();
                if method == "CANCEL" && !ics_to_store.contains("STATUS:CANCELLED") {
                    ics_to_store = ensure_status_cancelled(&ics_to_store);
                }
                let result = self
                    .store
                    .put_inbox_object(email, &object_id, &ics_to_store)
                    .await;
                statuses.push(match result {
                    Ok(()) => OutboxStatus::success(email.to_owned(), "inbox"),
                    Err(err) => OutboxStatus::failure(email.to_owned(), err.to_string()),
                });

                // Also email the invite so the attendee gets a notification
                // even without WebDAV Push (e.g. Apple Calendar).
                if let Some(account) = self.config.smtp_account(organizer).cloned() {
                    let subject = match method {
                        "CANCEL" => format!(
                            "Cancelled: {}",
                            event
                                .summary
                                .clone()
                                .unwrap_or_else(|| "Calendar event".into())
                        ),
                        _ => format!(
                            "Invitation: {}",
                            event
                                .summary
                                .clone()
                                .unwrap_or_else(|| "Calendar event".into())
                        ),
                    };
                    let rsvp_url = if method == "CANCEL" {
                        None
                    } else {
                        self.rsvp_link_url(event, organizer, email)
                    };
                    let body = match method {
                        "CANCEL" => mime::cancel_body(event, organizer),
                        _ => mime::invite_body(&account, event, organizer, rsvp_url.as_deref()),
                    };
                    self.spawn_email(
                        account,
                        organizer,
                        email,
                        &ics_for_email,
                        method,
                        body,
                        subject,
                    );
                } else {
                    warn!(
                        "scheduling: no SMTP account for organizer {organizer}; \
                         cannot email invite to internal attendee {email}"
                    );
                }
            } else {
                let Some(account) = self.config.smtp_account(organizer).cloned() else {
                    warn!(
                        "scheduling: no SMTP account for organizer {organizer}; cannot invite external attendee {email}"
                    );
                    statuses.push(OutboxStatus::failure(
                        email.to_owned(),
                        format!("no SMTP account configured for organizer {organizer}"),
                    ));
                    continue;
                };
                let subject = match method {
                    "CANCEL" => format!(
                        "Cancelled: {}",
                        event
                            .summary
                            .clone()
                            .unwrap_or_else(|| "Calendar event".into())
                    ),
                    _ => format!(
                        "Invitation: {}",
                        event
                            .summary
                            .clone()
                            .unwrap_or_else(|| "Calendar event".into())
                    ),
                };
                let rsvp_url = if method == "CANCEL" {
                    // No response page for cancellations
                    None
                } else {
                    self.rsvp_link_url(event, organizer, email)
                };
                let body = match method {
                    "CANCEL" => mime::cancel_body(event, organizer),
                    _ => mime::invite_body(&account, event, organizer, rsvp_url.as_deref()),
                };
                self.spawn_email(
                    account,
                    organizer,
                    email,
                    &ics_for_email,
                    method,
                    body,
                    subject,
                );
                statuses.push(OutboxStatus::success(email.to_owned(), "email queued"));
            }
        }
        statuses
    }

    #[allow(clippy::too_many_arguments)]
    fn spawn_email(
        &self,
        account: SmtpAccount,
        from: &str,
        to: &str,
        ics_with_method: &str,
        method: &str,
        body: String,
        subject: String,
    ) {
        let message = mime::build_imip(&account, to, ics_with_method, method, subject, body);
        let to = to.to_owned();
        let from = from.to_owned();
        let method = method.to_owned();
        tokio::spawn(async move {
            let mut attempt = 0;
            loop {
                attempt += 1;
                match smtp::send_mail(&account, &from, &to, &message).await {
                    Ok(()) => {
                        info!("scheduling: emailed {method} to {to} (attempt {attempt})");
                        return;
                    }
                    Err(err) if attempt < 3 => {
                        warn!(
                            "scheduling: email to {to} failed (attempt {attempt}): {err}; retrying in 30s"
                        );
                        tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                    }
                    Err(err) => {
                        warn!(
                            "scheduling: email to {to} FAILED permanently after {attempt} attempts: {err}"
                        );
                        return;
                    }
                }
            }
        });
    }
}

/// The attendee a REPLY speaks for. iMIP REPLYs normally carry exactly one
/// ATTENDEE (the replying party, with a PARTSTAT), but Outlook lists all of
/// them: candidates are attendees with a meaningful PARTSTAT, preferring the
/// one matching the email's From address and excluding NEEDS-ACTION
/// (non-responders in Outlook's all-attendees shape).
fn pick_reply_attendee<'a>(
    event: &'a ics::EventInfo,
    from: Option<&str>,
) -> Option<&'a ics::Attendee> {
    let candidates: Vec<&ics::Attendee> = event
        .attendees
        .iter()
        .filter(|a| {
            a.partstat
                .as_deref()
                .is_some_and(|p| !p.eq_ignore_ascii_case("NEEDS-ACTION") && !p.is_empty())
        })
        .collect();
    if let Some(from) = from {
        if let Some(found) = candidates
            .iter()
            .find(|a| a.email.eq_ignore_ascii_case(from))
        {
            return Some(found);
        }
    }
    candidates.first().copied()
}

fn ensure_status_cancelled(ics_body: &str) -> String {
    let lines = ics::unfold(ics_body);
    let mut out = vec![];
    let mut in_event = false;
    let mut inserted = false;
    for line in &lines {
        let parsed = ics::parse_single_line(line);
        match parsed.name.as_str() {
            "BEGIN" if parsed.value.eq_ignore_ascii_case("VEVENT") => {
                in_event = true;
                out.push(line.clone());
            }
            "END" if parsed.value.eq_ignore_ascii_case("VEVENT") => {
                if in_event && !inserted {
                    out.push("STATUS:CANCELLED".to_owned());
                    inserted = true;
                }
                in_event = false;
                out.push(line.clone());
            }
            "STATUS" if in_event => {
                out.push("STATUS:CANCELLED".to_owned());
                inserted = true;
            }
            _ => out.push(line.clone()),
        }
    }
    out.join("\r\n")
}

/// Page data for one invited attendee of `event`.
fn rsvp_page_event(event: &ics::EventInfo, attendee: &ics::Attendee) -> RsvpEvent {
    RsvpEvent {
        summary: event
            .summary
            .clone()
            .unwrap_or_else(|| "(no title)".to_owned()),
        when: ics::humanize_dtstart(event.dtstart.as_ref()),
        recurring: event.rrule,
        organizer: event.organizer.clone().unwrap_or_default(),
        attendee: attendee.email.clone(),
        partstat: attendee
            .partstat
            .clone()
            .unwrap_or_else(|| "NEEDS-ACTION".to_owned()),
    }
}
