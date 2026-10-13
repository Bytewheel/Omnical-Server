//! The §18.41 push mirror (`PLAN_DEPLOYMENTS.md`): one-way sync of a local
//! calendar into a remote `CalDAV` collection.
//!
//! The reference deployment (§18.41's two-calendar layout) mirrors the
//! user's omnical calendars into aphy twice over: canonical
//! `ORGANIZER`-stamped masters into an aphy web calendar ("omnical"),
//! and the flattened phone feed into the `Default` calendar the stock
//! MP02 syncs — replacing the manual
//! download-`.ics`-import-it-into-aphy pipeline of §18.38–§18.40.
//!
//! ## Why the bodies are shaped at all
//!
//! §18.41's live bisect (nine rounds of `PUT` against a scratch aphy
//! calendar) found that aphy's week/day grids render an event only when
//! its `VEVENT` carries an `ORGANIZER` (or `CREATED`); every event this
//! deployment owns was written by khal, which never writes an
//! `ORGANIZER` — that one absence is the entire original symptom. The
//! mirror therefore stamps `ORGANIZER`/`CREATED`/`LAST-MODIFIED` on
//! masters and leaves every other byte of the stored object alone:
//! recurrence is preserved (series operations keep working on aphy web),
//! and the shape stays the server's own.
//!
//! The phone is served by the optional instance feed
//! (`phone_instances = true`): the §18.39/§18.40 flattened concrete
//! instances the MP02 needs, because the phone never expands an `RRULE`
//! and files every body at its master's `DTSTART` (§18.37). Those bodies
//! are deliberately left `ORGANIZER`-less — aphy's grid gate drops them,
//! which keeps the feed invisible on the web — and their `{uid}-{stamp}`
//! family UIDs carry a trailing `-m` marker ([`feed_uid`]): aphy parses
//! a bare `{uid}-{datestamp}` UID as a Kolab recurrence override of that
//! master, and with the master in the web calendar and the family in
//! the phone calendar the web's series model broke (§18.41's live
//! finding: series operations vanished). The marker breaks the
//! datetime-suffix parse; the phone, which matches nothing but its own
//! time-range `REPORT`, files them on their own days exactly as the
//! §18.40 import did.
//!
//! ## Ownership
//!
//! The mirror touches only objects it can claim: the source calendar's
//! own UIDs (its masters and their `{uid}-{stamp}` instance UIDs) plus
//! what it previously wrote (state in `mirror_objects`). The remote
//! account's own events — an accepted invitation, an aphy-native test
//! event — are never read, rewritten or deleted. Deleting a mirror from
//! the config orphans its state rows harmlessly: nothing reads a name
//! that no longer runs, and re-adding it re-adopts by UID on the first
//! sync.

use crate::config::MirrorTargetConfig;
use chrono::{DateTime, Utc};
use rustical_store::{CalendarStore, MirrorObject, MirrorStore};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet};
use tracing::{info, instrument, warn};

/// One sync's outcome, for the log line and the CLI's summary.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SyncStats {
    /// Objects written (`PUT`), new or changed.
    pub put: usize,
    /// Objects deleted on the remote: vanished from the source, or stale
    /// `{uid}-…` instances of a current master beyond the horizon.
    pub deleted: usize,
    /// Objects already at the recorded hash on the remote and untouched.
    pub unchanged: usize,
}

/// The change-detection key stored in `mirror_objects`: the SHA-256 of the
/// exact body the mirror last pushed for this UID.
fn body_hash(body: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(body.as_bytes());
    hex::encode(hasher.finalize())
}

/// An href-safe object filename.
///
/// Keeps the characters every `CalDAV` server accepts unencoded in a
/// path segment and replaces the rest with `_`; deterministic per UID,
/// so state and remote hrefs always agree.
#[must_use]
pub fn href_component(uid: &str) -> String {
    uid.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '@') {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// Stamp the §18.41 fields on a mirrored body.
///
/// `DTSTAMP` (RFC 5545 required) and `CREATED`/`LAST-MODIFIED` are
/// added when missing, and `ORGANIZER` on `VEVENT`s that lack one —
/// aphy's week/day grids drop events without it, and khal never writes
/// it. `CREATED` and `LAST-MODIFIED` both inherit the object's own
/// `DTSTAMP` (the source's own last-modified) so a body is byte-stable
/// across syncs — change detection hashes the body, and a mirror that
/// re-stamped every run would re-`PUT` the whole source each cadence.
/// `DTSTAMP`'s own absence takes the sync time (the RFC's intent for a
/// copy). Every other byte is preserved.
///
/// The walk is line-level on purpose: the stored form (khal's minimal
/// `VTIMEZONE`, its property order, its folding) is exactly what a
/// round-trip through caldata would re-emit differently, and §18.41's
/// live tests confirmed the stored form renders once `ORGANIZER` is
/// present.
#[must_use]
pub fn shape_master_body(raw: &str, organizer: &str, now: &str) -> String {
    let lines: Vec<String> = raw
        .split('\n')
        .map(|line| line.trim_end_matches('\r'))
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .collect();

    let mut out: Vec<String> = Vec::with_capacity(lines.len() + 8);
    let mut i = 0;
    while i < lines.len() {
        // Only the addressable components get stamped — the container
        // (`VCALENDAR`) and its nested blocks (`VTIMEZONE`, `VALARM`, …)
        // pass through verbatim.
        let Some(component) = lines[i]
            .strip_prefix("BEGIN:")
            .filter(|name| matches!(*name, "VEVENT" | "VTODO" | "VJOURNAL"))
        else {
            out.push(lines[i].clone());
            i += 1;
            continue;
        };
        // Components never nest themselves in ICS (a VEVENT's VALARM is a
        // different name), so the first END of the same name closes it.
        let Some(len) = (1..lines.len() - i).find(|k| lines[i + *k] == format!("END:{component}"))
        else {
            // Unbalanced component: leave the rest verbatim.
            out.extend(lines[i..].iter().cloned());
            break;
        };
        let block = &lines[i + 1..i + len];
        let has = |name: &str| {
            block
                .iter()
                .any(|line| line.split(':').next() == Some(name))
        };
        out.push(lines[i].clone());
        if !has("DTSTAMP") {
            out.push(format!("DTSTAMP:{now}"));
        }
        if !has("CREATED") {
            let created = object_stamp(block).unwrap_or(now);
            out.push(format!("CREATED:{created}"));
        }
        if !has("LAST-MODIFIED") {
            let modified = object_stamp(block).unwrap_or(now);
            out.push(format!("LAST-MODIFIED:{modified}"));
        }
        if component == "VEVENT" && !has("ORGANIZER") && !organizer.is_empty() {
            out.push(format!("ORGANIZER:{organizer}"));
        }
        out.extend(block.iter().cloned());
        out.push(lines[i + len].clone());
        i += len + 1;
    }
    let mut body = out.join("\r\n");
    if !body.is_empty() {
        body.push_str("\r\n");
    }
    body
}

/// The object's own `DTSTAMP` — the source's last-modified, which the
/// mirror's `CREATED`/`LAST-MODIFIED` inherit so a mirrored body never
/// changes between syncs.
fn object_stamp(block: &[String]) -> Option<&str> {
    block.iter().find_map(|line| line.strip_prefix("DTSTAMP:"))
}

/// A non-recurring object's own DTSTART value, non-alphanumerics stripped:
/// the deterministic suffix of its phone-feed copy (the same family shape
/// the flattened instances carry). `DTSTART;TZID=…:20260928T190000`
/// becomes `20260928T190000`, a DATE-valued start `20261018`.
fn object_dtstart_stamp(raw: &str) -> String {
    // Inside the addressable component only: a VTIMEZONE's transition
    // lines carry DTSTARTs too, and the wrong one must not key the href.
    let mut in_component = false;
    for line in raw.split(['\r', '\n']) {
        match line {
            "BEGIN:VEVENT" | "BEGIN:VTODO" | "BEGIN:VJOURNAL" => in_component = true,
            "END:VEVENT" | "END:VTODO" | "END:VJOURNAL" => in_component = false,
            _ if in_component && line.starts_with("DTSTART") => {
                if let Some(value) = line.rsplit(':').next() {
                    let stripped: String =
                        value.chars().filter(char::is_ascii_alphanumeric).collect();
                    if !stripped.is_empty() {
                        return stripped;
                    }
                }
            }
            _ => {}
        }
    }
    String::new()
}

/// Rewrite every `UID:` line of a body to `new_uid` — the phone-feed
/// copies need their UID re-keyed to the marked family form ([`feed_uid`])
/// while every other byte of the shaped body stays.
fn override_uid(body: &str, new_uid: &str) -> String {
    let mut out = String::with_capacity(body.len());
    for line in body.split("\r\n") {
        if line.split(':').next() == Some("UID") {
            out.push_str("UID:");
            out.push_str(new_uid);
        } else {
            out.push_str(line);
        }
        out.push_str("\r\n");
    }
    out
}

/// The `UID:` value of a flattened instance block (§18.41's mirror owns the
/// block's shape, so a direct scan is honest).
fn block_uid(block: &str) -> Option<String> {
    block
        .split("\r\n")
        .find_map(|line| line.strip_prefix("UID:"))
        .map(str::to_owned)
}

/// The feed form of a UID: a trailing `-m` marker segment. aphy's
/// Roundcube parses `{uid}-{datestamp}` UIDs as Kolab recurrence
/// overrides of that master, and with the master in the web calendar
/// and the family in the phone calendar the series model breaks
/// (§18.41's live finding: series ops vanish). The marker breaks the
/// datetime-suffix parse while staying deterministic (re-syncs
/// upsert) and inside the `{uid}-` family (the adoption sweep still
/// claims stale old-scheme objects).
fn feed_uid(uid: &str) -> String {
    format!("{uid}-m")
}

/// A remote `CalDAV` collection to push into: one authenticated client per
/// mirror target. Kept deliberately thin — `PROPFIND` for the current
/// object list, `PUT` for writes, `DELETE` for removals; the sync policy
/// lives in [`sync_target`].
struct CaldavTarget {
    client: reqwest::Client,
    base: String,
    username: String,
    password: String,
}

impl CaldavTarget {
    fn new(target: &MirrorTargetConfig) -> Self {
        Self {
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(60))
                .build()
                .expect("a static reqwest client configuration always builds"),
            base: format!("{}/", target.url.trim_end_matches('/')),
            username: target.username.clone(),
            password: target.password.clone(),
        }
    }

    /// All object hrefs (paths) currently in the remote collection.
    async fn object_hrefs(&self) -> anyhow::Result<Vec<String>> {
        let response = self
            .client
            .request(
                reqwest::Method::from_bytes(b"PROPFIND").expect("PROPFIND is a valid method name"),
                &self.base,
            )
            .basic_auth(&self.username, Some(&self.password))
            .header(reqwest::header::CONTENT_TYPE, "application/xml")
            .header("Depth", "1")
            .body(
                "<?xml version=\"1.0\"?><D:propfind xmlns:D=\"DAV:\"><D:prop><D:getetag/>\
                 </D:prop></D:propfind>",
            )
            .send()
            .await?;
        anyhow::ensure!(
            response.status().is_success(),
            "PROPFIND {} returned {}",
            self.base,
            response.status()
        );
        Ok(parse_hrefs(&response.text().await?))
    }

    async fn put(&self, href: &str, body: &str) -> anyhow::Result<()> {
        let response = self
            .client
            .put(format!("{}{href}", self.base))
            .basic_auth(&self.username, Some(&self.password))
            .header(
                reqwest::header::CONTENT_TYPE,
                "text/calendar; charset=utf-8",
            )
            .body(body.to_owned())
            .send()
            .await?;
        anyhow::ensure!(
            response.status().is_success(),
            "PUT {href} returned {}",
            response.status()
        );
        Ok(())
    }

    /// `404` is success: the goal is the object being gone.
    async fn delete(&self, href: &str) -> anyhow::Result<()> {
        let response = self
            .client
            .delete(format!("{}{href}", self.base))
            .basic_auth(&self.username, Some(&self.password))
            .send()
            .await?;
        anyhow::ensure!(
            response.status().is_success() || response.status() == reqwest::StatusCode::NOT_FOUND,
            "DELETE {href} returned {}",
            response.status()
        );
        Ok(())
    }
}

/// Every `<…:href>` text in a `multistatus` body, whatever prefix the
/// server chose. A full pull-parse would validate more of the document;
/// this reads exactly one thing, from one server, that answered `207`
/// before we got here.
fn parse_hrefs(body: &str) -> Vec<String> {
    let mut reader = quick_xml::Reader::from_str(body);
    let mut hrefs = Vec::new();
    let mut buf = Vec::new();
    loop {
        buf.clear();
        match reader.read_event_into(&mut buf) {
            Ok(quick_xml::events::Event::Eof) => break,
            Ok(quick_xml::events::Event::Start(e) | quick_xml::events::Event::Empty(e)) => {
                if e.name().local_name().as_ref() == "href"
                    && let Ok(quick_xml::events::Event::Text(text)) =
                        reader.read_event_into(&mut buf)
                {
                    // The tree's own XML layer reads text events exactly this
                    // way (`crates/xml/src/de.rs`), so this stays on the one
                    // text-extraction form that compiles here.
                    let mut href = String::new();
                    href.push_str(&text);
                    hrefs.push(href);
                }
            }
            Ok(_) | Err(_) => {}
        }
    }
    hrefs
}

/// The path segment of a `PROPFIND` href: the remote reports absolute
/// paths, the mirror keys its objects on filenames, and the join is a
/// basename, not a full-path, comparison.
fn href_basename(href: &str) -> &str {
    href.rsplit('/').next().unwrap_or(href)
}

/// One full sync of one target.
///
/// Reads the source, computes the desired set (masters + optional phone
/// instances), `PUT`s what changed, `DELETE`s what the mirror owned but
/// no longer wants, adopts stale `{uid}-…` instances of current
/// masters, and records the new state.
///
/// Remote-listing failure degrades the run instead of failing it:
/// without the current hrefs the mirror cannot detect remote-side
/// deletions or adopt stale instances, so it only pushes hash-changed
/// objects and says so — a mirror that never made anything worse is the
/// right failure mode for a copy whose source of truth is intact.
///
/// # Errors
/// Store failures reading the source, or the first `PUT`/`DELETE` error
/// (the state is only replaced after every write succeeded, so a failed
/// run retries everything it did not finish on the next one).
// The target is recorded by name only: its `Debug` carries the remote
// password, and a config secret in the log stream is a finding, not a
// convenience.
#[instrument(skip(cal_store, mirror_store, now), fields(target = %target.name))]
#[allow(clippy::too_many_lines)]
pub async fn sync_target(
    target: &MirrorTargetConfig,
    cal_store: &dyn CalendarStore,
    mirror_store: &dyn MirrorStore,
    timezone: &str,
    now: DateTime<Utc>,
) -> anyhow::Result<SyncStats> {
    let objects = cal_store
        .get_objects(&target.principal, &target.calendar)
        .await?;
    let now_stamp = now.format("%Y%m%dT%H%M%SZ").to_string();

    // The desired set, keyed on the object UIDs the remote will carry.
    let mut desired: BTreeMap<String, (String, String, String)> = BTreeMap::new();
    let mut master_uids: Vec<String> = Vec::new();
    // A phone-feed target carries no ORGANIZER: the feed lives in the
    // phone's calendar, aphy's week/day gate drops ORGANIZER-less events,
    // and that is exactly what keeps the feed invisible on the web while
    // the canonical copies render in the web calendar.
    let organizer = if target.phone_feed_only {
        ""
    } else {
        target.organizer.as_str()
    };
    for (_, object) in &objects {
        let uid = object.get_uid().to_owned();
        if uid.is_empty() {
            warn!(
                calendar = %target.calendar,
                "skipping a source object without a UID (the mirror cannot own it)"
            );
            continue;
        }
        // §18.41's two paths, split by target kind.
        //
        // A canonical target carries the object as-is under its real UID:
        // the web calendar renders it (ORGANIZER-stamped) and series
        // operations work.
        //
        // A phone-feed target never claims a real UID: aphy's Cyrus
        // enforces RFC 6638's `unique-scheduling-object-resource` — a
        // VEVENT UID is unique across the whole account, so the same UID
        // in the feed calendar and the web calendar is a 403 (found live:
        // every omnical one-shot PUT failed exactly this way). Recurring
        // events reach the feed only as their flattened instances (the
        // `{uid}-{stamp}-m` feed scheme below, which the phone files on
        // each occurrence's own day, §18.37/§18.39); non-recurring
        // objects are the phone's only way to see a one-shot, so they
        // ride along with their UID suffixed by their own DTSTART stamp —
        // the same family shape, never a UID the web calendar owns. Both
        // forms take the `-m` marker (`feed_uid`): a bare
        // `{uid}-{datestamp}` UID parses on aphy as a Kolab recurrence
        // override of the mirrored master, and the cross-calendar split
        // broke the web's series model — the marker ends the parse.
        if !target.phone_feed_only {
            let body = shape_master_body(object.get_ics(), organizer, &now_stamp);
            let href = format!("{}.ics", href_component(&uid));
            desired.insert(uid.clone(), (href, body_hash(&body), body));
        } else if !rustical_caldav::dailyview::object_is_recurring(object) {
            let stamp = object_dtstart_stamp(object.get_ics());
            if stamp.is_empty() {
                warn!(
                    calendar = %target.calendar,
                    uid = %uid,
                    "a phone-feed object without a parsable DTSTART was skipped"
                );
            } else {
                let key = feed_uid(&format!("{uid}-{stamp}"));
                let body = override_uid(
                    &shape_master_body(object.get_ics(), organizer, &now_stamp),
                    &key,
                );
                let body = rustical_caldav::dailyview::apply_all_day_pass(&body, timezone);
                let href = format!("{}.ics", href_component(&key));
                desired.insert(key, (href, body_hash(&body), body));
            }
        }
        master_uids.push(uid.clone());

        if target.phone_instances {
            for block in rustical_caldav::dailyview::flattened_instances_of_object(
                object.clone(),
                timezone,
                now,
                target.horizon_days,
            ) {
                let Some(instance_uid) = block_uid(&block) else {
                    warn!("a flattened instance without a UID was dropped");
                    continue;
                };
                // The block's `{uid}-{stamp}` UID re-keys to the marked
                // feed form — key, href and body all move (the bare form
                // parses on aphy as a Kolab override of the mirrored
                // master, which broke the web's series model).
                let key = feed_uid(&instance_uid);
                let body = override_uid(
                    &rustical_caldav::dailyview::dailyview_instance_body(&block, timezone),
                    &key,
                );
                let href = format!("{}.ics", href_component(&key));
                desired.insert(key, (href, body_hash(&body), body));
            }
        }
    }
    if desired.len()
        != desired
            .values()
            .map(|(href, ..)| href)
            .collect::<HashSet<_>>()
            .len()
    {
        warn!("two source UIDs sanitize to the same remote filename; one will shadow the other");
    }

    let prev: BTreeMap<String, MirrorObject> = mirror_store
        .get_mirror_objects(&target.name)
        .await?
        .into_iter()
        .map(|object| (object.uid.clone(), object))
        .collect();

    let remote = CaldavTarget::new(target);
    let remote_listed: Option<HashSet<String>> = match remote.object_hrefs().await {
        Ok(hrefs) => Some(
            hrefs
                .iter()
                .map(|href| href_basename(href).to_owned())
                .collect(),
        ),
        Err(error) => {
            warn!(
                ?error,
                "remote listing failed: pushing hash changes only, no deletes this run"
            );
            None
        }
    };

    let mut stats = SyncStats::default();
    // What the mirror previously wrote that no longer exists in the source.
    let mut to_delete: Vec<String> = Vec::new();
    for (uid, object) in &prev {
        if !desired.contains_key(uid) {
            to_delete.push(object.href.clone());
        }
    }
    // Adoption: a `{master-uid}-…` object on the remote that the current
    // desired set does not carry is a stale instance (an old horizon, an
    // old scheme) — the mirror claims the whole UID family, so it goes.
    // Objects outside every family are the remote's own and stay.
    if let Some(basenames) = &remote_listed {
        for basename in basenames {
            let in_desired = desired.values().any(|(href, ..)| href == basename);
            if in_desired {
                continue;
            }
            let Some(stem) = basename[..].strip_suffix(".ics") else {
                continue;
            };
            if master_uids
                .iter()
                .any(|uid| stem.starts_with(&format!("{uid}-")))
            {
                to_delete.push(basename.clone());
            }
        }
    }
    for href in &to_delete {
        match remote.delete(href).await {
            Ok(()) => stats.deleted += 1,
            Err(error) => warn!(?error, href = %href, "remote delete failed"),
        }
    }

    for (uid, (href, hash, body)) in &desired {
        let unchanged = prev.get(uid).is_some_and(|p| &p.hash == hash)
            && remote_listed
                .as_ref()
                .is_some_and(|basenames| basenames.contains(href));
        if unchanged {
            stats.unchanged += 1;
            continue;
        }
        match remote.put(href, body).await {
            Ok(()) => stats.put += 1,
            Err(error) => warn!(?error, href = %href, "remote put failed"),
        }
    }

    // State is replaced only after the writes: a mid-run failure leaves the
    // previous state in place and the next run redoes exactly the delta.
    let recorded_state: Vec<MirrorObject> = desired
        .iter()
        .map(|(uid, (href, hash, _))| MirrorObject {
            uid: uid.clone(),
            href: href.clone(),
            hash: hash.clone(),
        })
        .collect();
    mirror_store
        .replace_mirror_objects(&target.name, &recorded_state)
        .await?;

    info!(
        target = %target.name,
        put = stats.put,
        deleted = stats.deleted,
        unchanged = stats.unchanged,
        "mirror sync complete"
    );
    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KHAL_MASTER: &str = "BEGIN:VCALENDAR\r\n\
VERSION:2.0\r\n\
PRODID:-//PIMUTILS.ORG//NONSGML khal / icalendar //EN\r\n\
BEGIN:VTIMEZONE\r\n\
TZID:America/New_York\r\n\
BEGIN:DAYLIGHT\r\n\
DTSTART:20260308T030000\r\n\
TZNAME:EDT\r\n\
TZOFFSETFROM:-0500\r\n\
TZOFFSETTO:-0400\r\n\
END:DAYLIGHT\r\n\
BEGIN:STANDARD\r\n\
DTSTART:20261101T010000\r\n\
TZNAME:EST\r\n\
TZOFFSETFROM:-0400\r\n\
TZOFFSETTO:-0500\r\n\
END:STANDARD\r\n\
END:VTIMEZONE\r\n\
BEGIN:VEVENT\r\n\
SUMMARY:Trash\r\n\
DTSTART;TZID=America/New_York:20260928T190000\r\n\
DTEND;TZID=America/New_York:20260928T190100\r\n\
DTSTAMP:20260925T103702Z\r\n\
UID:RGKW68NDCGRYYVVHH55NLH5PU8Z6QH1IDKBU\r\n\
SEQUENCE:0\r\n\
RRULE:FREQ=WEEKLY\r\n\
END:VEVENT\r\n\
END:VCALENDAR\r\n";

    #[test]
    fn shape_master_body_stamps_organizer_and_created() {
        let shaped = shape_master_body(
            KHAL_MASTER,
            "mailto:burningserenity@aphy.io",
            "20261012T220000Z",
        );
        assert!(shaped.contains("ORGANIZER:mailto:burningserenity@aphy.io\r\n"));
        // CREATED and LAST-MODIFIED both inherit the object's own DTSTAMP,
        // so a body is byte-stable across syncs (change detection hashes it).
        assert!(shaped.contains("CREATED:20260925T103702Z\r\n"));
        assert!(shaped.contains("LAST-MODIFIED:20260925T103702Z\r\n"));
        assert!(!shaped.contains("LAST-MODIFIED:20261012T220000Z\r\n"));
        // Everything else is preserved verbatim.
        assert!(shaped.contains("RRULE:FREQ=WEEKLY\r\n"));
        assert!(shaped.contains("DTSTART;TZID=America/New_York:20260928T190000\r\n"));
        assert!(shaped.contains("TZID:America/New_York\r\n"));
        // One stamp each, never duplicated on a re-run.
        assert_eq!(shaped.matches("ORGANIZER:").count(), 1);
        assert_eq!(shaped.matches("CREATED:").count(), 1);
        let twice = shape_master_body(&shaped, "mailto:x@y", "20261012T220001Z");
        assert_eq!(twice.matches("ORGANIZER:").count(), 1);
        assert_eq!(twice.matches("CREATED:").count(), 1);
        // Idempotent: a shaped body hashes the same before and after.
        assert_eq!(body_hash(&shaped), body_hash(&twice));
    }

    #[test]
    fn shape_master_body_empty_organizer_stamps_nothing() {
        // A phone-feed target (§18.41 two-calendar layout) passes no
        // organizer: the feed must stay out of aphy's week/day grids.
        let shaped = shape_master_body(KHAL_MASTER, "", "20261012T220000Z");
        assert!(!shaped.contains("ORGANIZER"));
        assert!(shaped.contains("CREATED:20260925T103702Z\r\n"));
        assert!(shaped.contains("RRULE:FREQ=WEEKLY\r\n"));
    }

    #[test]
    fn object_dtstart_stamp_and_override_uid_key_the_feed_copy() {
        // The §18.41 feed suffix: the object's own DTSTART value, the same
        // family form the flattened instances carry.
        assert_eq!(object_dtstart_stamp(KHAL_MASTER), "20260928T190000");
        assert_eq!(
            object_dtstart_stamp("BEGIN:VEVENT\r\nDTSTART;VALUE=DATE:20261018\r\nEND:VEVENT"),
            "20261018"
        );
        assert_eq!(object_dtstart_stamp("BEGIN:VEVENT\r\nEND:VEVENT"), "");
        // The re-key: every UID line moves to the marked family form,
        // nothing else changes.
        let shaped = shape_master_body(KHAL_MASTER, "", "20261012T220000Z");
        let rekeyed = override_uid(
            &shaped,
            &feed_uid("RGKW68NDCGRYYVVHH55NLH5PU8Z6QH1IDKBU-20260928T190000"),
        );
        assert!(rekeyed.contains("UID:RGKW68NDCGRYYVVHH55NLH5PU8Z6QH1IDKBU-20260928T190000-m\r\n"));
        assert_eq!(rekeyed.matches("UID:").count(), 1);
        assert!(rekeyed.contains("RRULE:FREQ=WEEKLY\r\n"));
        assert!(!rekeyed.contains("ORGANIZER"));
    }

    #[test]
    fn feed_uid_marks_the_family_form() {
        // The `-m` marker: a bare `{uid}-{datestamp}` UID parses on aphy
        // as a Kolab recurrence override of the master, which broke the
        // web's series model; the marker ends the datetime-suffix parse
        // while staying inside the `{uid}-` family the adoption sweep
        // claims.
        assert_eq!(
            feed_uid("RGKW68NDCGRYYVVHH55NLH5PU8Z6QH1IDKBU-20260928T190000"),
            "RGKW68NDCGRYYVVHH55NLH5PU8Z6QH1IDKBU-20260928T190000-m"
        );
    }

    #[test]
    fn shape_master_body_leaves_organizered_events_alone() {
        let native = "BEGIN:VCALENDAR\r\n\
BEGIN:VEVENT\r\n\
UID:106AF69F\r\n\
DTSTAMP:20261012T195155Z\r\n\
CREATED:20261012T132552Z\r\n\
LAST-MODIFIED:20261012T195155Z\r\n\
DTSTART;TZID=Atlantic/Reykjavik:20261012T230000\r\n\
SUMMARY:aphy test\r\n\
TRANSP:OPAQUE\r\n\
ORGANIZER:mailto:burningserenity@aphy.io\r\n\
END:VEVENT\r\n\
END:VCALENDAR\r\n";
        let shaped = shape_master_body(native, "mailto:never@added", "20261012T220000Z");
        assert!(!shaped.contains("never@added"));
        assert!(shaped.contains("ORGANIZER:mailto:burningserenity@aphy.io\r\n"));
        assert_eq!(shaped, native);
    }

    #[test]
    fn shape_master_body_adds_dtstamp_when_missing() {
        let bare = "BEGIN:VCALENDAR\r\n\
BEGIN:VEVENT\r\n\
UID:X1\r\n\
DTSTART;TZID=America/New_York:20261012T190000\r\n\
SUMMARY:no stamps\r\n\
END:VEVENT\r\n\
END:VCALENDAR\r\n";
        let shaped = shape_master_body(bare, "mailto:o@x", "20261012T220000Z");
        assert!(shaped.contains("DTSTAMP:20261012T220000Z\r\n"));
        assert!(shaped.contains("CREATED:20261012T220000Z\r\n"));
        assert!(shaped.contains("LAST-MODIFIED:20261012T220000Z\r\n"));
    }

    #[test]
    fn shape_master_body_normalizes_lone_lf() {
        let lf = "BEGIN:VCALENDAR\nBEGIN:VEVENT\nUID:X2\nDTSTAMP:20260925T103702Z\n\
SUMMARY:lf source\nEND:VEVENT\nEND:VCALENDAR\n";
        let shaped = shape_master_body(lf, "mailto:o@x", "20261012T220000Z");
        assert!(shaped.contains("SUMMARY:lf source\r\n"));
        assert!(!shaped.contains('\n') || shaped.contains("\r\n"));
        assert!(shaped.ends_with("\r\n"));
    }

    #[test]
    fn href_component_sanitizes() {
        assert_eq!(href_component("RGKW68NDCGRYY"), "RGKW68NDCGRYY");
        assert_eq!(
            href_component("hol-rc-1962-christmas@omnical"),
            "hol-rc-1962-christmas@omnical"
        );
        assert_eq!(href_component("a/b c"), "a_b_c");
    }

    #[test]
    fn parse_hrefs_reads_any_prefix() {
        let body = r#"<?xml version="1.0"?><D:multistatus xmlns:D="DAV:">
<D:response><D:href>/dav/calendars/user/x/Default/A.ics</D:href></D:response>
<D:response><D:href>/dav/calendars/user/x/Default/B.ics</D:href></D:response>
</D:multistatus>"#;
        let hrefs = parse_hrefs(body);
        assert_eq!(hrefs.len(), 2);
        assert!(hrefs.iter().any(|h| h.ends_with("A.ics")));
        assert_eq!(
            href_basename("/dav/calendars/user/x/Default/B.ics"),
            "B.ics"
        );
    }
}
