//! Omnical: the `DailyView` (Punkt MP02, `AphyOS`) compatibility shim.
//!
//! `DailyView` — the frozen, Punkt-signed build this deployment cannot patch —
//! is a view-only client whose sync and whose 4-day list are both simpler than
//! the `CalDAV` they speak:
//!
//! * **Event bodies come from `calendar-multiget` REPORT `<C:calendar-data/>`**
//!   (`CaldavFacade.getEvent` → `CalendarEvent.setICSasMultiStatus`), never
//!   from plain GETs; the `calendar-query` time-range REPORT that precedes it
//!   is consumed for `<D:getetag/>` + `<D:href/>` only.
//! * **Every fetched event is filed at its master's `DTSTART`**
//!   (`CalendarEvent.getTimestamp`), with the raw `RRULE` string beside it —
//!   no recurrence is ever expanded — into one flat `SQLite` table
//!   (`UserDBHelper`), wiped and reinserted on every sync.
//! * **The 4-day list is a plain SQL window over that column** —
//!   `DtStart between <local midnight> and <local midnight + 4d>` — so an
//!   event is visible only while its *stored* `DtStart` falls inside it.
//!
//! Two stored forms break against that pipeline, and both are rewritten on the
//! wire here — scoped to the client's fixed User-Agent prefix and armed by
//! `[caldav] dailyview_timezone` (the deployment vouches for the timezone
//! because the client sends none):
//!
//! 1. **All-day events** (`DTSTART;VALUE=DATE:20261018`): the app appends
//!    `T000000Z` — UTC midnight — while its window is local-midnight, so west
//!    of UTC every all-day event files one calendar day early. Served as
//!    TZID-qualified midnight DATE-TIMEs instead:
//!
//!    ```text
//!    DTSTART;VALUE=DATE:20261018  ->  DTSTART;TZID=America/New_York:20261018T000000
//!    ```
//!
//! 2. **Recurring events**: the app stores the master's (often long-past)
//!    `DTSTART` and never computes an occurrence, so a weekly event with a
//!    September master never appears again on any day it recurs. Served as the
//!    first occurrence inside the phone's own 4-day window, as a plain
//!    (non-recurring) event at its true UTC instant:
//!
//!    ```text
//!    DTSTART;TZID=America/New_York:20260928T190000
//!    RRULE:FREQ=WEEKLY                            ->  DTSTART:20261012T230000Z
//!    (Monday 2026-10-12 in-window)                   END:VEVENT — no RRULE
//!    ```
//!
//!    All-day recurrence (a yearly `VALUE=DATE` + `FREQ=YEARLY`, say) takes
//!    both rewrites: the occurrence's date, filed at its local midnight.
//!
//! The stored object, its `ETag`, and every other client (khal, vdirsyncer,
//! Thunderbird, Apple, `HawkBook`) keep the canonical data — the rewrite is
//! per-User-Agent, on the wire only, and `DailyView` is view-only, so no PUT
//! can write the shim's form back. PROPFIND paths stay canonical by
//! construction (a `None` [`DailyviewContext`]); `CALDAV:expand` REPORTs keep
//! RFC 4791 §10.6 semantics untouched.
//!
//! **§18.38 — the export route (`?dailyview=1`):** the stock MP02 syncs
//! `dav.aphy.app`, never omnical, so its only ingest of this server's data is
//! a manual import of the exported `.ics`. [`build_export_ics_dailyview`]
//! shapes that download for the phone: recurrences flattened to concrete
//! instances over a 90-day horizon, all-day lines as local midnights.

use std::borrow::Cow;

use caldata::component::{CalendarInnerData, Component, IcalEvent, IcalTimeZone};
use caldata::generator::Emitter;
use caldata::parser::ContentLine;
use caldata::types::CalDateOrDateTime;
use chrono::{DateTime, Days, NaiveDate, TimeZone, Utc};
use http::HeaderMap;
use rustical_ical::CalendarObject;
use rustical_store::Calendar;

/// The User-Agent prefix of the frozen `DailyView` client (`CaldavFacade` in
/// the app; stock and `dailyview-mod` builds share it, differing only in the
/// `Version:` suffix).
const DAILYVIEW_UA_PREFIX: &str = "CalDAV Sync Adapter (Android)";

/// The phone's list horizon (`TimeUtil.getFourDaysStamp`): four days past
/// local midnight of today.
const DAILYVIEW_WINDOW_DAYS: u64 = 4;

/// Per-request context for the shim: the client's User-Agent, the deployment
/// timezone that vouches for it, and the request's notion of now (the phone's
/// window is relative, so the rewrite must be too).
#[derive(Clone, Debug)]
pub struct DailyviewContext {
    pub(crate) user_agent: Option<String>,
    pub(crate) timezone: Option<String>,
    pub(crate) now: DateTime<Utc>,
}

impl DailyviewContext {
    /// Build the context from a request's headers and the serving `[caldav]`
    /// config. Stamped with the current time; the REPORT/GET routes construct
    /// one per request, the tests pass fixed stamps.
    #[must_use]
    pub fn from_request(header_map: &HeaderMap, config: &crate::CalDavConfig) -> Self {
        Self {
            user_agent: header_map
                .get(http::header::USER_AGENT)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned),
            timezone: config.dailyview_timezone().map(str::to_owned),
            now: Utc::now(),
        }
    }
}

/// Serve `object` to `DailyView`: canonical bytes to everyone else, and to the
/// phone (User-Agent prefix + armed timezone) the two wire forms above — the
/// first in-window occurrence of a recurring event, all-day lines as local
/// midnights.
///
/// Every fall-through serves the canonical serialization (optionally with the
/// all-day pass): a non-recurring event, a recurring event with no occurrence
/// inside the window (nothing to show there — the phone would store the master
/// out-of-window, which is its own correct nothing), a `VTODO`/`VJOURNAL`
/// (never fetched by the phone), a timezone that does not parse (the shim is
/// off rather than wrong), or a `CALDAV:expand`-requesting client.
#[must_use]
pub fn rewrite_for_dailyview<'a>(
    object: &'a CalendarObject,
    context: &DailyviewContext,
) -> Cow<'a, str> {
    let Some(timezone) = context.timezone.as_deref().filter(|tz| !tz.is_empty()) else {
        return canonical(object, context);
    };
    if !context
        .user_agent
        .as_deref()
        .is_some_and(|ua| ua.starts_with(DAILYVIEW_UA_PREFIX))
    {
        return canonical(object, context);
    }
    // The window is computed in the deployment's zone, so the timezone must
    // resolve; an unparsable one disarms the whole shim, not just half of it.
    let Ok(tz) = timezone.parse::<chrono_tz::Tz>() else {
        return canonical(object, context);
    };

    if let CalendarInnerData::Event(main, overrides) = object.get_inner().get_inner()
        && main.has_rruleset()
        && let Some(instance) = first_window_instance(main, overrides, tz, context.now)
    {
        return Cow::Owned(instance_body(&instance, timezone));
    }
    canonical(object, context)
}

/// The canonical serialization, with the §18.36 all-day pass applied.
fn canonical<'a>(object: &'a CalendarObject, context: &DailyviewContext) -> Cow<'a, str> {
    rewrite_all_day_ics(
        object.get_ics(),
        context.user_agent.as_deref(),
        context.timezone.as_deref(),
    )
}

/// The first occurrence of `main` (honouring `overrides`, `UNTIL`, `COUNT`,
/// `EXDATE`/`EXRULE`) that the phone would file inside its own 4-day window
/// `[today local midnight, +4d)` — `None` when there is none.
#[must_use]
fn first_window_instance(
    main: &IcalEvent,
    overrides: &[IcalEvent],
    tz: chrono_tz::Tz,
    now: DateTime<Utc>,
) -> Option<IcalEvent> {
    let today = now.with_timezone(&tz).date_naive();
    let win_start = tz
        .from_local_datetime(&today.and_hms_opt(0, 0, 0)?)
        .single()?
        .with_timezone(&Utc);
    let win_end = win_start + chrono::Duration::days(DAILYVIEW_WINDOW_DAYS.cast_signed());
    let win_last_day = today.checked_add_days(Days::new(DAILYVIEW_WINDOW_DAYS))?;

    // Coarse bounds for the expansion (a day of slack each side — the rrule
    // set's `after`/`before` are exclusive); the filter below is exact.
    let instances = main.expand_recurrence(
        Some(win_start - chrono::Duration::days(1)),
        Some(win_end + chrono::Duration::days(1)),
        overrides,
    );

    instances
        .into_iter()
        .filter(|event| match &event.dtstart.0 {
            // DATE-valued: filed at local midnight of the date, so it is
            // in-window exactly when the date is one of the window's four
            // local days.
            CalDateOrDateTime::Date(date) => {
                let date = *date.naive_date();
                (date >= today) && (date < win_last_day)
            }
            // DATE-TIME instances come back as true UTC instants.
            CalDateOrDateTime::DateTime(datetime) => {
                let stamp = datetime.utc();
                (stamp >= win_start) && (stamp < win_end)
            }
        })
        .min_by_key(|event| event.dtstart.0.utc())
}

/// A single-instance `VCALENDAR` for the phone's ical4j: the occurrence as a
/// plain event (caldata's expansion has already stripped the recurrence
/// properties), wrapped in a fixed envelope — the instances are UTC (or
/// DATE-valued), so no `VTIMEZONE` is needed, and the alarms the expansion
/// drops never rendered in the phone's list anyway. DATE-valued lines then
/// take the §18.36 all-day pass.
fn instance_body(instance: &IcalEvent, timezone: &str) -> String {
    let mut out = String::from(
        "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//omnical//dailyview-shim//EN\r\nCALSCALE:GREGORIAN\r\n",
    );
    out.push_str(&instance.generate());
    out.push_str("END:VCALENDAR\r\n");
    match rewrite_all_day_ics(&out, Some(DAILYVIEW_UA_PREFIX), Some(timezone)) {
        Cow::Borrowed(_) => out,
        Cow::Owned(rewritten) => rewritten,
    }
}

// ── §18.38: the DailyView-shaped export ─────────────────────────────────────
//
// The stock MP02's DailyView syncs `dav.aphy.app`, never omnical — the wire
// shim above is inert insurance for this deployment — so the phone's only
// ingest of omnical data is a **manual import of the exported `.ics` into
// aphy.io**. aphy relays what it stores verbatim, and the phone files every
// body at its master's `DTSTART` and never expands a recurrence, so the
// canonical export (masters with `RRULE`, `VALUE=DATE` lines) shows a
// recurring event on no day at all west of UTC.
//
// The export route's `?dailyview=1` serves this builder instead: the same
// envelope and metadata, with every recurring event flattened to its
// concrete occurrences over a horizon, each as a standalone plain event
// (per-instance UID suffix — the phone's `cal_info` table is `UID UNIQUE`,
// and a re-import must upsert, not collide), no `RECURRENCE-ID` (a lone
// override is not an event a real server should keep), the master's
// `DURATION` riding along, and the §18.36 all-day pass applied to the
// assembled text. Non-recurring events, `VTODO`s and `VJOURNAL`s stay
// canonical apart from the all-day pass.

/// How many days of concrete instances the `DailyView` export flattens a
/// recurring event into. The phone's window is 4 days, but its ingest is a
/// one-shot manual import on aphy — a horizon this long keeps one import
/// showing correct Mondays for a quarter, and each instance only ever
/// displays on its own day.
pub const DAILYVIEW_EXPORT_HORIZON_DAYS: u64 = 90;

/// Build the DailyView-shaped export of a calendar: the canonical envelope
/// (`VERSION`/`PRODID`/`CALSCALE` + `X-WR-*` metadata), a `VTIMEZONE` for the
/// deployment's zone, and every object DailyView-consumable — recurring
/// events flattened to their occurrences over
/// [`DAILYVIEW_EXPORT_HORIZON_DAYS`] days, all-day lines as local midnights.
///
/// Falls back to the canonical [`crate::calendar::methods::get::build_export_ics`]
/// when `timezone` does not parse: the export must never be wrong, only
/// less-shaped.
#[must_use]
pub fn build_export_ics_dailyview(
    calendar: &Calendar,
    objects: Vec<(String, CalendarObject)>,
    timezone: &str,
    now: DateTime<Utc>,
) -> String {
    let Ok(tz) = timezone.parse::<chrono_tz::Tz>() else {
        return crate::calendar::methods::get::build_export_ics(calendar, objects);
    };

    let mut out = String::from(
        "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:RustiCal Export (DailyView)\r\nCALSCALE:GREGORIAN\r\n",
    );
    out.push_str(&crate::calendar::methods::get::calendar_x_wr_props(calendar).generate());
    // The deployment's own zone block: the all-day pass below emits
    // `TZID`-qualified lines, and a consumer with no tz database of its own
    // (a strict CalDAV relay, unlike the phone's java-side lookup) must not
    // be asked to guess what `America/New_York` means.
    if let Some(vtimezone) = IcalTimeZone::from_tzid(timezone) {
        out.push_str(&vtimezone.generate());
    }

    let today = now.with_timezone(&tz).date_naive();
    let Some(win_last_day) = today.checked_add_days(Days::new(DAILYVIEW_EXPORT_HORIZON_DAYS))
    else {
        return crate::calendar::methods::get::build_export_ics(calendar, objects);
    };
    // Date-valued instances compare as local dates; timed ones as the UTC
    // instants caldata's expansion produces.
    let Some(win_start_local) = today
        .and_hms_opt(0, 0, 0)
        .and_then(|midnight| tz.from_local_datetime(&midnight).single())
    else {
        return crate::calendar::methods::get::build_export_ics(calendar, objects);
    };
    let win_start = win_start_local.with_timezone(&Utc);
    let win_end = win_start + chrono::Duration::days(DAILYVIEW_EXPORT_HORIZON_DAYS.cast_signed());

    for (_, object) in objects {
        let object: caldata::component::IcalCalendarObject = object.into();
        match object.get_inner() {
            CalendarInnerData::Event(main, overrides) => {
                if main.has_rruleset() {
                    // Coarse bounds for the expansion (a day of slack each
                    // side — the rrule set's after/before are exclusive);
                    // the filter below is exact.
                    let instances = main.expand_recurrence(
                        Some(win_start - chrono::Duration::days(1)),
                        Some(win_end + chrono::Duration::days(1)),
                        overrides,
                    );
                    for instance in instances {
                        if instance_in_window(
                            &instance.dtstart.0,
                            today,
                            win_last_day,
                            win_start,
                            win_end,
                        ) {
                            out.push_str(&flattened_instance(&instance));
                        }
                    }
                } else {
                    out.push_str(&main.generate());
                    for event in overrides {
                        out.push_str(&event.generate());
                    }
                }
            }
            // The phone never lists these; aphy stores them verbatim —
            // canonical apart from the all-day pass below.
            CalendarInnerData::Todo(main, overrides) => {
                out.push_str(&main.generate());
                for todo in overrides {
                    out.push_str(&todo.generate());
                }
            }
            CalendarInnerData::Journal(main, overrides) => {
                out.push_str(&main.generate());
                for journal in overrides {
                    out.push_str(&journal.generate());
                }
            }
        }
    }

    out.push_str("END:VCALENDAR\r\n");

    match rewrite_date_valued_lines(&out, timezone) {
        Cow::Borrowed(_) => out,
        Cow::Owned(rewritten) => rewritten,
    }
}

/// One flattened instance of a recurring event: the expansion's event with
/// the master's UID suffixed by the instance's own date (deterministic, so a
/// re-import upserts instead of duplicating on aphy) and its `RECURRENCE-ID`
/// dropped (a lone override line is not an event). Everything else —
/// `DTSTART` at the occurrence, the master's `DURATION`, summary, alarms
/// stripped by the expansion — rides along verbatim.
fn flattened_instance(instance: &IcalEvent) -> String {
    let suffix = match &instance.dtstart.0 {
        CalDateOrDateTime::Date(date) => date.naive_date().format("%Y%m%d").to_string(),
        CalDateOrDateTime::DateTime(datetime) => {
            datetime.utc().format("%Y%m%dT%H%M%SZ").to_string()
        }
    };
    let mut lines: Vec<ContentLine> = instance.get_properties().clone();
    for line in &mut lines {
        if line.name == "UID" {
            line.value = format!("{}-{suffix}", line.value);
        }
    }
    lines.retain(|line| line.name != "RECURRENCE-ID");
    let mut out = String::from("BEGIN:VEVENT\r\n");
    out.push_str(&lines.generate());
    out.push_str("END:VEVENT\r\n");
    out
}

/// Whether the phone would file this occurrence inside its own list window —
/// here the export horizon rather than the 4-day wire window.
fn instance_in_window(
    dtstart: &CalDateOrDateTime,
    today: NaiveDate,
    win_last_day: NaiveDate,
    win_start: DateTime<Utc>,
    win_end: DateTime<Utc>,
) -> bool {
    match dtstart {
        // DATE-valued: filed at local midnight of the date, so in-window
        // exactly when the date is one of the horizon's local days.
        CalDateOrDateTime::Date(date) => {
            let date = *date.naive_date();
            (date >= today) && (date < win_last_day)
        }
        // DATE-TIME instances come back as true UTC instants.
        CalDateOrDateTime::DateTime(datetime) => {
            let stamp = datetime.utc();
            (stamp >= win_start) && (stamp < win_end)
        }
    }
}

/// Serve `body` for `user_agent`, rewriting DATE-valued `DTSTART`/`DTEND`
/// into TZID-qualified midnight DATE-TIMEs when the client is `DailyView`
/// and the shim is configured (`[caldav] dailyview_timezone`). Every other
/// client — and a disabled or absent timezone — receives the body unchanged.
#[must_use]
pub fn rewrite_all_day_ics<'a>(
    body: &'a str,
    user_agent: Option<&str>,
    timezone: Option<&str>,
) -> Cow<'a, str> {
    let Some(timezone) = timezone.filter(|tz| !tz.is_empty()) else {
        return Cow::Borrowed(body);
    };
    if !user_agent.is_some_and(|ua| ua.starts_with(DAILYVIEW_UA_PREFIX)) {
        return Cow::Borrowed(body);
    }
    rewrite_date_valued_lines(body, timezone)
}

/// The §18.36 all-day pass itself, un-gated: every DATE-valued `DTSTART`/
/// `DTEND` line becomes a TZID-qualified midnight DATE-TIME in `timezone`.
/// The export builder applies it directly (no User-Agent on that wire).
#[must_use]
fn rewrite_date_valued_lines<'a>(body: &'a str, timezone: &str) -> Cow<'a, str> {
    // Only the early-out for bodies with no all-day line at all — the
    // per-line match below stays the sole authority on what rewrites.
    if !body.contains(";VALUE=DATE:") {
        return Cow::Borrowed(body);
    }
    let mut out = String::with_capacity(body.len() + 64);
    let mut rewritten = false;
    for line in body.split_inclusive('\n') {
        match rewrite_line(line, timezone) {
            Some(rewritten_line) => {
                out.push_str(&rewritten_line);
                rewritten = true;
            }
            None => out.push_str(line),
        }
    }
    if rewritten {
        Cow::Owned(out)
    } else {
        Cow::Borrowed(body)
    }
}

/// `DTSTART;VALUE=DATE:20261018\r\n` →
/// `DTSTART;TZID=America/New_York:20261018T000000\r\n` — same for `DTEND`,
/// line ending preserved. Only the exact uppercase form is rewritten: this
/// deployment's writers (the holiday generator, khal, Apple Calendar) all
/// emit it, and a strict match keeps foreign shapes — quoted params,
/// `VALUE=DATE` mid-parameter-list, malformed values — byte-identical rather
/// than guessed at.
fn rewrite_line(line: &str, timezone: &str) -> Option<String> {
    let content = line.trim_end_matches(['\r', '\n']);
    let line_end = &line[content.len()..];
    let (name_params, value) = content.split_once(':')?;
    let property = name_params.strip_suffix(";VALUE=DATE")?;
    if !matches!(property, "DTSTART" | "DTEND") {
        return None;
    }
    if value.len() != 8 || !value.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some(format!(
        "{property};TZID={timezone}:{value}T000000{line_end}"
    ))
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use super::{
        DAILYVIEW_UA_PREFIX, DailyviewContext, build_export_ics_dailyview, rewrite_all_day_ics,
        rewrite_for_dailyview,
    };
    use caldata::parser::ParserOptions;
    use chrono::NaiveDateTime;
    use rustical_ical::CalendarObject;

    const DAILYVIEW_UA: &str = "CalDAV Sync Adapter (Android) https://github.com/gggard/AndroidCaldavSyncAdapater Version:1.0.08";

    const ALL_DAY: &str = "BEGIN:VCALENDAR\r\nPRODID:-//omnical//holiday-sets//EN\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:hol-rc-1962-st-luke-evangelist-20261018@omnical\r\nDTSTAMP:20260101T000000Z\r\nDTSTART;VALUE=DATE:20261018\r\nDTEND;VALUE=DATE:20261019\r\nSUMMARY:St Luke\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";

    const TIMED: &str = "BEGIN:VCALENDAR\r\nPRODID:-//Apple Inc.//iPhone OS 16.7.16//EN\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:203057C8\r\nDTSTAMP:20260918T000901Z\r\nDTEND;TZID=America/New_York:20260917T210000\r\nDTSTART;TZID=America/New_York:20260917T200000\r\nSUMMARY:Purple\r\nTRANSP:OPAQUE\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";

    /// The weekly "Trash" master exactly as this deployment stores it: a
    /// September `DTSTART`, `FREQ=WEEKLY` — the phone would file it at
    /// September 28th forever, on a Monday it can never see again.
    const WEEKLY_TIMED: &str = "BEGIN:VCALENDAR\r\nPRODID:-//omnical//holiday-sets//EN\r\nVERSION:2.0\r\nCALSCALE:GREGORIAN\r\nBEGIN:VEVENT\r\nUID:RGKW68NDCGRYYVVHH55NLH5PU8Z6QH1IDKBU\r\nDTSTAMP:20260925T103702Z\r\nDTSTART;TZID=America/New_York:20260928T190000\r\nDTEND;TZID=America/New_York:20260928T190100\r\nSUMMARY:Trash\r\nRRULE:FREQ=WEEKLY\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";

    /// A yearly all-day birthday: `VALUE=DATE` + `FREQ=YEARLY` — both
    /// rewrites at once.
    const YEARLY_ALL_DAY: &str = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//omnical//holiday-sets//EN\r\nBEGIN:VEVENT\r\nUID:birthday-1962@omnical\r\nDTSTAMP:20260101T000000Z\r\nDTSTART;VALUE=DATE:19620409\r\nDTEND;VALUE=DATE:19620410\r\nSUMMARY:Birthday\r\nRRULE:FREQ=YEARLY\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";

    /// A weekly master that ended before the window: nothing to show, the
    /// canonical body is served.
    const EXPIRED_WEEKLY: &str = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//omnical//holiday-sets//EN\r\nBEGIN:VEVENT\r\nUID:expired@omnical\r\nDTSTAMP:20260101T000000Z\r\nDTSTART;TZID=America/New_York:20260907T190000\r\nDTEND;TZID=America/New_York:20260907T190100\r\nSUMMARY:Past\r\nRRULE:FREQ=WEEKLY;UNTIL=20260922T000000Z\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";

    fn context(user_agent: Option<&str>, timezone: Option<&str>, now: &str) -> DailyviewContext {
        DailyviewContext {
            user_agent: user_agent.map(str::to_owned),
            timezone: timezone.map(str::to_owned),
            now: NaiveDateTime::parse_from_str(now, "%Y-%m-%d %H:%M:%S")
                .unwrap()
                .and_utc(),
        }
    }

    /// Parse the way the serving paths do (`[caldav] rfc7809` resolves bare
    /// `TZID`s; `from_ics` would reject them without a VTIMEZONE).
    fn parse(ics: &str) -> CalendarObject {
        CalendarObject::import(ics, Some(ParserOptions { rfc7809: true })).unwrap()
    }

    // --- the §18.36 all-day pass, unchanged ---------------------------------

    #[test]
    fn rewrites_all_day_for_dailyview() {
        let out = rewrite_all_day_ics(ALL_DAY, Some(DAILYVIEW_UA), Some("America/New_York"));
        assert!(matches!(out, Cow::Owned(_)));
        assert!(
            out.contains("DTSTART;TZID=America/New_York:20261018T000000\r\n"),
            "DTSTART rewritten to a local-midnight DATE-TIME: {out}"
        );
        assert!(
            out.contains("DTEND;TZID=America/New_York:20261019T000000\r\n"),
            "DTEND rewritten alongside: {out}"
        );
        assert!(!out.contains("VALUE=DATE"));
        // The untouched lines survive byte-identical, CRLF included.
        assert!(out.contains("SUMMARY:St Luke\r\n"));
        assert!(out.ends_with("END:VCALENDAR\r\n"));
    }

    #[test]
    fn leaves_other_clients_untouched() {
        for ua in [
            Some("vdirsyncer/0.19.4"),
            Some("Thunderbird/128.0 CalDAV"),
            Some("macOS/13.6 CalendarAgent/1234"),
            None,
        ] {
            let out = rewrite_all_day_ics(ALL_DAY, ua, Some("America/New_York"));
            assert!(matches!(out, Cow::Borrowed(_)), "no rewrite for {ua:?}");
            assert_eq!(out, ALL_DAY);
        }
    }

    #[test]
    fn disabled_when_timezone_absent_or_empty() {
        let out = rewrite_all_day_ics(ALL_DAY, Some(DAILYVIEW_UA), None);
        assert!(matches!(out, Cow::Borrowed(_)));
        let out = rewrite_all_day_ics(ALL_DAY, Some(DAILYVIEW_UA), Some(""));
        assert!(matches!(out, Cow::Borrowed(_)));
        assert_eq!(out, ALL_DAY);
    }

    #[test]
    fn leaves_timed_events_untouched() {
        let out = rewrite_all_day_ics(TIMED, Some(DAILYVIEW_UA), Some("America/New_York"));
        assert!(matches!(out, Cow::Borrowed(_)));
        assert_eq!(out, TIMED);
    }

    #[test]
    fn leaves_malformed_values_untouched() {
        for body in [
            "DTSTART;VALUE=DATE:2026101\r\n",      // 7 digits
            "DTEND;VALUE=DATE:2026101A\r\n",       // non-digit
            "DTSTART;VALUE=DATE;X=1:20261018\r\n", // VALUE not the last param
            "SUMMARY;VALUE=DATE:20261018\r\n",     // not DTSTART/DTEND
        ] {
            let out = rewrite_all_day_ics(body, Some(DAILYVIEW_UA), Some("America/New_York"));
            assert!(matches!(out, Cow::Borrowed(_)), "no rewrite for {body:?}");
            assert_eq!(out, body);
        }
    }

    #[test]
    fn preserves_lf_only_bodies() {
        let body = "DTSTART;VALUE=DATE:20261018\n";
        let out = rewrite_all_day_ics(body, Some(DAILYVIEW_UA), Some("UTC"));
        assert_eq!(out, "DTSTART;TZID=UTC:20261018T000000\n");
    }

    #[test]
    fn matches_prefix_not_full_agent() {
        // A future/stock version with a different Version: suffix still matches.
        assert!(DAILYVIEW_UA.starts_with(DAILYVIEW_UA_PREFIX));
        let body = "DTSTART;VALUE=DATE:20261018\r\n";
        let out = rewrite_all_day_ics(
            body,
            Some("CalDAV Sync Adapter (Android) Version:2.0.0"),
            Some("UTC"),
        );
        assert_eq!(out, "DTSTART;TZID=UTC:20261018T000000\r\n");
    }

    // --- the §18.37 recurrence flattening ----------------------------------

    #[test]
    fn flattens_recurring_timed_master_into_window() {
        let object = parse(WEEKLY_TIMED);
        // Monday 2026-10-12: the phone's window is Oct 12–15 local, and the
        // Trash occurrence is 19:00 EDT = 23:00 UTC on the 12th.
        let ctx = context(
            Some(DAILYVIEW_UA),
            Some("America/New_York"),
            "2026-10-12 12:00:00",
        );
        let out = rewrite_for_dailyview(&object, &ctx);
        assert!(
            out.contains("DTSTART:20261012T230000Z\r\n"),
            "the in-window occurrence at its UTC instant: {out}"
        );
        assert!(
            out.contains("DURATION:"),
            "the master's length rides along (as DURATION): {out}"
        );
        assert!(!out.contains("RRULE"), "no recurrence is shipped: {out}");
        assert!(
            !out.contains("TZID="),
            "the instance is UTC, no zone parameter: {out}"
        );
        assert!(out.contains("SUMMARY:Trash\r\n"));
        assert!(out.contains("UID:RGKW68NDCGRYYVVHH55NLH5PU8Z6QH1IDKBU\r\n"));
        assert!(out.starts_with("BEGIN:VCALENDAR\r\n"));
        assert!(out.ends_with("END:VEVENT\r\nEND:VCALENDAR\r\n"));
    }

    #[test]
    fn picks_the_windows_own_occurrence_per_day() {
        let object = parse(WEEKLY_TIMED);
        // Saturday 2026-10-17: the window runs Sat–Tue, so it contains this
        // Monday's (Oct 19) occurrence — that day's own, not the master's.
        let ctx = context(
            Some(DAILYVIEW_UA),
            Some("America/New_York"),
            "2026-10-17 12:00:00",
        );
        let out = rewrite_for_dailyview(&object, &ctx);
        assert!(out.contains("DTSTART:20261019T230000Z\r\n"), "{out}");
    }

    #[test]
    fn recurring_without_window_occurrence_serves_canonical() {
        let object = parse(EXPIRED_WEEKLY);
        let ctx = context(
            Some(DAILYVIEW_UA),
            Some("America/New_York"),
            "2026-10-12 12:00:00",
        );
        let out = rewrite_for_dailyview(&object, &ctx);
        assert_eq!(
            out,
            object.get_ics(),
            "nothing in the window: the canonical master, no guess"
        );
    }

    #[test]
    fn flattens_recurring_all_day_master_into_window() {
        let object = parse(YEARLY_ALL_DAY);
        // Monday 2026-04-06: this year's birthday (Apr 9) is in the window
        // and lands as a local-midnight DATE-TIME via the §18.36 pass, with
        // its day of length riding along as DURATION.
        let ctx = context(
            Some(DAILYVIEW_UA),
            Some("America/New_York"),
            "2026-04-06 12:00:00",
        );
        let out = rewrite_for_dailyview(&object, &ctx);
        assert!(
            out.contains("DTSTART;TZID=America/New_York:20260409T000000\r\n"),
            "the occurrence's date at local midnight: {out}"
        );
        assert!(
            out.contains("DURATION:P1D"),
            "the day of length rides along: {out}"
        );
        assert!(!out.contains("RRULE"), "no recurrence is shipped: {out}");
        assert!(
            !out.contains("DTSTART;VALUE=DATE"),
            "the occurrence is the §18.36 local-midnight form: {out}"
        );
    }

    #[test]
    fn non_recurring_keeps_the_all_day_pass() {
        let object = parse(ALL_DAY);
        let ctx = context(
            Some(DAILYVIEW_UA),
            Some("America/New_York"),
            "2026-10-12 12:00:00",
        );
        let out = rewrite_for_dailyview(&object, &ctx);
        assert!(out.contains("DTSTART;TZID=America/New_York:20261018T000000\r\n"));
    }

    #[test]
    fn recurring_other_clients_serve_canonical() {
        let object = parse(WEEKLY_TIMED);
        let ctx = context(
            Some("vdirsyncer/0.19.4"),
            Some("America/New_York"),
            "2026-10-12 12:00:00",
        );
        let out = rewrite_for_dailyview(&object, &ctx);
        assert_eq!(out, object.get_ics());
        assert!(out.contains("RRULE:FREQ=WEEKLY"));
    }

    #[test]
    fn recurring_disabled_without_timezone() {
        let object = parse(WEEKLY_TIMED);
        let ctx = context(Some(DAILYVIEW_UA), None, "2026-10-12 12:00:00");
        let out = rewrite_for_dailyview(&object, &ctx);
        assert_eq!(out, object.get_ics());
    }

    #[test]
    fn recurring_disabled_with_unparsable_timezone() {
        let object = parse(WEEKLY_TIMED);
        let ctx = context(Some(DAILYVIEW_UA), Some("Solar/Pan"), "2026-10-12 12:00:00");
        let out = rewrite_for_dailyview(&object, &ctx);
        assert_eq!(out, object.get_ics());
    }

    #[test]
    fn recurring_vtodo_serves_canonical() {
        let vtodo = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//omnical//holiday-sets//EN\r\nBEGIN:VTODO\r\nUID:todo@omnical\r\nDTSTAMP:20260101T000000Z\r\nDTSTART;TZID=America/New_York:20260928T190000\r\nSUMMARY:Chore\r\nRRULE:FREQ=WEEKLY\r\nEND:VTODO\r\nEND:VCALENDAR\r\n";
        let object = parse(vtodo);
        let ctx = context(
            Some(DAILYVIEW_UA),
            Some("America/New_York"),
            "2026-10-12 12:00:00",
        );
        let out = rewrite_for_dailyview(&object, &ctx);
        assert_eq!(out, object.get_ics());
        assert!(out.contains("BEGIN:VTODO"));
    }

    // ── §18.38: the DailyView-shaped export ───────────────────────────────

    fn export_calendar() -> rustical_store::Calendar {
        rustical_store::Calendar {
            meta: rustical_store::CalendarMetadata {
                displayname: Some("personal".to_owned()),
                description: None,
                color: None,
                order: 0,
            },
            principal: "nfcalaway@novo-ordo.com".to_owned(),
            id: "personal".to_owned(),
            timezone_id: None,
            deleted_at: None,
            synctoken: 1,
            subscription_url: None,
            push_topic: String::new(),
            components: vec![],
        }
    }

    fn now(stamp: &str) -> chrono::DateTime<chrono::Utc> {
        NaiveDateTime::parse_from_str(stamp, "%Y-%m-%d %H:%M:%S")
            .unwrap()
            .and_utc()
    }

    /// A weekly timed master flattens into one standalone instance per
    /// occurrence over the horizon: suffixed UIDs, no `RRULE`, no
    /// `RECURRENCE-ID`, the occurrence's `DTSTART` as a UTC DATE-TIME, the
    /// master's `DURATION` riding along, and the envelope carrying the
    /// calendar's `X-WR-CALNAME` and the deployment's `VTIMEZONE`.
    #[test]
    fn export_flattens_weekly_timed() {
        let object = parse(WEEKLY_TIMED);
        let out = build_export_ics_dailyview(
            &export_calendar(),
            vec![(String::from("daily.ics"), object)],
            "America/New_York",
            now("2026-10-12 12:00:00"),
        );
        assert!(out.starts_with("BEGIN:VCALENDAR\r\nVERSION:2.0\r\n"));
        assert!(out.ends_with("END:VCALENDAR\r\n"));
        assert!(out.contains("X-WR-CALNAME:personal\r\n"));
        assert!(out.contains("BEGIN:VTIMEZONE\r\nTZID:America/New_York\r\n"));
        // The VTIMEZONE's own DST rules carry RRULEs; the discriminators are
        // the events': no weekly RRULE survives, no master UID unsuffixed,
        // no vestigial RECURRENCE-ID.
        assert!(
            !out.contains("FREQ=WEEKLY"),
            "no weekly recurrence is exported: {out}"
        );
        assert!(
            !out.contains("RECURRENCE-ID"),
            "no vestigial override lines: {out}"
        );
        assert!(
            !out.contains("UID:RGKW68NDCGRYYVVHH55NLH5PU8Z6QH1IDKBU\r\n"),
            "the master's unsuffixed UID does not survive: {out}"
        );
        assert!(
            out.contains("UID:RGKW68NDCGRYYVVHH55NLH5PU8Z6QH1IDKBU-20261012T230000Z\r\n"),
            "today's occurrence, UID suffixed by its own stamp: {out}"
        );
        assert!(
            out.contains("DTSTART:20261019T230000Z\r\n"),
            "next Monday's occurrence is flattened too (EDT): {out}"
        );
        assert!(
            out.contains("DTSTART:20261012T230000Z\r\n"),
            "the occurrence's own start as a UTC DATE-TIME: {out}"
        );
        assert!(out.contains("DURATION:"), "the master's length rides along");
        assert_eq!(
            out.matches("BEGIN:VEVENT\r\n").count(),
            13,
            "13 weekly Mondays in a 90-day horizon: {out}"
        );
        assert_eq!(out.matches("END:VEVENT\r\n").count(), 13);
    }

    /// A yearly all-day master takes both rewrites: the occurrences' dates as
    /// local-midnight DATE-TIMEs (the §18.36 pass) with suffixed UIDs.
    #[test]
    fn export_flattens_yearly_all_day() {
        let object = parse(YEARLY_ALL_DAY);
        let out = build_export_ics_dailyview(
            &export_calendar(),
            vec![(String::from("birthday.ics"), object)],
            "America/New_York",
            now("2026-04-06 12:00:00"),
        );
        // This year's occurrence (Apr 9) is in the horizon; next year's
        // (Apr 9 2027) is 363 days out — beyond it. One instance, and the
        // master's 1964 date does not survive.
        assert_eq!(out.matches("BEGIN:VEVENT\r\n").count(), 1, "{out}");
        assert!(
            out.contains("DTSTART;TZID=America/New_York:20260409T000000\r\n"),
            "the occurrence's date at local midnight: {out}"
        );
        assert!(
            out.contains("UID:birthday-1962@omnical-20260409\r\n"),
            "DATE-valued instances suffix by date: {out}"
        );
        assert!(
            !out.contains("19620409"),
            "the master does not survive: {out}"
        );
        assert!(
            !out.contains("VALUE=DATE"),
            "the pass left no DATE lines: {out}"
        );
    }

    /// Non-recurring events keep their canonical form — apart from the
    /// all-day pass, which applies to the whole assembled export.
    #[test]
    fn export_keeps_non_recurring_with_all_day_pass() {
        let stluke = parse(ALL_DAY);
        let purple = parse(TIMED);
        let out = build_export_ics_dailyview(
            &export_calendar(),
            vec![
                (String::from("stluke.ics"), stluke),
                (String::from("purple.ics"), purple),
            ],
            "America/New_York",
            now("2026-10-12 12:00:00"),
        );
        assert!(
            out.contains("DTSTART;TZID=America/New_York:20261018T000000\r\n"),
            "the all-day pass applies to canonical events too: {out}"
        );
        assert!(
            out.contains("UID:hol-rc-1962-st-luke-evangelist-20261018@omnical\r\n"),
            "canonical UID untouched (no suffix without recurrence): {out}"
        );
        assert!(
            out.contains("DTSTART;TZID=America/New_York:20260917T200000\r\n"),
            "timed canonical lines untouched by the pass: {out}"
        );
        assert!(!out.contains("VALUE=DATE"), "{out}");
    }

    /// `VTODO`s ride along canonically: the phone never lists them, aphy
    /// stores them verbatim.
    #[test]
    fn export_keeps_vtodos_canonical() {
        let vtodo = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//omnical//holiday-sets//EN\r\nBEGIN:VTODO\r\nUID:todo@omnical\r\nDTSTAMP:20260101T000000Z\r\nDTSTART;TZID=America/New_York:20260928T190000\r\nSUMMARY:Chore\r\nRRULE:FREQ=WEEKLY\r\nEND:VTODO\r\nEND:VCALENDAR\r\n";
        let object = parse(vtodo);
        let out = build_export_ics_dailyview(
            &export_calendar(),
            vec![(String::from("chore.ics"), object)],
            "America/New_York",
            now("2026-10-12 12:00:00"),
        );
        assert_eq!(out.matches("BEGIN:VTODO\r\n").count(), 1, "{out}");
        assert!(
            out.contains("RRULE:FREQ=WEEKLY"),
            "a VTODO's recurrence is untouched: {out}"
        );
    }

    /// An unparsable timezone serves the canonical export — the export must
    /// never be wrong, only less-shaped.
    #[test]
    fn export_falls_back_to_canonical() {
        let object = parse(WEEKLY_TIMED);
        let out = build_export_ics_dailyview(
            &export_calendar(),
            vec![(String::from("daily.ics"), object.clone())],
            "Solar/Pan",
            now("2026-10-12 12:00:00"),
        );
        assert_eq!(
            out,
            crate::calendar::methods::get::build_export_ics(
                &export_calendar(),
                vec![(String::from("daily.ics"), object)],
            ),
            "unparsable zone: canonical bytes"
        );
        assert!(out.contains("RRULE:FREQ=WEEKLY"));
    }
}
