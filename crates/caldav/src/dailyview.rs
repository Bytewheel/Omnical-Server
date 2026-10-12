//! Omnical: the `DailyView` (Punkt MP02, `AphyOS`) all-day compatibility shim.
//!
//! `DailyView` — the frozen, Punkt-signed build this deployment cannot patch —
//! parses `DTSTART;VALUE=DATE:20261018` by appending `T000000Z`: the event is
//! filed at **UTC midnight** (`CalendarEvent.getTimestamp` in the app). Its
//! 4-day list is windowed with **local**-midnight stamps
//! (`TimeUtil.getTodayStamp`), so west of UTC an all-day event lands one
//! calendar day early — a St Luke feast on Oct 18 files under Oct 17 20:00 in
//! `America/New_York` — and is missing entirely on its own day. That is the
//! "holidays never show up" report that traced here.
//!
//! The fix is on the wire, not in the data: GET responses to `DailyView`
//! (matched by its fixed User-Agent prefix, shared by the stock and
//! `dailyview-mod` builds) serve DATE-valued `DTSTART`/`DTEND` as midnight
//! DATE-TIMEs in the deployment's timezone:
//!
//! ```text
//! DTSTART;VALUE=DATE:20261018  ->  DTSTART;TZID=America/New_York:20261018T000000
//! DTEND;VALUE=DATE:20261019    ->  DTEND;TZID=America/New_York:20261019T000000
//! ```
//!
//! The app's parser resolves that form to local-midnight millis — its exact
//! window and day-bucket boundary — so the event displays on the correct day
//! (cosmetically as a `00:00` timed event; `DailyView` has no all-day marker
//! to lose). The stored object is untouched: every other client keeps the
//! canonical all-day data, and `DailyView` is view-only, so no PUT can write
//! the shim's form back. REPORT bodies are not rewritten: the app asks for
//! `<C:calendar-data/>` in its calendar-query reports but ignores it,
//! fetching each body with a plain GET — the only path it consumes.

use std::borrow::Cow;

/// The User-Agent prefix of the frozen `DailyView` client (`CaldavFacade` in
/// the app; stock and `dailyview-mod` builds share it, differing only in the
/// `Version:` suffix).
const DAILYVIEW_UA_PREFIX: &str = "CalDAV Sync Adapter (Android)";

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

    use super::{DAILYVIEW_UA_PREFIX, rewrite_all_day_ics};

    const DAILYVIEW_UA: &str = "CalDAV Sync Adapter (Android) https://github.com/gggard/AndroidCaldavSyncAdapater Version:1.0.08";

    const ALL_DAY: &str = "BEGIN:VCALENDAR\r\nPRODID:-//omnical//holiday-sets//EN\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:hol-rc-1962-st-luke-evangelist-20261018@omnical\r\nDTSTAMP:20260101T000000Z\r\nDTSTART;VALUE=DATE:20261018\r\nDTEND;VALUE=DATE:20261019\r\nSUMMARY:St Luke\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";

    const TIMED: &str = "BEGIN:VCALENDAR\r\nPRODID:-//Apple Inc.//iPhone OS 16.7.16//EN\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:203057C8\r\nDTSTAMP:20260918T000901Z\r\nDTEND;TZID=America/New_York:20260917T210000\r\nDTSTART;TZID=America/New_York:20260917T200000\r\nSUMMARY:Purple\r\nTRANSP:OPAQUE\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";

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
}
