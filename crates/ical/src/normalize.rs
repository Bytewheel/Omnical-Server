//! Normalisation of client-quirk iCalendar input on the import (DAV PUT)
//! path. The store load path (`CalendarObject::from_ics`) never runs these.

use std::borrow::Cow;

use chrono::{NaiveDate, NaiveDateTime, NaiveTime};

/// Convert RFC-5545-invalid floating or DATE-valued `UNTIL`s to UTC when the
/// component's `DTSTART` is timezone-qualified.
///
/// khal writes `UNTIL=20261204T090000` (floating) for `TZID`'d events, and
/// after an ikhal edit re-serialises it as a bare DATE `UNTIL=20261204`;
/// both mean the event's zone / the inclusive last-occurrence day (RFC 5545
/// §3.3.10: when `DTSTART` is timezone-qualified, `UNTIL` MUST be UTC, and
/// its value type must match `DTSTART`'s):
///
/// * `TZID=<zone>` `DTSTART` → a floating `UNTIL` DATE-TIME is interpreted
///   in that zone (via chrono-tz, earliest occurrence on DST folds) and
///   re-emitted as `UNTIL=YYYYMMDDTHHMMSSZ`; a DATE-valued `UNTIL` is
///   expanded to that date at the `DTSTART`'s time-of-day in that zone
///   (keeping the day's occurrences intact) and likewise re-emitted as UTC;
/// * UTC `DTSTART` → a floating `UNTIL` DATE-TIME is taken as UTC and gets
///   a `Z`; a DATE-valued `UNTIL` is expanded with the `DTSTART`'s
///   time-of-day;
/// * everything else (all-day, floating `DTSTART`, already-UTC `UNTIL`,
///   unknown `TZID`, `DTSTART`/`RRULE` inside nested components) is left
///   untouched.
///
/// Returns [`Cow`] so untouched bodies are zero-copy. Line folding is lost
/// on rewritten bodies (unfolded lines are universally parsed; `RustiCal`
/// re-folds on serialisation).
#[must_use]
pub fn normalize_rrule_until(ics: &str) -> Cow<'_, str> {
    let lines = unfold(ics);

    // Per schedulable component (VEVENT/VTODO/VJOURNAL directly inside the
    // VCALENDAR): its DTSTART shape, indexed by component instance.
    let mut dtstarts: Vec<DtStart> = vec![];
    // RRULE lines (index into `lines`) with the component instance they
    // belong to. Nested components (VALARM, …) never contribute.
    let mut rrules: Vec<(usize, usize)> = vec![];

    let mut stack: Vec<String> = vec![];
    let mut comp: Option<usize> = None;

    for (i, line) in lines.iter().enumerate() {
        let prop = parse_prop(line);
        match prop.name {
            "BEGIN" => {
                stack.push(prop.value.to_owned());
                if stack.len() == 2 && is_schedulable(prop.value) {
                    comp = Some(dtstarts.len());
                    dtstarts.push(DtStart::Other);
                }
            }
            "END" => {
                if stack.len() == 2 && comp.is_some() {
                    comp = None;
                }
                stack.pop();
            }
            "DTSTART" if stack.len() == 2 && comp.is_some() => {
                let dt = DtStart::parse(&prop);
                if let Some(comp) = comp
                    && matches!(dtstarts[comp], DtStart::Other)
                {
                    dtstarts[comp] = dt;
                }
            }
            "RRULE" if stack.len() == 2 && comp.is_some() => {
                if let Some(comp) = comp {
                    rrules.push((i, comp));
                }
            }
            _ => {}
        }
    }

    // Rewrite pass — only when the component's DTSTART is timezone-qualified.
    let mut rewrites: Vec<(usize, String)> = vec![];
    for &(line_idx, comp) in &rrules {
        let Some(dt) = dtstarts.get(comp) else {
            continue;
        };
        let (tz, dtstart_time) = match dt {
            DtStart::Tzid(tzid, time) => (tzid.parse::<chrono_tz::Tz>().ok(), *time),
            DtStart::Utc(time) => (Some(chrono_tz::Tz::UTC), *time),
            DtStart::Floating | DtStart::Date | DtStart::Other => (None, None),
        };
        let Some(tz) = tz else { continue };
        let (head, value) = split_line(&lines[line_idx]);
        let Some(new_value) = rewrite_rrule_value(value, tz, dtstart_time) else {
            continue;
        };
        rewrites.push((line_idx, format!("{head}:{new_value}")));
    }

    if rewrites.is_empty() {
        return Cow::Borrowed(ics);
    }

    let mut out = lines;
    for (line_idx, new_line) in rewrites {
        out[line_idx] = new_line;
    }
    let mut joined = out.join("\r\n");
    // unfold() drops the final CRLF on rejoin; keep the input's trailing
    // line ending (RFC 5545 content lines end with CRLF, including the last)
    if ics.ends_with('\n') {
        joined.push_str("\r\n");
    }
    Cow::Owned(joined)
}

/// The timezone shape of a component's `DTSTART` property. The tz-qualified
/// variants carry the value's time-of-day (needed to expand DATE-valued
/// `UNTIL`s); `None` when the value is not a parseable DATE-TIME.
#[derive(Debug, Clone, PartialEq, Eq)]
enum DtStart {
    /// `TZID` param present
    Tzid(String, Option<NaiveTime>),
    /// Value ends with `Z`, no `TZID`
    Utc(Option<NaiveTime>),
    /// Naive value, no `TZID`
    Floating,
    /// All-day (`VALUE=DATE` or 8-digit value)
    Date,
    /// Anything unparseable — leave the component untouched
    Other,
}

impl DtStart {
    fn parse(prop: &Prop<'_>) -> Self {
        let value = prop.value.trim();
        if prop.param_eq("VALUE", "DATE") || is_date(value) {
            return Self::Date;
        }
        let time = if is_date_time(value)
            || value.len() == 16 && value.ends_with('Z') && is_date_time(&value[..15])
        {
            NaiveTime::parse_from_str(&value[9..15], "%H%M%S").ok()
        } else {
            None
        };
        if let Some(tzid) = prop.param("TZID") {
            return Self::Tzid(tzid.to_owned(), time);
        }
        if value.len() == 16 && value.ends_with('Z') && is_date_time(&value[..15]) {
            return Self::Utc(time);
        }
        if is_date_time(value) {
            return Self::Floating;
        }
        Self::Other
    }
}

/// Whether `s` is a `YYYYMMDD` DATE.
fn is_date(s: &str) -> bool {
    s.len() == 8 && s.bytes().all(|b| b.is_ascii_digit())
}

/// Whether `s` is a `YYYYMMDDTHHMMSS` DATE-TIME.
fn is_date_time(s: &str) -> bool {
    s.len() == 15
        && s.as_bytes()[8] == b'T'
        && s.bytes()
            .enumerate()
            .all(|(i, b)| b.is_ascii_digit() || i == 8)
}

const fn is_schedulable(name: &str) -> bool {
    name.eq_ignore_ascii_case("VEVENT")
        || name.eq_ignore_ascii_case("VTODO")
        || name.eq_ignore_ascii_case("VJOURNAL")
}

/// Rewrite RRULE values to UTC in `tz`: floating `UNTIL` DATE-TIMEs are
/// interpreted in `tz`, DATE-valued `UNTIL`s (khal's post-edit form, the
/// inclusive last-occurrence day) are expanded to that date at the
/// `DTSTART`'s time-of-day. `dtstart_time` is `None` when the `DTSTART`
/// value is not a parseable DATE-TIME — then DATE-valued `UNTIL`s are left
/// alone. `None` is returned when there is nothing to rewrite (or a local
/// time does not exist, e.g. inside a DST spring-forward gap — then the
/// line is left untouched rather than guessed).
fn rewrite_rrule_value(
    value: &str,
    tz: chrono_tz::Tz,
    dtstart_time: Option<NaiveTime>,
) -> Option<String> {
    let mut out: Vec<String> = vec![];
    let mut changed = false;
    for part in value.split(';') {
        let Some((k, v)) = part.split_once('=') else {
            out.push(part.to_owned());
            continue;
        };
        let until_utc = if k.eq_ignore_ascii_case("UNTIL") && is_date_time(v) {
            let naive = NaiveDateTime::parse_from_str(v, "%Y%m%dT%H%M%S").ok()?;
            Some(naive.and_local_timezone(tz).earliest()?.naive_utc())
        } else if k.eq_ignore_ascii_case("UNTIL")
            && is_date(v)
            && let Some(time) = dtstart_time
        {
            let date = NaiveDate::parse_from_str(v, "%Y%m%d").ok()?;
            Some(
                date.and_time(time)
                    .and_local_timezone(tz)
                    .earliest()?
                    .naive_utc(),
            )
        } else {
            None
        };
        if let Some(utc) = until_utc {
            out.push(format!("{k}={}", utc.format("%Y%m%dT%H%M%SZ")));
            changed = true;
        } else {
            out.push(part.to_owned());
        }
    }
    if changed { Some(out.join(";")) } else { None }
}

/// A parsed (unfolded) content line, borrowed.
struct Prop<'a> {
    name: &'a str,
    params: Vec<(&'a str, &'a str)>,
    value: &'a str,
}

impl Prop<'_> {
    fn param(&self, key: &str) -> Option<&str> {
        self.params
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(key))
            .map(|(_, v)| *v)
    }

    fn param_eq(&self, key: &str, expected: &str) -> bool {
        self.param(key)
            .is_some_and(|v| v.eq_ignore_ascii_case(expected))
    }
}

/// Parse a content line into name/params/value. The name/params block is
/// separated from the value by the first `:` outside quoted parameter
/// values (RFC 5545 3.1); parameters are split on `;` the same way.
fn parse_prop(line: &str) -> Prop<'_> {
    let (head, value) = split_line(line);
    let mut params = vec![];
    let mut name = head;
    // The first `;` always separates the name from the params (quoted
    // values only occur inside params).
    if let Some(semicolon) = head.find(';') {
        name = &head[..semicolon];
        for param in split_on_semicolons(&head[semicolon + 1..]) {
            if let Some((k, v)) = param.split_once('=') {
                params.push((k.trim(), unquote(v)));
            }
        }
    }
    Prop {
        name: name.trim(),
        params,
        value: value.trim(),
    }
}

/// Split a content line into head (name + params) and value at the first
/// `:` outside quoted parameter values (RFC 5545 3.1).
fn split_line(line: &str) -> (&str, &str) {
    let mut in_quotes = false;
    for (i, ch) in line.char_indices() {
        if ch == '"' {
            in_quotes = !in_quotes;
        } else if ch == ':' && !in_quotes {
            return (&line[..i], &line[i + 1..]);
        }
    }
    (line.trim(), "")
}

/// Split a parameter list on `;` outside quoted values (RFC 5545 3.1).
fn split_on_semicolons(input: &str) -> Vec<&str> {
    let mut out = vec![];
    let mut in_quotes = false;
    let mut start = 0;
    for (i, ch) in input.char_indices() {
        match ch {
            '"' => in_quotes = !in_quotes,
            ';' if !in_quotes => {
                out.push(&input[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    out.push(&input[start..]);
    out
}

/// Trim an optional pair of double quotes around a value.
fn unquote(value: &str) -> &str {
    let value = value.trim();
    if value.len() >= 2 && value.starts_with('"') && value.ends_with('"') {
        &value[1..value.len() - 1]
    } else {
        value
    }
}

/// Split an ICS body into unfolded logical lines.
/// Also normalises lone `\n` line endings (rustical stores CRLF).
fn unfold(ics: &str) -> Vec<String> {
    let normalized = ics.replace("\r\n", "\n");
    let mut logical: Vec<String> = vec![];
    for raw_line in normalized.split('\n') {
        if raw_line.is_empty() {
            continue;
        }
        if let Some(stripped) = raw_line
            .strip_prefix(' ')
            .or_else(|| raw_line.strip_prefix('\t'))
            && let Some(last) = logical.last_mut()
        {
            last.push_str(stripped);
            continue;
        }
        logical.push(raw_line.to_owned());
    }
    logical
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The real-world khal event that used to 403 on PUT (floating
    /// `UNTIL` with a `TZID`'d `DTSTART`), verbatim.
    const REAL_EVENT: &str = "BEGIN:VCALENDAR\r\n\
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
SUMMARY:Stand Up\r\n\
DTSTART;TZID=America/New_York:20260918T110000\r\n\
DTEND;TZID=America/New_York:20260918T113000\r\n\
DTSTAMP:20260918T092542Z\r\n\
UID:25Z10RT2PWIEJR2ZRHH3MTF7FJYQB8NS428S\r\n\
SEQUENCE:0\r\n\
RRULE:FREQ=WEEKLY;UNTIL=20261204T090000;INTERVAL=2\r\n\
ATTENDEE;CUTYPE=INDIVIDUAL;PARTSTAT=NEEDS-ACTION;ROLE=REQ-PARTICIPANT;RSVP\r\n =TRUE:MAILTO:denis@hawksnestsoftware.com\r\n\
LOCATION:Phone\r\n\
BEGIN:VALARM\r\n\
ACTION:DISPLAY\r\n\
DESCRIPTION:\r\n\
TRIGGER:-PT10M\r\n\
END:VALARM\r\n\
END:VEVENT\r\n\
END:VCALENDAR\r\n";

    /// The same real-world event after an ikhal edit (time moved 11:00 →
    /// 09:00, `SEQUENCE` bumped): khal re-serialised the RRULE end as a
    /// bare DATE `UNTIL=20261204` next to the `TZID`'d `DTSTART` — a
    /// value-type mismatch that also fails caldata's
    /// `DtStartUntilMismatchTimezone` validation (the DATE parses as
    /// floating midnight). Verbatim including khal's folded ATTENDEE line.
    const EDITED_EVENT: &str = concat!(
        "BEGIN:VCALENDAR\r\n",
        "VERSION:2.0\r\n",
        "PRODID:-//PIMUTILS.ORG//NONSGML khal / icalendar //EN\r\n",
        "BEGIN:VTIMEZONE\r\n",
        "TZID:America/New_York\r\n",
        "BEGIN:DAYLIGHT\r\n",
        "DTSTART:20260308T030000\r\n",
        "TZNAME:EDT\r\n",
        "TZOFFSETFROM:-0500\r\n",
        "TZOFFSETTO:-0400\r\n",
        "END:DAYLIGHT\r\n",
        "BEGIN:STANDARD\r\n",
        "DTSTART:20261101T010000\r\n",
        "TZNAME:EST\r\n",
        "TZOFFSETFROM:-0400\r\n",
        "TZOFFSETTO:-0500\r\n",
        "END:STANDARD\r\n",
        "END:VTIMEZONE\r\n",
        "BEGIN:VEVENT\r\n",
        "SUMMARY:Stand Up\r\n",
        "DTSTART;TZID=America/New_York:20260918T090000\r\n",
        "DTEND;TZID=America/New_York:20260918T093000\r\n",
        "DTSTAMP:20260918T092542Z\r\n",
        "UID:25Z10RT2PWIEJR2ZRHH3MTF7FJYQB8NS428S\r\n",
        "SEQUENCE:1\r\n",
        "RRULE:FREQ=WEEKLY;UNTIL=20261204;INTERVAL=2\r\n",
        "ATTENDEE;CUTYPE=INDIVIDUAL;PARTSTAT=NEEDS-ACTION;ROLE=REQ-PARTICIPANT;RSVP\r\n =TRUE:MAILTO:denis@hawksnestsoftware.com\r\n",
        "LOCATION:Phone\r\n",
        "BEGIN:VALARM\r\n",
        "ACTION:DISPLAY\r\n",
        "DESCRIPTION:\r\n",
        "TRIGGER:-PT10M\r\n",
        "END:VALARM\r\n",
        "END:VEVENT\r\n",
        "END:VCALENDAR\r\n"
    );

    #[test]
    fn rewrites_floating_until_in_event_zone() {
        let out = normalize_rrule_until(REAL_EVENT);
        // Dec 4 is EST (UTC-5): 09:00 New York = 14:00 UTC
        assert!(
            out.contains("RRULE:FREQ=WEEKLY;UNTIL=20261204T140000Z;INTERVAL=2"),
            "got: {out}"
        );
        // The VTIMEZONE's own DTSTARTs (inside DAYLIGHT/STANDARD) untouched
        assert!(out.contains("DTSTART:20260308T030000"));
        assert!(out.contains("DTSTART:20261101T010000"));
        // Trailing CRLF preserved
        assert!(out.ends_with("END:VCALENDAR\r\n"));
    }

    #[test]
    fn rewrites_date_valued_until_in_event_zone() {
        // khal's post-edit form: the DATE is the inclusive last-occurrence
        // day, expanded at the DTSTART's time-of-day. Dec 4 is EST (UTC-5):
        // 09:00 New York = 14:00 UTC.
        let out = normalize_rrule_until(EDITED_EVENT);
        assert!(
            out.contains("RRULE:FREQ=WEEKLY;UNTIL=20261204T140000Z;INTERVAL=2"),
            "got: {out}"
        );
        // The VTIMEZONE's own DTSTARTs (inside DAYLIGHT/STANDARD) untouched
        assert!(out.contains("DTSTART:20260308T030000"));
        assert!(out.contains("DTSTART:20261101T010000"));
        // Trailing CRLF preserved
        assert!(out.ends_with("END:VCALENDAR\r\n"));
    }

    #[test]
    fn date_until_on_occurrence_day_keeps_that_day() {
        // UNTIL on an occurrence day must keep that day's occurrence
        // (09:00 EDT = 13:00 UTC — the occurrence itself, not midnight).
        let ics = "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:x\r\n\
                    DTSTART;TZID=America/New_York:20260918T090000\r\n\
                    RRULE:FREQ=WEEKLY;UNTIL=20260918\r\n\
                    END:VEVENT\r\nEND:VCALENDAR\r\n";
        let out = normalize_rrule_until(ics);
        assert!(
            out.contains("RRULE:FREQ=WEEKLY;UNTIL=20260918T130000Z"),
            "got: {out}"
        );
    }

    #[test]
    fn rewrites_date_valued_until_utc_dtstart() {
        let ics = "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:x\r\n\
                    DTSTART:20260918T090000Z\r\n\
                    RRULE:FREQ=WEEKLY;UNTIL=20261204;INTERVAL=2\r\n\
                    END:VEVENT\r\nEND:VCALENDAR\r\n";
        let out = normalize_rrule_until(ics);
        assert!(
            out.contains("RRULE:FREQ=WEEKLY;UNTIL=20261204T090000Z;INTERVAL=2"),
            "got: {out}"
        );
    }

    #[test]
    fn leaves_date_valued_until_floating_dtstart_untouched() {
        let ics = "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:x\r\n\
                    DTSTART:20260918T090000\r\n\
                    RRULE:FREQ=WEEKLY;UNTIL=20261204;INTERVAL=2\r\n\
                    END:VEVENT\r\nEND:VCALENDAR\r\n";
        let out = normalize_rrule_until(ics);
        assert!(matches!(out, Cow::Borrowed(_)));
        assert_eq!(out, ics);
    }

    #[test]
    fn import_edited_event_now_parses() {
        // Regression test for the second production 403 (the ikhal-edited
        // khal event with a DATE-valued UNTIL): import used to fail
        // caldata's DtStartUntilMismatchTimezone validation.
        crate::CalendarObject::import(EDITED_EVENT, None).expect("must parse");
    }

    #[test]
    fn import_real_event_now_parses() {
        // Regression test for the production 403: the khal event PUT used
        // to fail caldata's DtStartUntilMismatchTimezone validation.
        crate::CalendarObject::import(REAL_EVENT, None).expect("must parse");
    }

    #[test]
    fn rewrites_until_first_param_position() {
        // UNTIL first: RRULE parts are order-independent
        let ics = "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:x\r\n\
                    DTSTART;TZID=America/New_York:20260918T110000\r\n\
                    RRULE:UNTIL=20261204T090000;FREQ=WEEKLY;INTERVAL=2\r\n\
                    END:VEVENT\r\nEND:VCALENDAR\r\n";
        let out = normalize_rrule_until(ics);
        assert!(
            out.contains("RRULE:UNTIL=20261204T140000Z;FREQ=WEEKLY;INTERVAL=2"),
            "got: {out}"
        );
    }

    #[test]
    fn rewrites_summer_until_in_event_zone() {
        // Sep 18 is EDT (UTC-4): 09:00 New York = 13:00 UTC
        let ics = "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:x\r\n\
                    DTSTART;TZID=America/New_York:20260918T110000\r\n\
                    RRULE:FREQ=DAILY;UNTIL=20260918T090000\r\n\
                    END:VEVENT\r\nEND:VCALENDAR\r\n";
        let out = normalize_rrule_until(ics);
        assert!(
            out.contains("RRULE:FREQ=DAILY;UNTIL=20260918T130000Z"),
            "got: {out}"
        );
    }

    #[test]
    fn appends_z_for_utc_dtstart() {
        let ics = "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:x\r\n\
                    DTSTART:20260918T150000Z\r\n\
                    RRULE:FREQ=WEEKLY;UNTIL=20261204T140000\r\n\
                    END:VEVENT\r\nEND:VCALENDAR\r\n";
        let out = normalize_rrule_until(ics);
        assert!(
            out.contains("RRULE:FREQ=WEEKLY;UNTIL=20261204T140000Z"),
            "got: {out}"
        );
    }

    #[test]
    fn rewrites_folded_rrule() {
        // UNTIL token split across a fold
        let ics = "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:x\r\n\
                    DTSTART;TZID=America/New_York:20260918T110000\r\n\
                    RRULE:FREQ=WEEKLY;UNTIL=20261204T09\r\n 0000;INTERVAL=2\r\n\
                    END:VEVENT\r\nEND:VCALENDAR\r\n";
        let out = normalize_rrule_until(ics);
        assert!(
            out.contains("RRULE:FREQ=WEEKLY;UNTIL=20261204T140000Z;INTERVAL=2"),
            "got: {out}"
        );
    }

    #[test]
    fn rewrites_vtodo() {
        let ics = "BEGIN:VCALENDAR\r\nBEGIN:VTODO\r\nUID:x\r\n\
                    DTSTART;TZID=America/New_York:20260918T110000\r\n\
                    RRULE:FREQ=WEEKLY;UNTIL=20261204T090000\r\n\
                    END:VTODO\r\nEND:VCALENDAR\r\n";
        let out = normalize_rrule_until(ics);
        assert!(
            out.contains("RRULE:FREQ=WEEKLY;UNTIL=20261204T140000Z"),
            "got: {out}"
        );
    }

    #[test]
    fn leaves_all_day_untouched() {
        let ics = "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:x\r\n\
                    DTSTART;VALUE=DATE:20260918\r\n\
                    RRULE:FREQ=WEEKLY;UNTIL=20261204;INTERVAL=2\r\n\
                    END:VEVENT\r\nEND:VCALENDAR\r\n";
        let out = normalize_rrule_until(ics);
        assert!(matches!(out, Cow::Borrowed(_)));
        assert_eq!(out, ics);
    }

    #[test]
    fn leaves_floating_dtstart_untouched() {
        // Floating DTSTART + floating UNTIL is RFC-correct
        let ics = "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:x\r\n\
                    DTSTART:20260918T110000\r\n\
                    RRULE:FREQ=WEEKLY;UNTIL=20261204T090000\r\n\
                    END:VEVENT\r\nEND:VCALENDAR\r\n";
        let out = normalize_rrule_until(ics);
        assert!(matches!(out, Cow::Borrowed(_)));
        assert_eq!(out, ics);
    }

    #[test]
    fn leaves_utc_until_untouched() {
        let ics = "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:x\r\n\
                    DTSTART;TZID=America/New_York:20260918T110000\r\n\
                    RRULE:FREQ=WEEKLY;UNTIL=20261204T140000Z;INTERVAL=2\r\n\
                    END:VEVENT\r\nEND:VCALENDAR\r\n";
        let out = normalize_rrule_until(ics);
        assert!(matches!(out, Cow::Borrowed(_)));
        assert_eq!(out, ics);
    }

    #[test]
    fn leaves_unknown_tzid_untouched() {
        // Unparseable TZID (e.g. khal's "Local") — the parser rejects it
        // as today; do not paper over it with a wrong offset.
        let ics = "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:x\r\n\
                    DTSTART;TZID=Local:20260918T110000\r\n\
                    RRULE:FREQ=WEEKLY;UNTIL=20261204T090000\r\n\
                    END:VEVENT\r\nEND:VCALENDAR\r\n";
        let out = normalize_rrule_until(ics);
        assert!(matches!(out, Cow::Borrowed(_)));
        assert_eq!(out, ics);
    }

    #[test]
    fn leaves_until_less_rrule_untouched() {
        // RRULE without UNTIL is untouched
        let ics = "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:x\r\n\
                    DTSTART;TZID=America/New_York:20260918T110000\r\n\
                    RRULE:FREQ=WEEKLY;INTERVAL=2\r\n\
                    END:VEVENT\r\nEND:VCALENDAR\r\n";
        let out = normalize_rrule_until(ics);
        assert!(matches!(out, Cow::Borrowed(_)));
        assert_eq!(out, ics);
    }

    #[test]
    fn rrule_before_dtstart_and_valarm_depth() {
        // RRULE before DTSTART in the same component still rewrites (RFC
        // does not mandate property order); a DTSTART inside a nested
        // component does not become the event's DTSTART.
        let ics = "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:x\r\n\
                    RRULE:FREQ=WEEKLY;UNTIL=20261204T090000\r\n\
                    DTSTART;TZID=America/New_York:20260918T110000\r\n\
                    BEGIN:VALARM\r\n\
                    DTSTART:20300101T000000Z\r\n\
                    END:VALARM\r\n\
                    END:VEVENT\r\nEND:VCALENDAR\r\n";
        let out = normalize_rrule_until(ics);
        assert!(
            out.contains("RRULE:FREQ=WEEKLY;UNTIL=20261204T140000Z"),
            "got: {out}"
        );
        assert!(out.contains("DTSTART:20300101T000000Z"));
    }

    #[test]
    fn per_component_dtstart() {
        // Each VEVENT uses its own DTSTART zone
        let ics = "BEGIN:VCALENDAR\r\n\
BEGIN:VEVENT\r\nUID:x\r\n\
DTSTART;TZID=America/New_York:20260918T110000\r\n\
RRULE:FREQ=WEEKLY;UNTIL=20261204T090000\r\n\
END:VEVENT\r\n\
BEGIN:VEVENT\r\nUID:y\r\n\
DTSTART;TZID=Europe/Berlin:20260918T110000\r\n\
RRULE:FREQ=WEEKLY;UNTIL=20261204T090000\r\n\
END:VEVENT\r\n\
END:VCALENDAR\r\n";
        let out = normalize_rrule_until(ics);
        assert!(
            out.contains("RRULE:FREQ=WEEKLY;UNTIL=20261204T140000Z"),
            "got: {out}"
        );
        // Dec 4 is CET (UTC+1): 09:00 Berlin = 08:00 UTC
        assert!(
            out.contains("RRULE:FREQ=WEEKLY;UNTIL=20261204T080000Z"),
            "got: {out}"
        );
    }

    #[test]
    fn idempotent() {
        for ics in [REAL_EVENT, EDITED_EVENT] {
            let once = normalize_rrule_until(ics);
            let twice = normalize_rrule_until(&once);
            assert_eq!(once, twice);
        }
    }
}
