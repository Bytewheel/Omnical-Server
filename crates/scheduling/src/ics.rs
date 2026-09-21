//! Minimal iCalendar/iTIP property utilities for the Omnical scheduling
//! extension.
//!
//! `caldata` (the parser used for storage) does not model ORGANIZER/ATTENDEE,
//! and for scheduling decisions we deliberately work on the raw (unfolded)
//! property lines of the stored ICS: the same bytes the client sent, without
//! any normalisation in between.

/// One unfolded logical content line of an ICS body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Line {
    /// Property name, uppercased (e.g. `ATTENDEE`)
    pub name: String,
    /// Parsed parameters in source order
    pub params: Vec<(String, String)>,
    /// Raw property value (after the last `:`)
    pub value: String,
}

impl Line {
    fn parse(raw: &str) -> Self {
        // The name/params block is separated from the value by the first ':'
        // that is not inside a quoted parameter value (RFC 5545 3.1).
        let mut in_quotes = false;
        let head_end = raw
            .char_indices()
            .find(|(_, ch)| {
                if *ch == '"' {
                    in_quotes = !in_quotes;
                }
                *ch == ':' && !in_quotes
            })
            .map(|(i, _)| i);
        let Some(head_end) = head_end else {
            // No ':' at all -> treat whole line as name with empty value
            return Self {
                name: raw.to_ascii_uppercase(),
                params: vec![],
                value: String::new(),
            };
        };
        let head = &raw[..head_end];
        let value = &raw[head_end + 1..];

        let mut params = vec![];
        let name = match head.split_once(';') {
            Some((n, rest)) => {
                for param in split_params(rest) {
                    if let Some((k, v)) = param.split_once('=') {
                        params.push((k.to_ascii_uppercase(), unquote(v)));
                    }
                }
                n.to_ascii_uppercase()
            }
            None => head.to_ascii_uppercase(),
        };
        Self {
            name,
            params,
            value: value.to_owned(),
        }
    }

    pub fn param(&self, key: &str) -> Option<&str> {
        self.params
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    /// The address of an ORGANIZER/ATTENDEE value, if any. Accepts three
    /// CAL-ADDRESS forms:
    /// * `mailto:user@example.com` — taken verbatim (principal ids are
    ///   arbitrary strings and need not contain `@`);
    /// * a CalDAV principal URL — RustiCal advertises the principal URL as
    ///   the calendar-user-address, so clients such as iOS write the account
    ///   owner's ORGANIZER/self-ATTENDEE in this form
    ///   (`/caldav[-compat]/principal/<percent-encoded id>/`, absolute or
    ///   path-only); reduced to the decoded principal id;
    /// * bare `user@example.com` — the `@` heuristic guards this form
    ///   against random text.
    pub fn as_email(&self) -> Option<String> {
        let value = self.value.trim();
        let email = if let Some(rest) = value
            .strip_prefix("mailto:")
            .or_else(|| value.strip_prefix("MAILTO:"))
        {
            rest.to_owned()
        } else if let Some(id) = principal_url_id(value) {
            id
        } else if value.contains('@') && !value.contains(' ') {
            value.to_owned()
        } else {
            return None;
        };
        let email = email.trim().to_ascii_lowercase();
        if !email.is_empty() && !email.contains(':') && !email.contains(' ') {
            Some(email)
        } else {
            None
        }
    }
}

/// Percent-decode a URI path segment (RFC 3986): `%XX` hex escapes only.
fn percent_decode(segment: &str) -> String {
    let bytes = segment.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = (bytes[i + 1] as char).to_digit(16);
            let lo = (bytes[i + 2] as char).to_digit(16);
            if let (Some(hi), Some(lo)) = (hi, lo) {
                out.push((hi * 16 + lo) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The principal id of a principal-URL CAL-ADDRESS, if `value` is one.
/// Handles absolute (`https://host:port/caldav/principal/<id>/…`) and
/// path-only (`/caldav-compat/principal/<id>/`) forms; the id is the
/// percent-decoded path segment after `/principal/`. Principal ids cannot
/// contain `/` in this form (RustiCal percent-encodes them otherwise).
fn principal_url_id(value: &str) -> Option<String> {
    // Drop an optional scheme://host[:port] prefix to get to the path.
    let path = match value.find("://") {
        Some(i) => &value[i + 3..],
        None => value,
    };
    let path = match path.find('/') {
        Some(i) => &path[i..],
        None => return None,
    };
    const MARKER: &str = "/principal/";
    let idx = path.find(MARKER)?;
    let rest = &path[idx + MARKER.len()..];
    let id = rest.split('/').next()?;
    if id.is_empty() {
        return None;
    }
    Some(percent_decode(id))
}

/// Split a parameter list on `;` outside quoted values (RFC 5545 3.1).
pub(crate) fn split_params(input: &str) -> Vec<String> {
    let mut out = vec![];
    let mut current = String::new();
    let mut in_quotes = false;
    for ch in input.chars() {
        match ch {
            '"' => {
                in_quotes = !in_quotes;
                current.push(ch);
            }
            ';' if !in_quotes => {
                out.push(current.clone());
                current.clear();
            }
            _ => current.push(ch),
        }
    }
    out.push(current);
    out
}

/// Trim an optional pair of double quotes around a value.
pub(crate) fn unquote(value: &str) -> String {
    let value = value.trim();
    if value.len() >= 2 && value.starts_with('"') && value.ends_with('"') {
        value[1..value.len() - 1].to_owned()
    } else {
        value.to_owned()
    }
}

/// Split an ICS body into unfolded logical lines.
/// Also normalises lone `\n` line endings (rustical stores CRLF).
pub fn unfold(ics: &str) -> Vec<String> {
    let normalized = ics.replace("\r\n", "\n");
    let mut logical: Vec<String> = vec![];
    for raw_line in normalized.split('\n') {
        if raw_line.is_empty() {
            continue;
        }
        if let Some(stripped) = raw_line
            .strip_prefix(' ')
            .or_else(|| raw_line.strip_prefix('\t'))
        {
            if let Some(last) = logical.last_mut() {
                last.push_str(stripped);
                continue;
            }
        }
        logical.push(raw_line.to_owned());
    }
    logical
}

/// Parse all lines of an ICS body into [`Line`]s.
pub fn parse_lines(ics: &str) -> Vec<Line> {
    unfold(ics).iter().map(|l| Line::parse(l)).collect()
}

/// Parse a single (already unfolded) line.
pub(crate) fn parse_single_line(line: &str) -> Line {
    Line::parse(line)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attendee {
    pub email: String,
    pub partstat: Option<String>,
    pub cn: Option<String>,
    pub rsvp: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct EventInfo {
    pub uid: String,
    pub method: Option<String>,
    pub organizer: Option<String>,
    pub attendees: Vec<Attendee>,
    pub sequence: u32,
    pub status: Option<String>,
    pub summary: Option<String>,
    pub dtstart: Option<Line>,
    pub dtend: Option<Line>,
    pub duration: Option<String>,
    pub rrule: bool,
    pub url: Option<String>,
}

/// Extract scheduling-relevant properties from the first VEVENT of an ICS body.
/// Returns `None` if there is no VEVENT component.
pub fn parse_event(ics: &str) -> Option<EventInfo> {
    let mut info = EventInfo::default();
    let mut in_event = false;
    let mut seen_event = false;
    // Nesting depth inside the VEVENT: 1 = directly in the VEVENT, >1 = in a
    // nested component (VALARM, …). iOS writes a UID into every VALARM (and
    // ATTENDEEs into EMAIL alarms); those must not leak into the event's
    // scheduling data — the VALARM UID used to shadow the event UID, making
    // every attendee REPLY unmatchable against the organizer's stored copy
    // ("no response" on the organizer's iPhone).
    let mut depth = 0_usize;

    for line in parse_lines(ics) {
        match line.name.as_str() {
            "BEGIN" if line.value.eq_ignore_ascii_case("VEVENT") => {
                in_event = true;
                seen_event = true;
                depth = 1;
                continue;
            }
            "END" if in_event && line.value.eq_ignore_ascii_case("VEVENT") => {
                in_event = false;
                continue;
            }
            "BEGIN" if in_event => {
                depth += 1;
                continue;
            }
            "END" if in_event => {
                depth = depth.saturating_sub(1);
                continue;
            }
            _ => {}
        }
        if !in_event {
            if line.name == "METHOD" && info.method.is_none() {
                info.method = Some(line.value.to_ascii_uppercase());
            }
            continue;
        }
        if depth > 1 {
            continue; // property of a nested component (VALARM, …)
        }
        match line.name.as_str() {
            "UID" => info.uid = line.value.to_owned(),
            "ORGANIZER" => info.organizer = line.as_email(),
            "ATTENDEE" => {
                if let Some(email) = line.as_email() {
                    info.attendees.push(Attendee {
                        email,
                        partstat: line.param("PARTSTAT").map(str::to_owned),
                        cn: line.param("CN").map(str::to_owned),
                        rsvp: line.param("RSVP").map(str::to_owned),
                    });
                }
            }
            "SEQUENCE" => info.sequence = line.value.trim().parse().unwrap_or(0),
            "STATUS" => info.status = Some(line.value.to_ascii_uppercase()),
            "SUMMARY" => info.summary = Some(unescape_text(&line.value)),
            "DTSTART" => info.dtstart = Some(line),
            "DTEND" => info.dtend = Some(line),
            "DURATION" => info.duration = Some(line.value.to_owned()),
            "RRULE" => info.rrule = true,
            "URL" if info.url.is_none() => info.url = Some(line.value.to_owned()),
            _ => {}
        }
    }

    if seen_event && !info.uid.is_empty() {
        // Drop attendees that are identical to the organizer
        if let Some(organizer) = &info.organizer {
            info.attendees.retain(|a| a.email != *organizer);
        }
        Some(info)
    } else {
        None
    }
}

fn unescape_text(value: &str) -> String {
    // RFC 5545 3.3.11: \n, \N, \,, \; are escaped in text values
    let mut out = String::with_capacity(value.len());
    let mut chars = value.chars();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            match chars.next() {
                Some('n') | Some('N') => out.push('\n'),
                Some(escaped @ (',' | ';' | '\\')) => out.push(escaped),
                Some(other) => {
                    out.push('\\');
                    out.push(other);
                }
                None => out.push('\\'),
            }
        } else {
            out.push(ch);
        }
    }
    out
}

/// Properties whose changes are irrelevant to scheduling decisions.
fn is_noise_prop(name: &str) -> bool {
    matches!(
        name,
        "DTSTAMP" | "LAST-MODIFIED" | "CREATED" | "PRODID" | "CALSCALE"
    ) || name.starts_with("X-")
}

/// Attendee parameters that carry no scheduling signal when *the client
/// re-uploads* the same object (PARTSTAT may change as replies come in, RSVP
/// and Apple's X- params are client-internal).
fn is_noise_attendee_param(param: &str) -> bool {
    matches!(
        param,
        "PARTSTAT" | "RSVP" | "SCHEDULE-STATUS" | "SCHEDULE-AGENT"
    ) || param.starts_with("X-")
}

/// Build a canonical representation of the scheduling-relevant content of an
/// ICS body. Two objects with the same canonical form must not trigger new
/// invitations when one replaces the other.
pub fn canonical_scheduling_form(ics: &str) -> Vec<String> {
    let mut out = vec![];
    for line in parse_lines(ics) {
        if is_noise_prop(&line.name) {
            continue;
        }
        if line.name == "ATTENDEE" || line.name == "ORGANIZER" {
            // Keep the address and CN/ROLE/CUTYPE/DELEGATED params, drop the rest
            let params: Vec<(String, String)> = line
                .params
                .iter()
                .filter(|(k, _)| !is_noise_attendee_param(k))
                .map(|(k, v)| (k.to_ascii_uppercase(), v.to_ascii_lowercase()))
                .collect();
            let email = line.as_email().unwrap_or_default();
            out.push(format!("{}:{}:{:?}", line.name, email, params));
            continue;
        }
        out.push(format!("{}:{}:{:?}", line.name, line.value, line.params));
    }
    out.sort();
    out
}

/// Whether two ICS bodies differ in scheduling-relevant content.
#[must_use]
pub fn scheduling_relevant_change(old_ics: &str, new_ics: &str) -> bool {
    canonical_scheduling_form(old_ics) != canonical_scheduling_form(new_ics)
}

/// Insert a `METHOD:<method>` property after the VCALENDAR header properties
/// (VERSION/PRODID), as iTIP expects METHOD among the calendar properties.
#[must_use]
pub fn add_method(ics: &str, method: &str) -> String {
    let lines = unfold(ics);
    let mut insert_at: Option<usize> = None;
    for (i, line) in lines.iter().enumerate() {
        let parsed = Line::parse(line);
        if parsed.name == "BEGIN" && parsed.value.eq_ignore_ascii_case("VCALENDAR") {
            insert_at = Some(i + 1);
            continue;
        }
        if insert_at.is_some_and(|at| at == i) {
            if matches!(parsed.name.as_str(), "VERSION" | "PRODID") {
                insert_at = Some(i + 1);
            } else {
                break;
            }
        } else if insert_at.is_some_and(|at| at < i) {
            break;
        }
    }
    let mut out = lines.clone();
    match insert_at {
        Some(at) => out.insert(at, format!("METHOD:{method}")),
        None => out.push(format!("METHOD:{method}")),
    }
    out.join("\r\n")
}

/// Rewrite principal-URL CAL-ADDRESSes to their `mailto:` form so outgoing
/// iTIP messages (inbox REQUEST/CANCEL copies, iMIP attachments) carry an
/// ORGANIZER/ATTENDEE remote systems can address. `mailto:` and bare values
/// pass through unchanged. Line folding is lost (unfolded lines are
/// universally parsed; RustiCal re-folds on serialization).
#[must_use]
pub fn normalize_caladdresses(ics_body: &str) -> String {
    let mut out: Vec<String> = vec![];
    for line in unfold(ics_body) {
        let parsed = Line::parse(&line);
        match parsed.name.as_str() {
            "ORGANIZER" | "ATTENDEE" => {
                let value = parsed.value.trim();
                let is_principal_url = !value.starts_with("mailto:")
                    && !value.starts_with("MAILTO:")
                    && principal_url_id(value).is_some();
                if is_principal_url {
                    // principal_url_id succeeded above
                    #[allow(clippy::unwrap_used)]
                    let id = principal_url_id(value).unwrap();
                    out.push(rebuild_line(&parsed, &format!("mailto:{id}")));
                    continue;
                }
                out.push(line);
            }
            _ => out.push(line),
        }
    }
    let mut joined = out.join("\r\n");
    // unfold() drops the final CRLF on rejoin; keep the input's trailing
    // line ending (RFC 5545 content lines end with CRLF, including the last)
    if ics_body.ends_with('\n') {
        joined.push_str("\r\n");
    }
    joined
}

/// Strip Apple-specific properties that cause Android Google Calendar to
/// reject the .ics file ("cannot launch event"):
/// * `X-APPLE-*` and `X-WR-*` custom properties
/// * `ACKNOWLEDGED` inside VALARM (not valid per RFC 5545)
/// * Empty `URL;VALUE=URI:` properties
pub fn strip_apple_properties(ics_body: &str) -> String {
    let mut out = Vec::new();
    let mut in_valarm = false;
    for line in unfold(ics_body) {
        let parsed = Line::parse(&line);
        match parsed.name.as_str() {
            "BEGIN" if parsed.value.eq_ignore_ascii_case("VALARM") => {
                in_valarm = true;
                out.push(line);
            }
            "END" if parsed.value.eq_ignore_ascii_case("VALARM") => {
                in_valarm = false;
                out.push(line);
            }
            _ if parsed.name.starts_with("X-APPLE-") || parsed.name.starts_with("X-WR-") => {
                continue;
            }
            _ if in_valarm && parsed.name == "ACKNOWLEDGED" => continue,
            _ if parsed.name == "URL" && parsed.value.trim().is_empty() => continue,
            _ => out.push(line),
        }
    }
    let mut joined = out.join("\r\n");
    if ics_body.ends_with('\n') {
        joined.push_str("\r\n");
    }
    joined
}

/// Insert `ORGANIZER:mailto:<organizer>` before the first ATTENDEE property
/// (depth 1) of the first VEVENT.
///
/// Unfolded rejoin, CRLF, trailing-CRLF guard — mirror
/// `add_method`/`normalize_caladdresses`. No-op when the first VEVENT
/// already carries an ORGANIZER property or has no ATTENDEE (the caller is
/// expected to gate on `parse_event`, this keeps the helper self-consistent
/// for direct use).
#[must_use]
pub fn default_organizer(ics: &str, organizer: &str) -> String {
    let lines = unfold(ics);
    let mut out: Vec<String> = vec![];
    let mut in_event = false;
    let mut seen_event = false;
    // Nesting depth inside the VEVENT (1 = directly in it) — mirrors
    // parse_event: VALARM attendees are not event attendees.
    let mut depth = 0_usize;
    let mut has_organizer = false;
    let mut inserted = false;

    for line in &lines {
        let parsed = Line::parse(line);
        match parsed.name.as_str() {
            "BEGIN" if parsed.value.eq_ignore_ascii_case("VEVENT") => {
                // Only the first VEVENT is in scope (parse_event semantics)
                in_event = !seen_event;
                seen_event = true;
                depth = 1;
            }
            "END" if in_event && parsed.value.eq_ignore_ascii_case("VEVENT") => {
                in_event = false;
            }
            "BEGIN" if in_event => {
                depth += 1;
            }
            "END" if in_event => {
                depth = depth.saturating_sub(1);
            }
            "ORGANIZER" if in_event && depth == 1 => {
                has_organizer = true;
            }
            "ATTENDEE" if in_event && depth == 1 && !inserted && !has_organizer => {
                out.push(format!("ORGANIZER:mailto:{organizer}"));
                inserted = true;
            }
            _ => {}
        }
        out.push(line.clone());
    }

    let mut joined = out.join("\r\n");
    if ics.ends_with('\n') {
        joined.push_str("\r\n");
    }
    joined
}

/// Rebuild a content line from its parsed parts with a new value, re-quoting
/// parameter values that require it (RFC 5545 3.1).
fn rebuild_line(line: &Line, new_value: &str) -> String {
    let mut out = line.name.clone();
    for (k, v) in &line.params {
        if v.contains(',') || v.contains(';') || v.contains('"') || v.contains(' ') {
            out.push_str(&format!(";{k}=\"{v}\""));
        } else {
            out.push_str(&format!(";{k}={v}"));
        }
    }
    out.push(':');
    out.push_str(new_value);
    out
}

/// Rewrite (or add) `PARTSTAT=<partstat>` on the ATTENDEE line matching
/// `email` in the first VEVENT. Returns the new ICS body (unchanged if the
/// attendee was not found or nothing changed).
#[must_use]
pub fn set_attendee_partstat(ics: &str, email: &str, partstat: &str) -> String {
    let email = email.to_ascii_lowercase();
    let lines = unfold(ics);
    let mut out: Vec<String> = vec![];
    let mut in_event = false;
    let mut changed = false;

    for line in &lines {
        let parsed = Line::parse(line);
        match parsed.name.as_str() {
            "BEGIN" if parsed.value.eq_ignore_ascii_case("VEVENT") => in_event = true,
            "END" if parsed.value.eq_ignore_ascii_case("VEVENT") => in_event = false,
            "ATTENDEE" if in_event && parsed.as_email().as_deref() == Some(email.as_str()) => {
                if parsed
                    .param("PARTSTAT")
                    .is_some_and(|p| p.eq_ignore_ascii_case(partstat))
                {
                    out.push(line.clone());
                    continue;
                }
                let replaced = rewrite_attendee_line(&parsed, partstat);
                out.push(replaced);
                changed = true;
                continue;
            }
            _ => {}
        }
        out.push(line.clone());
    }

    if changed {
        out.join("\r\n")
    } else {
        ics.to_owned()
    }
}

fn rewrite_attendee_line(line: &Line, partstat: &str) -> String {
    let mut out = String::from("ATTENDEE");
    let mut has_partstat = false;
    for (k, v) in &line.params {
        if k == "PARTSTAT" {
            has_partstat = true;
            out.push_str(&format!(";PARTSTAT={partstat}"));
        } else if v.contains(',') || v.contains(';') || v.contains('"') || v.contains(' ') {
            out.push_str(&format!(";{k}=\"{v}\""));
        } else {
            out.push_str(&format!(";{k}={v}"));
        }
    }
    if !has_partstat {
        out.push_str(&format!(";PARTSTAT={partstat}"));
    }
    out.push(':');
    out.push_str(&line.value);
    out
}

/// Build a minimal iTIP REPLY message for one attendee.
#[must_use]
pub fn build_reply(
    organizer: &str,
    attendee_email: &str,
    attendee_cn: Option<&str>,
    partstat: &str,
    uid: &str,
    sequence: u32,
) -> String {
    let dtstamp = chrono::Utc::now().format("%Y%m%dT%H%M%SZ");
    let attendee = match attendee_cn {
        Some(cn) => {
            let quoted = if cn.contains(',') || cn.contains(';') || cn.contains('"') {
                format!("\"{cn}\"")
            } else {
                cn.to_owned()
            };
            format!("ATTENDEE;CN={quoted};PARTSTAT={partstat}:mailto:{attendee_email}")
        }
        None => format!("ATTENDEE;PARTSTAT={partstat}:mailto:{attendee_email}"),
    };
    let mut out = String::new();
    out.push_str("BEGIN:VCALENDAR\r\n");
    out.push_str("VERSION:2.0\r\n");
    out.push_str("PRODID:-//Omnical//Scheduling//EN\r\n");
    out.push_str("METHOD:REPLY\r\n");
    out.push_str("BEGIN:VEVENT\r\n");
    out.push_str(&format!("UID:{uid}\r\n"));
    out.push_str(&format!("SEQUENCE:{sequence}\r\n"));
    out.push_str(&format!("DTSTAMP:{dtstamp}\r\n"));
    out.push_str(&format!("ORGANIZER:mailto:{organizer}\r\n"));
    out.push_str(&attendee);
    out.push_str("\r\n");
    out.push_str("END:VEVENT\r\n");
    out.push_str("END:VCALENDAR\r\n");
    out
}

/// Turn a UID into a filesystem-safe object id for inbox storage.
#[must_use]
pub fn sanitize_id(prefix: &str, uid: &str, suffix: &str) -> String {
    let mut sanitized: String = uid
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect();
    // Guard against pathological ids
    if sanitized.len() > 120 {
        sanitized = sanitized[..120].to_owned();
    }
    format!("{prefix}-{sanitized}{suffix}.ics")
}

/// Render a DTSTART property human-readable for email bodies.
#[must_use]
pub fn humanize_dtstart(line: Option<&Line>) -> String {
    let Some(line) = line else {
        return String::from("(unknown time)");
    };
    let value = line.value.trim();
    if line
        .param("VALUE")
        .is_some_and(|v| v.eq_ignore_ascii_case("DATE"))
        || value.len() == 8
    {
        // All-day date: YYYYMMDD
        if let Ok(date) = chrono::NaiveDate::parse_from_str(value, "%Y%m%d") {
            return format!("{} (all day)", date.format("%A, %B %e, %Y"));
        }
    }
    if let Some(tzid) = line.param("TZID") {
        let Ok(tz) = tzid.parse::<chrono_tz::Tz>() else {
            return format!("{} ({tzid})", value);
        };
        if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(value, "%Y%m%dT%H%M%S") {
            let local = naive.and_local_timezone(tz).earliest();
            if let Some(local) = local {
                return local
                    .format("%A, %B %e, %Y at %l:%M %p %Z")
                    .to_string()
                    .replace("  ", " ");
            }
        }
        return format!("{} ({tzid})", value);
    }
    if let Some(rest) = value.strip_suffix('Z') {
        if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(rest, "%Y%m%dT%H%M%S") {
            let utc = naive.and_utc();
            return format!("{} (UTC)", utc.format("%A, %B %e, %Y at %H:%M"));
        }
    }
    value.to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Test//EN\r\nBEGIN:VEVENT\r\nUID:abc123\r\nDTSTAMP:20260905T120000Z\r\nDTSTART;TZID=America/New_York:20260906T110000\r\nDTEND;TZID=America/New_York:20260906T113000\r\nSUMMARY:Test event\r\nORGANIZER;CN=Nick:mailto:nick@example.com\r\nATTENDEE;CN=Bob;PARTSTAT=NEEDS-ACTION:mailto:bob@example.org\r\nATTENDEE;CN=\"Alice, B\";PARTSTAT=ACCEPTED:mailto:alice@example.net\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";

    #[test]
    fn parses_event() {
        let info = parse_event(SAMPLE).expect("event");
        assert_eq!(info.uid, "abc123");
        assert_eq!(info.organizer.as_deref(), Some("nick@example.com"));
        assert_eq!(info.attendees.len(), 2);
        assert_eq!(info.attendees[0].email, "bob@example.org");
        assert_eq!(info.attendees[0].partstat.as_deref(), Some("NEEDS-ACTION"));
        assert_eq!(info.attendees[1].cn.as_deref(), Some("Alice, B"));
        assert_eq!(info.summary.as_deref(), Some("Test event"));
        assert!(!info.rrule);
    }

    #[test]
    fn mailto_without_at_is_an_address() {
        // Principal ids are arbitrary strings and need not contain '@'
        // (e.g. RustiCal's test fixture principal `user`): a mailto:
        // CAL-ADDRESS must parse so ORGANIZER can match such an id.
        let ics = "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:x\r\n\
                    ORGANIZER:mailto:user\r\nATTENDEE:mailto:attendee@example.com\r\n\
                    END:VEVENT\r\nEND:VCALENDAR\r\n";
        let info = parse_event(ics).expect("event");
        assert_eq!(info.organizer.as_deref(), Some("user"));
        assert_eq!(info.attendees[0].email, "attendee@example.com");
        // Bare (non-mailto) values still require '@'
        let ics = ics.replace("ORGANIZER:mailto:user", "ORGANIZER:user");
        assert_eq!(parse_event(&ics).unwrap().organizer, None);
    }

    #[test]
    fn principal_url_organizer_is_an_address() {
        // iOS writes the account owner's ORGANIZER and self-ATTENDEE as the
        // CalDAV principal URL (RustiCal's advertised calendar-user-address),
        // percent-encoded — the exact shape found in production (iPhone OS
        // 16.7). Without handling it, no invitation is ever delivered.
        let ics = "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:x\r\n\
                    ORGANIZER;CN=nicholas@carltonaudio.com:/caldav-compat/principal/nicholas%40carltonaudio.com/\r\n\
                    ATTENDEE;CN=nfcarlton;PARTSTAT=NEEDS-ACTION:mailto:nfcarlton@gmail.com\r\n\
                    ATTENDEE;PARTSTAT=ACCEPTED:/caldav-compat/principal/nicholas%40carltonaudio.com/\r\n\
                    END:VEVENT\r\nEND:VCALENDAR\r\n";
        let info = parse_event(ics).expect("event");
        assert_eq!(info.organizer.as_deref(), Some("nicholas@carltonaudio.com"));
        // The principal-URL self-attendee is recognized as the organizer
        // duplicate and dropped; only the real attendee remains.
        assert_eq!(info.attendees.len(), 1);
        assert_eq!(info.attendees[0].email, "nfcarlton@gmail.com");
    }

    #[test]
    fn principal_url_forms() {
        // Absolute URL form
        let line = parse_single_line(
            "ORGANIZER;CN=x:https://0115d8cf.duckdns.org:8443/caldav/principal/nicholas%40carltonaudio.com/",
        );
        assert_eq!(
            line.as_email().as_deref(),
            Some("nicholas@carltonaudio.com")
        );
        // Path-only form, principal id without '@'
        let line = parse_single_line("ATTENDEE:/caldav/principal/user/");
        assert_eq!(line.as_email().as_deref(), Some("user"));
        // Unencoded id in the path (no percent-decoding needed)
        let line = parse_single_line("ORGANIZER:/caldav/principal/user@example.com/");
        assert_eq!(line.as_email().as_deref(), Some("user@example.com"));
        // Non-principal paths are not addresses
        let line = parse_single_line("ORGANIZER:/other/path/");
        assert_eq!(line.as_email(), None);
        // Other servers' principal paths (e.g. Nextcloud /principals/) stay
        // unrecognized
        let line = parse_single_line("ATTENDEE:/remote.php/dav/principals/users/bob/");
        assert_eq!(line.as_email(), None);
    }

    #[test]
    fn normalize_rewrites_principal_urls() {
        let ics = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:x\r\n\
                    ORGANIZER;CN=\"Carlton, Nicholas\":/caldav-compat/principal/nicholas%40carltonaudio.com/\r\n\
                    ATTENDEE;PARTSTAT=ACCEPTED:/caldav/principal/nicholas%40carltonaudio.com/\r\n\
                    ATTENDEE;CN=Bob:mailto:bob@example.org\r\n\
                    END:VEVENT\r\nEND:VCALENDAR\r\n";
        let normalized = normalize_caladdresses(ics);
        // Principal-URL lines become mailto:, params (incl. quoted CN) intact
        assert!(
            normalized
                .contains("ORGANIZER;CN=\"Carlton, Nicholas\":mailto:nicholas@carltonaudio.com")
        );
        assert!(normalized.contains("ATTENDEE;PARTSTAT=ACCEPTED:mailto:nicholas@carltonaudio.com"));
        // mailto: lines and structure untouched
        assert!(normalized.contains("ATTENDEE;CN=Bob:mailto:bob@example.org"));
        assert!(normalized.contains("BEGIN:VEVENT"));
        assert!(normalized.ends_with("END:VCALENDAR\r\n"));
    }

    #[test]
    fn folded_lines() {
        let ics = "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nSUMMARY:Hello\r\n  World\r\nUID:x\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
        let info = parse_event(ics).expect("event");
        assert_eq!(info.summary.as_deref(), Some("Hello World"));
    }

    #[test]
    fn method_extracted() {
        let ics = "BEGIN:VCALENDAR\r\nMETHOD:REQUEST\r\nBEGIN:VEVENT\r\nUID:x\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
        assert_eq!(parse_event(ics).unwrap().method.as_deref(), Some("REQUEST"));
    }

    #[test]
    fn noise_changes_are_ignored() {
        let modified = SAMPLE.replace("20260905T120000Z", "20260906T093000Z");
        assert!(!scheduling_relevant_change(SAMPLE, &modified));
        let modified = SAMPLE.replace("Test event", "Other event");
        assert!(scheduling_relevant_change(SAMPLE, &modified));
        // PARTSTAT-only changes on attendees are not scheduling-relevant
        let modified = SAMPLE.replace("PARTSTAT=NEEDS-ACTION", "PARTSTAT=ACCEPTED");
        assert!(!scheduling_relevant_change(SAMPLE, &modified));
    }

    #[test]
    fn adds_method() {
        let with_method = add_method(SAMPLE, "REQUEST");
        assert!(with_method.contains("METHOD:REQUEST\r\n"));
        let info = parse_event(&with_method);
        assert_eq!(info.unwrap().method.as_deref(), Some("REQUEST"));
        assert!(with_method.contains("VERSION:2.0"));
    }

    #[test]
    fn sets_partstat() {
        let updated = set_attendee_partstat(SAMPLE, "bob@example.org", "ACCEPTED");
        assert!(updated.contains("ATTENDEE;CN=Bob;PARTSTAT=ACCEPTED:mailto:bob@example.org"));
        // idempotent
        assert_eq!(
            updated,
            set_attendee_partstat(&updated, "bob@example.org", "ACCEPTED")
        );
        // other attendees untouched
        assert!(updated.contains("PARTSTAT=ACCEPTED:mailto:alice@example.net"));
        // unknown attendee -> unchanged
        assert_eq!(
            SAMPLE,
            set_attendee_partstat(SAMPLE, "nobody@example.com", "ACCEPTED")
        );
    }

    #[test]
    fn partstat_added_when_missing() {
        let ics = "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:x\r\nATTENDEE:mailto:bob@example.org\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
        let updated = set_attendee_partstat(ics, "bob@example.org", "DECLINED");
        assert!(updated.contains("ATTENDEE;PARTSTAT=DECLINED:mailto:bob@example.org"));
    }

    #[test]
    fn default_organizer_inserts_before_first_attendee() {
        let ics = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:x\r\n\
                    DTSTAMP:20260905T120000Z\r\nDTSTART:20260906T100000Z\r\n\
                    SUMMARY:Stand Up\r\n\
                    ATTENDEE;CUTYPE=INDIVIDUAL;PARTSTAT=NEEDS-ACTION:mailto:bob@example.org\r\n\
                    ATTENDEE:mailto:alice@example.net\r\n\
                    END:VEVENT\r\nEND:VCALENDAR\r\n";
        let stamped = default_organizer(ics, "user@example.com");
        assert!(
            stamped.contains(
                "ORGANIZER:mailto:user@example.com\r\nATTENDEE;CUTYPE=INDIVIDUAL;PARTSTAT=NEEDS-ACTION:mailto:bob@example.org"
            ),
            "got: {stamped}"
        );
        // only one ORGANIZER, both attendees kept, structure intact
        assert_eq!(stamped.matches("ORGANIZER:").count(), 1);
        assert!(stamped.contains("ATTENDEE:mailto:alice@example.net"));
        assert!(stamped.ends_with("END:VCALENDAR\r\n"));
    }

    #[test]
    fn default_organizer_preserves_existing_organizer() {
        let ics = "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:x\r\n\
                    ORGANIZER;CN=Nick:mailto:nick@example.com\r\n\
                    ATTENDEE:mailto:bob@example.org\r\n\
                    END:VEVENT\r\nEND:VCALENDAR\r\n";
        assert_eq!(default_organizer(ics, "other@example.com"), ics);
    }

    #[test]
    fn default_organizer_skips_attendee_less_events() {
        let ics = "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:x\r\n\
                    DTSTART:20260906T100000Z\r\n\
                    END:VEVENT\r\nEND:VCALENDAR\r\n";
        assert_eq!(default_organizer(ics, "user@example.com"), ics);
    }

    #[test]
    fn default_organizer_skips_valarm_attendee_and_second_vevent() {
        // EMAIL alarms carry ATTENDEEs (mail recipients) that are not event
        // attendees; and only the first VEVENT is in scope.
        let ics = "BEGIN:VCALENDAR\r\n\
BEGIN:VEVENT\r\nUID:x\r\n\
BEGIN:VALARM\r\n\
ACTION:EMAIL\r\n\
ATTENDEE:mailto:alarmtarget@example.net\r\n\
TRIGGER:-PT30M\r\n\
END:VALARM\r\n\
END:VEVENT\r\n\
BEGIN:VEVENT\r\nUID:y\r\n\
ATTENDEE:mailto:bob@example.org\r\n\
END:VEVENT\r\n\
END:VCALENDAR\r\n";
        assert_eq!(default_organizer(ics, "user@example.com"), ics);
    }

    #[test]
    fn default_organizer_handles_folded_attendee() {
        // khal folds long ATTENDEE lines: the ORGANIZER must land before
        // the whole (folded) line
        let ics = "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:x\r\nATTENDEE;CUTYPE=INDIVIDUAL;PARTSTAT=NEEDS-ACTION;ROLE=REQ-PARTICIPANT;RSVP\r\n =TRUE:MAILTO:bob@example.org\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
        let stamped = default_organizer(ics, "user@example.com");
        assert!(
            stamped.contains("ORGANIZER:mailto:user@example.com\r\nATTENDEE;CUTYPE=INDIVIDUAL"),
            "got: {stamped}"
        );
    }

    #[test]
    fn reply_shape() {
        let reply = build_reply(
            "nick@example.com",
            "bob@example.org",
            Some("Bob"),
            "ACCEPTED",
            "uid-1",
            0,
        );
        assert!(reply.starts_with("BEGIN:VCALENDAR"));
        assert!(reply.contains("METHOD:REPLY"));
        assert!(reply.contains("UID:uid-1"));
        assert!(reply.contains("PARTSTAT=ACCEPTED:mailto:bob@example.org"));
        assert_eq!(
            parse_event(&reply).unwrap().method.as_deref(),
            Some("REPLY")
        );
    }

    #[test]
    fn valarm_uid_does_not_shadow_event_uid() {
        // Production shape (iPhone OS 16.7): every VALARM carries its own UID
        // (X-WR-ALARMUID). parse_event used to let it overwrite the VEVENT's
        // UID, so attendee REPLYs could never be matched against the
        // organizer's stored copy ("no response" on the organizer's iPhone).
        let ics = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Apple Inc.//iPhone OS 16.7.16//EN\r\n\
                   BEGIN:VEVENT\r\n\
                   UID:77A7E01C-E3A5-4DA5-9D0F-DEEB8E42149F\r\n\
                   DTSTAMP:20260906T131303Z\r\n\
                   SUMMARY:Test\r\n\
                   ORGANIZER;CN=nicholas@carltonaudio.com:/caldav-compat/principal/nicholas%40carltonaudio.com/\r\n\
                   ATTENDEE;CN=Lyn;PARTSTAT=NEEDS-ACTION:mailto:lynscarlton@gmail.com\r\n\
                   ATTENDEE;PARTSTAT=ACCEPTED:/caldav-compat/principal/nicholas%40carltonaudio.com/\r\n\
                   BEGIN:VALARM\r\n\
                   ACTION:DISPLAY\r\n\
                   DESCRIPTION:Reminder\r\n\
                   TRIGGER:-PT10M\r\n\
                   UID:A215B080-02C4-4A6C-8A97-AB555C727920\r\n\
                   X-WR-ALARMUID:A215B080-02C4-4A6C-8A97-AB555C727920\r\n\
                   END:VALARM\r\n\
                   END:VEVENT\r\n\
                   END:VCALENDAR\r\n";
        let info = parse_event(ics).expect("event");
        assert_eq!(info.uid, "77A7E01C-E3A5-4DA5-9D0F-DEEB8E42149F");
        // The organizer's principal-URL self-attendee is dropped; only Lyn remains
        assert_eq!(info.attendees.len(), 1);
        assert_eq!(info.attendees[0].email, "lynscarlton@gmail.com");
    }

    #[test]
    fn valarm_attendee_is_not_an_event_attendee() {
        // EMAIL-type VALARMs carry their own ATTENDEE (the mail recipient);
        // it must not become a phantom event attendee receiving invitations.
        let ics = "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:x\r\n\
                   ORGANIZER:mailto:org@example.com\r\n\
                   ATTENDEE;PARTSTAT=NEEDS-ACTION:mailto:bob@example.org\r\n\
                   BEGIN:VALARM\r\n\
                   ACTION:EMAIL\r\n\
                   ATTENDEE:mailto:alarmtarget@example.net\r\n\
                   TRIGGER:-PT30M\r\n\
                   END:VALARM\r\n\
                   END:VEVENT\r\nEND:VCALENDAR\r\n";
        let info = parse_event(ics).expect("event");
        assert_eq!(info.uid, "x");
        assert_eq!(info.attendees.len(), 1);
        assert_eq!(info.attendees[0].email, "bob@example.org");
    }

    #[test]
    fn humanize() {
        let ics = "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:x\r\nDTSTART;TZID=America/New_York:20260906T110000\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
        let info = parse_event(ics).unwrap();
        let human = humanize_dtstart(info.dtstart.as_ref());
        assert!(human.contains("September"), "got: {human}");
        assert!(human.contains("11:00"), "got: {human}");
    }

    #[test]
    fn strip_apple_properties_removes_apple_custom_and_invalid_props() {
        let apple_ics = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Apple Inc.//iPhone OS 16.7.16//EN\r\nBEGIN:VEVENT\r\nUID:x\r\nSUMMARY:Test\r\nURL;VALUE=URI:\r\nBEGIN:VALARM\r\nACTION:DISPLAY\r\nTRIGGER:-PT10M\r\nUID:alarm-1\r\nACKNOWLEDGED:20260910T180837Z\r\nX-APPLE-DEFAULT-ALARM:TRUE\r\nX-WR-ALARMUID:alarm-1\r\nEND:VALARM\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
        let stripped = strip_apple_properties(apple_ics);
        // Apple custom properties removed
        assert!(!stripped.contains("X-APPLE-DEFAULT-ALARM"));
        assert!(!stripped.contains("X-WR-ALARMUID"));
        // Invalid VALARM property removed
        assert!(!stripped.contains("ACKNOWLEDGED"));
        // Empty URL removed
        assert!(!stripped.contains("URL;VALUE=URI:"));
        // Core structure preserved
        assert!(stripped.contains("BEGIN:VCALENDAR"));
        assert!(stripped.contains("END:VCALENDAR"));
        assert!(stripped.contains("BEGIN:VEVENT"));
        assert!(stripped.contains("END:VEVENT"));
        assert!(stripped.contains("BEGIN:VALARM"));
        assert!(stripped.contains("END:VALARM"));
        assert!(stripped.contains("ACTION:DISPLAY"));
        assert!(stripped.contains("TRIGGER:-PT10M"));
    }
}
