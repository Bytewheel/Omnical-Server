//! Minimal RFC 5322 / MIME parsing for *inbound* iMIP messages: just enough
//! to find the first `text/calendar` part (RFC 6047) and the sender address
//! in a real-world email — nested multiparts, base64 and quoted-printable
//! transfer encodings, folded headers.
//!
//! Hand-rolled like the rest of the extension (no new dependencies); the
//! outbound counterpart is [`crate::mime`].

use base64::Engine;

use crate::ics::{split_params, unquote};

/// One parsed header block.
#[derive(Debug, Default)]
struct Headers {
    fields: Vec<(String, String)>,
}

impl Headers {
    /// Case-insensitive lookup, returning the *unfolded* value of the first
    /// matching field.
    fn get(&self, name: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// Split a message (or MIME part) into its header block and body. Returns
/// `None` if no header/body separator exists.
fn split_message(raw: &str) -> Option<(Headers, &str)> {
    let (head, body) = raw
        .split_once("\r\n\r\n")
        .or_else(|| raw.split_once("\n\n"))?;

    let lines: Vec<&str> = if head.contains("\r\n") {
        head.split("\r\n").collect()
    } else {
        head.split('\n').collect()
    };

    let mut fields: Vec<(String, String)> = vec![];
    for line in lines {
        // Unfold continuation lines (RFC 5322 2.2.3): leading WSP continues
        // the previous field.
        if (line.starts_with(' ') || line.starts_with('\t')) && !fields.is_empty() {
            let last = &mut fields.last_mut().expect("checked non-empty").1;
            last.push_str(line.trim_end_matches('\r'));
            last.push(' ');
            continue;
        }
        if let Some((name, value)) = line.split_once(':') {
            fields.push((name.trim().to_owned(), value.trim().to_owned()));
        }
    }
    Some((Headers { fields }, body))
}

/// Parse `type/subtype; param=value; ...` (RFC 2045). Returns the (lowercased)
/// type and the parameters; parameter names are uppercased.
fn parse_content_type(value: &str) -> (String, Vec<(String, String)>) {
    let mut parts = split_params(value).into_iter();
    let Some(first) = parts.next() else {
        return (String::new(), vec![]);
    };
    let ctype = first.trim().to_ascii_lowercase();
    let params = parts
        .filter_map(|param| {
            param
                .split_once('=')
                .map(|(k, v)| (k.trim().to_ascii_uppercase(), unquote(v.trim())))
        })
        .collect();
    (ctype, params)
}

/// Extract the first `text/calendar` body (as plain text) from a full RFC 5322
/// message. Also returns the Content-Type `method` parameter when present —
/// RFC 6047 puts the iTIP method on both the MIME part and the VCALENDAR;
/// callers act on the body's METHOD property, this is informational.
pub fn extract_calendar_part(raw_message: &str) -> Option<(String, Option<String>)> {
    let (headers, body) = split_message(raw_message)?;
    extract_from_part(&headers, body)
}

fn extract_from_part(headers: &Headers, body: &str) -> Option<(String, Option<String>)> {
    let (ctype, params) = parse_content_type(headers.get("content-type").unwrap_or("text/plain"));

    if ctype == "text/calendar" {
        let method = params
            .iter()
            .find(|(k, _)| k == "METHOD")
            .map(|(_, v)| v.to_ascii_uppercase())
            .filter(|m| !m.is_empty());
        let ics = decode_body(headers, body)?;
        if ics.contains("BEGIN:VCALENDAR") {
            return Some((ics, method));
        }
        return None;
    }

    if ctype.starts_with("multipart/") {
        let boundary = params
            .iter()
            .find(|(k, _)| k == "BOUNDARY")
            .map(|(_, v)| v.to_owned())?;
        for part in split_multipart(body, &boundary) {
            if let Some((part_headers, part_body)) = split_message(part) {
                if let Some(found) = extract_from_part(&part_headers, part_body) {
                    return Some(found);
                }
            }
        }
    }
    None
}

/// Decode a part body according to its Content-Transfer-Encoding. Returns
/// `None` if the declared encoding is broken.
fn decode_body(headers: &Headers, body: &str) -> Option<String> {
    let cte = headers
        .get("content-transfer-encoding")
        .unwrap_or("7bit")
        .trim()
        .to_ascii_lowercase();
    match cte.as_str() {
        "base64" => {
            let cleaned: String = body.chars().filter(|c| !c.is_whitespace()).collect();
            let engine = base64::engine::general_purpose::STANDARD;
            let bytes = engine.decode(cleaned.as_bytes()).ok()?;
            Some(String::from_utf8_lossy(&bytes).into_owned())
        }
        "quoted-printable" => Some(String::from_utf8_lossy(&qp_decode(body)).into_owned()),
        _ => Some(body.to_owned()),
    }
}

/// Decode quoted-printable (RFC 2045 6.7): `=XX` hex escapes and `=\r\n` /
/// `=\n` soft line breaks.
fn qp_decode(input: &str) -> Vec<u8> {
    fn hex(byte: u8) -> Option<u8> {
        match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'A'..=b'F' => Some(byte - b'A' + 10),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            _ => None,
        }
    }

    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'=' => {
                // Soft break: "=CRLF" or "=LF" at end of line
                let rest = &bytes[i + 1..];
                if rest.starts_with(b"\r\n") || rest.starts_with(b"\n") {
                    i += 1 + if rest.starts_with(b"\r\n") { 2 } else { 1 };
                    continue;
                }
                // Hex escape "=XX"
                if rest.len() >= 2 {
                    if let (Some(hi), Some(lo)) = (hex(rest[0]), hex(rest[1])) {
                        out.push(hi * 16 + lo);
                        i += 3;
                        continue;
                    }
                }
                // Stray "=": lenient pass-through when bytes follow; only a
                // "=" dangling at the very end of input is dropped.
                if !rest.is_empty() {
                    out.push(b'=');
                }
                i += 1;
            }
            byte => {
                out.push(byte);
                i += 1;
            }
        }
    }
    out
}

/// Split a multipart body into its parts at `--boundary` delimiter lines
/// (RFC 2046). Preamble and epilogue are dropped; each part retains its own
/// trailing CRLF (harmless for the ICS/base64 consumers).
fn split_multipart<'a>(body: &'a str, boundary: &str) -> Vec<&'a str> {
    let delim = format!("--{boundary}");
    let closing = format!("{delim}--");
    let mut parts = vec![];
    let mut part_start: Option<usize> = None;
    let mut closed = false;
    let mut pos = 0;
    for line in body.split_inclusive('\n') {
        let line_end = pos + line.len();
        let trimmed = line.trim_end();
        if trimmed == delim || trimmed == closing {
            if let Some(start) = part_start {
                let mut end = pos;
                // The CRLF preceding a boundary belongs to the delimiter
                if end >= 2 && &body[end - 2..end] == "\r\n" {
                    end -= 2;
                } else if end >= 1 && body.as_bytes()[end - 1] == b'\n' {
                    end -= 1;
                }
                parts.push(&body[start..end]);
            }
            closed = closed || trimmed == closing;
            part_start = Some(line_end);
        }
        pos = line_end;
    }
    // Anything left after the closing boundary is epilogue, not a part.
    if let (Some(start), false) = (part_start, closed) {
        parts.push(&body[start..pos]);
    }
    parts
}

/// The first From (or Sender) address of a message, lowercased — used to
/// disambiguate which attendee replied when a REPLY lists several.
pub fn from_address(raw_message: &str) -> Option<String> {
    let (headers, _) = split_message(raw_message)?;
    for field in ["from", "sender"] {
        if let Some(value) = headers.get(field) {
            if let Some(addr) = extract_addr(value) {
                return Some(addr);
            }
        }
    }
    None
}

/// Extract one address from a header value: prefer the last `<...>` group,
/// fall back to the first bare address of a list. Comments and display
/// names are ignored.
fn extract_addr(value: &str) -> Option<String> {
    let value = value.trim();
    if let Some(open) = value.rfind('<') {
        let close = value[open..].find('>')? + open;
        let addr = &value[open + 1..close];
        return valid(addr).then(|| addr.to_ascii_lowercase());
    }
    let first = value
        .split(',')
        .next()?
        .trim()
        .trim_start_matches('"')
        .trim_end_matches('"');
    valid(first).then(|| first.to_ascii_lowercase())
}

fn valid(addr: &str) -> bool {
    addr.contains('@') && !addr.contains(' ') && !addr.contains('<')
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SmtpAccount;
    use crate::ics;
    use crate::mime;

    fn account() -> SmtpAccount {
        SmtpAccount {
            identity: "nick@example.com".to_owned(),
            host: "smtp.example.com".to_owned(),
            port: 587,
            username: "nick".to_owned(),
            password: "secret".to_owned(),
            displayname: None,
        }
    }

    #[test]
    fn apple_single_part_reply() {
        // Apple Calendar replies are single-part text/calendar
        let mail = "From: Bob <bob@example.org>\r\n\
                    To: nick@example.com\r\n\
                    Subject: Accepted: Test\r\n\
                    MIME-Version: 1.0\r\n\
                    Content-Type: text/calendar; charset=utf-8; method=REPLY\r\n\
                    Content-Transfer-Encoding: 8bit\r\n\
                    \r\n\
                    BEGIN:VCALENDAR\r\n\
                    VERSION:2.0\r\n\
                    METHOD:REPLY\r\n\
                    BEGIN:VEVENT\r\n\
                    UID:abc-1\r\n\
                    ORGANIZER:mailto:nick@example.com\r\n\
                    ATTENDEE;PARTSTAT=ACCEPTED:mailto:bob@example.org\r\n\
                    END:VEVENT\r\n\
                    END:VCALENDAR\r\n";
        let (ics, method) = extract_calendar_part(mail).expect("calendar part");
        assert_eq!(method.as_deref(), Some("REPLY"));
        assert!(ics.contains("UID:abc-1"));
        assert_eq!(from_address(mail).as_deref(), Some("bob@example.org"));
    }

    #[test]
    fn round_trips_own_imip_builder() {
        // The exact shape our own mime::build_imip produces must extract
        let ics_body = ics::add_method(
            "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//x//EN\r\nBEGIN:VEVENT\r\nUID:u1\r\n\
             SUMMARY:Café\r\nDTSTART:20260906T110000Z\r\n\
             ORGANIZER:mailto:nick@example.com\r\n\
             ATTENDEE:mailto:bob@example.org\r\n\
             END:VEVENT\r\nEND:VCALENDAR\r\n",
            "REQUEST",
        );
        let event = ics::parse_event(&ics_body).unwrap();
        let mail = mime::build_imip(
            &account(),
            "bob@example.org",
            &ics_body,
            "REQUEST",
            mime::itip_subject("REQUEST", &event),
            "You are invited.".to_owned(),
        );
        let (extracted, method) = extract_calendar_part(&mail).expect("calendar part");
        assert_eq!(method.as_deref(), Some("REQUEST"));
        assert!(extracted.starts_with("BEGIN:VCALENDAR"));
        assert!(extracted.contains("SUMMARY:Caf\u{e9}")); // base64-decoded UTF-8
        assert_eq!(from_address(&mail).as_deref(), Some("nick@example.com"));
    }

    #[test]
    fn multipart_alternative_gmail_shape() {
        // Gmail's web "yes" answers: multipart/alternative with a
        // quoted-printable text part and a base64 text/calendar part
        let reply_ics = "BEGIN:VCALENDAR\r\nMETHOD:REPLY\r\nBEGIN:VEVENT\r\nUID:g-1\r\n\
                         ORGANIZER:mailto:nick@example.com\r\n\
                         ATTENDEE;PARTSTAT=ACCEPTED:mailto:bob@example.org\r\n\
                         END:VEVENT\r\nEND:VCALENDAR\r\n";
        let engine = base64::engine::general_purpose::STANDARD;
        let mail = format!(
            "From: Bob <bob@example.org>\r\n\
             MIME-Version: 1.0\r\n\
             Content-Type: multipart/alternative; boundary=\"B\"\r\n\
             \r\n\
             --B\r\n\
             Content-Type: text/plain; charset=utf-8\r\n\
             Content-Transfer-Encoding: quoted-printable\r\n\
             \r\n\
             Bob has accepted your invitation to=20Test.\r\n\
             --B\r\n\
             Content-Type: text/calendar; charset=utf-8; method=REPLY\r\n\
             Content-Transfer-Encoding: base64\r\n\
             \r\n\
             {}\r\n\
             --B--\r\n",
            engine.encode(reply_ics)
        );
        let (extracted, _) = extract_calendar_part(&mail).expect("calendar part");
        assert!(extracted.contains("UID:g-1"));
        assert_eq!(from_address(&mail).as_deref(), Some("bob@example.org"));
    }

    #[test]
    fn nested_multipart() {
        // Thunderbird-style: mixed(alternative(text/plain, text/calendar))
        let ics_body = "BEGIN:VCALENDAR\r\nMETHOD:REPLY\r\nBEGIN:VEVENT\r\nUID:n-1\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
        let mail = format!(
            "From: alice@example.net\r\n\
             Content-Type: multipart/mixed; boundary=OUTER\r\n\
             \r\n\
             This is the preamble.\r\n\
             --OUTER\r\n\
             Content-Type: multipart/alternative; boundary=INNER\r\n\
             \r\n\
             --INNER\r\n\
             Content-Type: text/plain\r\n\
             \r\n\
             Alice accepted.\r\n\
             --INNER\r\n\
             Content-Type: text/calendar; method=REPLY\r\n\
             \r\n\
             {ics_body}\
             --INNER--\r\n\
             --OUTER--\r\n"
        );
        let (extracted, _) = extract_calendar_part(&mail).expect("calendar part");
        assert!(extracted.contains("UID:n-1"));
        assert_eq!(from_address(&mail).as_deref(), Some("alice@example.net"));
    }

    #[test]
    fn folded_content_type_header() {
        // concat! keeps the leading folding WSP that a `\`-continued string
        // literal would strip — lines 2 and 3 must arrive folded, not as
        // separate fields.
        let mail = concat!(
            "From: a@b.c\r\n",
            "Content-Type: text/calendar;\r\n",
            " charset=utf-8;\r\n",
            " method=REPLY\r\n",
            "\r\n",
            "BEGIN:VCALENDAR\r\n",
            "END:VCALENDAR\r\n"
        );
        let (extracted, method) = extract_calendar_part(mail).expect("calendar part");
        assert_eq!(method.as_deref(), Some("REPLY"));
        assert!(extracted.contains("BEGIN:VCALENDAR"));
    }

    #[test]
    fn non_imip_mail_is_rejected() {
        let mail = "From: Bob <bob@example.org>\r\n\
                    Content-Type: multipart/alternative; boundary=B\r\n\
                    \r\n\
                    --B\r\n\
                    Content-Type: text/plain\r\n\
                    \r\n\
                    Hello!\r\n\
                    --B\r\n\
                    Content-Type: text/html\r\n\
                    \r\n\
                    <p>Hello!</p>\r\n\
                    --B--\r\n";
        assert_eq!(extract_calendar_part(mail), None);
        // A bare non-MIME email also extracts nothing
        assert_eq!(extract_calendar_part("Subject: hi\r\n\r\nplain body"), None);
    }

    #[test]
    fn base64_parts_folded_across_lines() {
        let ics_body = "BEGIN:VCALENDAR\r\nMETHOD:REPLY\r\nEND:VCALENDAR\r\n";
        let engine = base64::engine::general_purpose::STANDARD;
        let encoded = engine.encode(ics_body);
        assert!(encoded.len() > 20);
        let (a, b) = encoded.split_at(encoded.len() / 2);
        let mail = format!(
            "Content-Type: multipart/mixed; boundary=X\r\n\r\n\
             --X\r\n\
             Content-Type: text/calendar; method=REPLY\r\n\
             Content-Transfer-Encoding: base64\r\n\r\n\
             {a}\r\n\
             {b}\r\n\
             --X--\r\n"
        );
        let (extracted, _) = extract_calendar_part(&mail).expect("calendar part");
        assert!(extracted.contains("METHOD:REPLY"));
    }

    #[test]
    fn from_address_forms() {
        assert_eq!(
            from_address("From: Bob <bob@example.org>\r\n\r\nx").as_deref(),
            Some("bob@example.org")
        );
        assert_eq!(
            from_address("From: bob@example.org\r\n\r\nx").as_deref(),
            Some("bob@example.org")
        );
        // RFC 2047 display name before a bracketed address
        assert_eq!(
            from_address("From: =?utf-8?B?QsO2Yg==?= <bob@example.org>\r\n\r\nx").as_deref(),
            Some("bob@example.org")
        );
        // Sender fallback when From has no address
        assert_eq!(
            from_address("From: The Boss\r\nSender: ceo@example.com\r\n\r\nx").as_deref(),
            Some("ceo@example.com")
        );
        // Comment-only From and garbage yield nothing
        assert_eq!(from_address("From: (nobody)\r\n\r\nx"), None);
    }

    #[test]
    fn qp_decoding() {
        assert_eq!(qp_decode("abc=\r\ndef"), b"abcdef");
        assert_eq!(qp_decode("abc=\ndef"), b"abcdef");
        assert_eq!(qp_decode("caf=C3=A9"), "caf\u{e9}".as_bytes());
        assert_eq!(qp_decode("dangling="), b"dangling");
        assert_eq!(qp_decode("stray=z"), b"stray=z");
    }

    #[test]
    fn split_multipart_handles_crlf_and_trailing_ws() {
        let body = "preamble\r\n--B\r\nContent-Type: text/plain\r\n\r\nhi\r\n--B--  \r\nepilogue";
        let parts = split_multipart(body, "B");
        assert_eq!(parts.len(), 1);
        assert!(parts[0].starts_with("Content-Type"));
        assert!(parts[0].ends_with("hi"));
    }

    #[test]
    fn lf_only_messages_are_parsed() {
        let mail = "From: bob@example.org\nContent-Type: text/calendar; method=REPLY\n\nBEGIN:VCALENDAR\nEND:VCALENDAR\n";
        let (extracted, method) = extract_calendar_part(mail).expect("calendar part");
        assert_eq!(method.as_deref(), Some("REPLY"));
        assert!(extracted.contains("BEGIN:VCALENDAR"));
    }
}
