//! iMIP email construction (RFC 6047): the iTIP object wrapped in a
//! human-readable multipart email.

use base64::Engine;
use std::fmt::Write as _;

use crate::config::SmtpAccount;
use crate::ics;

/// Build a complete RFC 5322 message (CRLF line endings) carrying an iTIP object.
///
/// `method` is the iTIP method (REQUEST, CANCEL or REPLY), `ics_with_method`
/// the ICS body *including* its METHOD property.
#[must_use]
pub fn build_imip(
    account: &SmtpAccount,
    to: &str,
    ics_with_method: &str,
    method: &str,
    subject: String,
    body: String,
) -> String {
    let from_domain = account
        .identity
        .rsplit('@')
        .next()
        .unwrap_or("omnical.local");
    let message_id = uuid::Uuid::new_v4();
    let date = chrono::Utc::now().to_rfc2822();
    let boundary = format!("=_omnical_{}", uuid::Uuid::new_v4().simple());
    let subject_encoded = rfc2047_encode(&subject);

    let ics_b64 = {
        let engine = base64::engine::general_purpose::STANDARD;
        let raw = engine.encode(ics_with_method);
        // Fold base64 at 75 chars + 2-char transport padding per MIME
        let mut folded = String::with_capacity(raw.len() + raw.len() / 75 * 3);
        for (i, chunk) in raw.as_bytes().chunks(75).enumerate() {
            if i > 0 {
                folded.push_str("\r\n");
            }
            folded.push_str(std::str::from_utf8(chunk).expect("base64 is ascii"));
        }
        folded
    };

    let from_header = match &account.displayname {
        Some(name) => format!("{} <{}>", rfc2047_encode(name), account.identity),
        None => account.identity.clone(),
    };

    let mut out = String::new();
    out.push_str(&format!("From: {from_header}\r\n"));
    out.push_str(&format!("To: <{to}>\r\n"));
    out.push_str(&format!("Subject: {subject_encoded}\r\n"));
    out.push_str(&format!("Date: {date}\r\n"));
    out.push_str(&format!("Message-ID: <{message_id}@{from_domain}>\r\n"));
    out.push_str("X-Mailer: Omnical (RustiCal scheduling extension)\r\n");
    out.push_str("Auto-Submitted: auto-generated\r\n");
    out.push_str("MIME-Version: 1.0\r\n");
    out.push_str(&format!(
        "Content-Type: multipart/mixed; boundary=\"{boundary}\"\r\n"
    ));
    out.push_str("\r\n");
    out.push_str("This is a multipart message in MIME format.\r\n");
    out.push_str(&format!("--{boundary}\r\n"));
    out.push_str("Content-Type: text/plain; charset=utf-8\r\n");
    out.push_str("Content-Transfer-Encoding: 8bit\r\n");
    out.push_str("\r\n");
    out.push_str(&body);
    if !body.ends_with("\r\n") {
        out.push_str("\r\n");
    }
    out.push_str(&format!("--{boundary}\r\n"));
    out.push_str(&format!(
        "Content-Type: text/calendar; method={method}; charset=utf-8\r\n"
    ));
    out.push_str("Content-Transfer-Encoding: base64\r\n");
    out.push_str("Content-Disposition: attachment; filename=\"invite.ics\"\r\n");
    out.push_str("\r\n");
    out.push_str(&ics_b64);
    out.push_str("\r\n");
    out.push_str(&format!("--{boundary}--\r\n"));
    out
}

/// Encode a header value as an RFC 2047 encoded-word if it is not pure ASCII.
fn rfc2047_encode(input: &str) -> String {
    if input.is_ascii() {
        input.to_owned()
    } else {
        let engine = base64::engine::general_purpose::STANDARD;
        format!("=?utf-8?B?{}?=", engine.encode(input.as_bytes()))
    }
}

/// Build the human-readable part for an invitation from `organizer`.
///
/// `rsvp_url`, when present, is the public one-click response page for
/// the invited attendee (RSVP link extension): the email then leads
/// with the browser response option and presents the attached
/// `invite.ics` as the alternative. `None` renders the classic
/// attachment-only body.
#[must_use]
pub fn invite_body(
    account: &SmtpAccount,
    event: &ics::EventInfo,
    organizer: &str,
    rsvp_url: Option<&str>,
) -> String {
    let summary = event
        .summary
        .clone()
        .unwrap_or_else(|| "(no title)".to_owned());
    let when = ics::humanize_dtstart(event.dtstart.as_ref());
    let recurring = if event.rrule { " (repeats)" } else { "" };
    let mut body = String::new();
    body.push_str(&format!(
        "You have been invited to an event by {organizer}.\r\n\r\n"
    ));
    body.push_str(&format!("  Event: {summary}\r\n"));
    body.push_str(&format!("  When:  {when}{recurring}\r\n"));
    if let Some(url) = &event.url {
        body.push_str(&format!("  URL:   {url}\r\n"));
    }
    body.push_str("\r\n");
    if let Some(url) = rsvp_url {
        body.push_str(
            "Respond directly in your browser — accept, decline or answer \r\n\
             maybe with one click, no calendar application needed:\r\n",
        );
        body.push_str("\r\n");
        let _ = write!(body, "  {url}\r\n");
        body.push_str("\r\n");
        body.push_str(
            "Alternatively, open the attached invitation (invite.ics) in \r\n\
             your calendar application to accept or decline it there.\r\n",
        );
    } else {
        body.push_str(
            "The calendar invitation is attached (invite.ics). Opening the attachment in \r\n\
             your calendar application lets you accept or decline the invitation.\r\n",
        );
    }
    body.push_str("\r\n");
    body.push_str(&format!(
        "This message was generated automatically by the Omnical calendar server on \r\n\
         behalf of {organizer}. Replies to this email go to the organizer.\r\n"
    ));
    let _ = account; // reserved for footer/config-driven text
    body
}

/// Human-readable text for a cancellation.
#[must_use]
pub fn cancel_body(event: &ics::EventInfo, organizer: &str) -> String {
    let summary = event
        .summary
        .clone()
        .unwrap_or_else(|| "(no title)".to_owned());
    let when = ics::humanize_dtstart(event.dtstart.as_ref());
    let mut body = String::new();
    body.push_str(&format!(
        "An event you were invited to has been cancelled by {organizer}.\r\n\r\n"
    ));
    body.push_str(&format!("  Event: {summary}\r\n"));
    body.push_str(&format!("  When:  {when}\r\n"));
    if let Some(url) = &event.url {
        body.push_str(&format!("  URL:   {url}\r\n"));
    }
    body.push_str("\r\n");
    body.push_str(
        "The calendar cancellation is attached (invite.ics); opening it updates your \r\n\
         calendar accordingly.\r\n",
    );
    body
}

/// Human-readable text for a scheduling reply (an attendee's PARTSTAT update
/// being emailed to a remote organizer).
#[must_use]
pub fn reply_body(attendee: &str, partstat: &str, event: &ics::EventInfo) -> String {
    let summary = event
        .summary
        .clone()
        .unwrap_or_else(|| "(no title)".to_owned());
    let partstat_human = match partstat.to_ascii_uppercase().as_str() {
        "ACCEPTED" => "accepted",
        "DECLINED" => "declined",
        "TENTATIVE" => "answered tentatively to",
        _ => "updated their response to",
    };
    let mut body = String::new();
    body.push_str(&format!(
        "{attendee} has {partstat_human} an invitation.\r\n\r\n"
    ));
    body.push_str(&format!("  Event: {summary}\r\n"));
    body.push_str(&format!(
        "  UID:   {}\r\n",
        event.uid.split('#').next().unwrap_or(&event.uid)
    ));
    body.push_str("\r\n");
    body.push_str(
        "The iTIP reply is attached (invite.ics); opening it updates the attendee's \r\n\
         participation status in your calendar.\r\n",
    );
    body
}

/// Subject line for an iTIP email.
#[must_use]
pub fn itip_subject(method: &str, event: &ics::EventInfo) -> String {
    let summary = event
        .summary
        .clone()
        .unwrap_or_else(|| "Calendar event".to_owned());
    match method {
        "CANCEL" => format!("Cancelled: {summary}"),
        "REPLY" => format!("Response: {summary}"),
        _ => format!("Invitation: {summary}"),
    }
}

/// Build a plaintext guest-calendar-share email (Omnical §17.10.7): the
/// one-time credential the owner has just minted, with the server URL, the
/// guest username and the app token a CalDAV client needs.
///
/// The credential is shown once in the portal banner and mailed here so the
/// owner does not have to copy it manually. `subscribe_url`, when present, is
/// the credential-less `/export/{token}.ics` share link of the same calendar —
/// for clients that take a URL only (Google Calendar "From URL", webcal),
/// where CalDAV credentials cannot be entered. CRLF line endings, single
/// `-`-free body so `send_mail` dot-stuffing never kicks in.
#[must_use]
pub fn build_guest_invite(
    account: &SmtpAccount,
    to: &str,
    server_url: &str,
    username: &str,
    credential: &str,
    calendar_id: &str,
    owner: &str,
    subscribe_url: Option<&str>,
) -> String {
    let from_domain = account
        .identity
        .rsplit('@')
        .next()
        .unwrap_or("omnical.local");
    let message_id = uuid::Uuid::new_v4();
    let date = chrono::Utc::now().to_rfc2822();
    let from_header = match &account.displayname {
        Some(name) => format!("{} <{}>", rfc2047_encode(name), account.identity),
        None => account.identity.clone(),
    };

    let subscribe = match subscribe_url {
        Some(url) if !url.is_empty() => format!(
            "\r\n\
             Need it in an app that only accepts a URL (e.g. Google Calendar \
             \"From URL\" or a webcal client)? No account or app token is \
             needed — subscribe with:\r\n\
             \r\n\
             {url}\r\n"
        ),
        _ => String::new(),
    };

    let mut out = String::new();
    out.push_str(&format!("From: {from_header}\r\n"));
    out.push_str(&format!("To: <{to}>\r\n"));
    out.push_str(&format!(
        "Subject: =?utf-8?B?{}?=\r\n",
        base64::engine::general_purpose::STANDARD
            .encode(format!("Calendar access for you: {calendar_id}").as_bytes(),)
    ));
    out.push_str(&format!("Date: {date}\r\n"));
    out.push_str(&format!("Message-ID: <{message_id}@{from_domain}>\r\n"));
    out.push_str("X-Mailer: Omnical (RustiCal guest share)\r\n");
    out.push_str("MIME-Version: 1.0\r\n");
    out.push_str("Content-Type: text/plain; charset=utf-8\r\n");
    out.push_str("Content-Transfer-Encoding: 8bit\r\n");
    out.push_str("\r\n");
    out.push_str(&format!(
        "You have been given access to the calendar \"{calendar_id}\" by {owner}.\r\n\
         \r\n\
         Add it to your CalDAV calendar app (Apple Calendar, DAVx5, ...) with:\r\n\
         \r\n\
         Server URL: {server_url}\r\n\
         Username: {username}\r\n\
         App token: {credential}\r\n\
         \r\n\
         The app token is only shown here and in the Share page right after \
         creating it. Keep it secret.{subscribe}\r\n"
    ));
    out
}

/// Build a plaintext one-time registration-link email (Omnical §17.8). The
/// single-use invite code is embedded in the `{base}/register?code=…` link,
/// matching what the portal Share section mints. `register_url` is the full
/// clickable link; `expires_at` (optional, ISO 8601 UTC) becomes a plain-line
/// footnote. CRLF line endings; no body line starts with a dot so `send_mail`
/// dot-stuffing never kicks in.
#[must_use]
pub fn build_registration_invite(
    account: &SmtpAccount,
    to: &str,
    register_url: &str,
    created_by: &str,
    expires_at: Option<&str>,
) -> String {
    let from_domain = account
        .identity
        .rsplit('@')
        .next()
        .unwrap_or("omnical.local");
    let message_id = uuid::Uuid::new_v4();
    let date = chrono::Utc::now().to_rfc2822();
    let from_header = match &account.displayname {
        Some(name) => format!("{} <{}>", rfc2047_encode(name), account.identity),
        None => account.identity.clone(),
    };

    let expiry = match expires_at {
        Some(date) if !date.is_empty() => format!("\r\nThis invite expires on {date}."),
        _ => String::new(),
    };

    let mut out = String::new();
    out.push_str(&format!("From: {from_header}\r\n"));
    out.push_str(&format!("To: <{to}>\r\n"));
    out.push_str(&format!(
        "Subject: {}\r\n",
        rfc2047_encode("Invitation to Omnical calendar server")
    ));
    out.push_str(&format!("Date: {date}\r\n"));
    out.push_str(&format!("Message-ID: <{message_id}@{from_domain}>\r\n"));
    out.push_str("X-Mailer: Omnical (RustiCal registration invite)\r\n");
    out.push_str("MIME-Version: 1.0\r\n");
    out.push_str("Content-Type: text/plain; charset=utf-8\r\n");
    out.push_str("Content-Transfer-Encoding: 8bit\r\n");
    out.push_str("\r\n");
    out.push_str(&format!(
        "You have been invited to create an account on Omnical by {created_by}.\r\n\
         \r\n\
         Open this one-time link to set a password and finish signing up:\r\n\
         \r\n\
         {register_url}\r\n\
         \r\n\
         The link (and the code behind it) can only be used once, for the \r\n\
         address it was sent to.{expiry}\r\n\
         \r\n\
         If you did not expect this email, you can ignore it.\r\n\
         \r\n\
         This message was generated automatically by the Omnical calendar server.\r\n"
    ));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ics;

    fn account() -> crate::config::SmtpAccount {
        crate::config::SmtpAccount {
            identity: "nick@example.com".to_owned(),
            host: "smtp.example.com".to_owned(),
            port: 587,
            username: "nick".to_owned(),
            password: "secret".to_owned(),
            displayname: Some("Nick Example".to_owned()),
        }
    }

    #[test]
    fn guest_invite_is_plaintext_with_credential() {
        let account = account();
        let mail = build_guest_invite(
            &account,
            "guest@example.org",
            "https://cal.example.com/caldav",
            "guest-abc",
            "defg_zQ9W...",
            "Personal",
            "nick",
            None,
        );
        assert!(mail.starts_with("From: Nick Example <nick@example.com>\r\n"));
        assert!(mail.contains("To: <guest@example.org>\r\n"));
        assert!(mail.contains("Server URL: https://cal.example.com/caldav\r\n"));
        assert!(mail.contains("Username: guest-abc\r\n"));
        assert!(mail.contains("App token: defg_zQ9W...\r\n"));
        assert!(mail.contains("only shown here and in the Share page right after"));
        assert!(!mail.contains("From URL"));
    }

    #[test]
    fn guest_invite_carries_credential_less_subscribe_link() {
        let account = account();
        let mail = build_guest_invite(
            &account,
            "guest@example.org",
            "https://cal.example.com/caldav",
            "guest-abc",
            "defg_zQ9W...",
            "Personal",
            "nick",
            Some("https://cal.example.com:8443/export/abc123.ics"),
        );
        assert!(mail.contains("only accepts a URL (e.g. Google Calendar"));
        assert!(mail.contains("https://cal.example.com:8443/export/abc123.ics\r\n"));
        assert!(mail.contains("No account or app token is"));
        assert!(!mail.contains("None"));
    }

    #[test]
    fn registration_invite_carries_register_url() {
        let account = account();
        let mail = build_registration_invite(
            &account,
            "newcomer@example.org",
            "https://cal.example.com:8443/register?code=abc123",
            "admin",
            Some("2026-12-31T23:59:59Z"),
        );
        assert!(mail.starts_with("From: Nick Example <nick@example.com>\r\n"));
        assert!(mail.contains("To: <newcomer@example.org>\r\n"));
        assert!(mail.contains("Subject: Invitation to Omnical calendar server\r\n"));
        assert!(mail.contains("https://cal.example.com:8443/register?code=abc123\r\n"));
        assert!(mail.contains("by admin.\r\n"));
        assert!(mail.contains("This invite expires on 2026-12-31T23:59:59Z."));
        assert!(mail.contains("for the \r\naddress it was sent to."));
    }

    #[test]
    fn registration_invite_without_expiry_omits_the_line() {
        let account = account();
        let mail = build_registration_invite(
            &account,
            "newcomer@example.org",
            "https://cal.example.com:8443/register?code=abc123",
            "admin",
            None,
        );
        assert!(mail.contains("used once, for the \r\naddress it was sent to.\r\n"));
        assert!(!mail.contains("expires on"));
        // No line may start with a dot (SMTP dot-stuffing safety)
        for line in mail.lines() {
            assert!(
                !line.starts_with('.'),
                "unexpected dot-stuffed line: {line:?}"
            );
        }
    }

    #[test]
    fn builds_mime() {
        let ics_body = ics::add_method(
            "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//x//EN\r\nBEGIN:VEVENT\r\nUID:u1\r\nSUMMARY:Test café\r\nDTSTART;TZID=America/New_York:20260906T110000\r\nORGANIZER:mailto:nick@example.com\r\nATTENDEE:mailto:bob@example.org\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n",
            "REQUEST",
        );
        let event = ics::parse_event(&ics_body).unwrap();
        let account = account();
        let mail = build_imip(
            &account,
            "bob@example.org",
            &ics_body,
            "REQUEST",
            itip_subject("REQUEST", &event),
            invite_body(&account, &event, "nick@example.com", None),
        );
        assert!(mail.starts_with("From: Nick Example <nick@example.com>\r\n"));
        assert!(mail.contains("To: <bob@example.org>\r\n"));
        assert!(mail.contains("Subject: =?utf-8?B?"));
        assert!(mail.contains("method=REQUEST"));
        assert!(mail.contains("Content-Transfer-Encoding: base64\r\n"));
        assert!(mail.contains("--=_omnical_"));
        assert!(mail.trim_end().ends_with("--"));
        // The ICS payload is base64-encoded in the last MIME part
        let payload = mail.split("\r\n\r\n").last().unwrap();
        assert!(!payload.is_empty());
        assert!(mail.contains("filename=\"invite.ics\""));
        // Without an RSVP URL the body stays attachment-only
        let body = invite_body(&account, &event, "nick@example.com", None);
        assert!(body.contains("The calendar invitation is attached"));
        assert!(!body.contains("Respond directly"));
    }

    #[test]
    fn invite_body_with_rsvp_link() {
        let ics_body = ics::add_method(
            "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//x//EN\r\nBEGIN:VEVENT\r\nUID:u1\r\nSUMMARY:Board games night\r\nDTSTART:20260906T110000Z\r\nORGANIZER:mailto:nick@example.com\r\nATTENDEE:mailto:bob@example.org\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n",
            "REQUEST",
        );
        let event = ics::parse_event(&ics_body).unwrap();
        let body = invite_body(
            &account(),
            &event,
            "nick@example.com",
            Some("https://cal.example.com:8443/rsvp/v1.AB-CD.EF-GH"),
        );
        // The response link leads, on its own line
        assert!(body.contains("Respond directly in your browser"));
        assert!(body.contains("\r\n  https://cal.example.com:8443/rsvp/v1.AB-CD.EF-GH\r\n"));
        // The attachment is still offered as the alternative
        assert!(body.contains("Alternatively, open the attached invitation"));
        assert!(!body.contains("The calendar invitation is attached"));
    }
}
