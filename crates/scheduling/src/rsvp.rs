//! One-click RSVP link tokens carried in iMIP invitation emails.
//!
//! External attendees get an email with a link to a public response page
//! (Accept / Maybe / Decline) instead of having to open the attached
//! `invite.ics` in a calendar client. The token in the URL is the only
//! credential: it is HMAC-signed state (uid, organizer, attendee,
//! expiry) — no database row, no session, nothing personal beyond the
//! addresses the invitation email already carries. The response choice
//! itself rides unsigned in the query string (`?r=accept`): the token
//! holder may pick any of the three responses, which is exactly the
//! capability an emailed invitation grants anyway.
//!
//! The email deliberately carries ONE neutral link (to the response
//! page) rather than three action links: mail scanners (Outlook
//! `SafeLinks` and friends) prefetch URLs from emails, and a prefetched
//! `?r=accept` would silently record a response the attendee never
//! gave. Scanners fetching the neutral page is harmless.

use base64::Engine;
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

/// How long an RSVP link stays valid. Invitations are often sent far in
/// advance of the event, so the window is generous; every REQUEST email
/// mints a fresh token, so re-invites always carry live links.
pub const TOKEN_TTL_SECS: i64 = 365 * 24 * 3600;

/// Domain separation prefix inside the MAC input, so a token can never
/// be confused with a (future) signature over the same base64 payload
/// in another scheme.
const MAC_DOMAIN: &str = "omnical-rsvp-v1.";

/// What an RSVP link authorizes: one attendee's response to one event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RsvpClaims {
    /// UID of the invited event.
    pub uid: String,
    /// Organizer address; the link only works while this is a local
    /// principal (the endpoint refuses otherwise).
    pub organizer: String,
    /// The invited attendee's address — the only identity the token
    /// speaks for.
    pub attendee: String,
    /// Unix time (seconds) after which the token stops working.
    pub exp: i64,
}

/// Response words accepted on the public RSVP page, in URL shape.
pub const RESPONSES: [&str; 3] = ["accept", "maybe", "decline"];

/// Map a response word to its iTIP PARTSTAT.
#[must_use]
pub fn partstat_for_response(response: &str) -> Option<&'static str> {
    match response.to_ascii_lowercase().as_str() {
        "accept" => Some("ACCEPTED"),
        "maybe" => Some("TENTATIVE"),
        "decline" => Some("DECLINED"),
        _ => None,
    }
}

fn b64url_encode(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn b64url_decode(input: &str) -> Option<Vec<u8>> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(input)
        .ok()
}

fn mac(secret: &[u8], mac_input: &[u8]) -> Vec<u8> {
    let mut mac = <Hmac<Sha256>>::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(mac_input);
    mac.finalize().into_bytes().to_vec()
}

/// Mint an RSVP link token for `attendee`'s response to the event `uid`
/// organized by `organizer`, valid for [`TOKEN_TTL_SECS`] from `now`.
///
/// Shape: `v1.<base64url(claims JSON)>.<base64url(HMAC-SHA256)>`.
#[must_use]
pub fn mint_token(secret: &str, uid: &str, organizer: &str, attendee: &str, now: i64) -> String {
    let claims = RsvpClaims {
        uid: uid.to_owned(),
        organizer: organizer.to_owned(),
        attendee: attendee.to_owned(),
        exp: now + TOKEN_TTL_SECS,
    };
    let payload = serde_json::to_string(&claims).expect("claims serialize");
    let payload_b64 = b64url_encode(payload.as_bytes());
    let signature = mac(
        secret.as_bytes(),
        format!("{MAC_DOMAIN}{payload_b64}").as_bytes(),
    );
    format!("v1.{payload_b64}.{}", b64url_encode(&signature))
}

/// Verify an RSVP link token: correct shape, valid signature, not yet
/// expired.
///
/// Returns the claims on success, `None` on any failure — the endpoint
/// treats all failures identically (404) so the public route offers no
/// validity oracle.
#[must_use]
pub fn verify_token(secret: &str, token: &str, now: i64) -> Option<RsvpClaims> {
    let (payload_b64, signature_b64) = token.strip_prefix("v1.")?.split_once('.')?;
    let signature = b64url_decode(signature_b64)?;
    // Constant-time compare via the hmac crate
    let mut mac = <Hmac<Sha256>>::new_from_slice(secret.as_bytes()).expect("any key length");
    mac.update(format!("{MAC_DOMAIN}{payload_b64}").as_bytes());
    mac.verify_slice(&signature).ok()?;
    let payload = b64url_decode(payload_b64)?;
    let claims: RsvpClaims = serde_json::from_slice(&payload).ok()?;
    (claims.exp >= now).then_some(claims)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "test-secret-0123456789abcdef";

    fn mint(uid: &str, attendee: &str, now: i64) -> String {
        mint_token(SECRET, uid, "organizer@example.com", attendee, now)
    }

    #[test]
    fn round_trip() {
        let now = 1_700_000_000;
        let token = mint("event-uid-1", "attendee@example.org", now);
        let claims = verify_token(SECRET, &token, now).expect("token verifies");
        assert_eq!(claims.uid, "event-uid-1");
        assert_eq!(claims.organizer, "organizer@example.com");
        assert_eq!(claims.attendee, "attendee@example.org");
        assert_eq!(claims.exp, now + TOKEN_TTL_SECS);
    }

    #[test]
    fn expires_but_not_early() {
        let now = 1_700_000_000;
        let token = mint("event-uid-1", "attendee@example.org", now);
        // Last second of validity: still fine
        assert!(verify_token(SECRET, &token, now + TOKEN_TTL_SECS).is_some());
        // One second past expiry: refused
        assert!(verify_token(SECRET, &token, now + TOKEN_TTL_SECS + 1).is_none());
    }

    #[test]
    fn wrong_secret_rejected() {
        let token = mint("event-uid-1", "attendee@example.org", 1_700_000_000);
        assert!(verify_token("other-secret", &token, 1_700_000_000).is_none());
    }

    #[test]
    fn tampered_payload_rejected() {
        let now = 1_700_000_000;
        let token = mint("event-uid-1", "attendee@example.org", now);
        let mut parts: Vec<&str> = token.split('.').collect();
        // Flip the attendee inside the (still validly shaped) payload
        let payload = b64url_decode(parts[1]).unwrap();
        let doctored = String::from_utf8(payload)
            .unwrap()
            .replace("attendee@example.org", "victim@example.org");
        let doctored_b64 = b64url_encode(doctored.as_bytes());
        parts[1] = &doctored_b64;
        let token = parts.join(".");
        assert!(verify_token(SECRET, &token, now).is_none());
    }

    #[test]
    fn garbage_rejected() {
        let now = 1_700_000_000;
        assert!(verify_token(SECRET, "", now).is_none());
        assert!(verify_token(SECRET, "v1.onlyonepart", now).is_none());
        assert!(verify_token(SECRET, "v2.a.b", now).is_none());
        assert!(verify_token(SECRET, "v1.!!!.???", now).is_none());
        // Valid base64 but not JSON claims
        let junk = format!(
            "v1.{}.{}",
            b64url_encode(b"not json"),
            b64url_encode(&mac(
                SECRET.as_bytes(),
                format!("{MAC_DOMAIN}{}", b64url_encode(b"not json")).as_bytes(),
            ))
        );
        assert!(verify_token(SECRET, &junk, now).is_none());
    }

    #[test]
    fn partstat_mapping() {
        assert_eq!(partstat_for_response("accept"), Some("ACCEPTED"));
        assert_eq!(partstat_for_response("MAYBE"), Some("TENTATIVE"));
        assert_eq!(partstat_for_response("decline"), Some("DECLINED"));
        assert_eq!(partstat_for_response("accepted"), None);
        assert_eq!(partstat_for_response(""), None);
    }
}
