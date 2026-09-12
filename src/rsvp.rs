//! Public one-click RSVP routes for iMIP invitations — Omnical extension
//! (`PLAN_SHARING.md` §9 item 3).
//!
//! Invitation emails to external attendees carry one neutral link to a
//! response page (`GET /rsvp/{token}`); the page carries the actual
//! Accept/Maybe/Decline links (`GET /rsvp/{token}?r=…`). The split is
//! deliberate: mail scanners (Outlook `SafeLinks` and friends) prefetch
//! URLs from emails — a prefetched action link would silently record a
//! response the attendee never gave, while a prefetched *page* is
//! harmless. The page links are plain GETs so they work in every
//! in-app mail browser without scripting.
//!
//! The token in the URL is the only credential (HMAC-signed uid +
//! organizer + attendee + expiry — see `rustical_scheduling::rsvp`), so
//! like the share-link export router this mounts OUTSIDE the DAV
//! `AuthenticationLayer`. Recording a response feeds the exact same
//! machinery an emailed iMIP REPLY uses: the organizer's stored copies
//! get the new PARTSTAT and a REPLY is filed into their scheduling
//! inbox.
//!
//! Status mapping (a human clicks these, so each failure renders a
//! friendly page, never an auth prompt): invalid/expired token → 404,
//! cancelled/deleted/uninvited → 410, unknown response word → 400,
//! store failure → 500.

use axum::Router;
use axum::extract::{Path, Query, State};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;
use http::StatusCode;
use rustical_scheduling::{RsvpError, RsvpEvent, Scheduler};
use serde::Deserialize;
use std::sync::Arc;
use tracing::instrument;
use tracing::warn;

/// `?r=<response>` on the response page links.
#[derive(Deserialize, Default, Debug)]
struct RsvpQuery {
    r: Option<String>,
}

/// Build the public RSVP router.
///
/// Must be mounted OUTSIDE any `AuthenticationLayer` — the token in the
/// URL is the only credential — and only while the scheduler's RSVP
/// links are fully configured (`Scheduler::rsvp_links_enabled`), so a
/// disabled config has zero public footprint.
pub fn rsvp_router(scheduler: Arc<Scheduler>) -> Router {
    Router::new()
        .route("/rsvp/{token}", get(route_rsvp))
        .with_state(scheduler)
}

#[instrument(skip(scheduler))]
async fn route_rsvp(
    State(scheduler): State<Arc<Scheduler>>,
    Path(token): Path<String>,
    Query(query): Query<RsvpQuery>,
) -> Response {
    match query.r.as_deref() {
        // The response page: event details + the three response links
        None => match scheduler.rsvp_page_data(&token).await {
            Ok(event) => page(StatusCode::OK, &render_landing(&event, &token)),
            Err(RsvpError::Invalid) => page(StatusCode::NOT_FOUND, &render_invalid()),
            Err(RsvpError::Gone) => page(StatusCode::GONE, &render_gone()),
            Err(RsvpError::Store(err)) => {
                warn!("rsvp page: store failure: {err}");
                page(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &render_error("loading the invitation"),
                )
            }
            Err(RsvpError::BadResponse) => unreachable!("page data never validates a response"),
        },
        // A response link was clicked: record it, then confirm
        Some(response) => match scheduler.rsvp_apply(&token, response).await {
            Ok(event) => page(StatusCode::OK, &render_confirmation(&event, &token)),
            Err(RsvpError::Invalid) => page(StatusCode::NOT_FOUND, &render_invalid()),
            Err(RsvpError::Gone) => page(StatusCode::GONE, &render_gone()),
            Err(RsvpError::BadResponse) => {
                page(StatusCode::BAD_REQUEST, &render_bad_response(&token))
            }
            Err(RsvpError::Store(err)) => {
                warn!("rsvp apply: store failure: {err}");
                page(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &render_error("recording your response"),
                )
            }
        },
    }
}

// --- Pages -------------------------------------------------------------------

fn partstat_word(partstat: &str) -> &'static str {
    match partstat {
        "ACCEPTED" => "accepted",
        "TENTATIVE" => "answered maybe to",
        "DECLINED" => "declined",
        _ => "responded to",
    }
}

/// The chosen-response link matching `partstat`, for page highlighting.
fn partstat_link(partstat: &str) -> Option<&'static str> {
    match partstat {
        "ACCEPTED" => Some("accept"),
        "TENTATIVE" => Some("maybe"),
        "DECLINED" => Some("decline"),
        _ => None,
    }
}

fn render_landing(event: &RsvpEvent, token: &str) -> String {
    let current_note = partstat_link(&event.partstat).map_or_else(String::new, |link| {
        let word = match link {
            "accept" => "accepted",
            "maybe" => "answered maybe",
            _ => "declined",
        };
        format!(
            r#"<p class="current">You have already {word} this invitation. You can change your response below.</p>"#
        )
    });
    // Highlight the button matching the current response, if any
    let current_link = partstat_link(&event.partstat);
    let buttons = ["accept", "maybe", "decline"]
        .map(|link| {
            let label = match link {
                "accept" => "Accept",
                "maybe" => "Maybe",
                _ => "Decline",
            };
            let current = if Some(link) == current_link {
                r#" class="btn current" aria-current="true"#
            } else {
                " class=\"btn\""
            };
            format!(r#"<a{current} href="?r={link}">{label}</a>"#)
        })
        .join("\n");
    let recurring = if event.recurring { " (repeats)" } else { "" };
    format!(
        r#"<h1>Event invitation</h1>
<p class="muted">You were invited by <strong>{organizer}</strong> (as {attendee}).</p>
<div class="event">
  <p class="summary">{summary}</p>
  <p>{when}{recurring}</p>
</div>
{current_note}
<p class="question">Will you attend?</p>
<div class="actions">
{buttons}
</div>
<p class="muted">No account needed — your response goes straight to the organizer's calendar. You can also open the attached invitation email in your calendar application instead.</p>
<p class="muted"><a href="{path}">Reload the page</a> to see your current response.</p>"#,
        organizer = escape_html(&event.organizer),
        attendee = escape_html(&event.attendee),
        summary = escape_html(&event.summary),
        when = escape_html(&event.when),
        recurring = escape_html(recurring),
        path = escape_html(&format!("/rsvp/{token}")),
    )
}

fn render_confirmation(event: &RsvpEvent, token: &str) -> String {
    let recurring = if event.recurring { " (repeats)" } else { "" };
    format!(
        r#"<h1>Response recorded</h1>
<p class="status">You have {word} this invitation. The organizer's calendar has been updated.</p>
<div class="event">
  <p class="summary">{summary}</p>
  <p>{when}{recurring}</p>
</div>
<p class="muted">Organizer: {organizer}</p>
<p>Changed your mind? <a href="{path}">Choose a different response</a>.</p>"#,
        word = partstat_word(&event.partstat),
        summary = escape_html(&event.summary),
        when = escape_html(&event.when),
        recurring = escape_html(recurring),
        organizer = escape_html(&event.organizer),
        path = escape_html(&format!("/rsvp/{token}")),
    )
}

fn render_invalid() -> String {
    "<h1>Invitation link unavailable</h1>
<p>This link is invalid or has expired.</p>
<p class=\"muted\">Ask the organizer to send you a new invitation, or respond using the calendar attachment of the invitation email.</p>"
        .to_owned()
}

fn render_gone() -> String {
    "<h1>Invitation no longer available</h1>
<p>This event has been cancelled, deleted, or you are no longer invited.</p>"
        .to_owned()
}

fn render_bad_response(token: &str) -> String {
    format!(
        "<h1>Unknown response</h1>\n<p class=\"muted\"><a href=\"{path}\">Back to the invitation</a>.</p>",
        path = escape_html(&format!("/rsvp/{token}"))
    )
}

fn render_error(action: &str) -> String {
    format!(
        "<h1>Something went wrong</h1>\n<p>An error occurred while {action}. Please try again later.</p>"
    )
}

// --- Plumbing ----------------------------------------------------------------

fn page(status: StatusCode, body: &str) -> Response {
    (status, [("cache-control", "no-store")], render_page(body)).into_response()
}

/// Escape a value for safe embedding in the HTML pages (the event
/// summary/organizer/attendee come from user-created calendar data).
fn escape_html(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            _ => out.push(ch),
        }
    }
    out
}

fn render_page(body: &str) -> Html<String> {
    Html(format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>Omnical — Event invitation</title>
<style>
  body {{ font-family: system-ui, sans-serif; max-width: 34rem; margin: 3rem auto; padding: 0 1rem; line-height: 1.5; }}
  h1 {{ font-size: 1.4rem; }}
  .muted {{ color: #666; }}
  .event {{ border: 1px solid #ccc; border-radius: 6px; padding: 0.8rem 1rem; margin: 1rem 0; }}
  .event .summary {{ font-size: 1.1rem; font-weight: 600; margin: 0 0 0.3rem; }}
  .question {{ font-weight: 600; }}
  .current {{ border-left: 4px solid #f0ad4e; padding: 0.5rem 0.8rem; background: rgba(240,173,78,.15); }}
  .actions {{ display: flex; gap: 0.8rem; margin: 1rem 0 1.5rem; }}
  .btn {{ display: inline-block; padding: 0.6rem 1.6rem; font-size: 1rem; text-decoration: none;
         border: 1px solid #2c6dac; border-radius: 6px; color: #2c6dac; }}
  .btn:hover {{ background: #e8f0f8; }}
  .btn.current {{ background: #2c6dac; color: #fff; }}
  .status {{ border-left: 4px solid #3c9a3c; padding: 0.5rem 0.8rem; background: rgba(60,154,60,.12); }}
</style>
</head>
<body>
{body}
</body>
</html>"#
    ))
}

#[cfg(test)]
mod tests {
    //! Route-level tests for the public RSVP pages (`PLAN_SHARING.md` §9
    //! item 3, sub-item 3), following the `register.rs` `TestRig` pattern:
    //! the RSVP router is merged next to the authenticated `CalDAV` router
    //! exactly like `make_app` mounts it (one shared scheduler), and every
    //! request runs through `oneshot`.
    //!
    //! Covered: the landing page (200, the three response links, live
    //! data never cached), the accept flow (confirmation page + the
    //! organizer's stored PARTSTAT + the REPLY in their scheduling
    //! inbox), bad tokens (404, no validity oracle), cancelled events
    //! (410), unknown response words (400, checked before the token) and
    //! HTML escaping of the event summary (user data).
    use super::*;
    use axum::body::Body as AxBody;
    use headers::{Authorization, HeaderMapExt};
    use http::Request;
    use rustical_caldav::{CalDavConfig, caldav_router};
    use rustical_ical::CalendarObjectType;
    use rustical_scheduling::config::SchedulingConfig;
    use rustical_scheduling::rsvp;
    use rustical_store::{Calendar, CalendarMetadata, CalendarWriteStore};
    use rustical_store_sqlite::SqliteSchedulingStore;
    use rustical_store_sqlite::tests::{TestStoreContext, test_store_context};
    use tower::ServiceExt;

    /// The invited attendee — deliberately NOT a local principal: RSVP
    /// links exist for external attendees, who respond without an account.
    const ATTENDEE: &str = "attendee@example.com";

    /// The RSVP link signing secret configured in [`TestRig::new`]
    /// (tokens minted with it verify against the rig's scheduler).
    const RSVP_SECRET: &str = "test-rsvp-secret-0123456789abcdef";

    struct TestRig {
        router: Router,
    }

    impl TestRig {
        async fn new() -> Self {
            let context = test_store_context().await;
            setup_fixtures(&context).await;

            let scheduler = Arc::new(Scheduler::new(
                SchedulingConfig {
                    enabled: true,
                    // Fully configured RSVP links: tokens minted with
                    // `RSVP_SECRET` verify against this scheduler.
                    rsvp_secret: Some(RSVP_SECRET.to_owned()),
                    rsvp_base_url: Some("https://cal.example.com:8443".to_owned()),
                    ..Default::default()
                },
                Arc::new(SqliteSchedulingStore::new(context.cal_store.clone())),
            ));

            // Mirrors `make_app`: the public RSVP router is merged next
            // to the authenticated CalDAV router (mounting it outside any
            // auth layer), both sharing one scheduler.
            let router = caldav_router(
                "/caldav",
                Arc::new(context.principal_store),
                Arc::new(context.cal_store),
                Arc::new(context.dav_push_store),
                false,
                Arc::new(CalDavConfig::default()),
                Some(scheduler.clone()),
            )
            .merge(rsvp_router(scheduler));

            Self { router }
        }

        /// Unauthenticated GET — the token in the URL is the only
        /// credential the RSVP routes may require.
        async fn get(&self, uri: &str) -> Response {
            self.router
                .clone()
                .oneshot(Request::get(uri).body(AxBody::empty()).unwrap())
                .await
                .unwrap()
        }

        /// PUT the organizer's stored copy through the real `CalDAV` path
        /// with a sync-client UA: the copy is stored, but the UA exclusion
        /// skips implicit scheduling delivery (same shape as the caldav
        /// scheduling tests).
        async fn put_organizer_copy(&self, object_id: &str, ics: String) {
            let mut request = Request::put(format!("/caldav/principal/user/personal/{object_id}"))
                .header("User-Agent", "vdirsyncer/0.20.7 (Linux) requests/2")
                .body(AxBody::from(ics))
                .unwrap();
            request
                .headers_mut()
                .typed_insert(Authorization::basic("user", "pass"));
            let response = self.router.clone().oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::CREATED);
        }

        /// Owner-authenticated GET of a calendar/inbox object through the
        /// `CalDAV` router.
        async fn get_authed(&self, uri: &str) -> String {
            let mut request = Request::get(uri).body(AxBody::empty()).unwrap();
            request
                .headers_mut()
                .typed_insert(Authorization::basic("user", "pass"));
            let response = self.router.clone().oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            body_string(response).await
        }
    }

    /// A writable VEVENT calendar for the fixture principal `user`
    /// (whose app token `user`/`pass` comes from the store fixture).
    async fn setup_fixtures(context: &TestStoreContext) {
        context
            .cal_store
            .insert_calendar(Calendar {
                id: "personal".to_owned(),
                principal: "user".to_owned(),
                meta: CalendarMetadata {
                    displayname: Some("Personal".to_owned()),
                    order: 0,
                    description: None,
                    color: None,
                },
                timezone_id: None,
                deleted_at: None,
                synctoken: 0,
                subscription_url: None,
                push_topic: "personal-push-topic".to_owned(),
                components: vec![CalendarObjectType::Event],
            })
            .await
            .unwrap();
    }

    async fn body_string(response: Response) -> String {
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    /// Mint the RSVP link token an invitation email would carry for
    /// `ATTENDEE`'s response to the event `uid` organized by `user`.
    fn rsvp_token(uid: &str) -> String {
        rsvp::mint_token(
            RSVP_SECRET,
            uid,
            "user",
            ATTENDEE,
            chrono::Utc::now().timestamp(),
        )
    }

    fn event_ics(uid: &str, summary: &str) -> String {
        format!(
            "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Omnical//RSVP Route Tests//EN\r\n\
             BEGIN:VEVENT\r\nUID:{uid}\r\nDTSTAMP:20260905T120000Z\r\n\
             DTSTART:20260906T100000Z\r\nDTEND:20260906T110000Z\r\nSUMMARY:{summary}\r\n\
             ORGANIZER:mailto:user\r\nATTENDEE:mailto:{ATTENDEE}\r\n\
             END:VEVENT\r\nEND:VCALENDAR\r\n"
        )
    }

    /// [`event_ics`](event_ics()) with `STATUS:CANCELLED`: the organizer
    /// cancelled the event while the token is still valid.
    fn cancelled_event_ics(uid: &str, summary: &str) -> String {
        format!(
            "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Omnical//RSVP Route Tests//EN\r\n\
             BEGIN:VEVENT\r\nUID:{uid}\r\nDTSTAMP:20260905T120000Z\r\n\
             DTSTART:20260906T100000Z\r\nDTEND:20260906T110000Z\r\nSUMMARY:{summary}\r\n\
             STATUS:CANCELLED\r\nORGANIZER:mailto:user\r\nATTENDEE:mailto:{ATTENDEE}\r\n\
             END:VEVENT\r\nEND:VCALENDAR\r\n"
        )
    }

    /// The neutral landing page an emailed link points at: event details,
    /// the attendee's current (non-)response, and exactly the three
    /// response links — never cached, because it reflects a live PARTSTAT.
    #[tokio::test]
    async fn landing_page_shows_event_and_response_links() {
        let rig = TestRig::new().await;
        rig.put_organizer_copy("rsvp-http-1.ics", event_ics("rsvp-http-1", "Garden party"))
            .await;

        let response = rig
            .get(&format!("/rsvp/{}", rsvp_token("rsvp-http-1")))
            .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["cache-control"], "no-store");
        let body = body_string(response).await;
        assert!(body.contains("Event invitation"), "{body}");
        assert!(body.contains("Garden party"), "{body}");
        assert!(
            body.contains(&format!("invited by <strong>user</strong> (as {ATTENDEE})")),
            "{body}"
        );
        // The three response links (plain GETs, relative to the page)
        for link in ["accept", "maybe", "decline"] {
            assert!(body.contains(&format!(r#"href="?r={link}""#)), "{body}");
        }
        // Not yet answered: no current-response note
        assert!(!body.contains("already"), "{body}");
    }

    /// Clicking a response link records it exactly like an emailed iMIP
    /// REPLY would: confirmation page, the organizer's stored copy flips
    /// to the new PARTSTAT (still the full event), and a REPLY is filed
    /// into their scheduling inbox.
    #[tokio::test]
    async fn accept_records_response_and_updates_organizer_copy() {
        let rig = TestRig::new().await;
        rig.put_organizer_copy(
            "rsvp-http-2.ics",
            event_ics("rsvp-http-2", "RSVP HTTP test"),
        )
        .await;

        let token = rsvp_token("rsvp-http-2");
        let response = rig.get(&format!("/rsvp/{token}?r=accept")).await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_string(response).await;
        assert!(body.contains("Response recorded"), "{body}");
        assert!(body.contains("You have accepted this invitation"), "{body}");
        // The change-mind link points back at the neutral response page
        assert!(body.contains(&format!(r#"href="/rsvp/{token}""#)), "{body}");

        // The organizer's stored copy carries the new PARTSTAT — and is
        // still the full event, not the minimal iTIP REPLY
        let body = rig
            .get_authed("/caldav/principal/user/personal/rsvp-http-2.ics")
            .await;
        assert!(
            body.contains(&format!("ATTENDEE;PARTSTAT=ACCEPTED:mailto:{ATTENDEE}")),
            "{body}"
        );
        assert!(body.contains("RSVP HTTP test"), "{body}");
        assert!(!body.contains("METHOD:REPLY"), "{body}");

        // The REPLY was filed into the organizer's scheduling inbox
        let body = rig
            .get_authed(&format!(
                "/caldav/principal/user/inbox/reply-rsvp-http-2-{ATTENDEE}.ics"
            ))
            .await;
        assert!(body.contains("METHOD:REPLY"), "{body}");
        assert!(body.contains("UID:rsvp-http-2"), "{body}");
        assert!(body.contains("PARTSTAT=ACCEPTED"), "{body}");
    }

    /// Garbage and well-shaped-but-unknown tokens must answer 404 — the
    /// route offers no validity oracle — for the page and apply alike.
    #[tokio::test]
    async fn bad_token_is_404() {
        let rig = TestRig::new().await;

        for uri in ["/rsvp/v1.garbage.token", "/rsvp/not-even-shaped?r=accept"] {
            let response = rig.get(uri).await;
            assert_eq!(response.status(), StatusCode::NOT_FOUND, "uri: {uri}");
            let body = body_string(response).await;
            assert!(
                body.contains("invalid or has expired"),
                "uri: {uri}: {body}"
            );
        }
    }

    /// A valid link to a cancelled event must answer 410 and record
    /// nothing — the response page must not offer responses to a dead
    /// event.
    #[tokio::test]
    async fn cancelled_event_is_410() {
        let rig = TestRig::new().await;
        rig.put_organizer_copy(
            "rsvp-http-cancelled.ics",
            cancelled_event_ics("rsvp-http-cancelled", "Cancelled HTTP test"),
        )
        .await;

        let token = rsvp_token("rsvp-http-cancelled");
        for uri in [format!("/rsvp/{token}"), format!("/rsvp/{token}?r=accept")] {
            let response = rig.get(&uri).await;
            assert_eq!(response.status(), StatusCode::GONE, "uri: {uri}");
            let body = body_string(response).await;
            assert!(body.contains("cancelled"), "uri: {uri}: {body}");
        }

        // No response was recorded
        let body = rig
            .get_authed("/caldav/principal/user/personal/rsvp-http-cancelled.ics")
            .await;
        assert!(!body.contains("PARTSTAT=ACCEPTED"), "{body}");
    }

    /// Unknown response words answer 400, even for a garbage token (the
    /// word check precedes the token check), and nothing is applied.
    #[tokio::test]
    async fn unknown_response_word_is_400() {
        let rig = TestRig::new().await;
        rig.put_organizer_copy(
            "rsvp-http-bogus.ics",
            event_ics("rsvp-http-bogus", "Bogus word test"),
        )
        .await;

        let token = rsvp_token("rsvp-http-bogus");
        for uri in [
            format!("/rsvp/{token}?r=bogus"),
            "/rsvp/v1.garbage.token?r=bogus".to_owned(),
        ] {
            let response = rig.get(&uri).await;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "uri: {uri}");
            let body = body_string(response).await;
            assert!(body.contains("Unknown response"), "uri: {uri}: {body}");
        }
        // The back link returns to the (valid) invitation
        let response = rig.get(&format!("/rsvp/{token}?r=bogus")).await;
        let body = body_string(response).await;
        assert!(body.contains(&format!(r#"href="/rsvp/{token}""#)), "{body}");

        // The stored copy is untouched
        let body = rig
            .get_authed("/caldav/principal/user/personal/rsvp-http-bogus.ics")
            .await;
        assert!(
            body.contains(&format!("ATTENDEE:mailto:{ATTENDEE}")),
            "{body}"
        );
        assert!(!body.contains("PARTSTAT=ACCEPTED"), "{body}");
    }

    /// The event summary is user-created calendar data — it must arrive
    /// on the page escaped, never raw markup.
    #[tokio::test]
    async fn summary_is_html_escaped() {
        let rig = TestRig::new().await;
        rig.put_organizer_copy(
            "rsvp-http-escape.ics",
            event_ics("rsvp-http-escape", r"Tea & <script>party</script>"),
        )
        .await;

        let response = rig
            .get(&format!("/rsvp/{}", rsvp_token("rsvp-http-escape")))
            .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_string(response).await;
        assert!(
            body.contains("Tea &amp; &lt;script&gt;party&lt;/script&gt;"),
            "{body}"
        );
        assert!(!body.contains("<script>"), "{body}");
    }
}
