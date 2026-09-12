//! Integration tests for the scheduling extension (Omnical RFC 6638 subset).
//!
//! These exercise the full `caldav_router` with an enabled `Scheduler`
//! backed by `SqliteSchedulingStore`, proving:
//! * the `/inbox` and `/outbox` static routes coexist with `/{calendar_id}`
//!   (route precedence — constructing the router must not panic),
//! * the scheduling DAV tokens are advertised via `OPTIONS`,
//! * the RFC 6638 principal properties are filled by `PROPFIND`,
//! * implicit scheduling on PUT delivers a REQUEST to the internal
//!   attendee's inbox (PROPFIND/GET/DELETE round-trip) and DELETE delivers
//!   a CANCEL,
//! * excluded sync-client user agents (vdirsyncer) trigger nothing,
//! * the outbox POST answers with a `schedule-response`,
//! * inbound iMIP REPLY ingestion (`ingest_imip_reply`, the IMAP poll
//!   leg) updates the organizer's stored copy and files the REPLY into
//!   their inbox, ignoring foreign organizers, non-REPLY methods and
//!   unknown mailbox identities,
//! * one-click RSVP link tokens (`rsvp_page_data` / `rsvp_apply`, the
//!   response flow behind the links invitation emails carry) resolve
//!   against the organizer's stored copies, apply a response exactly
//!   like an emailed REPLY would, and refuse garbage/expired/forged
//!   tokens, foreign organizers, unknown UIDs, cancelled events,
//!   uninvited attendees and unknown response words.

use crate::{CalDavConfig, caldav_router};
use axum::body::Body;
use axum::response::Response;
use headers::{Authorization, HeaderMapExt};
use http::{HeaderValue, Request, StatusCode};
use rustical_ical::CalendarObjectType;
use rustical_scheduling::{DAV_TOKENS, RsvpError, Scheduler, config::SchedulingConfig, rsvp};
use rustical_store::auth::{AuthenticationProvider, Principal, PrincipalType};
use rustical_store::{Calendar, CalendarMetadata, CalendarWriteStore};
use rustical_store_sqlite::SqliteSchedulingStore;
use rustical_store_sqlite::tests::{TestStoreContext, test_store_context};
use std::sync::Arc;
use tower::ServiceExt;

const ATTENDEE: &str = "attendee@example.com";

/// The RSVP link signing secret configured in
/// [`scheduling_app_with_scheduler`] (tokens minted with it verify
/// against the fixture's scheduler; everything else must not).
const RSVP_SECRET: &str = "test-rsvp-secret-0123456789abcdef";

/// Public base URL configured alongside [`RSVP_SECRET`].
const RSVP_BASE_URL: &str = "https://cal.example.com:8443";

/// Full caldav_router with scheduling enabled (router construction itself
/// proves the `/inbox`/`/outbox` vs `/{calendar_id}` route precedence).
async fn scheduling_app() -> axum::Router {
    scheduling_app_with_scheduler().await.0
}

/// [`scheduling_app`], but also handing back the `Scheduler` so tests can
/// drive it directly (e.g. the inbound iMIP ingestion entry point and
/// the RSVP link entry points).
async fn scheduling_app_with_scheduler() -> (axum::Router, Arc<Scheduler>) {
    let context = test_store_context().await;
    setup_fixtures(&context).await;

    let scheduler = Arc::new(Scheduler::new(
        SchedulingConfig {
            enabled: true,
            // Fully configured RSVP links: invitation emails would carry
            // `RSVP_BASE_URL/rsvp/<token>`; tokens minted with
            // `RSVP_SECRET` verify against this scheduler.
            rsvp_secret: Some(RSVP_SECRET.to_owned()),
            rsvp_base_url: Some(RSVP_BASE_URL.to_owned()),
            ..Default::default()
        },
        Arc::new(SqliteSchedulingStore::new(context.cal_store.clone())),
    ));

    let app = caldav_router(
        "/caldav",
        Arc::new(context.principal_store),
        Arc::new(context.cal_store),
        Arc::new(context.dav_push_store),
        false,
        Arc::new(CalDavConfig::default()),
        Some(scheduler.clone()),
    );

    (app, scheduler)
}

/// Second principal (the internal attendee) + a writable VEVENT calendar for
/// the fixture principal `user`.
async fn setup_fixtures(context: &TestStoreContext) {
    context
        .principal_store
        .insert_principal(
            Principal {
                id: ATTENDEE.to_owned(),
                displayname: None,
                memberships: vec![],
                password: None,
                principal_type: PrincipalType::Individual,
            },
            false,
        )
        .await
        .unwrap();
    context
        .principal_store
        .add_app_token(ATTENDEE, "test".to_owned(), "pass".to_owned())
        .await
        .unwrap();

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

fn request(method: &str, uri: &str, user: &str, body: Body) -> Request<Body> {
    let mut request = Request::builder()
        .method(method)
        .uri(uri)
        .body(body)
        .unwrap();
    request
        .headers_mut()
        .typed_insert(Authorization::basic(user, "pass"));
    request
}

async fn extract_string(response: Response) -> String {
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    String::from_utf8(bytes.to_vec()).unwrap()
}

fn event_ics(uid: &str, summary: &str) -> String {
    format!(
        "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Omnical//Scheduling Tests//EN\r\n\
         BEGIN:VEVENT\r\nUID:{uid}\r\nDTSTAMP:20260905T120000Z\r\n\
         DTSTART:20260906T100000Z\r\nDTEND:20260906T110000Z\r\nSUMMARY:{summary}\r\n\
         ORGANIZER:mailto:user\r\nATTENDEE:mailto:{ATTENDEE}\r\n\
         END:VEVENT\r\nEND:VCALENDAR\r\n"
    )
}

/// Events without an ORGANIZER line (e.g. khal-created) still
/// trigger scheduling when the acting user is an attendee —
/// they act as the organizer. Puts into the attendee's own
/// calendar (they must own the target calendar).
#[tokio::test]
async fn test_put_no_organizer_delivers_request_when_attendee() {
    let context = test_store_context().await;
    setup_fixtures(&context).await;

    // Give the attendee their own calendar so they can PUT to it
    context
        .cal_store
        .insert_calendar(Calendar {
            id: "default".to_owned(),
            principal: ATTENDEE.to_owned(),
            meta: CalendarMetadata {
                displayname: Some("Default".to_owned()),
                order: 0,
                description: None,
                color: None,
            },
            timezone_id: None,
            deleted_at: None,
            synctoken: 0,
            subscription_url: None,
            push_topic: "default-push-topic".to_owned(),
            components: vec![CalendarObjectType::Event],
        })
        .await
        .unwrap();
    context
        .principal_store
        .add_app_token(ATTENDEE, "test".to_owned(), "pass".to_owned())
        .await
        .unwrap();

    let scheduler = Arc::new(Scheduler::new(
        SchedulingConfig {
            enabled: true,
            rsvp_secret: Some(RSVP_SECRET.to_owned()),
            rsvp_base_url: Some(RSVP_BASE_URL.to_owned()),
            ..Default::default()
        },
        Arc::new(SqliteSchedulingStore::new(context.cal_store.clone())),
    ));

    let app = caldav_router(
        "/caldav",
        Arc::new(context.principal_store),
        Arc::new(context.cal_store),
        Arc::new(context.dav_push_store),
        false,
        Arc::new(CalDavConfig::default()),
        Some(scheduler),
    );

    // Event has NO ORGANIZER; attendees are the acting user and user.
    // The acting user (attendee) is an attendee → they act as organizer.
    // parse_event drops the attendee identical to the organizer (attendee),
    // leaving user as the sole attendee → REQUEST lands in user's inbox.
    let ics = format!(
        "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Omnical//Scheduling Tests//EN\r\n\
         BEGIN:VEVENT\r\nUID:sched-no-org-1\r\nDTSTAMP:20260905T120000Z\r\n\
         DTSTART:20260906T100000Z\r\nDTEND:20260906T110000Z\r\nSUMMARY:No organizer test\r\n\
         ATTENDEE:mailto:{ATTENDEE}\r\nATTENDEE:mailto:user\r\n\
         END:VEVENT\r\nEND:VCALENDAR\r\n"
    );

    let response = app
        .clone()
        .oneshot(request(
            "PUT",
            &format!("/caldav/principal/{ATTENDEE}/default/sched-no-org-1.ics"),
            ATTENDEE,
            Body::from(ics),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    // The acting user is the organizer; user is the attendee →
    // the REQUEST lands in user's inbox.
    let body = propfind_inbox(&app, "user").await;
    assert!(body.contains("req-sched-no-org-1.ics"), "{body}");
}

async fn propfind_inbox(app: &axum::Router, user: &str) -> String {
    let mut request = request(
        "PROPFIND",
        &format!("/caldav/principal/{user}/inbox"),
        user,
        Body::empty(),
    );
    request
        .headers_mut()
        .insert("Depth", HeaderValue::from_static("1"));
    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::MULTI_STATUS);
    extract_string(response).await
}

#[tokio::test]
async fn test_options_advertises_scheduling() {
    let app = scheduling_app().await;

    for uri in ["/caldav/principal/user", "/caldav/principal/user/personal"] {
        let response = app
            .clone()
            .oneshot(request("OPTIONS", uri, "user", Body::empty()))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let dav = response.headers()["DAV"].to_str().unwrap();
        assert!(dav.contains(DAV_TOKENS), "missing tokens in: {dav}");
    }
}

#[tokio::test]
async fn test_propfind_principal_scheduling_props() {
    let app = scheduling_app().await;

    let propfind = r#"<?xml version="1.0" encoding="UTF-8"?>
<propfind xmlns="DAV:" xmlns:caldav="urn:ietf:params:xml:ns:caldav">
    <prop>
        <caldav:schedule-inbox-URL/>
        <caldav:schedule-outbox-URL/>
        <caldav:schedule-default-calendar-URL/>
    </prop>
</propfind>"#;

    let response = app
        .oneshot(request(
            "PROPFIND",
            "/caldav/principal/user",
            "user",
            Body::from(propfind),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::MULTI_STATUS);
    let body = extract_string(response).await;
    assert!(body.contains("schedule-inbox-URL"), "{body}");
    assert!(body.contains("/caldav/principal/user/inbox/"), "{body}");
    assert!(body.contains("schedule-outbox-URL"), "{body}");
    assert!(body.contains("/caldav/principal/user/outbox/"), "{body}");
    assert!(body.contains("schedule-default-calendar-URL"), "{body}");
    assert!(body.contains("/caldav/principal/user/personal/"), "{body}");
}

#[tokio::test]
async fn test_put_delivers_request_to_attendee_inbox() {
    let app = scheduling_app().await;

    let response = app
        .clone()
        .oneshot(request(
            "PUT",
            "/caldav/principal/user/personal/sched-req-1.ics",
            "user",
            Body::from(event_ics("sched-req-1", "Scheduling test")),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    // The REQUEST shows up in the attendee's inbox
    let body = propfind_inbox(&app, ATTENDEE).await;
    assert!(body.contains("req-sched-req-1.ics"), "{body}");

    // GET returns the iTIP message with an ETag
    let response = app
        .clone()
        .oneshot(request(
            "GET",
            &format!("/caldav/principal/{ATTENDEE}/inbox/req-sched-req-1.ics"),
            ATTENDEE,
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers().contains_key("ETag"));
    let body = extract_string(response).await;
    assert!(body.contains("METHOD:REQUEST"), "{body}");
    assert!(body.contains("SUMMARY:Scheduling test"), "{body}");

    // DELETE removes the inbox object again
    let response = app
        .clone()
        .oneshot(request(
            "DELETE",
            &format!("/caldav/principal/{ATTENDEE}/inbox/req-sched-req-1.ics"),
            ATTENDEE,
            Body::empty(),
        ))
        .await
        .unwrap();
    assert!(response.status().is_success());

    let body = propfind_inbox(&app, ATTENDEE).await;
    assert!(!body.contains("req-sched-req-1.ics"), "{body}");
}

#[tokio::test]
async fn test_delete_delivers_cancel_to_attendee_inbox() {
    let app = scheduling_app().await;

    let response = app
        .clone()
        .oneshot(request(
            "PUT",
            "/caldav/principal/user/personal/sched-del-1.ics",
            "user",
            Body::from(event_ics("sched-del-1", "Cancel me")),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    let response = app
        .clone()
        .oneshot(request(
            "DELETE",
            "/caldav/principal/user/personal/sched-del-1.ics",
            "user",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert!(response.status().is_success());

    let body = propfind_inbox(&app, ATTENDEE).await;
    assert!(body.contains("cancel-sched-del-1.ics"), "{body}");

    // The CANCEL iTIP message is retrievable
    let response = app
        .clone()
        .oneshot(request(
            "GET",
            &format!("/caldav/principal/{ATTENDEE}/inbox/cancel-sched-del-1.ics"),
            ATTENDEE,
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = extract_string(response).await;
    assert!(body.contains("METHOD:CANCEL"), "{body}");
}

/// vdirsyncer UA no longer excluded — scheduling triggers
/// on PUT through a sync client (UA exclusion was removed).
#[tokio::test]
async fn test_sync_client_user_agent_triggers_scheduling() {
    let app = scheduling_app().await;

    let mut request = request(
        "PUT",
        "/caldav/principal/user/personal/sched-ua-1.ics",
        "user",
        Body::from(event_ics("sched-ua-1", "Mirrored by a sync client")),
    );
    request.headers_mut().insert(
        "User-Agent",
        HeaderValue::from_static("vdirsyncer/0.20.7 (Linux) requests/2"),
    );
    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    // The REQUEST landed in the attendee's inbox (UA exclusion removed)
    let body = propfind_inbox(&app, ATTENDEE).await;
    assert!(body.contains("req-sched-ua-1.ics"), "{body}");
}

#[tokio::test]
async fn test_outbox_post_returns_schedule_response() {
    let app = scheduling_app().await;

    let mut ics = event_ics("sched-outbox-1", "Outbox test");
    // Outbox messages are iTIP messages: they carry a METHOD
    ics.insert_str(ics.find("BEGIN:VEVENT").unwrap(), "METHOD:REQUEST\r\n");

    let response = app
        .clone()
        .oneshot(request(
            "POST",
            "/caldav/principal/user/outbox",
            "user",
            Body::from(ics),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = extract_string(response).await;
    assert!(body.contains("schedule-response"), "{body}");
    assert!(body.contains(&format!("mailto:{ATTENDEE}")), "{body}");
    assert!(body.contains("2.0;Success"), "{body}");

    // The explicit REQUEST was delivered to the internal attendee's inbox
    let body = propfind_inbox(&app, ATTENDEE).await;
    assert!(body.contains("req-sched-outbox-1.ics"), "{body}");
}

#[tokio::test]
async fn test_outbox_rejects_non_organizer() {
    let app = scheduling_app().await;

    let mut ics = event_ics("sched-outbox-2", "Not my event");
    ics.insert_str(ics.find("BEGIN:VEVENT").unwrap(), "METHOD:REQUEST\r\n");

    // The attendee posts the organizer's REQUEST: must be rejected
    let response = app
        .clone()
        .oneshot(request(
            "POST",
            &format!("/caldav/principal/{ATTENDEE}/outbox"),
            ATTENDEE,
            Body::from(ics),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

/// Regression test for the production iPhone failure (2026-09-06): iOS
/// writes the account owner's ORGANIZER (and self-ATTENDEE) as the CalDAV
/// principal URL — RustiCal's advertised calendar-user-address — not as
/// `mailto:`. The scheduler must still recognize the organizer and deliver.
#[tokio::test]
async fn test_principal_url_organizer_delivers_request() {
    let app = scheduling_app().await;

    let ics = format!(
        "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Apple Inc.//iPhone OS 16.7.16//EN\r\n\
         BEGIN:VEVENT\r\nUID:sched-ios-1\r\nDTSTAMP:20260906T010526Z\r\n\
         DTSTART:20260905T211500Z\r\nDTEND:20260905T221500Z\r\nSUMMARY:iOS test\r\n\
         ORGANIZER;CN=user:/caldav/principal/user/\r\n\
         ATTENDEE;CN=user;PARTSTAT=ACCEPTED:/caldav/principal/user/\r\n\
         ATTENDEE;CN=Bob;CUTYPE=INDIVIDUAL;PARTSTAT=NEEDS-ACTION:mailto:{ATTENDEE}\r\n\
         END:VEVENT\r\nEND:VCALENDAR\r\n"
    );

    let response = app
        .clone()
        .oneshot(request(
            "PUT",
            "/caldav/principal/user/personal/sched-ios-1.ics",
            "user",
            Body::from(ics),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    // The REQUEST reached the internal attendee's inbox
    let body = propfind_inbox(&app, ATTENDEE).await;
    assert!(body.contains("req-sched-ios-1.ics"), "{body}");

    // The stored copy carries the organizer (and the self-attendee,
    // recognized as the organizer duplicate) in mailto: form
    let response = app
        .clone()
        .oneshot(request(
            "GET",
            &format!("/caldav/principal/{ATTENDEE}/inbox/req-sched-ios-1.ics"),
            ATTENDEE,
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = extract_string(response).await;
    assert!(body.contains("METHOD:REQUEST"), "{body}");
    assert!(body.contains("ORGANIZER;CN=user:mailto:user"), "{body}");
    assert!(body.contains("mailto:user\r\n"), "{body}");
    assert!(body.contains(&format!("mailto:{ATTENDEE}")), "{body}");
}

// ---------------------------------------------------------------------------
// Inbound iMIP ingestion (IMAP poll leg → Scheduler::ingest_imip_reply)
// ---------------------------------------------------------------------------

/// PUT through the real CalDAV router with a sync-client (`vdirsyncer`) UA:
/// the organizer copy is stored through the normal path, but the UA
/// exclusion skips implicit scheduling (nothing is delivered).
async fn put_as_sync_client(app: &axum::Router, uri: &str, ics: String) -> StatusCode {
    let mut request = request("PUT", uri, "user", Body::from(ics));
    request.headers_mut().insert(
        "User-Agent",
        HeaderValue::from_static("vdirsyncer/0.20.7 (Linux) requests/2"),
    );
    let response = app.clone().oneshot(request).await.unwrap();
    response.status()
}

/// GET a calendar/inbox object body through the router.
async fn get_object(app: &axum::Router, uri: &str, user: &str) -> String {
    let response = app
        .clone()
        .oneshot(request("GET", uri, user, Body::empty()))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    extract_string(response).await
}

/// An inbound iMIP REPLY as the IMAP poller extracts it from an email.
fn imip_reply_ics(uid: &str, organizer: &str, attendee: &str, partstat: &str) -> String {
    format!(
        "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Omnical//Scheduling Tests//EN\r\n\
         METHOD:REPLY\r\nBEGIN:VEVENT\r\nUID:{uid}\r\nDTSTAMP:20260908T120000Z\r\n\
         ORGANIZER:mailto:{organizer}\r\nATTENDEE;PARTSTAT={partstat}:mailto:{attendee}\r\n\
         END:VEVENT\r\nEND:VCALENDAR\r\n"
    )
}

/// An inbound iMIP REQUEST: an invitation addressed *to* the mailbox.
fn imip_request_ics(uid: &str, organizer: &str, attendee: &str) -> String {
    format!(
        "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Omnical//Scheduling Tests//EN\r\n\
         METHOD:REQUEST\r\nBEGIN:VEVENT\r\nUID:{uid}\r\nDTSTAMP:20260908T120000Z\r\n\
         DTSTART:20260910T100000Z\r\nDTEND:20260910T110000Z\r\nSUMMARY:Invitation\r\n\
         ORGANIZER:mailto:{organizer}\r\nATTENDEE;PARTSTAT=NEEDS-ACTION:mailto:{attendee}\r\n\
         END:VEVENT\r\nEND:VCALENDAR\r\n"
    )
}

/// The missing inbound leg of email scheduling: an attendee answers by
/// email; the IMAP poller feeds the REPLY to `ingest_imip_reply`, which
/// must update the organizer's stored copy and file the REPLY into the
/// organizer's scheduling inbox.
#[tokio::test]
async fn test_ingest_imip_reply_updates_organizer_copy_and_inbox() {
    let (app, scheduler) = scheduling_app_with_scheduler().await;

    // The organizer's copy of the event, stored via the real PUT path
    let status = put_as_sync_client(
        &app,
        "/caldav/principal/user/personal/sched-ingest-1.ics",
        event_ics("sched-ingest-1", "Ingest test"),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    let reply = imip_reply_ics("sched-ingest-1", "user", ATTENDEE, "ACCEPTED");
    let applied = scheduler
        .ingest_imip_reply("user", &reply, Some(ATTENDEE))
        .await
        .unwrap();
    assert_eq!(applied, Some((ATTENDEE.to_owned(), "ACCEPTED".to_owned())));

    // The organizer's stored copy carries the new PARTSTAT — and is still
    // the full event, not the minimal iTIP REPLY
    let body = get_object(
        &app,
        "/caldav/principal/user/personal/sched-ingest-1.ics",
        "user",
    )
    .await;
    assert!(
        body.contains(&format!("ATTENDEE;PARTSTAT=ACCEPTED:mailto:{ATTENDEE}")),
        "{body}"
    );
    assert!(body.contains("Ingest test"), "{body}");
    assert!(!body.contains("METHOD:REPLY"), "{body}");

    // The REPLY was filed into the organizer's inbox (the `@` of the
    // attendee address is percent-encoded in PROPFIND hrefs)
    let body = propfind_inbox(&app, "user").await;
    assert!(
        body.contains("reply-sched-ingest-1-attendee%40example.com.ics"),
        "{body}"
    );

    // ...and is retrievable as an iTIP REPLY
    let body = get_object(
        &app,
        "/caldav/principal/user/inbox/reply-sched-ingest-1-attendee@example.com.ics",
        "user",
    )
    .await;
    assert!(body.contains("METHOD:REPLY"), "{body}");
    assert!(body.contains("UID:sched-ingest-1"), "{body}");
    assert!(body.contains("PARTSTAT=ACCEPTED"), "{body}");
}

/// A REPLY for an event organized by somebody else must never be applied
/// to the polled mailbox's own copies — even when the UID collides with
/// one of the user's events.
#[tokio::test]
async fn test_ingest_imip_reply_ignores_foreign_organizer() {
    let (app, scheduler) = scheduling_app_with_scheduler().await;

    let status = put_as_sync_client(
        &app,
        "/caldav/principal/user/personal/sched-ingest-2.ics",
        event_ics("sched-ingest-2", "Foreign organizer"),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let stored_before = get_object(
        &app,
        "/caldav/principal/user/personal/sched-ingest-2.ics",
        "user",
    )
    .await;

    let reply = imip_reply_ics("sched-ingest-2", "other@example.net", ATTENDEE, "ACCEPTED");
    let result = scheduler
        .ingest_imip_reply("user", &reply, Some(ATTENDEE))
        .await;
    assert_eq!(result, Ok(None));

    // The stored copy is byte-for-byte unchanged and the inbox stays empty
    let body = get_object(
        &app,
        "/caldav/principal/user/personal/sched-ingest-2.ics",
        "user",
    )
    .await;
    assert_eq!(body, stored_before);
    let body = propfind_inbox(&app, "user").await;
    assert!(!body.contains("reply-"), "{body}");
}

/// An invite (METHOD:REQUEST) in the mailbox is addressed *to* the user —
/// mail for their client, not a reply to apply.
#[tokio::test]
async fn test_ingest_imip_reply_ignores_request_method() {
    let (app, scheduler) = scheduling_app_with_scheduler().await;

    let invite = imip_request_ics("sched-ingest-3", "organizer@example.net", "user");
    let result = scheduler
        .ingest_imip_reply("user", &invite, Some("organizer@example.net"))
        .await;
    assert_eq!(result, Ok(None));

    // Nothing was filed into the user's inbox
    let body = propfind_inbox(&app, "user").await;
    assert!(!body.contains("sched-ingest-3"), "{body}");
}

/// A mailbox identity that is not a local principal must be ignored:
/// applying the REPLY would email the very mailbox being polled (mail
/// loop). Without the guard this would return an error (no SMTP account
/// for the attendee) or re-send the reply — never a clean `Ok(None)`.
#[tokio::test]
async fn test_ingest_imip_reply_ignores_unknown_mailbox_identity() {
    let (app, scheduler) = scheduling_app_with_scheduler().await;

    let reply = imip_reply_ics("sched-ingest-4", "ghost@example.com", ATTENDEE, "ACCEPTED");
    let result = scheduler
        .ingest_imip_reply("ghost@example.com", &reply, Some(ATTENDEE))
        .await;
    assert_eq!(result, Ok(None));

    // No side effects: nothing was filed for the UID anywhere
    let body = propfind_inbox(&app, "user").await;
    assert!(!body.contains("sched-ingest-4"), "{body}");
}

// ---------------------------------------------------------------------------
// One-click RSVP links (invitation emails → Scheduler::rsvp_page_data / rsvp_apply)
// ---------------------------------------------------------------------------

/// Mint the RSVP link token an invitation email would carry for
/// `attendee`'s response to the event `uid` organized by `organizer`,
/// signed with the fixture's [`RSVP_SECRET`].
fn rsvp_token(uid: &str, organizer: &str, attendee: &str) -> String {
    rsvp::mint_token(
        RSVP_SECRET,
        uid,
        organizer,
        attendee,
        chrono::Utc::now().timestamp(),
    )
}

/// [`event_ics`](event_ics()) without the ATTENDEE line: the organizer
/// removed the attendee from the stored copy (or never invited them).
fn event_ics_without_attendee(uid: &str, summary: &str) -> String {
    format!(
        "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Omnical//Scheduling Tests//EN\r\n\
         BEGIN:VEVENT\r\nUID:{uid}\r\nDTSTAMP:20260905T120000Z\r\n\
         DTSTART:20260906T100000Z\r\nDTEND:20260906T110000Z\r\nSUMMARY:{summary}\r\n\
         ORGANIZER:mailto:user\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"
    )
}

/// [`event_ics`](event_ics()) with `STATUS:CANCELLED`: the organizer
/// cancelled the event while the token is still valid.
fn cancelled_event_ics(uid: &str, summary: &str) -> String {
    format!(
        "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Omnical//Scheduling Tests//EN\r\n\
         BEGIN:VEVENT\r\nUID:{uid}\r\nDTSTAMP:20260905T120000Z\r\n\
         DTSTART:20260906T100000Z\r\nDTEND:20260906T110000Z\r\nSUMMARY:{summary}\r\n\
         STATUS:CANCELLED\r\nORGANIZER:mailto:user\r\nATTENDEE:mailto:{ATTENDEE}\r\n\
         END:VEVENT\r\nEND:VCALENDAR\r\n"
    )
}

/// The full one-click RSVP flow behind an emailed invitation link: the
/// page resolves the organizer's stored copy and shows the attendee's
/// current PARTSTAT, and applying a response works exactly like an
/// emailed iMIP REPLY — the organizer's stored copy flips and a REPLY is
/// filed into their scheduling inbox (mirror of the ingest test).
#[tokio::test]
async fn test_rsvp_page_data_and_apply_update_organizer_copy_and_inbox() {
    let (app, scheduler) = scheduling_app_with_scheduler().await;
    assert!(scheduler.rsvp_links_enabled());

    // The organizer's copy of the event, stored via the real PUT path
    let status = put_as_sync_client(
        &app,
        "/caldav/principal/user/personal/sched-rsvp-1.ics",
        event_ics("sched-rsvp-1", "RSVP link test"),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    let token = rsvp_token("sched-rsvp-1", "user", ATTENDEE);

    // The response page shows the event, not yet answered
    let page = scheduler.rsvp_page_data(&token).await.unwrap();
    assert_eq!(page.summary, "RSVP link test");
    assert_eq!(page.organizer, "user");
    assert_eq!(page.attendee, ATTENDEE);
    assert_eq!(page.partstat, "NEEDS-ACTION");
    assert!(!page.recurring);

    // Accepting applies the response through the REPLY machinery
    let confirmation = scheduler.rsvp_apply(&token, "accept").await.unwrap();
    assert_eq!(confirmation.partstat, "ACCEPTED");

    // The organizer's stored copy carries the new PARTSTAT — and is
    // still the full event, not the minimal iTIP REPLY
    let body = get_object(
        &app,
        "/caldav/principal/user/personal/sched-rsvp-1.ics",
        "user",
    )
    .await;
    assert!(
        body.contains(&format!("ATTENDEE;PARTSTAT=ACCEPTED:mailto:{ATTENDEE}")),
        "{body}"
    );
    assert!(body.contains("RSVP link test"), "{body}");
    assert!(!body.contains("METHOD:REPLY"), "{body}");

    // The REPLY was filed into the organizer's inbox (the `@` of the
    // attendee address is percent-encoded in PROPFIND hrefs)
    let body = propfind_inbox(&app, "user").await;
    assert!(
        body.contains("reply-sched-rsvp-1-attendee%40example.com.ics"),
        "{body}"
    );

    // ...and is retrievable as an iTIP REPLY
    let body = get_object(
        &app,
        "/caldav/principal/user/inbox/reply-sched-rsvp-1-attendee@example.com.ics",
        "user",
    )
    .await;
    assert!(body.contains("METHOD:REPLY"), "{body}");
    assert!(body.contains("UID:sched-rsvp-1"), "{body}");
    assert!(body.contains("PARTSTAT=ACCEPTED"), "{body}");

    // Changing one's mind through the same link updates the copy again
    // and overwrites the inbox REPLY
    let confirmation = scheduler.rsvp_apply(&token, "maybe").await.unwrap();
    assert_eq!(confirmation.partstat, "TENTATIVE");
    let body = get_object(
        &app,
        "/caldav/principal/user/personal/sched-rsvp-1.ics",
        "user",
    )
    .await;
    assert!(
        body.contains(&format!("ATTENDEE;PARTSTAT=TENTATIVE:mailto:{ATTENDEE}")),
        "{body}"
    );
    let body = get_object(
        &app,
        "/caldav/principal/user/inbox/reply-sched-rsvp-1-attendee@example.com.ics",
        "user",
    )
    .await;
    assert!(body.contains("PARTSTAT=TENTATIVE"), "{body}");
}

/// Unknown shape, expired and wrongly-signed tokens are all
/// indistinguishably `Invalid` (the public route must offer no validity
/// oracle) and have no side effects.
#[tokio::test]
async fn test_rsvp_rejects_garbage_expired_and_forged_tokens() {
    let (app, scheduler) = scheduling_app_with_scheduler().await;

    // Garbage: not even token-shaped
    assert_eq!(
        scheduler.rsvp_page_data("v1.garbage.token").await,
        Err(RsvpError::Invalid)
    );
    assert_eq!(
        scheduler.rsvp_apply("not-even-shaped", "accept").await,
        Err(RsvpError::Invalid)
    );

    // Expired: minted a year + 10 s in the past
    let expired = rsvp::mint_token(
        RSVP_SECRET,
        "sched-rsvp-expired",
        "user",
        ATTENDEE,
        chrono::Utc::now().timestamp() - rsvp::TOKEN_TTL_SECS - 10,
    );
    assert_eq!(
        scheduler.rsvp_page_data(&expired).await,
        Err(RsvpError::Invalid)
    );
    assert_eq!(
        scheduler.rsvp_apply(&expired, "accept").await,
        Err(RsvpError::Invalid)
    );

    // Forged: valid shape, signed with a different secret
    let forged = rsvp::mint_token(
        "attacker-secret",
        "sched-rsvp-forged",
        "user",
        ATTENDEE,
        chrono::Utc::now().timestamp(),
    );
    assert_eq!(
        scheduler.rsvp_apply(&forged, "accept").await,
        Err(RsvpError::Invalid)
    );

    // No side effects: nothing was filed anywhere
    let body = propfind_inbox(&app, "user").await;
    assert!(!body.contains("reply-"), "{body}");
}

/// A valid token for an event the organizer deleted (or never stored)
/// is `Gone`, not `Invalid`: the link is fine, the event is not.
#[tokio::test]
async fn test_rsvp_unknown_uid_is_gone() {
    let (app, scheduler) = scheduling_app_with_scheduler().await;

    let token = rsvp_token("sched-rsvp-missing", "user", ATTENDEE);
    assert_eq!(scheduler.rsvp_page_data(&token).await, Err(RsvpError::Gone));
    assert_eq!(
        scheduler.rsvp_apply(&token, "accept").await,
        Err(RsvpError::Gone)
    );

    let body = propfind_inbox(&app, "user").await;
    assert!(!body.contains("reply-"), "{body}");
}

/// A valid link to a cancelled event must answer `Gone` — the response
/// page must not offer responses to a dead event.
#[tokio::test]
async fn test_rsvp_cancelled_event_is_gone() {
    let (app, scheduler) = scheduling_app_with_scheduler().await;

    let status = put_as_sync_client(
        &app,
        "/caldav/principal/user/personal/sched-rsvp-cancelled.ics",
        cancelled_event_ics("sched-rsvp-cancelled", "Cancelled RSVP test"),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    let token = rsvp_token("sched-rsvp-cancelled", "user", ATTENDEE);
    assert_eq!(scheduler.rsvp_page_data(&token).await, Err(RsvpError::Gone));
    assert_eq!(
        scheduler.rsvp_apply(&token, "accept").await,
        Err(RsvpError::Gone)
    );

    let body = propfind_inbox(&app, "user").await;
    assert!(!body.contains("reply-"), "{body}");
}

/// A valid token whose attendee is no longer on the stored copy is
/// `Gone`: the invitation was revoked.
#[tokio::test]
async fn test_rsvp_uninvited_attendee_is_gone() {
    let (app, scheduler) = scheduling_app_with_scheduler().await;

    let status = put_as_sync_client(
        &app,
        "/caldav/principal/user/personal/sched-rsvp-uninvited.ics",
        event_ics_without_attendee("sched-rsvp-uninvited", "No attendees"),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    let token = rsvp_token("sched-rsvp-uninvited", "user", ATTENDEE);
    assert_eq!(scheduler.rsvp_page_data(&token).await, Err(RsvpError::Gone));
    assert_eq!(
        scheduler.rsvp_apply(&token, "accept").await,
        Err(RsvpError::Gone)
    );

    let body = propfind_inbox(&app, "user").await;
    assert!(!body.contains("reply-"), "{body}");
}

/// Unknown response words are `BadResponse` — checked before the token
/// (the route's 400-beats-404 semantics), so even a garbage token with
/// a bogus word answers `BadResponse`, and nothing is ever applied.
#[tokio::test]
async fn test_rsvp_unknown_response_word_is_bad_response() {
    let (app, scheduler) = scheduling_app_with_scheduler().await;

    let status = put_as_sync_client(
        &app,
        "/caldav/principal/user/personal/sched-rsvp-bogus.ics",
        event_ics("sched-rsvp-bogus", "Bogus word test"),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    // Valid token, unknown response word
    let token = rsvp_token("sched-rsvp-bogus", "user", ATTENDEE);
    assert_eq!(
        scheduler.rsvp_apply(&token, "bogus").await,
        Err(RsvpError::BadResponse)
    );

    // The word check precedes the token check
    assert_eq!(
        scheduler.rsvp_apply("v1.garbage.token", "bogus").await,
        Err(RsvpError::BadResponse)
    );

    // The stored copy and the organizer's inbox are untouched
    let body = get_object(
        &app,
        "/caldav/principal/user/personal/sched-rsvp-bogus.ics",
        "user",
    )
    .await;
    assert!(
        body.contains(&format!("ATTENDEE:mailto:{ATTENDEE}")),
        "{body}"
    );
    assert!(!body.contains("PARTSTAT=ACCEPTED"), "{body}");
    let body = propfind_inbox(&app, "user").await;
    assert!(!body.contains("reply-"), "{body}");
}

/// A token naming an organizer this server does not serve must look
/// exactly like a bogus link (`Invalid`, mirroring the iMIP ingest
/// mail-loop guard) — and never touch any stored copy.
#[tokio::test]
async fn test_rsvp_foreign_organizer_is_invalid() {
    let (app, scheduler) = scheduling_app_with_scheduler().await;

    let token = rsvp_token("sched-rsvp-foreign", "stranger@example.net", ATTENDEE);
    assert_eq!(
        scheduler.rsvp_page_data(&token).await,
        Err(RsvpError::Invalid)
    );
    assert_eq!(
        scheduler.rsvp_apply(&token, "accept").await,
        Err(RsvpError::Invalid)
    );

    let body = propfind_inbox(&app, "user").await;
    assert!(!body.contains("reply-"), "{body}");
}
