// Route-level tests for the Omnical subscription export feeds (PLAN.md
// §17.7): byte-parity against the *real* owner exports, and the 404 matrix.
//
// The unauthenticated token URL must serve the exact bytes of the
// owner-authenticated `route_get` export, for `.ics` (CalDAV) and `.vcf`
// (CardDAV) alike. The 404 tests cover every failure the design lists —
// unknown token, missing/unknown extension, kind/extension mismatch,
// revoked subscription and vanished (deleted) collection — and prove the
// different cases are indistinguishable from the outside.
use axum::body::Body;
use axum::response::Response;
use headers::{Authorization, HeaderMapExt};
use http::{Request, StatusCode, header::CONTENT_TYPE};
use rustical::export::export_router;
use rustical_caldav::{CalDavConfig, caldav_router};
use rustical_carddav::carddav_router;
use rustical_ical::CalendarObjectType;
use rustical_store::{
    Addressbook, AddressbookWriteStore, Calendar, CalendarMetadata, CalendarWriteStore,
    SubscriptionKind, SubscriptionStore,
};
use rustical_store_sqlite::SqliteSubscriptionStore;
use rustical_store_sqlite::tests::test_store_context;
use std::sync::Arc;
use tower::ServiceExt;

// 64-char alphanumeric, the `generate_app_token` shape (§17.7 design)
const CAL_TOKEN: &str = "CalendarExportToken00000000000000000000000000000000000000000000000";
const ADDR_TOKEN: &str = "AddressbookExportToken00000000000000000000000000000000000000000000";

const EVENT_ICS: &str = concat!(
    "BEGIN:VCALENDAR\r\n",
    "VERSION:2.0\r\n",
    "PRODID:-//Omnical//Export Tests//EN\r\n",
    "BEGIN:VEVENT\r\n",
    "UID:export-test-1\r\n",
    "DTSTAMP:20260906T120000Z\r\n",
    "DTSTART:20260907T100000Z\r\n",
    "DTEND:20260907T110000Z\r\n",
    "SUMMARY:Export parity event\r\n",
    "END:VEVENT\r\n",
    "END:VCALENDAR\r\n",
);
const CARD_VCF: &str = concat!(
    "BEGIN:VCARD\r\n",
    "VERSION:4.0\r\n",
    "FN:Jane Doe\r\n",
    "N:Doe;Jane;;;\r\n",
    "UID:export-test-card-1\r\n",
    "END:VCARD\r\n",
);

struct TestApp {
    export: axum::Router,
    caldav: axum::Router,
    carddav: axum::Router,
    context: rustical_store_sqlite::tests::TestStoreContext,
    sub_store: SqliteSubscriptionStore,
    cal_sub_id: String,
    addr_sub_id: String,
}

/// Export router + owner-authenticated CalDAV/CardDAV routers over one
/// scratch SQLite database (`user` principal + app token come from the
/// store fixture), with one calendar and one addressbook subscription.
async fn test_app() -> TestApp {
    let context = test_store_context().await;

    // A calendar with all metadata props set (exercises every X-WR-* line)
    context
        .cal_store
        .insert_calendar(Calendar {
            id: "personal".to_owned(),
            principal: "user".to_owned(),
            meta: CalendarMetadata {
                displayname: Some("Personal".to_owned()),
                order: 0,
                description: Some("Export parity calendar".to_owned()),
                color: Some("#3a87ad".to_owned()),
            },
            timezone_id: Some("America/New_York".to_owned()),
            deleted_at: None,
            synctoken: 0,
            subscription_url: None,
            push_topic: "personal-push-topic".to_owned(),
            components: vec![CalendarObjectType::Event],
        })
        .await
        .unwrap();

    context
        .addr_store
        .insert_addressbook(Addressbook {
            id: "contacts".to_owned(),
            principal: "user".to_owned(),
            displayname: Some("Contacts".to_owned()),
            description: None,
            deleted_at: None,
            synctoken: 0,
            push_topic: "contacts-push-topic".to_owned(),
        })
        .await
        .unwrap();

    let sub_store = SqliteSubscriptionStore::new(context.cal_store.clone());
    let cal_sub_id = sub_store
        .add_subscription("user", SubscriptionKind::Calendar, "personal", CAL_TOKEN)
        .await
        .unwrap();
    let addr_sub_id = sub_store
        .add_subscription(
            "user",
            SubscriptionKind::Addressbook,
            "contacts",
            ADDR_TOKEN,
        )
        .await
        .unwrap();

    let export = export_router(
        Arc::new(context.addr_store.clone()),
        Arc::new(context.cal_store.clone()),
        Arc::new(sub_store.clone()),
    );
    let caldav = caldav_router(
        "/caldav",
        Arc::new(context.principal_store.clone()),
        Arc::new(context.cal_store.clone()),
        Arc::new(context.dav_push_store.clone()),
        false,
        Arc::new(CalDavConfig::default()),
        None,
    );
    let carddav = carddav_router(
        "/carddav",
        Arc::new(context.principal_store.clone()),
        Arc::new(context.addr_store.clone()),
        Arc::new(context.dav_push_store.clone()),
    );

    TestApp {
        export,
        caldav,
        carddav,
        context,
        sub_store,
        cal_sub_id,
        addr_sub_id,
    }
}

/// Seed one event + one vCard through the real DAV PUT paths.
async fn seed_objects(app: &TestApp) {
    let response = app
        .caldav
        .clone()
        .oneshot(authed_request(
            "PUT",
            "/caldav/principal/user/personal/export-test-1.ics",
            Body::from(EVENT_ICS),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    let response = app
        .carddav
        .clone()
        .oneshot(authed_request(
            "PUT",
            "/carddav/principal/user/contacts/export-test-card-1.vcf",
            Body::from(CARD_VCF),
        ))
        .await
        .unwrap();
    assert!(response.status().is_success());
}

/// An unauthenticated request — the export routes must never need credentials.
fn request(method: &str, uri: &str, body: Body) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .body(body)
        .unwrap()
}

/// An owner-authenticated request (basic auth against the fixture principal).
fn authed_request(method: &str, uri: &str, body: Body) -> Request<Body> {
    let mut request = request(method, uri, body);
    request
        .headers_mut()
        .typed_insert(Authorization::basic("user", "pass"));
    request
}

async fn body_string(response: Response) -> String {
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    String::from_utf8(bytes.to_vec()).unwrap()
}

#[tokio::test]
async fn test_export_ics_matches_owner_export() {
    let app = test_app().await;
    seed_objects(&app).await;

    let owner = app
        .caldav
        .clone()
        .oneshot(authed_request(
            "GET",
            "/caldav/principal/user/personal",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(owner.status(), StatusCode::OK);

    let feed = app
        .export
        .clone()
        .oneshot(request(
            "GET",
            &format!("/export/{CAL_TOKEN}.ics"),
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(feed.status(), StatusCode::OK);

    // Byte-parity of body and content type; no ETag (polling is client-driven)
    assert_eq!(
        owner.headers().get(CONTENT_TYPE),
        feed.headers().get(CONTENT_TYPE)
    );
    assert!(!feed.headers().contains_key("ETag"));
    assert_eq!(body_string(feed).await, body_string(owner).await);
}

#[tokio::test]
async fn test_export_vcf_matches_owner_export() {
    let app = test_app().await;
    seed_objects(&app).await;

    let owner = app
        .carddav
        .clone()
        .oneshot(authed_request(
            "GET",
            "/carddav/principal/user/contacts",
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(owner.status(), StatusCode::OK);

    let feed = app
        .export
        .clone()
        .oneshot(request(
            "GET",
            &format!("/export/{ADDR_TOKEN}.vcf"),
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(feed.status(), StatusCode::OK);

    assert_eq!(
        owner.headers().get(CONTENT_TYPE),
        feed.headers().get(CONTENT_TYPE)
    );
    assert!(!feed.headers().contains_key("ETag"));
    assert_eq!(body_string(feed).await, body_string(owner).await);
}

#[tokio::test]
async fn test_head_serves_headers_only() {
    let app = test_app().await;
    seed_objects(&app).await;

    for uri in [
        format!("/export/{CAL_TOKEN}.ics"),
        format!("/export/{ADDR_TOKEN}.vcf"),
    ] {
        let response = app
            .export
            .clone()
            .oneshot(request("HEAD", &uri, Body::empty()))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "uri: {uri}");
        assert!(response.headers().contains_key(CONTENT_TYPE), "uri: {uri}");
        assert!(body_string(response).await.is_empty(), "uri: {uri}");
    }
}

#[tokio::test]
async fn test_404_matrix_is_indistinguishable() {
    let app = test_app().await;
    seed_objects(&app).await;

    // Unknown token, missing extension, unknown extension and both
    // kind/extension mismatches
    let uris = [
        "/export/SomeUnknownTokenThatExistsNowhere0000000000000000000000000.ics".to_owned(),
        format!("/export/{CAL_TOKEN}"),
        format!("/export/{CAL_TOKEN}.txt"),
        format!("/export/{CAL_TOKEN}.vcf"),
        format!("/export/{ADDR_TOKEN}.ics"),
    ];

    let mut bodies = vec![];
    for uri in &uris {
        let response = app
            .export
            .clone()
            .oneshot(request("GET", uri, Body::empty()))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "uri: {uri}");
        assert!(!response.headers().contains_key("ETag"), "uri: {uri}");
        bodies.push(body_string(response).await);
    }

    // No token-validity oracle: every failure renders the same body
    for body in &bodies[1..] {
        assert_eq!(body, &bodies[0]);
    }
}

#[tokio::test]
async fn test_revoked_subscription_is_gone() {
    let app = test_app().await;
    seed_objects(&app).await;

    app.sub_store
        .delete_subscription("user", &app.cal_sub_id)
        .await
        .unwrap();
    app.sub_store
        .delete_subscription("user", &app.addr_sub_id)
        .await
        .unwrap();

    for uri in [
        format!("/export/{CAL_TOKEN}.ics"),
        format!("/export/{ADDR_TOKEN}.vcf"),
    ] {
        let response = app
            .export
            .clone()
            .oneshot(request("GET", &uri, Body::empty()))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "uri: {uri}");
    }
}

#[tokio::test]
async fn test_vanished_collections_are_404() {
    let app = test_app().await;
    seed_objects(&app).await;

    // Soft-deleted (trashed) collections vanish from the feeds as well
    app.context
        .cal_store
        .delete_calendar("user", "personal", true)
        .await
        .unwrap();
    let response = app
        .export
        .clone()
        .oneshot(request(
            "GET",
            &format!("/export/{CAL_TOKEN}.ics"),
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    app.context
        .addr_store
        .delete_addressbook("user", "contacts", true)
        .await
        .unwrap();
    let response = app
        .export
        .clone()
        .oneshot(request(
            "GET",
            &format!("/export/{ADDR_TOKEN}.vcf"),
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}
