use super::{
    ResponseExtractString,
    calendar::{mkcalendar_template, mkcalendar_template_with_components},
    get_app,
};
use axum::body::Body;
use headers::{Authorization, HeaderMapExt};
use http::{Request, StatusCode};
use rstest::rstest;
use rustical_store::CalendarMetadata;
use rustical_store_sqlite::tests::{TestStoreContext, test_store_context};
use tower::ServiceExt;

#[rstest]
#[tokio::test]
async fn test_put_invalid(
    #[from(test_store_context)]
    #[future]
    context: TestStoreContext,
) {
    let context = context.await;
    let app = get_app(context.clone());

    let calendar_meta = CalendarMetadata {
        displayname: Some("Calendar".to_string()),
        description: Some("Description".to_string()),
        color: Some("#00FF00".to_string()),
        order: 0,
    };
    let (principal, cal_id) = ("user", "calendar");
    let url = format!("/caldav/principal/{principal}/{cal_id}");

    let mut request = Request::builder()
        .method("MKCALENDAR")
        .uri(&url)
        .body(Body::from(mkcalendar_template(&calendar_meta)))
        .unwrap();
    request
        .headers_mut()
        .typed_insert(Authorization::basic("user", "pass"));
    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    // Invalid calendar data
    let ical = r"BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Example Corp.//CalDAV Client//EN
BEGIN:VEVENT
UID:20010712T182145Z-123401@example.com
DTSTAMP:20060712T182145Z
DTSTART:20060714T170000Z
RRULE:UNTIL=123
DTEND:20060715T040000Z
SUMMARY:Bastille Day Party
END:VEVENT
END:VCALENDAR";

    let mut request = Request::builder()
        .method("PUT")
        .uri(format!("{url}/qwue23489.ics"))
        .header("If-None-Match", "*")
        .header("Content-Type", "text/calendar")
        .body(Body::from(ical))
        .unwrap();
    request
        .headers_mut()
        .typed_insert(Authorization::basic("user", "pass"));

    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = response.extract_string().await;
    insta::assert_snapshot!(body, @r#"
    <?xml version="1.0" encoding="utf-8"?>
    <error xmlns="DAV:">
        <valid-calendar-data xmlns="urn:ietf:params:xml:ns:caldav"/>
    </error>
    "#);
}

/// Thunderbird creates VTIMEZONE objects with invalid RRULEs.
/// While invalid, we still want to accept them since Thunderbird is quite commonly used.
/// In the future, we might fix invalid timezones ourself.
#[rstest]
#[tokio::test]
async fn test_put_thunderbird(
    #[from(test_store_context)]
    #[future]
    context: TestStoreContext,
) {
    let context = context.await;
    let app = get_app(context.clone());

    let calendar_meta = CalendarMetadata {
        displayname: Some("Calendar".to_string()),
        description: Some("Description".to_string()),
        color: Some("#00FF00".to_string()),
        order: 0,
    };
    let (principal, cal_id) = ("user", "calendar");
    let url = format!("/caldav/principal/{principal}/{cal_id}");

    let mut request = Request::builder()
        .method("MKCALENDAR")
        .uri(&url)
        .body(Body::from(mkcalendar_template(&calendar_meta)))
        .unwrap();
    request
        .headers_mut()
        .typed_insert(Authorization::basic("user", "pass"));
    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    let ical = include_str!("resources/ical_thunderbird.ics");

    let mut request = Request::builder()
        .method("PUT")
        .uri(format!("{url}/ical_thunderbird.ics"))
        .header("If-None-Match", "*")
        .header("Content-Type", "text/calendar")
        .body(Body::from(ical))
        .unwrap();
    request
        .headers_mut()
        .typed_insert(Authorization::basic("user", "pass"));

    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    {
        let mut request = Request::builder()
            .method("GET")
            .uri(format!("{url}/ical_thunderbird.ics"))
            .body(Body::empty())
            .unwrap();
        request
            .headers_mut()
            .typed_insert(Authorization::basic("user", "pass"));
        let response = app.clone().oneshot(request).await.unwrap();
        let body = response.extract_string().await;
        similar_asserts::assert_eq!(body.replace("\r", ""), ical);
    }

    {
        let mut request = Request::builder()
            .method("PROPFIND")
            .uri(format!("{url}/ical_thunderbird.ics"))
            .body(Body::empty())
            .unwrap();
        request
            .headers_mut()
            .typed_insert(Authorization::basic("user", "pass"));

        let response = app.clone().oneshot(request).await.unwrap();
        let body = response.extract_string().await;
        insta::assert_snapshot!("propfind_response", body);
    }
}

#[rstest]
#[tokio::test]
#[case("nice%20calendar", "nice%20event.ics")]
#[case("nic€ calendar", "nice,evänt.ics")]
async fn test_put_special_characters(
    #[from(test_store_context)]
    #[future]
    context: TestStoreContext,
    #[case] cal_id: &str,
    #[case] filename: &str,
) {
    let context = context.await;
    let app = get_app(context.clone());

    let calendar_meta = CalendarMetadata {
        displayname: Some("Calendar".to_string()),
        description: Some("Description".to_string()),
        color: Some("#00FF00".to_string()),
        order: 0,
    };
    let principal = "user";
    let url = format!("/caldav/principal/{principal}/{cal_id}");

    let mut request = Request::builder()
        .method("MKCALENDAR")
        .uri(&url)
        .body(Body::from(mkcalendar_template(&calendar_meta)))
        .unwrap();
    request
        .headers_mut()
        .typed_insert(Authorization::basic("user", "pass"));
    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    let ical = include_str!("resources/ical_thunderbird.ics");

    let mut request = Request::builder()
        .method("PUT")
        .uri(format!("{url}/{filename}"))
        .header("If-None-Match", "*")
        .header("Content-Type", "text/calendar")
        .body(Body::from(ical))
        .unwrap();
    request
        .headers_mut()
        .typed_insert(Authorization::basic("user", "pass"));

    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    {
        let mut request = Request::builder()
            .method("GET")
            .uri(format!("{url}/{filename}"))
            .body(Body::empty())
            .unwrap();
        request
            .headers_mut()
            .typed_insert(Authorization::basic("user", "pass"));
        let response = app.clone().oneshot(request).await.unwrap();
        let body = response.extract_string().await;
        similar_asserts::assert_eq!(body.replace("\r", ""), ical);
    }
}

/// Create a calendar via MKCALENDAR with an explicit component set.
async fn mkcalendar_with_components(
    app: &axum::Router,
    url: &str,
    meta: &CalendarMetadata,
    components: &[&str],
) {
    let mut request = Request::builder()
        .method("MKCALENDAR")
        .uri(url)
        .body(Body::from(mkcalendar_template_with_components(
            meta, components,
        )))
        .unwrap();
    request
        .headers_mut()
        .typed_insert(Authorization::basic("user", "pass"));
    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
}

/// PUT an ics file at `{url}/{object_id}.ics` and return the response.
async fn put_ics(
    app: &axum::Router,
    url: &str,
    object_id: &str,
    ical: &str,
) -> axum::response::Response {
    let mut request = Request::builder()
        .method("PUT")
        .uri(format!("{url}/{object_id}.ics"))
        .header("If-None-Match", "*")
        .header("Content-Type", "text/calendar")
        .body(Body::from(ical.to_owned()))
        .unwrap();
    request
        .headers_mut()
        .typed_insert(Authorization::basic("user", "pass"));
    app.clone().oneshot(request).await.unwrap()
}

/// RFC 4791 §5.3.2: a VJOURNAL PUT into an event-only calendar is rejected
/// with 403 and a `CALDAV:supported-calendar-component-set` precondition
/// naming the types the calendar does accept.
#[rstest]
#[tokio::test]
async fn test_put_component_not_supported(
    #[from(test_store_context)]
    #[future]
    context: TestStoreContext,
) {
    let context = context.await;
    let app = get_app(context.clone());

    let calendar_meta = CalendarMetadata {
        displayname: Some("Calendar".to_string()),
        description: Some("Description".to_string()),
        color: Some("#00FF00".to_string()),
        order: 0,
    };
    let url = "/caldav/principal/user/calendar";
    mkcalendar_with_components(&app, url, &calendar_meta, &["VEVENT"]).await;

    let journal = include_str!("resources/ical_journal.ics");
    let response = put_ics(&app, url, "journal-entry", journal).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = response.extract_string().await;
    insta::assert_snapshot!(body, @r#"
    <?xml version="1.0" encoding="utf-8"?>
    <error xmlns="DAV:">
        <supported-calendar-component-set xmlns="urn:ietf:params:xml:ns:caldav">
            <comp xmlns="urn:ietf:params:xml:ns:caldav" name="VEVENT"/>
        </supported-calendar-component-set>
    </error>
    "#);
}

/// The same calendar accepts the components it does declare.
#[rstest]
#[tokio::test]
async fn test_put_component_supported(
    #[from(test_store_context)]
    #[future]
    context: TestStoreContext,
) {
    let context = context.await;
    let app = get_app(context.clone());

    let calendar_meta = CalendarMetadata {
        displayname: Some("Calendar".to_string()),
        description: Some("Description".to_string()),
        color: Some("#00FF00".to_string()),
        order: 0,
    };
    let url = "/caldav/principal/user/calendar";
    mkcalendar_with_components(&app, url, &calendar_meta, &["VEVENT", "VJOURNAL"]).await;

    let journal = include_str!("resources/ical_journal.ics");
    let response = put_ics(&app, url, "journal-entry", journal).await;
    assert_eq!(response.status(), StatusCode::CREATED);

    // and it round-trips
    let mut request = Request::builder()
        .method("GET")
        .uri(format!("{url}/journal-entry.ics"))
        .body(Body::empty())
        .unwrap();
    request
        .headers_mut()
        .typed_insert(Authorization::basic("user", "pass"));
    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.extract_string().await;
    assert!(
        body.contains("BEGIN:VJOURNAL") && body.contains("SUMMARY:Staff meeting minutes"),
        "journal did not round-trip: {body}"
    );
}

/// The rejected object must not have been stored: a subsequent PUT of a
/// *supported* component at the same URI still succeeds (If-None-Match: *
/// would fail if the first PUT had written anything).
#[rstest]
#[tokio::test]
async fn test_put_component_not_supported_writes_nothing(
    #[from(test_store_context)]
    #[future]
    context: TestStoreContext,
) {
    let context = context.await;
    let app = get_app(context.clone());

    let calendar_meta = CalendarMetadata {
        displayname: Some("Calendar".to_string()),
        description: Some("Description".to_string()),
        color: Some("#00FF00".to_string()),
        order: 0,
    };
    let url = "/caldav/principal/user/calendar";
    mkcalendar_with_components(&app, url, &calendar_meta, &["VEVENT"]).await;

    let journal = include_str!("resources/ical_journal.ics");
    let response = put_ics(&app, url, "shared-id", journal).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let event = include_str!("resources/ical_thunderbird.ics");
    let response = put_ics(&app, url, "shared-id", event).await;
    assert_eq!(
        response.status(),
        StatusCode::CREATED,
        "the rejected journal must not occupy the URI"
    );
}

/// An entry stored before its component type was removed from the calendar's
/// set stays editable — otherwise dropping VJOURNAL would freeze every entry
/// already written.
#[rstest]
#[tokio::test]
async fn test_overwrite_survives_component_removal(
    #[from(test_store_context)]
    #[future]
    context: TestStoreContext,
) {
    let context = context.await;
    let app = get_app(context.clone());

    let calendar_meta = CalendarMetadata {
        displayname: Some("Calendar".to_string()),
        description: Some("Description".to_string()),
        color: Some("#00FF00".to_string()),
        order: 0,
    };
    let url = "/caldav/principal/user/calendar";
    mkcalendar_with_components(&app, url, &calendar_meta, &["VEVENT", "VJOURNAL"]).await;

    let journal = include_str!("resources/ical_journal.ics");
    let response = put_ics(&app, url, "journal-entry", journal).await;
    assert_eq!(response.status(), StatusCode::CREATED);

    // PROPPATCH the component set down to VEVENT only
    let mut request = Request::builder()
        .method("PROPPATCH")
        .uri(url)
        .header("Content-Type", "application/xml")
        .body(Body::from(
            r#"<propertyupdate xmlns="DAV:" xmlns:CAL="urn:ietf:params:xml:ns:caldav">
                <set>
                    <prop>
                        <CAL:supported-calendar-component-set>
                            <CAL:comp name="VEVENT"/>
                        </CAL:supported-calendar-component-set>
                    </prop>
                </set>
            </propertyupdate>"#,
        ))
        .unwrap();
    request
        .headers_mut()
        .typed_insert(Authorization::basic("user", "pass"));
    let response = app.clone().oneshot(request).await.unwrap();
    // 207 Multi-Status: WebDAV reports per-property results, even when all
    // properties applied.
    assert_eq!(response.status(), StatusCode::MULTI_STATUS);

    // The already-stored journal can still be overwritten …
    let edited = journal.replace("Staff meeting minutes", "Staff meeting minutes (edited)");
    let mut request = Request::builder()
        .method("PUT")
        .uri(format!("{url}/journal-entry.ics"))
        .header("Content-Type", "text/calendar")
        .body(Body::from(edited))
        .unwrap();
    request
        .headers_mut()
        .typed_insert(Authorization::basic("user", "pass"));
    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    // … but a *new* journal is still refused.
    let response = put_ics(&app, url, "another-entry", journal).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}
