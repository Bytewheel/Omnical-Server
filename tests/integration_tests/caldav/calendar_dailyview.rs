use super::{
    ResponseExtractString, calendar::mkcalendar_template, get_app_with_frontend_and_caldav_config,
};
use axum::body::Body;
use headers::{Authorization, HeaderMapExt};
use http::{Request, StatusCode};
use rstest::rstest;
use rustical_caldav::CalDavConfig;
use rustical_frontend::FrontendConfig;
use rustical_store::CalendarMetadata;
use rustical_store_sqlite::tests::{TestStoreContext, test_store_context};
use tower::ServiceExt;

/// The frozen DailyView client's User-Agent (`CaldavFacade` in the app),
/// stock and `dailyview-mod` builds alike.
const DAILYVIEW_UA: &str = "CalDAV Sync Adapter (Android) https://github.com/gggard/AndroidCaldavSyncAdapater Version:1.0.08";

const OTHER_CLIENT_UA: &str = "vdirsyncer/0.19.4";

/// An all-day holiday event exactly as the §18.34 holiday generator writes
/// it: DATE-valued `DTSTART`/`DTEND`, fixed `DTSTAMP`.
const ALL_DAY_EVENT: &str = "BEGIN:VCALENDAR\r\nPRODID:-//omnical//holiday-sets//EN\r\nVERSION:2.0\r\nCALSCALE:GREGORIAN\r\nBEGIN:VEVENT\r\nUID:hol-rc-1962-st-luke-evangelist-20261018@omnical\r\nDTSTAMP:20260101T000000Z\r\nDTSTART;VALUE=DATE:20261018\r\nDTEND;VALUE=DATE:20261019\r\nSUMMARY:St Luke\r\nDESCRIPTION:II class\\, red\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";

/// The app with a calendar at `/caldav/principal/user/calendar` holding
/// [`ALL_DAY_EVENT`], exactly as the holiday import would have stored it.
/// The caller supplies the `[caldav]` section; the frontend mirrors
/// [`get_app`]'s.
async fn app_with_all_day_event(
    context: TestStoreContext,
    caldav_config: CalDavConfig,
) -> axum::Router {
    let app = get_app_with_frontend_and_caldav_config(
        context,
        FrontendConfig {
            enabled: true,
            allow_password_login: true,
            ..FrontendConfig::default()
        },
        caldav_config,
    );

    let url = "/caldav/principal/user/calendar";
    let mut request = Request::builder()
        .method("MKCALENDAR")
        .uri(url)
        .body(Body::from(mkcalendar_template(&CalendarMetadata {
            displayname: Some("Liturgy".to_owned()),
            description: None,
            color: None,
            order: 0,
        })))
        .unwrap();
    request
        .headers_mut()
        .typed_insert(Authorization::basic("user", "pass"));
    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    let mut request = Request::builder()
        .method("PUT")
        .uri(format!("{url}/stluke.ics"))
        .header("If-None-Match", "*")
        .header("Content-Type", "text/calendar")
        .body(Body::from(ALL_DAY_EVENT))
        .unwrap();
    request
        .headers_mut()
        .typed_insert(Authorization::basic("user", "pass"));
    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    app
}

/// GET the stored event as `user_agent`, returning `(etag, body)`.
async fn get_event(app: &axum::Router, user_agent: &str) -> (Option<String>, String) {
    let mut request = Request::builder()
        .method("GET")
        .uri("/caldav/principal/user/calendar/stluke.ics")
        .header("User-Agent", user_agent)
        .body(Body::empty())
        .unwrap();
    request
        .headers_mut()
        .typed_insert(Authorization::basic("user", "pass"));
    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let etag = response
        .headers()
        .get("ETag")
        .map(|etag| etag.to_str().unwrap().to_owned());
    (etag, response.extract_string().await)
}

/// DailyView's GET is served DATE-valued lines rewritten to local-midnight
/// DATE-TIMEs — the form its parser resolves to the correct day — while
/// every other client still sees the canonical all-day data and both GETs
/// answer the same ETag: the rewrite is on the wire only.
#[rstest]
#[tokio::test]
async fn test_get_dailyview_rewrites_all_day(
    #[from(test_store_context)]
    #[future]
    context: TestStoreContext,
) {
    let context = context.await;
    let app = app_with_all_day_event(
        context,
        CalDavConfig::with_dailyview_timezone("America/New_York"),
    )
    .await;

    let (dailyview_etag, body) = get_event(&app, DAILYVIEW_UA).await;
    assert!(
        body.contains("DTSTART;TZID=America/New_York:20261018T000000\r\n"),
        "DTSTART served as a local-midnight DATE-TIME: {body}"
    );
    assert!(
        body.contains("DTEND;TZID=America/New_York:20261019T000000\r\n"),
        "DTEND rewritten alongside: {body}"
    );
    assert!(
        !body.contains("VALUE=DATE"),
        "no DATE-valued line remains: {body}"
    );
    assert!(body.contains("SUMMARY:St Luke\r\n"));

    let (other_etag, body) = get_event(&app, OTHER_CLIENT_UA).await;
    assert!(
        body.contains("DTSTART;VALUE=DATE:20261018\r\n"),
        "other clients keep the canonical data: {body}"
    );
    assert_eq!(dailyview_etag, other_etag, "one stored object, one ETag");
}

/// Without `dailyview_timezone` the shim is inert: even DailyView's GET
/// answers the canonical all-day body.
#[rstest]
#[tokio::test]
async fn test_get_dailyview_shim_disabled_by_default(
    #[from(test_store_context)]
    #[future]
    context: TestStoreContext,
) {
    let context = context.await;
    let app = app_with_all_day_event(context, CalDavConfig::default()).await;

    let (_, body) = get_event(&app, DAILYVIEW_UA).await;
    assert!(
        body.contains("DTSTART;VALUE=DATE:20261018\r\n"),
        "disabled shim serves the canonical data: {body}"
    );
}
