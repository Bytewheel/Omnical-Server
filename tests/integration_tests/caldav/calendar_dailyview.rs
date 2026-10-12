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

/// A daily recurring timed event with a past master — the "Trash"-master
/// shape this deployment's calendars carry: a September `DTSTART` beside
/// `FREQ=DAILY`, which the phone would file at September 28th forever.
const DAILY_TIMED_EVENT: &str = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//omnical//holiday-sets//EN\r\nCALSCALE:GREGORIAN\r\nBEGIN:VEVENT\r\nUID:daily-shim-test@omnical\r\nDTSTAMP:20260925T103702Z\r\nDTSTART;TZID=America/New_York:20260928T190000\r\nDTEND;TZID=America/New_York:20260928T190100\r\nSUMMARY:Trash\r\nRRULE:FREQ=DAILY\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";

/// The app with a calendar at `/caldav/principal/user/calendar` holding
/// [`ALL_DAY_EVENT`], exactly as the holiday import would have stored it.
/// The caller supplies the `[caldav]` section; the frontend mirrors
/// [`get_app`]'s.
async fn app_with_all_day_event(
    context: TestStoreContext,
    caldav_config: CalDavConfig,
) -> axum::Router {
    app_with_event(context, caldav_config, "stluke.ics", ALL_DAY_EVENT).await
}

/// The same, holding [`DAILY_TIMED_EVENT`] as `daily.ics`.
async fn app_with_daily_event(
    context: TestStoreContext,
    caldav_config: CalDavConfig,
) -> axum::Router {
    app_with_event(context, caldav_config, "daily.ics", DAILY_TIMED_EVENT).await
}

/// The app with a calendar at `/caldav/principal/user/calendar` holding
/// `ics` as `filename`, exactly as an import would have stored it.
async fn app_with_event(
    context: TestStoreContext,
    caldav_config: CalDavConfig,
    filename: &str,
    ics: &str,
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
        .uri(format!("{url}/{filename}"))
        .header("If-None-Match", "*")
        .header("Content-Type", "text/calendar")
        .body(Body::from(ics.to_owned()))
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

/// The phone's `calendar-multiget` REPORT — the only path its sync consumes
/// event bodies through (`CaldavFacade.getEvent` reads the
/// `<C:calendar-data/>`; it never issues plain GETs).
async fn report_multiget(app: &axum::Router, user_agent: &str, filename: &str) -> String {
    let report = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<C:calendar-multiget xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav">
<D:prop><D:getetag/><C:calendar-data/></D:prop>
<D:href>/caldav/principal/user/calendar/{filename}</D:href>
</C:calendar-multiget>"#
    );
    let mut request = Request::builder()
        .method("REPORT")
        .uri("/caldav/principal/user/calendar")
        .header("User-Agent", user_agent)
        .body(Body::from(report))
        .unwrap();
    request
        .headers_mut()
        .typed_insert(Authorization::basic("user", "pass"));
    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::MULTI_STATUS);
    response.extract_string().await
}

/// DailyView's multiget carries the §18.36 all-day rewrite in its
/// `<C:calendar-data/>` — the path the phone actually parses — while every
/// other client's identical REPORT answers the canonical DATE-valued bytes.
#[rstest]
#[tokio::test]
async fn test_report_dailyview_rewrites_all_day(
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

    let body = report_multiget(&app, DAILYVIEW_UA, "stluke.ics").await;
    assert!(
        body.contains("DTSTART;TZID=America/New_York:20261018T000000"),
        "the phone's calendar-data is the local-midnight form: {body}"
    );
    assert!(
        body.contains("DTEND;TZID=America/New_York:20261019T000000"),
        "DTEND rewritten alongside: {body}"
    );

    let body = report_multiget(&app, OTHER_CLIENT_UA, "stluke.ics").await;
    assert!(
        body.contains("DTSTART;VALUE=DATE:20261018"),
        "other clients keep the canonical data: {body}"
    );
}

/// GET the calendar-collection export (the `Download` button's route) with
/// `query` appended, returning the body.
async fn get_export(app: &axum::Router, query: &str) -> String {
    let mut request = Request::builder()
        .method("GET")
        .uri(format!("/caldav/principal/user/calendar{query}"))
        .body(Body::empty())
        .unwrap();
    request
        .headers_mut()
        .typed_insert(Authorization::basic("user", "pass"));
    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    response.extract_string().await
}

/// The §18.38 export: `?dailyview=1` (armed config) serves the phone-shaped
/// download — recurrence flattened, per-instance UIDs, a VTIMEZONE for the
/// zone, all-day lines as local midnights — while the same route without
/// the param keeps serving the canonical masters.
#[rstest]
#[tokio::test]
async fn test_export_dailyview_flattens(
    #[from(test_store_context)]
    #[future]
    context: TestStoreContext,
) {
    let context = context.await;
    let app = app_with_daily_event(
        context,
        CalDavConfig::with_dailyview_timezone("America/New_York"),
    )
    .await;

    let body = get_export(&app, "?dailyview=1").await;
    assert!(
        body.starts_with("BEGIN:VCALENDAR\r\nVERSION:2.0\r\n"),
        "one VCALENDAR envelope: {body}"
    );
    assert!(
        !body.contains("FREQ=DAILY"),
        "no recurrence is exported to the phone: {body}"
    );
    assert!(
        !body.contains("RECURRENCE-ID"),
        "instances are standalone events: {body}"
    );
    assert!(
        body.contains("BEGIN:VTIMEZONE\r\nTZID:America/New_York\r\n"),
        "the deployment's own zone block: {body}"
    );
    assert!(
        body.contains("UID:daily-shim-test@omnical-"),
        "per-instance UID suffixes: {body}"
    );
    assert!(
        body.contains("DTSTART;TZID=America/New_York:"),
        "instance starts in the deployment's own zone — the form aphy itself writes (§18.40): {body}"
    );
    assert!(
        body.contains("DTEND;TZID=America/New_York:"),
        "materialized local DTEND pairs, not DURATION (§18.39/§18.40): {body}"
    );
    assert!(
        !body.contains("DURATION:"),
        "no DURATION-only instances are exported: {body}"
    );
    let instances = body.matches("BEGIN:VEVENT\r\n").count();
    assert!(
        instances > 1,
        "the horizon flattens into concrete instances: {body}"
    );
    assert_eq!(instances, body.matches("END:VEVENT\r\n").count());

    let canonical = get_export(&app, "").await;
    assert!(
        canonical.contains("RRULE:FREQ=DAILY"),
        "the plain export stays canonical: {canonical}"
    );
    assert!(
        canonical.contains("DTSTART;TZID=America/New_York:20260928T190000"),
        "the master rides along untouched: {canonical}"
    );
}

/// The param is inert without `[caldav] dailyview_timezone`: the export
/// stays canonical.
#[rstest]
#[tokio::test]
async fn test_export_dailyview_unarmed_ignores_param(
    #[from(test_store_context)]
    #[future]
    context: TestStoreContext,
) {
    let context = context.await;
    let app = app_with_daily_event(context, CalDavConfig::default()).await;

    let body = get_export(&app, "?dailyview=1").await;
    assert!(
        body.contains("RRULE:FREQ=DAILY"),
        "unarmed config: canonical export: {body}"
    );
    assert!(
        body.contains("DTSTART;TZID=America/New_York:20260928T190000"),
        "the master stays: {body}"
    );
}

/// The all-day pass applies through the export: St Luke's `VALUE=DATE` lines
/// arrive as local-midnight DATE-TIMEs, unsuffixed (non-recurring).
#[rstest]
#[tokio::test]
async fn test_export_dailyview_all_day_pass(
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

    let body = get_export(&app, "?dailyview=1").await;
    assert!(
        body.contains("DTSTART;TZID=America/New_York:20261018T000000\r\n"),
        "all-day lines as local midnights: {body}"
    );
    assert!(
        body.contains("DTEND;TZID=America/New_York:20261019T000000\r\n"),
        "DTEND rewritten alongside: {body}"
    );
    assert!(
        body.contains("UID:hol-rc-1962-st-luke-evangelist-20261018@omnical\r\n"),
        "non-recurring: no UID suffix: {body}"
    );
    assert!(!body.contains("VALUE=DATE"), "{body}");
}

/// DailyView's multiget carries the §18.37 recurrence flattening: a daily
/// event with a September master is served as its first occurrence inside
/// the phone's own 4-day window, as a plain UTC DATE-TIME with no `RRULE` —
/// the exact form `CalendarEvent.getTimestamp` files on the right day.
/// Every other client's identical REPORT answers the canonical master.
#[rstest]
#[tokio::test]
async fn test_report_dailyview_flattens_recurrence(
    #[from(test_store_context)]
    #[future]
    context: TestStoreContext,
) {
    let context = context.await;
    let app = app_with_daily_event(
        context,
        CalDavConfig::with_dailyview_timezone("America/New_York"),
    )
    .await;

    let body = report_multiget(&app, DAILYVIEW_UA, "daily.ics").await;
    assert!(
        !body.contains("RRULE"),
        "no recurrence is shipped to the phone: {body}"
    );
    let instance = body
        .split("DTSTART:")
        .nth(1)
        .and_then(|rest| rest.get(..16));
    assert!(
        instance.is_some_and(|value| value.ends_with('Z') && value.as_bytes()[8] == b'T'),
        "a concrete UTC DATE-TIME occurrence is shipped: {body}"
    );
    assert!(
        body.contains("SUMMARY:Trash"),
        "the event's own lines survive: {body}"
    );

    let body = report_multiget(&app, OTHER_CLIENT_UA, "daily.ics").await;
    assert!(
        body.contains("DTSTART;TZID=America/New_York:20260928T190000"),
        "other clients keep the canonical master: {body}"
    );
    assert!(
        body.contains("RRULE:FREQ=DAILY"),
        "other clients keep the recurrence: {body}"
    );
}
