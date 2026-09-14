//! Portal Linked-platforms tests (PLAN.md §17.8.3): the per-user surface for
//! importing a foreign HTTPS .ics feed into one of the user's calendars —
//! list with add form, SSRF-guarded add (no dead mapping on refusal/error),
//! refresh with failure banner, and remove (keeps the materialized data).
//! The fetch/materialize happy path needs a real public feed and stays for the
//! live-deploy gate (§17.8.7 item 5); the offline materialize/refresh-diff
//! pipeline itself is covered by `routes::linked_platforms` unit tests.
use super::{ResponseExtractString, get_app};
use axum::body::Body;
use axum::extract::Request;
use headers::{Authorization, HeaderMapExt};
use http::header::CONTENT_TYPE;
use http::{Method, StatusCode};
use rstest::rstest;
use rustical_ical::CalendarObject;
use rustical_ical::CalendarObjectType;
use rustical_store::auth::{AuthenticationProvider, Principal, PrincipalType};
use rustical_store::{
    Calendar, CalendarMetadata, CalendarReadStore, CalendarSourceStore, CalendarWriteStore,
};
use rustical_store_sqlite::SqliteCalendarSourceStore;
use rustical_store_sqlite::tests::{TestStoreContext, test_store_context};
use tower::ServiceExt;

async fn insert_calendar(context: &TestStoreContext, id: &str, principal: &str) {
    context
        .cal_store
        .insert_calendar(Calendar {
            id: id.to_owned(),
            principal: principal.to_owned(),
            meta: CalendarMetadata {
                displayname: Some(id.to_owned()),
                order: 0,
                description: None,
                color: None,
            },
            timezone_id: None,
            deleted_at: None,
            synctoken: 0,
            subscription_url: None,
            push_topic: format!("linked-{id}"),
            components: vec![CalendarObjectType::Event],
        })
        .await
        .unwrap();
}

async fn seed_source(
    context: &TestStoreContext,
    principal: &str,
    calendar_id: &str,
    source_url: &str,
) -> String {
    let store = SqliteCalendarSourceStore::new(context.cal_store.clone());
    store
        .add_calendar_source(principal, calendar_id, source_url, "calendar.example.com")
        .await
        .unwrap()
}

async fn seed_event(context: &TestStoreContext, calendar_id: &str, uid: &str) {
    context
        .cal_store
        .put_object(
            "user",
            calendar_id,
            uid,
            CalendarObject::from_ics(format!(
                "BEGIN:VCALENDAR\n\
                 PRODID:-//test//EN\n\
                 VERSION:2.0\n\
                 BEGIN:VEVENT\n\
                 UID:{uid}\n\
                 DTSTAMP:20260801T000000Z\n\
                 DTSTART:20260810T100000Z\n\
                 SUMMARY:imported\n\
                 END:VEVENT\n\
                 END:VCALENDAR"
            ))
            .unwrap(),
            true,
        )
        .await
        .unwrap();
}

async fn insert_user(context: &TestStoreContext, id: &str) {
    context
        .principal_store
        .insert_principal(
            Principal {
                id: id.to_owned(),
                displayname: Some(id.to_owned()),
                memberships: vec![],
                password: None,
                principal_type: PrincipalType::Individual,
                needs_password_change: false,
            },
            false,
        )
        .await
        .unwrap();
    context
        .principal_store
        .add_app_token(id, id.to_owned(), id.to_owned())
        .await
        .unwrap();
}

fn request(
    method: Method,
    uri: &str,
    user: &str,
    pass: &str,
    body: Option<String>,
) -> Request<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("host", "public.example");
    let body = body.map(Body::from);
    if body.is_some() {
        builder = builder.header(CONTENT_TYPE, "application/x-www-form-urlencoded");
    }
    let mut request = builder.body(body.unwrap_or_else(Body::empty)).unwrap();
    request
        .headers_mut()
        .typed_insert(Authorization::basic(user, pass));
    request
}

fn add_body(source_url: &str, calendar_id: &str) -> Option<String> {
    let enc: String = url::form_urlencoded::byte_serialize(source_url.as_bytes()).collect();
    Some(format!("source_url={enc}&calendar_id={calendar_id}"))
}

#[rstest]
#[tokio::test]
async fn test_page_lists_sources_with_actions(
    #[from(test_store_context)]
    #[future]
    context: TestStoreContext,
) {
    let context = context.await;
    insert_calendar(&context, "personal", "user").await;
    seed_source(
        &context,
        "user",
        "personal",
        "https://calendar.example.com/team.ics",
    )
    .await;
    let app = get_app(context);

    let response = app
        .oneshot(request(
            Method::GET,
            "/frontend/user/user/linked-platforms",
            "user",
            "pass",
            None,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.extract_string().await;
    assert!(body.contains("calendar.example.com/team.ics"));
    assert!(body.contains("collection: personal"));
    assert!(body.contains("Refresh"));
    assert!(body.contains("Remove"));
    assert!(body.contains("Add linked platform"));
}

#[rstest]
#[tokio::test]
async fn test_page_empty_state(
    #[from(test_store_context)]
    #[future]
    context: TestStoreContext,
) {
    let context = context.await;
    insert_calendar(&context, "personal", "user").await;
    let app = get_app(context);

    let response = app
        .oneshot(request(
            Method::GET,
            "/frontend/user/user/linked-platforms",
            "user",
            "pass",
            None,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.extract_string().await;
    assert!(body.contains("No linked platforms yet"));
    assert!(body.contains("Add linked platform"));
}

#[rstest]
#[tokio::test]
async fn test_add_rejects_non_https_and_stores_nothing(
    #[from(test_store_context)]
    #[future]
    context: TestStoreContext,
) {
    let context = context.await;
    insert_calendar(&context, "personal", "user").await;
    let store = SqliteCalendarSourceStore::new(context.cal_store.clone());
    let app = get_app(context);

    let response = app
        .oneshot(request(
            Method::POST,
            "/frontend/user/user/linked-platforms/add",
            "user",
            "pass",
            add_body("http://example.com/team.ics", "personal"),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.extract_string().await;
    assert!(body.contains("Only HTTPS URLs are allowed"));
    assert!(store.get_calendar_sources("user").await.unwrap().is_empty());
}

#[rstest]
#[tokio::test]
async fn test_add_rejects_private_range_and_stores_nothing(
    #[from(test_store_context)]
    #[future]
    context: TestStoreContext,
) {
    let context = context.await;
    insert_calendar(&context, "personal", "user").await;
    let store = SqliteCalendarSourceStore::new(context.cal_store.clone());
    let app = get_app(context);

    let response = app
        .clone()
        .oneshot(request(
            Method::POST,
            "/frontend/user/user/linked-platforms/add",
            "user",
            "pass",
            add_body("https://192.168.1.10/team.ics", "personal"),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.extract_string().await;
    assert!(
        body.contains("Refused: private-range address"),
        "body: {body}"
    );
    assert!(store.get_calendar_sources("user").await.unwrap().is_empty());
}

#[rstest]
#[tokio::test]
async fn test_add_unknown_calendar_is_rejected(
    #[from(test_store_context)]
    #[future]
    context: TestStoreContext,
) {
    let context = context.await;
    insert_calendar(&context, "personal", "user").await;
    let store = SqliteCalendarSourceStore::new(context.cal_store.clone());
    let app = get_app(context);

    let response = app
        .clone()
        .oneshot(request(
            Method::POST,
            "/frontend/user/user/linked-platforms/add",
            "user",
            "pass",
            add_body("https://calendar.example.com/team.ics", "nope"),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.extract_string().await;
    assert!(body.contains("No such calendar"), "body: {body}");
    assert!(store.get_calendar_sources("user").await.unwrap().is_empty());
}

#[rstest]
#[tokio::test]
async fn test_add_wrong_user_unauthorized(
    #[from(test_store_context)]
    #[future]
    context: TestStoreContext,
) {
    let context = context.await;
    insert_user(&context, "bob").await;
    insert_calendar(&context, "personal", "user").await;
    let app = get_app(context);

    let response = app
        .oneshot(request(
            Method::POST,
            "/frontend/user/user/linked-platforms/add",
            "bob",
            "bob",
            add_body("https://calendar.example.com/team.ics", "personal"),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[rstest]
#[tokio::test]
async fn test_remove_unlinks_but_keeps_materialized_data(
    #[from(test_store_context)]
    #[future]
    context: TestStoreContext,
) {
    let context = context.await;
    insert_calendar(&context, "personal", "user").await;
    seed_event(&context, "personal", "uid-1").await;
    let id = seed_source(
        &context,
        "user",
        "personal",
        "https://calendar.example.com/team.ics",
    )
    .await;
    let store = SqliteCalendarSourceStore::new(context.cal_store.clone());
    let app = get_app(context.clone());

    let response = app
        .oneshot(request(
            Method::POST,
            &format!("/frontend/user/user/linked-platforms/{id}/remove"),
            "user",
            "pass",
            None,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);

    assert!(
        matches!(
            store.get_calendar_source("user", &id).await,
            Err(rustical_store::Error::NotFound)
        ),
        "the mapping must be gone after Remove"
    );
    let objects = context
        .cal_store
        .get_objects("user", "personal")
        .await
        .unwrap();
    assert_eq!(objects.len(), 1, "the materialized copy stays behind");
    assert_eq!(objects[0].0, "uid-1");
}

#[rstest]
#[tokio::test]
async fn test_remove_foreign_source_is_404(
    #[from(test_store_context)]
    #[future]
    context: TestStoreContext,
) {
    let context = context.await;
    insert_user(&context, "bob").await;
    insert_calendar(&context, "bobcal", "bob").await;
    let id = seed_source(
        &context,
        "bob",
        "bobcal",
        "https://calendar.example.com/bob.ics",
    )
    .await;
    let store = SqliteCalendarSourceStore::new(context.cal_store.clone());
    let app = get_app(context);

    let response = app
        .oneshot(request(
            Method::POST,
            &format!("/frontend/user/user/linked-platforms/{id}/remove"),
            "user",
            "pass",
            None,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert!(store.get_calendar_source("bob", &id).await.is_ok());
}

#[rstest]
#[tokio::test]
async fn test_remove_wrong_user_unauthorized(
    #[from(test_store_context)]
    #[future]
    context: TestStoreContext,
) {
    let context = context.await;
    insert_user(&context, "bob").await;
    insert_calendar(&context, "personal", "user").await;
    let id = seed_source(
        &context,
        "user",
        "personal",
        "https://calendar.example.com/team.ics",
    )
    .await;
    let app = get_app(context);

    let response = app
        .oneshot(request(
            Method::POST,
            &format!("/frontend/user/user/linked-platforms/{id}/remove"),
            "bob",
            "bob",
            None,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[rstest]
#[tokio::test]
async fn test_refresh_unknown_source_is_404(
    #[from(test_store_context)]
    #[future]
    context: TestStoreContext,
) {
    let context = context.await;
    let app = get_app(context);

    let response = app
        .oneshot(request(
            Method::POST,
            "/frontend/user/user/linked-platforms/unknown-id/refresh",
            "user",
            "pass",
            None,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[rstest]
#[tokio::test]
async fn test_refresh_failure_banner_guard_supported(
    #[from(test_store_context)]
    #[future]
    context: TestStoreContext,
) {
    // seed a source whose URL the SSRF guard refuses — refresh must surface a
    // deterministic failure banner and change nothing
    let context = context.await;
    insert_calendar(&context, "personal", "user").await;
    let id = seed_source(
        &context,
        "user",
        "personal",
        "https://169.254.169.254/latest/meta-data",
    )
    .await;
    let app = get_app(context);

    let response = app
        .oneshot(request(
            Method::POST,
            &format!("/frontend/user/user/linked-platforms/{id}/refresh"),
            "user",
            "pass",
            None,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.extract_string().await;
    assert!(
        body.contains("Refresh failed: Refused: private-range address"),
        "body: {body}"
    );
}

#[rstest]
#[tokio::test]
async fn test_refresh_wrong_user_unauthorized(
    #[from(test_store_context)]
    #[future]
    context: TestStoreContext,
) {
    let context = context.await;
    insert_user(&context, "bob").await;
    insert_calendar(&context, "personal", "user").await;
    let id = seed_source(
        &context,
        "user",
        "personal",
        "https://calendar.example.com/team.ics",
    )
    .await;
    let app = get_app(context);

    let response = app
        .oneshot(request(
            Method::POST,
            &format!("/frontend/user/user/linked-platforms/{id}/refresh"),
            "bob",
            "bob",
            None,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}
