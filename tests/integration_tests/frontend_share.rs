//! Portal Share-section tests (PLAN.md §17.8.4): the per-user surface for
//! the §17.7 share-link subscriptions — list with full export URLs, create
//! (own + owned-group collections), ownership enforcement, revoke, and the
//! public `/export` round-trip through the same app.
use super::{ResponseExtractString, get_app};
use axum::body::Body;
use axum::extract::Request;
use headers::{Authorization, HeaderMapExt};
use http::header::CONTENT_TYPE;
use http::{Method, StatusCode};
use rstest::rstest;
use rustical_ical::CalendarObjectType;
use rustical_store::auth::{AuthenticationProvider, Principal, PrincipalType};
use rustical_store::{
    Addressbook, AddressbookWriteStore, Calendar, CalendarMetadata, CalendarWriteStore,
    CollectionShareStore, InviteStore,
};
use rustical_store_sqlite::tests::{TestStoreContext, test_store_context};
use rustical_store_sqlite::{SqliteCollectionShareStore, SqliteInviteStore, SqlitePrincipalStore};
use tower::ServiceExt;

async fn insert_group(context: &TestStoreContext, group_id: &str, displayname: &str, owner: &str) {
    context
        .principal_store
        .insert_principal(
            Principal {
                id: group_id.to_owned(),
                displayname: Some(displayname.to_owned()),
                memberships: vec![],
                password: None,
                principal_type: PrincipalType::Group,
                needs_password_change: false,
                privileges: Default::default(),
            },
            false,
        )
        .await
        .unwrap();
    context
        .principal_store
        .set_group_owner(group_id, owner)
        .await
        .unwrap();
    context
        .principal_store
        .add_membership(owner, group_id)
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
                privileges: Default::default(),
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

/// Own calendar + addressbook, an owned group with a calendar, and a foreign
/// group (owned by `bob`) with a calendar.
async fn setup_share_fixtures(context: &TestStoreContext) {
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
            push_topic: "share-test-personal".to_owned(),
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
            push_topic: "share-test-contacts".to_owned(),
        })
        .await
        .unwrap();

    insert_group(context, "testgroup", "Test Group", "user").await;
    context
        .cal_store
        .insert_calendar(Calendar {
            id: "groupcal".to_owned(),
            principal: "testgroup".to_owned(),
            meta: CalendarMetadata {
                displayname: Some("Group Calendar".to_owned()),
                order: 0,
                description: None,
                color: None,
            },
            timezone_id: None,
            deleted_at: None,
            synctoken: 0,
            subscription_url: None,
            push_topic: "share-test-groupcal".to_owned(),
            components: vec![CalendarObjectType::Event],
        })
        .await
        .unwrap();

    insert_user(context, "bob").await;
    insert_group(context, "foreigngroup", "Foreign Group", "bob").await;
    context
        .cal_store
        .insert_calendar(Calendar {
            id: "foreigncal".to_owned(),
            principal: "foreigngroup".to_owned(),
            meta: CalendarMetadata {
                displayname: Some("Foreign Calendar".to_owned()),
                order: 0,
                description: None,
                color: None,
            },
            timezone_id: None,
            deleted_at: None,
            synctoken: 0,
            subscription_url: None,
            push_topic: "share-test-foreigncal".to_owned(),
            components: vec![CalendarObjectType::Event],
        })
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

fn form(body: &str) -> Option<String> {
    Some(body.to_owned())
}

/// Extract the first `https://public.example/export/…{extension}` URL.
fn extract_share_url(body: &str, extension: &str) -> String {
    let marker = "https://public.example/export/";
    let start = body.find(marker).expect("share URL in body");
    let rest = &body[start..];
    let end = rest.find(extension).expect("extension in share URL");
    rest[..end + extension.len()].to_owned()
}

/// Extract the first revoke form action (`/frontend/user/user/share/{id}/revoke`).
fn extract_revoke_action(body: &str) -> String {
    let end = body.find("/revoke").expect("revoke form action in body");
    let start = body[..end]
        .rfind("/frontend/user/user/share/")
        .expect("share path before revoke action");
    body[start..end + "/revoke".len()].to_owned()
}

#[rstest]
#[tokio::test]
async fn test_share_page_lists_collections_with_create_buttons(
    #[from(test_store_context)]
    #[future]
    context: TestStoreContext,
) {
    let context = context.await;
    setup_share_fixtures(&context).await;
    let app = get_app(context);

    let req = request(
        Method::GET,
        "/frontend/user/user/share",
        "user",
        "pass",
        None,
    );
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.extract_string().await;
    assert!(body.contains("Create share link"));
    assert!(body.contains("Personal"));
    assert!(body.contains("Contacts"));
    // Own + owned-group collections are listed …
    assert!(body.contains("Group Calendar"));
    // … but not collections of groups the user does not own.
    assert!(!body.contains("Foreign Calendar"));
    // No share link exists yet, so no URL is shown.
    assert!(!body.contains("/export/"));
}

#[rstest]
#[tokio::test]
async fn test_share_create_shows_url_and_serves_export(
    #[from(test_store_context)]
    #[future]
    context: TestStoreContext,
) {
    let context = context.await;
    setup_share_fixtures(&context).await;
    let app = get_app(context);

    let req = request(
        Method::POST,
        "/frontend/user/user/share/create",
        "user",
        "pass",
        form("principal=user&kind=calendar&collection_id=personal"),
    );
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        resp.headers().get("location").unwrap(),
        "/frontend/user/user/share"
    );

    let req = request(
        Method::GET,
        "/frontend/user/user/share",
        "user",
        "pass",
        None,
    );
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.extract_string().await;
    let url = extract_share_url(&body, ".ics");
    let token = url
        .trim_start_matches("https://public.example/export/")
        .trim_end_matches(".ics");
    assert_eq!(token.len(), 64, "app-token shape: {url}");
    assert!(token.chars().all(|c| c.is_ascii_alphanumeric()));

    // The public export URL serves without any authentication.
    let req = Request::builder()
        .method(Method::GET)
        .uri(&url["https://public.example".len()..])
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(
        resp.headers()
            .get(CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("text/calendar")
    );
}

#[rstest]
#[tokio::test]
async fn test_share_create_addressbook_serves_vcf(
    #[from(test_store_context)]
    #[future]
    context: TestStoreContext,
) {
    let context = context.await;
    setup_share_fixtures(&context).await;
    let app = get_app(context);

    let req = request(
        Method::POST,
        "/frontend/user/user/share/create",
        "user",
        "pass",
        form("principal=user&kind=addressbook&collection_id=contacts"),
    );
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);

    let req = request(
        Method::GET,
        "/frontend/user/user/share",
        "user",
        "pass",
        None,
    );
    let resp = app.clone().oneshot(req).await.unwrap();
    let body = resp.extract_string().await;
    let url = extract_share_url(&body, ".vcf");

    let req = Request::builder()
        .method(Method::GET)
        .uri(&url["https://public.example".len()..])
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(
        resp.headers()
            .get(CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("text/vcard")
    );
}

#[rstest]
#[tokio::test]
async fn test_share_create_group_collection(
    #[from(test_store_context)]
    #[future]
    context: TestStoreContext,
) {
    let context = context.await;
    setup_share_fixtures(&context).await;
    let app = get_app(context);

    let req = request(
        Method::POST,
        "/frontend/user/user/share/create",
        "user",
        "pass",
        form("principal=testgroup&kind=calendar&collection_id=groupcal"),
    );
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);

    // The group's share link shows on the user's Share page …
    let req = request(
        Method::GET,
        "/frontend/user/user/share",
        "user",
        "pass",
        None,
    );
    let resp = app.clone().oneshot(req).await.unwrap();
    let body = resp.extract_string().await;
    let url = extract_share_url(&body, ".ics");

    // … and serves through the public export route.
    let req = Request::builder()
        .method(Method::GET)
        .uri(&url["https://public.example".len()..])
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[rstest]
#[tokio::test]
async fn test_share_create_rejects_foreign_group(
    #[from(test_store_context)]
    #[future]
    context: TestStoreContext,
) {
    let context = context.await;
    setup_share_fixtures(&context).await;
    let app = get_app(context);

    let req = request(
        Method::POST,
        "/frontend/user/user/share/create",
        "user",
        "pass",
        form("principal=foreigngroup&kind=calendar&collection_id=foreigncal"),
    );
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[rstest]
#[tokio::test]
async fn test_share_create_rejects_other_user_principal(
    #[from(test_store_context)]
    #[future]
    context: TestStoreContext,
) {
    let context = context.await;
    setup_share_fixtures(&context).await;
    let app = get_app(context);

    let req = request(
        Method::POST,
        "/frontend/user/user/share/create",
        "user",
        "pass",
        form("principal=bob&kind=calendar&collection_id=personal"),
    );
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[rstest]
#[tokio::test]
async fn test_share_create_rejects_unknown_collection(
    #[from(test_store_context)]
    #[future]
    context: TestStoreContext,
) {
    let context = context.await;
    setup_share_fixtures(&context).await;
    let app = get_app(context);

    let req = request(
        Method::POST,
        "/frontend/user/user/share/create",
        "user",
        "pass",
        form("principal=user&kind=calendar&collection_id=nope"),
    );
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[rstest]
#[tokio::test]
async fn test_share_create_rejects_unknown_kind(
    #[from(test_store_context)]
    #[future]
    context: TestStoreContext,
) {
    let context = context.await;
    setup_share_fixtures(&context).await;
    let app = get_app(context);

    let req = request(
        Method::POST,
        "/frontend/user/user/share/create",
        "user",
        "pass",
        form("principal=user&kind=bogus&collection_id=personal"),
    );
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[rstest]
#[tokio::test]
async fn test_share_revoke_makes_url_404(
    #[from(test_store_context)]
    #[future]
    context: TestStoreContext,
) {
    let context = context.await;
    setup_share_fixtures(&context).await;
    let app = get_app(context);

    let req = request(
        Method::POST,
        "/frontend/user/user/share/create",
        "user",
        "pass",
        form("principal=user&kind=calendar&collection_id=personal"),
    );
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);

    let req = request(
        Method::GET,
        "/frontend/user/user/share",
        "user",
        "pass",
        None,
    );
    let resp = app.clone().oneshot(req).await.unwrap();
    let body = resp.extract_string().await;
    let url = extract_share_url(&body, ".ics");
    let revoke_action = extract_revoke_action(&body);

    let req = request(
        Method::POST,
        &revoke_action,
        "user",
        "pass",
        form("principal=user"),
    );
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);

    // The Share page shows the create button again …
    let req = request(
        Method::GET,
        "/frontend/user/user/share",
        "user",
        "pass",
        None,
    );
    let resp = app.clone().oneshot(req).await.unwrap();
    let body = resp.extract_string().await;
    assert!(body.contains("Create share link"));
    assert!(!body.contains("/export/"));

    // … and the export URL is gone immediately.
    let req = Request::builder()
        .method(Method::GET)
        .uri(&url["https://public.example".len()..])
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[rstest]
#[tokio::test]
async fn test_share_page_wrong_user(
    #[from(test_store_context)]
    #[future]
    context: TestStoreContext,
) {
    let context = context.await;
    setup_share_fixtures(&context).await;
    let app = get_app(context);

    let req = request(Method::GET, "/frontend/user/user/share", "bob", "bob", None);
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

/// The `https://public.example/register?code=…` URL printed in the invite
/// banner (terminated by the closing `</code>` element).
fn extract_register_url(body: &str) -> String {
    const MARKER: &str = "https://public.example/register?code=";
    let start = body.find(MARKER).expect("register URL in body");
    let rest = &body[start..];
    let end = rest.find('<').expect("end of register URL");
    rest[..end].to_owned()
}

#[rstest]
#[tokio::test]
async fn test_share_generate_invite_link_without_email(
    #[from(test_store_context)]
    #[future]
    context: TestStoreContext,
) {
    let context = context.await;
    setup_share_fixtures(&context).await;
    let invite_store = SqliteInviteStore::new(context.cal_store.clone());
    let app = get_app(context);

    // "Generate invite link": no email field is posted at all.
    let req = request(
        Method::POST,
        "/frontend/user/user/share/invite",
        "user",
        "pass",
        form("principal=testgroup&kind=calendar&collection_id=groupcal"),
    );
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.extract_string().await;
    assert!(body.contains("Invite link generated"));

    // The invite was stored bound to the group, without any email.
    let url = extract_register_url(&body);
    let code = url.trim_start_matches("https://public.example/register?code=");
    assert_eq!(code.len(), 12);
    let invite = invite_store
        .get_invite(code)
        .await
        .unwrap()
        .expect("invite stored");
    assert_eq!(invite.target_email, None);
    assert_eq!(invite.target_group.as_deref(), Some("testgroup"));
    assert_eq!(invite.collection_id.as_deref(), Some("groupcal"));
    assert_eq!(invite.kind.as_deref(), Some("calendar"));
    assert_eq!(invite.created_by, "user");
}

#[rstest]
#[tokio::test]
async fn test_share_invite_with_email_binds_target_email(
    #[from(test_store_context)]
    #[future]
    context: TestStoreContext,
) {
    let context = context.await;
    setup_share_fixtures(&context).await;
    let invite_store = SqliteInviteStore::new(context.cal_store.clone());
    let app = get_app(context);

    let req = request(
        Method::POST,
        "/frontend/user/user/share/invite",
        "user",
        "pass",
        form("principal=testgroup&kind=calendar&collection_id=groupcal&email=Alice%40example.com"),
    );
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.extract_string().await;
    assert!(body.contains("Invite sent"));
    assert!(body.contains("alice@example.com"));

    let url = extract_register_url(&body);
    let code = url.trim_start_matches("https://public.example/register?code=");
    let invite = invite_store
        .get_invite(code)
        .await
        .unwrap()
        .expect("invite stored");
    assert_eq!(invite.target_email.as_deref(), Some("alice@example.com"));
    assert_eq!(invite.target_group.as_deref(), Some("testgroup"));
    assert_eq!(invite.collection_id.as_deref(), Some("groupcal"));
    assert_eq!(invite.kind.as_deref(), Some("calendar"));
}

#[rstest]
#[tokio::test]
async fn test_share_invite_rejects_invalid_email(
    #[from(test_store_context)]
    #[future]
    context: TestStoreContext,
) {
    let context = context.await;
    setup_share_fixtures(&context).await;
    let invite_store = SqliteInviteStore::new(context.cal_store.clone());
    let app = get_app(context);

    let req = request(
        Method::POST,
        "/frontend/user/user/share/invite",
        "user",
        "pass",
        form("principal=testgroup&kind=calendar&collection_id=groupcal&email=notanemail"),
    );
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.extract_string().await;
    assert!(body.contains("Please enter a valid email address."));
    assert!(invite_store.list_invites(true).await.unwrap().is_empty());
}

#[rstest]
#[tokio::test]
async fn test_share_invite_rejects_unowned_group(
    #[from(test_store_context)]
    #[future]
    context: TestStoreContext,
) {
    let context = context.await;
    setup_share_fixtures(&context).await;
    let app = get_app(context);

    let req = request(
        Method::POST,
        "/frontend/user/user/share/invite",
        "user",
        "pass",
        form("principal=foreigngroup&kind=calendar&collection_id=foreigncal"),
    );
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[rstest]
#[tokio::test]
async fn test_share_invite_rejects_unknown_collection(
    #[from(test_store_context)]
    #[future]
    context: TestStoreContext,
) {
    let context = context.await;
    setup_share_fixtures(&context).await;
    let invite_store = SqliteInviteStore::new(context.cal_store.clone());
    let app = get_app(context);

    let req = request(
        Method::POST,
        "/frontend/user/user/share/invite",
        "user",
        "pass",
        form("principal=user&kind=calendar&collection_id=nope"),
    );
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.extract_string().await;
    assert!(body.contains("No such calendar"));
    assert!(body.contains("nope"));
    assert!(invite_store.list_invites(true).await.unwrap().is_empty());
}

#[rstest]
#[tokio::test]
async fn test_share_invite_rejects_addressbook_kind(
    #[from(test_store_context)]
    #[future]
    context: TestStoreContext,
) {
    let context = context.await;
    setup_share_fixtures(&context).await;
    let invite_store = SqliteInviteStore::new(context.cal_store.clone());
    let app = get_app(context);

    let req = request(
        Method::POST,
        "/frontend/user/user/share/invite",
        "user",
        "pass",
        form("principal=user&kind=addressbook&collection_id=contacts"),
    );
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.extract_string().await;
    assert!(body.contains("Invites are only supported for calendars."));
    assert!(invite_store.list_invites(true).await.unwrap().is_empty());
}

/// Mint an invite for one collection and read its code back from the store.
async fn mint_invite(app: &axum::Router, invite_store: &SqliteInviteStore, form: &str) -> String {
    let req = request(
        Method::POST,
        "/frontend/user/user/share/invite",
        "user",
        "pass",
        Some(form.to_owned()),
    );
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.extract_string().await;
    let url = extract_register_url(&body);
    let code = url
        .trim_start_matches("https://public.example/register?code=")
        .to_owned();
    assert!(
        invite_store.get_invite(&code).await.unwrap().is_some(),
        "invite stored under {code}"
    );
    code
}

#[rstest]
#[tokio::test]
async fn test_share_tile_shows_invite_link_and_revoke_removes_it(
    #[from(test_store_context)]
    #[future]
    context: TestStoreContext,
) {
    let context = context.await;
    setup_share_fixtures(&context).await;
    let invite_store = SqliteInviteStore::new(context.cal_store.clone());
    let app = get_app(context);

    let code = mint_invite(
        &app,
        &invite_store,
        "principal=testgroup&kind=calendar&collection_id=groupcal",
    )
    .await;
    let url = format!("https://public.example/register?code={code}");

    // On the next page load the link persists under the group-calendar tile
    // (no one-time banner anymore).
    let req = request(
        Method::GET,
        "/frontend/user/user/share",
        "user",
        "pass",
        None,
    );
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.extract_string().await;
    assert!(body.contains("Invite link"));
    assert!(body.contains(&url), "tile shows the link");
    assert_eq!(
        body.matches(&format!("/frontend/user/user/share/invite/{code}/revoke"))
            .count(),
        1,
        "exactly one revoke form for the tile"
    );

    // Revoking the invite removes it from the tile immediately.
    let req = request(
        Method::POST,
        &format!("/frontend/user/user/share/invite/{code}/revoke"),
        "user",
        "pass",
        form("principal=testgroup"),
    );
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);

    let req = request(
        Method::GET,
        "/frontend/user/user/share",
        "user",
        "pass",
        None,
    );
    let resp = app.clone().oneshot(req).await.unwrap();
    let body = resp.extract_string().await;
    assert!(!body.contains(&url), "revoked link is gone from the tile");
    assert!(invite_store.get_invite(&code).await.unwrap().is_none());
}

#[rstest]
#[tokio::test]
async fn test_share_tile_invite_scoped_to_its_collection(
    #[from(test_store_context)]
    #[future]
    context: TestStoreContext,
) {
    let context = context.await;
    setup_share_fixtures(&context).await;
    // A group calendar with the SAME id as the user's own calendar: an invite
    // for one must not leak onto the other's tile.
    context
        .cal_store
        .insert_calendar(Calendar {
            id: "personal".to_owned(),
            principal: "testgroup".to_owned(),
            meta: CalendarMetadata {
                displayname: Some("Group Personal".to_owned()),
                order: 0,
                description: None,
                color: None,
            },
            timezone_id: None,
            deleted_at: None,
            synctoken: 0,
            subscription_url: None,
            push_topic: "share-test-group-personal".to_owned(),
            components: vec![CalendarObjectType::Event],
        })
        .await
        .unwrap();
    let invite_store = SqliteInviteStore::new(context.cal_store.clone());
    let app = get_app(context);

    let own_code = mint_invite(
        &app,
        &invite_store,
        "principal=user&kind=calendar&collection_id=personal",
    )
    .await;
    let group_code = mint_invite(
        &app,
        &invite_store,
        "principal=testgroup&kind=calendar&collection_id=personal",
    )
    .await;
    let own_url = format!("https://public.example/register?code={own_code}");
    let group_url = format!("https://public.example/register?code={group_code}");

    let req = request(
        Method::GET,
        "/frontend/user/user/share",
        "user",
        "pass",
        None,
    );
    let resp = app.clone().oneshot(req).await.unwrap();
    let body = resp.extract_string().await;
    assert!(body.contains(&own_url));
    assert!(body.contains(&group_url));

    // Each tile revokes only its own invite.
    let req = request(
        Method::POST,
        &format!("/frontend/user/user/share/invite/{own_code}/revoke"),
        "user",
        "pass",
        form("principal=user"),
    );
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);

    let req = request(
        Method::GET,
        "/frontend/user/user/share",
        "user",
        "pass",
        None,
    );
    let resp = app.oneshot(req).await.unwrap();
    let body = resp.extract_string().await;
    assert!(!body.contains(&own_url));
    assert!(
        body.contains(&group_url),
        "the other tile's invite survives"
    );
}

/// ──────────────────────────────────────────────────────────────────────────
/// Guest-shares tests (Omnical §17.10 portal flow)
/// ──────────────────────────────────────────────────────────────────────────

fn extract_between<'a>(body: &'a str, open: &str, close: &str) -> &'a str {
    let start = body.find(open).expect("open marker") + open.len();
    let rest = &body[start..];
    let end = rest.find(close).expect("close marker");
    &rest[..end]
}

fn extract_guest_username(body: &str) -> String {
    extract_between(body, "Username: <code>", "</code>").to_owned()
}

fn extract_guest_credential(body: &str) -> String {
    extract_between(body, "App token: <code>", "</code>").to_owned()
}

#[rstest]
#[tokio::test]
async fn test_guest_invite_mints_share_and_shows_credential_banner(
    #[from(test_store_context)]
    #[future]
    context: TestStoreContext,
) {
    let context = context.await;
    setup_share_fixtures(&context).await;
    let principal_store = SqlitePrincipalStore::new(context.db.clone());
    let share_store = SqliteCollectionShareStore::new(context.cal_store.clone());
    let app = get_app(context);

    let req = request(
        Method::POST,
        "/frontend/user/user/share/guest-invite",
        "user",
        "pass",
        form("principal=user&collection_id=personal&privilege=edit&email=Guest%40example.com"),
    );
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.extract_string().await;

    // One-time credential banner.
    assert!(
        body.contains("Guest access sent to guest@example.com!")
            || body.contains("Guest access created!"),
        "credential banner shown: {body}"
    );
    assert!(body.contains("https://public.example/caldav"));
    let username = extract_guest_username(&body);
    assert!(username.starts_with("guest-"), "username: {username}");
    let credential = extract_guest_credential(&body);
    let (prefix, secret) = credential.split_once('_').expect("id_token format");
    assert_eq!(prefix.len(), 4, "4-char prefix: {prefix}");
    assert_eq!(secret.len(), 64, "64-char secret: {secret}");

    // The banner shows the target email.
    assert!(body.contains("guest@example.com"));

    // Guest principal was created.
    let guest = principal_store
        .get_principal(&username)
        .await
        .unwrap()
        .expect("guest principal exists");
    assert!(guest.password.is_none(), "no portal password");
    assert_eq!(
        guest.principal_type,
        rustical_store::auth::PrincipalType::Individual
    );

    // Share row persisted.
    let shares = share_store
        .get_shares_for_collection("user", "personal")
        .await
        .unwrap();
    assert_eq!(shares.len(), 1);
    let share = &shares[0];
    assert_eq!(share.guest_principal, username);
    assert_eq!(share.privilege.as_str(), "edit");
    assert_eq!(share.target_email.as_deref(), Some("guest@example.com"));
    assert_eq!(share.created_by, "user");

    // DAV auth path: validate_app_token authenticates the guest and
    // stamps the share privilege.
    let authed = principal_store
        .validate_app_token(&username, &credential)
        .await
        .unwrap()
        .expect("valid credential");
    assert_eq!(
        authed.privilege_for(&username),
        rustical_store::auth::Privilege::Edit
    );
    assert!(authed.can_write(&username));
}

#[rstest]
#[tokio::test]
async fn test_guest_invite_rejects_non_admin_and_foreign(
    #[from(test_store_context)]
    #[future]
    context: TestStoreContext,
) {
    let context = context.await;
    setup_share_fixtures(&context).await;
    let app = get_app(context);

    // Foreign group (owned by bob) → 403.
    let req = request(
        Method::POST,
        "/frontend/user/user/share/guest-invite",
        "user",
        "pass",
        form("principal=foreigngroup&collection_id=foreigncal&privilege=view"),
    );
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // Other user's principal → 403.
    let req = request(
        Method::POST,
        "/frontend/user/user/share/guest-invite",
        "user",
        "pass",
        form("principal=bob&collection_id=personal&privilege=view"),
    );
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[rstest]
#[tokio::test]
async fn test_guest_invite_rejects_invalid_privilege(
    #[from(test_store_context)]
    #[future]
    context: TestStoreContext,
) {
    let context = context.await;
    setup_share_fixtures(&context).await;
    let share_store = SqliteCollectionShareStore::new(context.cal_store.clone());
    let app = get_app(context);

    let req = request(
        Method::POST,
        "/frontend/user/user/share/guest-invite",
        "user",
        "pass",
        form("principal=user&collection_id=personal&privilege=bogus"),
    );
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.extract_string().await;
    assert!(body.contains("Invalid privilege"), "error shown: {body}");
    assert!(
        share_store
            .get_shares_for_collection("user", "personal")
            .await
            .unwrap()
            .is_empty()
    );
}

#[rstest]
#[tokio::test]
async fn test_guest_invite_revoke_removes_access_from_tile(
    #[from(test_store_context)]
    #[future]
    context: TestStoreContext,
) {
    let context = context.await;
    setup_share_fixtures(&context).await;
    let share_store = SqliteCollectionShareStore::new(context.cal_store.clone());
    let app = get_app(context);

    // Mint a guest share.
    let req = request(
        Method::POST,
        "/frontend/user/user/share/guest-invite",
        "user",
        "pass",
        form("principal=user&collection_id=personal&privilege=view"),
    );
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Tile shows the guest row with a revoke form.
    let req = request(
        Method::GET,
        "/frontend/user/user/share",
        "user",
        "pass",
        None,
    );
    let resp = app.clone().oneshot(req).await.unwrap();
    let body = resp.extract_string().await;
    assert!(body.contains("Guest guest-"), "guest row shown");
    assert!(body.contains("· view access"), "privilege badge");
    // The revoke form points to the share id.
    let share_id = share_store
        .get_shares_for_collection("user", "personal")
        .await
        .unwrap()
        .remove(0)
        .id;
    let revoke_path = format!("/frontend/user/user/share/guest-invite/{share_id}/revoke");
    assert!(
        body.contains(&revoke_path),
        "revoke form present: {revoke_path}"
    );

    // Revoke the share.
    let req = request(
        Method::POST,
        &revoke_path,
        "user",
        "pass",
        form("principal=user"),
    );
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);

    // The tile no longer shows the guest row.
    let req = request(
        Method::GET,
        "/frontend/user/user/share",
        "user",
        "pass",
        None,
    );
    let resp = app.oneshot(req).await.unwrap();
    let body = resp.extract_string().await;
    assert!(!body.contains("Guest guest-"), "guest row gone");

    // Access resolved through get_share_by_guest is gone.
    assert!(
        share_store
            .get_shares_for_collection("user", "personal")
            .await
            .unwrap()
            .is_empty()
    );
}
