//! Portal share-route tests (PLAN.md §17.8.4 + §17.15): the per-user surface
//! for the §17.7 share-link subscriptions. The Share tab is gone — share
//! links, invites and guest shares render on the Calendars/Addressbooks
//! tabs and the POST routes redirect back there.
use super::{ResponseExtractString, get_app};
use axum::body::Body;
use axum::extract::Request;
use headers::{Authorization, HeaderMapExt};
use http::header::CONTENT_TYPE;
use http::{Method, StatusCode};
use rstest::rstest;
use rustical_ical::CalendarObjectType;
use rustical_store::SubscriptionKind;
use rustical_store::auth::{AuthenticationProvider, Principal, PrincipalType, Privilege};
use rustical_store::{
    Addressbook, AddressbookWriteStore, Calendar, CalendarMetadata, CalendarWriteStore,
    CollectionShareStore, InviteStore, SubscriptionStore,
};
use rustical_store_sqlite::tests::{TestStoreContext, test_store_context};
use rustical_store_sqlite::{
    SqliteCollectionShareStore, SqliteInviteStore, SqlitePrincipalStore, SqliteSubscriptionStore,
};
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

async fn insert_guest(
    context: &TestStoreContext,
    id: &str,
    owner: &str,
    collection: &str,
    privilege: Privilege,
) {
    context
        .principal_store
        .insert_principal(
            Principal {
                id: id.to_owned(),
                displayname: Some(format!("Guest of {collection}")),
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
    SqliteCollectionShareStore::new(context.cal_store.clone())
        .add_share(
            owner,
            collection,
            "calendar",
            privilege,
            id,
            &Some(format!("{id}@example.com")),
            owner,
        )
        .await
        .unwrap();
}

async fn insert_calendar(context: &TestStoreContext, principal: &str, id: &str, displayname: &str) {
    context
        .cal_store
        .insert_calendar(Calendar {
            id: id.to_owned(),
            principal: principal.to_owned(),
            meta: CalendarMetadata {
                displayname: Some(displayname.to_owned()),
                order: 0,
                description: None,
                color: None,
            },
            timezone_id: None,
            deleted_at: None,
            synctoken: 0,
            subscription_url: None,
            push_topic: format!("share-test-{principal}-{id}"),
            components: vec![CalendarObjectType::Event],
        })
        .await
        .unwrap();
}

/// Own calendar + addressbook, an owned group with a calendar, and a foreign
/// group (owned by `bob`) with a calendar.
async fn setup_share_fixtures(context: &TestStoreContext) {
    insert_calendar(context, "user", "personal", "Personal").await;
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
    insert_calendar(context, "testgroup", "groupcal", "Group Calendar").await;

    insert_user(context, "bob").await;
    insert_group(context, "foreigngroup", "Foreign Group", "bob").await;
    insert_calendar(context, "foreigngroup", "foreigncal", "Foreign Calendar").await;
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

async fn get_page(app: &axum::Router, uri: &str) -> String {
    let req = request(Method::GET, uri, "user", "pass", None);
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "page {uri} renders");
    resp.extract_string().await
}

#[rstest]
#[tokio::test]
async fn test_share_tab_removed_and_tile_blocks_live_on_calendars_tab(
    #[from(test_store_context)]
    #[future]
    context: TestStoreContext,
) {
    let context = context.await;
    setup_share_fixtures(&context).await;
    let app = get_app(context);

    // The Share tab is gone: no nav entry, the page 404s.
    let body = get_page(&app, "/frontend/user/user/calendar").await;
    assert!(!body.contains("/share\""), "no Share nav entry: {body}");
    let req = request(
        Method::GET,
        "/frontend/user/user/share",
        "user",
        "pass",
        None,
    );
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    // Calendars tab: own + owned-group collections are listed …
    assert!(body.contains("Personal"));
    assert!(body.contains("Group Calendar"));
    // … but not collections of groups the user does not own.
    assert!(!body.contains("Foreign Calendar"));
    // No share link exists yet, so no URL is shown anywhere on the page.
    assert!(!body.contains("/export/"));
    // The subscribe-block label and per-tile create button are present.
    assert!(body.contains("Subscribe link (read-only)"));
    assert!(body.contains("Create subscribe link"));
    // The full-access block with its label renders on every tile.
    assert!(body.contains("Full access (CalDAV)"));
    // Per-client instructions render with the client matrix (§17.15 §6).
    assert!(body.contains("Set up on your device"));
    assert!(body.contains("Google Calendar"));
    assert!(body.contains("DAVx5"));
    assert!(body.contains("not possible"));

    // Addressbooks tab: the share-link block lives there now.
    let body = get_page(&app, "/frontend/user/user/addressbook").await;
    assert!(body.contains("Contacts"));
    assert!(body.contains("Share link (read-only)"));
    assert!(body.contains("Create share link"));
    assert!(!body.contains("/export/"));
}

#[rstest]
#[tokio::test]
async fn test_share_create_shows_url_on_calendar_tile_and_serves_export(
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
        "/frontend/user/user/calendar#cal-personal"
    );

    let body = get_page(&app, "/frontend/user/user/calendar").await;
    let url = extract_share_url(&body, ".ics");
    let token = url
        .trim_start_matches("https://public.example/export/")
        .trim_end_matches(".ics");
    assert_eq!(token.len(), 64, "app-token shape: {url}");
    assert!(token.chars().all(|c| c.is_ascii_alphanumeric()));

    // The tile carries the create button again for that calendar? No — the
    // minted tile shows the URL instead; the create button remains only on
    // the group tile.
    assert_eq!(body.matches("Create subscribe link").count(), 1);

    // The instructions block offers both URL variants (§17.15 §6).
    let webcal_url = url.replacen("https://", "webcal://", 1);
    assert!(
        body.contains(&webcal_url),
        "webcal variant shown: {webcal_url}"
    );

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
async fn test_share_create_addressbook_shows_url_on_tile_and_serves_vcf(
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
    assert_eq!(
        resp.headers().get("location").unwrap(),
        "/frontend/user/user/addressbook#ab-contacts"
    );

    let body = get_page(&app, "/frontend/user/user/addressbook").await;
    let url = extract_share_url(&body, ".vcf");
    // The tile shows the URL with Copy + Revoke instead of the create button.
    assert_eq!(body.matches("Create share link").count(), 0);

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
    assert_eq!(
        resp.headers().get("location").unwrap(),
        "/frontend/user/user/calendar#cal-groupcal"
    );

    // The group calendar's share link shows on the user's Calendars tab …
    let body = get_page(&app, "/frontend/user/user/calendar").await;
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

    let body = get_page(&app, "/frontend/user/user/calendar").await;
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
    // The redirect anchors the tile the link belonged to.
    assert_eq!(
        resp.headers().get("location").unwrap(),
        "/frontend/user/user/calendar#cal-personal"
    );

    // The Calendars tab shows the create button again …
    let body = get_page(&app, "/frontend/user/user/calendar").await;
    assert!(body.contains("Create subscribe link"));
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
async fn test_addressbook_share_revoke_from_tile(
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

    let body = get_page(&app, "/frontend/user/user/addressbook").await;
    let url = extract_share_url(&body, ".vcf");
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
    // Addressbook revokes land back on the Addressbooks tab, anchored.
    assert_eq!(
        resp.headers().get("location").unwrap(),
        "/frontend/user/user/addressbook#ab-contacts"
    );

    let body = get_page(&app, "/frontend/user/user/addressbook").await;
    assert!(body.contains("Create share link"));
    assert!(!body.contains("/export/"));

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
async fn test_share_wrong_user_on_calendars_page(
    #[from(test_store_context)]
    #[future]
    context: TestStoreContext,
) {
    let context = context.await;
    setup_share_fixtures(&context).await;
    let app = get_app(context);

    let req = request(
        Method::GET,
        "/frontend/user/user/calendar",
        "bob",
        "bob",
        None,
    );
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

/// The `https://public.example/register?code=…` URL printed in the invite
/// banner (terminated by the closing `</code>` element). The banner wraps
/// the URL in `<code>…</code>`, unlike the persistent tile rows which use
/// `<a href="…">` — anchoring on the `<code>` keeps this stable when the
/// page also lists earlier invite rows.
fn extract_register_url(body: &str) -> String {
    const MARKER: &str = "<code>https://public.example/register?code=";
    let start = body.find(MARKER).expect("register URL in banner");
    let rest = &body[start + MARKER.len()..];
    let end = rest.find('<').expect("end of register URL");
    format!("https://public.example/register?code={}", &rest[..end])
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
async fn test_calendar_tile_shows_invite_link_and_revoke_removes_it(
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
    let body = get_page(&app, "/frontend/user/user/calendar").await;
    assert!(body.contains("Invite link"));
    assert!(body.contains(&url), "tile shows the link");
    assert!(
        !body.contains("Invite link generated"),
        "banner is one-time"
    );
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
    assert_eq!(
        resp.headers().get("location").unwrap(),
        "/frontend/user/user/calendar#cal-groupcal"
    );

    let body = get_page(&app, "/frontend/user/user/calendar").await;
    assert!(!body.contains(&url), "revoked link is gone from the tile");
    assert!(invite_store.get_invite(&code).await.unwrap().is_none());
}

#[rstest]
#[tokio::test]
async fn test_calendar_tile_invite_scoped_to_its_collection(
    #[from(test_store_context)]
    #[future]
    context: TestStoreContext,
) {
    let context = context.await;
    setup_share_fixtures(&context).await;
    // A group calendar with the SAME id as the user's own calendar: an invite
    // for one must not leak onto the other's tile.
    insert_calendar(&context, "testgroup", "personal", "Group Personal").await;
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

    let body = get_page(&app, "/frontend/user/user/calendar").await;
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

    let body = get_page(&app, "/frontend/user/user/calendar").await;
    assert!(!body.contains(&own_url));
    assert!(
        body.contains(&group_url),
        "the other tile's invite survives"
    );
}

// ──────────────────────────────────────────────────────────────────────────
// Guest-shares tests (Omnical §17.10 portal flow)
// ──────────────────────────────────────────────────────────────────────────

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
    // The banner renders exactly once — on the tile of the minted calendar,
    // not on every calendar of the Calendars tab.
    assert_eq!(
        body.matches("This one-time credential was created for")
            .count(),
        1,
        "banner rendered exactly once: {body}"
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
    let resp = app.oneshot(req).await.unwrap();
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

    // The tile shows the guest row with a revoke form.
    let body = get_page(&app, "/frontend/user/user/calendar").await;
    assert!(
        body.contains("CalDAV access: <code>guest-"),
        "guest row shown"
    );
    assert!(body.contains("· view access"), "privilege badge");
    // The revoke form points to the share id.
    let share_id = share_store
        .get_shares_for_collection("user", "personal")
        .await
        .unwrap()
        .remove(0)
        .id;
    let revoke_path = format!("/frontend/user/user/calendar/credentials/{share_id}/revoke");
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
    let body = get_page(&app, "/frontend/user/user/calendar").await;
    assert!(
        !body.contains("CalDAV access: <code>guest-"),
        "guest row gone"
    );

    // Access resolved through get_share_by_guest is gone.
    assert!(
        share_store
            .get_shares_for_collection("user", "personal")
            .await
            .unwrap()
            .is_empty()
    );
}

/// Regression for the §17.15 root-cause report ("no controls on the CAS
/// calendar"): a CAS-shaped fixture — one calendar with an existing
/// subscription, three guest shares (view/edit/admin) and zero invites —
/// must render every control on its Calendars tile.
#[rstest]
#[tokio::test]
async fn test_calendar_tile_renders_full_share_state_cas_regression(
    #[from(test_store_context)]
    #[future]
    context: TestStoreContext,
) {
    let context = context.await;
    setup_share_fixtures(&context).await;
    insert_calendar(&context, "user", "CAS", "CAS").await;
    let sub_store = SqliteSubscriptionStore::new(context.cal_store.clone());
    let invite_store = SqliteInviteStore::new(context.cal_store.clone());

    // One existing subscription (minted long ago) …
    let token = format!("CAS{}", "a".repeat(61));
    sub_store
        .add_subscription("user", SubscriptionKind::Calendar, "CAS", &token)
        .await
        .unwrap();

    // … three active guest shares with different privileges …
    insert_guest(&context, "guest-viewer", "user", "CAS", Privilege::View).await;
    insert_guest(&context, "guest-editor", "user", "CAS", Privilege::Edit).await;
    insert_guest(&context, "guest-admin", "user", "CAS", Privilege::Admin).await;

    // … and zero registration invites.
    assert!(invite_store.list_invites(false).await.unwrap().is_empty());

    let app = get_app(context);
    let body = get_page(&app, "/frontend/user/user/calendar").await;

    // The subscribe block: URL + Copy + Revoke (never a create button).
    let url = format!("https://public.example/export/{token}.ics");
    assert!(body.contains(&url), "subscribe URL shown: {body}");
    // The URL appears 5 times on the CAS tile: block anchor + text + Copy
    // button, instructions code + Copy button.
    assert_eq!(
        body.matches(&url).count(),
        5,
        "URL on the subscribe block and in the instructions"
    );
    assert!(
        body.matches("Create subscribe link").count() >= 1,
        "other tiles keep their create button"
    );
    let cas_revoke = extract_revoke_action(&body);
    assert!(
        cas_revoke.starts_with("/frontend/user/user/share/"),
        "subscribe revoke action: {cas_revoke}"
    );

    // All three guest rows render with their privilege and revoke forms.
    for (guest, privilege) in [
        ("guest-viewer", "view"),
        ("guest-editor", "edit"),
        ("guest-admin", "admin"),
    ] {
        assert!(
            body.contains(&format!("CalDAV access: <code>{guest}</code>")),
            "guest row for {guest}: {body}"
        );
        assert!(body.contains(&format!("· {privilege} access")));
    }

    // No invite rows (none minted) …
    assert!(!body.contains("Invite link for"), "no invite rows");

    // … but all three minting forms are present on the CAS tile.
    assert!(body.contains("Send invite"));
    assert!(body.contains("Generate invite link"));
    assert!(body.contains("Invite guest"));
    assert!(body.contains("Generate credentials"));
}
