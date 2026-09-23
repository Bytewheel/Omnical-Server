//! Portal Calendars-screen tests for per-calendar credential generation: the
//! "Generate credentials" action mints a fresh `guest-{uuid}` principal +
//! app token scoped by a `collection_shares` row to exactly one calendar with
//! `admin` privilege (full read / write / admin), shows the credential once,
//! and is only permitted for the user's own calendars or groups they admin.
use super::{ResponseExtractString, get_app};
use rustical_store::SubscriptionStore;
use rustical_store::auth::{AuthenticationProvider, Principal, PrincipalType, Privilege};
use rustical_store::{Calendar, CalendarMetadata, CalendarWriteStore, CollectionShareStore};
use rustical_store_sqlite::tests::{TestStoreContext, test_store_context};
use rustical_store_sqlite::{
    SqliteCollectionShareStore, SqlitePrincipalStore, SqliteSubscriptionStore,
};
use tower::ServiceExt;

use axum::body::Body;
use axum::extract::Request;
use headers::{Authorization, HeaderMapExt};
use http::header::CONTENT_TYPE;
use http::{Method, StatusCode};
use rstest::rstest;

async fn insert_group(
    context: &TestStoreContext,
    group_id: &str,
    owner: &str,
    member: Option<&str>,
) {
    context
        .principal_store
        .insert_principal(
            Principal {
                id: group_id.to_owned(),
                displayname: Some(group_id.to_owned()),
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
    if let Some(member) = member {
        context
            .principal_store
            .add_membership(member, group_id)
            .await
            .unwrap();
    }
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

/// One calendar per principal: own `personal`, admin group `testgroup`'s
/// `groupcal`, edit-only group `editablegroup`'s `editablecal` (user is a
/// member with the default `edit` privilege — not an admin), and bob's
/// `foreigngroup`/`foreigncal` (user is not a member at all).
async fn setup_calendar_fixtures(context: &TestStoreContext) {
    for (principal, id, displayname) in [
        ("user", "personal", "Personal"),
        ("testgroup", "groupcal", "Group Calendar"),
        ("editablegroup", "editablecal", "Editable Calendar"),
        ("foreigngroup", "foreigncal", "Foreign Calendar"),
    ] {
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
                push_topic: format!("calendar-cred-{id}"),
                components: vec![],
            })
            .await
            .unwrap();
    }
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

fn extract_credential_body(body: &str, marker: &str) -> String {
    let start = body.find(marker).expect(marker) + marker.len();
    let rest = &body[start..];
    let end = rest.find("</code>").expect("credential code end");
    rest[..end].to_owned()
}

fn extract_guest_username(body: &str) -> String {
    extract_credential_body(body, "Username: <code>")
}

fn extract_guest_credential(body: &str) -> String {
    extract_credential_body(body, "App token: <code>")
}

/// Setup with `editablegroup` (member, edit-only) so we can test both the
/// visible button gating and the POST rejection for non-admin groups.
async fn setup_fixtures(context: &TestStoreContext) {
    insert_user(context, "bob").await;
    insert_group(context, "testgroup", "user", None).await;
    insert_group(context, "editablegroup", "bob", Some("user")).await;
    insert_group(context, "foreigngroup", "bob", None).await;
    setup_calendar_fixtures(context).await;
}

#[rstest]
#[tokio::test]
async fn test_calendars_page_shows_generate_button_only_for_admin_tiles(
    #[from(test_store_context)]
    #[future]
    context: TestStoreContext,
) {
    let context = context.await;
    setup_fixtures(&context).await;
    let app = get_app(context);

    let req = request(
        Method::GET,
        "/frontend/user/user/calendar",
        "user",
        "pass",
        None,
    );
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.extract_string().await;

    // Own and admin-group calendars get a Generate-credentials form pointing
    // at the new route with the right hidden fields.
    assert_eq!(
        body.matches("/frontend/user/user/calendar/credentials")
            .count(),
        2,
        "exactly the two mintable tiles get a generate button"
    );
    let personal_form = "name=\"principal\" value=\"user\"";
    let group_form = "name=\"principal\" value=\"testgroup\"";
    assert!(body.contains(personal_form), "own calendar form present");
    assert!(
        body.contains(group_form),
        "admin-group calendar form present"
    );

    // The edit-only group's calendar is listed but has no generate button.
    assert!(
        body.contains("Editable Calendar"),
        "edit-only calendar still listed"
    );
    let tile_start = body.find("Editable Calendar").expect("tile present");
    let tile_end = tile_start + body[tile_start..].find("</li>").expect("tile end");
    assert!(
        !body[tile_start..tile_end].contains("Generate credentials"),
        "no generate button on the edit-only tile"
    );

    // Foreign group's calendars are not visible at all.
    assert!(!body.contains("Foreign Calendar"));
}

#[rstest]
#[tokio::test]
async fn test_calendar_credentials_mints_admin_share_and_shows_banner(
    #[from(test_store_context)]
    #[future]
    context: TestStoreContext,
) {
    let context = context.await;
    setup_fixtures(&context).await;
    let principal_store = SqlitePrincipalStore::new(context.db.clone());
    let share_store = SqliteCollectionShareStore::new(context.cal_store.clone());
    let app = get_app(context);

    let req = request(
        Method::POST,
        "/frontend/user/user/calendar/credentials",
        "user",
        "pass",
        form("principal=user&calendar_id=personal"),
    );
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.extract_string().await;

    // One-time credential banner.
    assert!(
        body.contains("Calendar credentials generated!"),
        "banner shown: {body}"
    );
    assert!(body.contains("https://public.example/caldav"), "server URL");
    let username = extract_guest_username(&body);
    assert!(username.starts_with("guest-"), "username: {username}");
    let credential = extract_guest_credential(&body);
    let (prefix, secret) = credential.split_once('_').expect("id_token format");
    assert_eq!(prefix.len(), 4, "4-char prefix: {prefix}");
    assert_eq!(secret.len(), 64, "64-char secret: {secret}");

    // Guest principal created without a portal password.
    let guest = principal_store
        .get_principal(&username)
        .await
        .unwrap()
        .expect("guest principal exists");
    assert!(guest.password.is_none(), "no portal password");
    assert_eq!(guest.principal_type, PrincipalType::Individual);

    // Share row persisted with FULL admin privilege, scoped to this calendar.
    let shares = share_store
        .get_shares_for_collection("user", "personal")
        .await
        .unwrap();
    assert_eq!(shares.len(), 1);
    let share = &shares[0];
    assert_eq!(share.guest_principal, username);
    assert_eq!(share.collection_id, "personal");
    assert_eq!(share.privilege.as_str(), "admin");
    assert_eq!(share.created_by, "user");

    // DAV auth path: the credential authenticates the guest with admin.
    let authed = principal_store
        .validate_app_token(&username, &credential)
        .await
        .unwrap()
        .expect("valid credential");
    assert_eq!(authed.privilege_for(&username), Privilege::Admin);
    assert!(authed.can_write(&username));
    assert!(authed.is_admin(&username));
}

#[rstest]
#[tokio::test]
async fn test_calendar_credentials_group_calendar_and_email_target(
    #[from(test_store_context)]
    #[future]
    context: TestStoreContext,
) {
    let context = context.await;
    setup_fixtures(&context).await;
    let share_store = SqliteCollectionShareStore::new(context.cal_store.clone());
    let app = get_app(context);

    let req = request(
        Method::POST,
        "/frontend/user/user/calendar/credentials",
        "user",
        "pass",
        form("principal=testgroup&calendar_id=groupcal&email=Guest%40example.com"),
    );
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.extract_string().await;
    assert!(body.contains("Calendar credentials generated!"));
    assert!(
        body.contains("and sent to guest@example.com"),
        "email banner"
    );

    let shares = share_store
        .get_shares_for_collection("testgroup", "groupcal")
        .await
        .unwrap();
    assert_eq!(shares.len(), 1);
    assert_eq!(shares[0].privilege.as_str(), "admin");
    assert_eq!(shares[0].target_email.as_deref(), Some("guest@example.com"));

    let req = request(
        Method::POST,
        "/frontend/user/user/calendar/credentials",
        "user",
        "pass",
        form("principal=user&calendar_id=personal&email=notanemail"),
    );
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.extract_string().await;
    assert!(
        body.contains("Please enter a valid email address."),
        "error shown: {body}"
    );
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
async fn test_calendar_credentials_rejects_non_admin_and_foreign(
    #[from(test_store_context)]
    #[future]
    context: TestStoreContext,
) {
    let context = context.await;
    setup_fixtures(&context).await;
    let share_store = SqliteCollectionShareStore::new(context.cal_store.clone());
    let app = get_app(context);

    // Edit-only group → 403 (minting admin credentials requires admin).
    let req = request(
        Method::POST,
        "/frontend/user/user/calendar/credentials",
        "user",
        "pass",
        form("principal=editablegroup&calendar_id=editablecal&privilege=view"),
    );
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // Foreign group → 403.
    let req = request(
        Method::POST,
        "/frontend/user/user/calendar/credentials",
        "user",
        "pass",
        form("principal=foreigngroup&calendar_id=foreigncal"),
    );
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // Other user's principal → 403.
    let req = request(
        Method::POST,
        "/frontend/user/user/calendar/credentials",
        "user",
        "pass",
        form("principal=bob&calendar_id=personal"),
    );
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

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
async fn test_calendar_credentials_rejects_unknown_collection(
    #[from(test_store_context)]
    #[future]
    context: TestStoreContext,
) {
    let context = context.await;
    setup_fixtures(&context).await;
    let share_store = SqliteCollectionShareStore::new(context.cal_store.clone());
    let app = get_app(context);

    let req = request(
        Method::POST,
        "/frontend/user/user/calendar/credentials",
        "user",
        "pass",
        form("principal=user&calendar_id=nope"),
    );
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.extract_string().await;
    assert!(body.contains("No such calendar"), "error shown: {body}");
    assert!(body.contains("nope"));
    assert!(
        share_store
            .get_shares_for_collection("user", "nope")
            .await
            .unwrap()
            .is_empty()
    );
}

#[rstest]
#[tokio::test]
async fn test_calendar_credentials_revoke_removes_access_and_hides_row(
    #[from(test_store_context)]
    #[future]
    context: TestStoreContext,
) {
    let context = context.await;
    setup_fixtures(&context).await;
    let principal_store = SqlitePrincipalStore::new(context.db.clone());
    let share_store = SqliteCollectionShareStore::new(context.cal_store.clone());
    let app = get_app(context);

    // Mint a credential for the own calendar, then for the admin group's
    // calendar too, so the group-calendar revoke path is covered as well.
    let req = request(
        Method::POST,
        "/frontend/user/user/calendar/credentials",
        "user",
        "pass",
        form("principal=user&calendar_id=personal"),
    );
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let mint_body = resp.extract_string().await;
    let username = extract_guest_username(&mint_body);
    let credential = extract_guest_credential(&mint_body);

    let personal_shares = share_store
        .get_shares_for_collection("user", "personal")
        .await
        .unwrap();
    assert_eq!(personal_shares.len(), 1);
    let personal_share_id = personal_shares[0].id.clone();

    let req = request(
        Method::POST,
        "/frontend/user/user/calendar/credentials",
        "user",
        "pass",
        form("principal=testgroup&calendar_id=groupcal"),
    );
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let group_shares = share_store
        .get_shares_for_collection("testgroup", "groupcal")
        .await
        .unwrap();
    assert_eq!(group_shares.len(), 1);
    let group_share_id = group_shares[0].id.clone();

    // The Calendars screen lists both credentials with a Revoke control.
    let req = request(
        Method::GET,
        "/frontend/user/user/calendar",
        "user",
        "pass",
        None,
    );
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.extract_string().await;
    assert!(
        body.contains(&format!("CalDAV access: <code>{username}</code>")),
        "credential row shown: {body}"
    );
    assert!(body.contains("admin access"), "full-access label present");
    let personal_revoke =
        format!("/frontend/user/user/calendar/credentials/{personal_share_id}/revoke");
    let group_revoke = format!("/frontend/user/user/calendar/credentials/{group_share_id}/revoke");
    assert!(
        body.contains(&personal_revoke),
        "personal revoke action present"
    );
    assert!(body.contains(&group_revoke), "group revoke action present");

    // Revoke the personal credential → redirect back to the Calendars screen.
    let req = request(
        Method::POST,
        &personal_revoke,
        "user",
        "pass",
        form("principal=user"),
    );
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    drop(resp);

    // The share row is revoked: revoked rows no longer resolve access (the
    // row is kept for audit — covered by the store-sqlite unit tests).
    let shares = share_store
        .get_shares_for_collection("user", "personal")
        .await
        .unwrap();
    assert!(
        shares.is_empty(),
        "revoked credential no longer resolves access"
    );
    assert!(
        share_store
            .get_share_by_guest(&username)
            .await
            .unwrap()
            .is_none(),
        "revoked row is filtered out of active-share lookups"
    );
    let authed = principal_store
        .validate_app_token(&username, &credential)
        .await
        .unwrap()
        .expect("revoked guest still authenticates (no privileges)");
    assert!(
        !authed.privileges.contains_key(&username),
        "revoked credential has no stamped access"
    );

    // The Calendars screen no longer lists the revoked credential.
    let req = request(
        Method::GET,
        "/frontend/user/user/calendar",
        "user",
        "pass",
        None,
    );
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.extract_string().await;
    assert!(
        !body.contains(&format!("CalDAV access: <code>{username}</code>")),
        "credential row gone: {body}"
    );
    assert!(!body.contains(&personal_revoke), "personal revoke gone");
    assert!(
        body.contains(&group_revoke),
        "group credential still listed after its sibling's revoke"
    );

    // Revoke the group credential the same way (admin of the group).
    let req = request(
        Method::POST,
        &group_revoke,
        "user",
        "pass",
        form("principal=testgroup"),
    );
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let shares = share_store
        .get_shares_for_collection("testgroup", "groupcal")
        .await
        .unwrap();
    assert!(shares.is_empty(), "group share revoked");
}

#[rstest]
#[tokio::test]
async fn test_calendar_credentials_revoke_rejects_non_admin_and_foreign(
    #[from(test_store_context)]
    #[future]
    context: TestStoreContext,
) {
    let context = context.await;
    setup_fixtures(&context).await;
    let share_store = SqliteCollectionShareStore::new(context.cal_store.clone());
    let app = get_app(context);

    // bob (admin of `editablegroup`) mints a credential for its calendar so a
    // real share exists to try to revoke.
    let req = request(
        Method::POST,
        "/frontend/user/bob/calendar/credentials",
        "bob",
        "bob",
        form("principal=editablegroup&calendar_id=editablecal"),
    );
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let share = share_store
        .get_shares_for_collection("editablegroup", "editablecal")
        .await
        .unwrap()
        .into_iter()
        .next()
        .expect("share minted");
    let revoke = format!(
        "/frontend/user/user/calendar/credentials/{}/revoke",
        share.id
    );

    // Edit-only member of the group → 403 (revoking requires group admin).
    let req = request(
        Method::POST,
        &revoke,
        "user",
        "pass",
        form("principal=editablegroup"),
    );
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let shares = share_store
        .get_shares_for_collection("editablegroup", "editablecal")
        .await
        .unwrap();
    assert_eq!(shares.len(), 1);
    assert!(shares[0].revoked_at.is_none(), "share still active");

    // Foreign principal → 403.
    let req = request(
        Method::POST,
        &revoke,
        "user",
        "pass",
        form("principal=foreigngroup"),
    );
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let shares = share_store
        .get_shares_for_collection("editablegroup", "editablecal")
        .await
        .unwrap();
    assert!(shares[0].revoked_at.is_none(), "share still active");

    // Revoking on behalf of another user's page → 401.
    let req = request(
        Method::POST,
        &format!(
            "/frontend/user/bob/calendar/credentials/{}/revoke",
            share.id
        ),
        "user",
        "pass",
        form("principal=editablegroup"),
    );
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[rstest]
#[tokio::test]
async fn test_calendar_subscribe_mints_url_shown_on_tile(
    #[from(test_store_context)]
    #[future]
    context: TestStoreContext,
) {
    let context = context.await;
    setup_fixtures(&context).await;
    let sub_store = SqliteSubscriptionStore::new(context.cal_store.clone());
    let app = get_app(context);

    // Before minting: every listed calendar the user may write (own, admin
    // group, edit group) offers the Subscribe URL button — three tiles.
    let req = request(
        Method::GET,
        "/frontend/user/user/calendar",
        "user",
        "pass",
        None,
    );
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.extract_string().await;
    assert_eq!(
        body.matches("/frontend/user/user/calendar/subscribe")
            .count(),
        3,
        "own + admin-group + edit-group tiles get a subscribe button"
    );
    assert!(!body.contains("/export/"), "no share link exists yet");

    // Mint for the own calendar → redirect back to the Calendars screen.
    let req = request(
        Method::POST,
        "/frontend/user/user/calendar/subscribe",
        "user",
        "pass",
        form("principal=user&calendar_id=personal"),
    );
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);

    // The tile now shows the credential-less URL; the create button for that
    // tile is gone (two remain: the group calendars).
    let req = request(
        Method::GET,
        "/frontend/user/user/calendar",
        "user",
        "pass",
        None,
    );
    let resp = app.clone().oneshot(req).await.unwrap();
    let body = resp.extract_string().await;
    assert!(
        body.contains("https://public.example/export/"),
        "export URL shown on the tile"
    );
    assert_eq!(
        body.matches("/frontend/user/user/calendar/subscribe")
            .count(),
        2,
        "the minted tile no longer offers a create button"
    );

    // Exactly one subscription row, and the URL is served publicly.
    let subs = sub_store.get_subscriptions("user").await.unwrap();
    assert_eq!(subs.len(), 1, "one subscription minted");
    let url = format!("https://public.example/export/{}.ics", subs[0].token);
    assert!(
        body.contains(&url),
        "tile shows the subscription URL: {url}"
    );
    let req = Request::builder()
        .method(Method::GET)
        .uri(&url["https://public.example".len()..])
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "export feed serves");

    // Minting again reuses the same subscription (stable URL, no pile-up).
    let req = request(
        Method::POST,
        "/frontend/user/user/calendar/subscribe",
        "user",
        "pass",
        form("principal=user&calendar_id=personal"),
    );
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let subs = sub_store.get_subscriptions("user").await.unwrap();
    assert_eq!(subs.len(), 1, "existing subscription reused");
}

#[rstest]
#[tokio::test]
async fn test_calendar_subscribe_rejects_foreign_and_unknown(
    #[from(test_store_context)]
    #[future]
    context: TestStoreContext,
) {
    let context = context.await;
    setup_fixtures(&context).await;
    let sub_store = SqliteSubscriptionStore::new(context.cal_store.clone());
    let app = get_app(context);

    // Foreign principal (no membership at all) → 403, nothing minted.
    let req = request(
        Method::POST,
        "/frontend/user/user/calendar/subscribe",
        "user",
        "pass",
        form("principal=foreigngroup&calendar_id=foreigncal"),
    );
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // Unknown calendar → error banner, nothing minted.
    let req = request(
        Method::POST,
        "/frontend/user/user/calendar/subscribe",
        "user",
        "pass",
        form("principal=user&calendar_id=nope"),
    );
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.extract_string().await;
    assert!(
        body.contains("No such calendar &#39;nope&#39; for &#39;user&#39;."),
        "error banner shown: {body}"
    );
    assert!(
        sub_store
            .get_subscriptions("user")
            .await
            .unwrap()
            .is_empty()
    );

    // Another user's page → 401.
    let req = request(
        Method::POST,
        "/frontend/user/bob/calendar/subscribe",
        "user",
        "pass",
        form("principal=user&calendar_id=personal"),
    );
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

/// The calendar detail page (the tile link target) shows the per-client
/// setup instructions — not the old raw calendar JSON dump: with a subscribe
/// link minted, the export + webcal URLs and the CalDAV server URL appear;
/// without one, the page points back to the Calendars tab.
#[rstest]
#[tokio::test]
async fn test_calendar_detail_page_shows_setup_instructions(
    #[from(test_store_context)]
    #[future]
    context: TestStoreContext,
) {
    let context = context.await;
    setup_fixtures(&context).await;
    let sub_store = SqliteSubscriptionStore::new(context.cal_store.clone());
    let app = get_app(context);

    // Mint a subscribe link for the own calendar first.
    let req = request(
        Method::POST,
        "/frontend/user/user/calendar/subscribe",
        "user",
        "pass",
        form("principal=user&calendar_id=personal"),
    );
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let subs = sub_store.get_subscriptions("user").await.unwrap();
    assert_eq!(subs.len(), 1);

    // Detail page of the own calendar: instructions, no JSON dump.
    let req = request(
        Method::GET,
        "/frontend/user/user/calendar/personal",
        "user",
        "pass",
        None,
    );
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.extract_string().await;
    assert!(!body.contains("Debug information"), "JSON dump gone");
    assert!(
        body.contains("Set up on your device"),
        "setup instructions present: {body}"
    );
    let url = format!("https://public.example/export/{}.ics", subs[0].token);
    assert!(body.contains(&url), "subscribe URL shown: {url}");
    assert!(
        body.contains("webcal://public.example/export/"),
        "webcal:// variant offered"
    );
    assert!(
        body.contains("https://public.example/caldav"),
        "CalDAV server URL prefilled"
    );
    assert!(body.contains("DAVx5"));
    assert!(body.contains("Thunderbird"));

    // Detail page of a group calendar without a subscribe link (tile links
    // use the owning principal in the path): the fallback points to the
    // Calendars tab, CalDAV instructions still shown.
    let req = request(
        Method::GET,
        "/frontend/user/editablegroup/calendar/editablecal",
        "user",
        "pass",
        None,
    );
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.extract_string().await;
    assert!(!body.contains("/export/"), "no subscribe link exists");
    assert!(
        body.contains("Create a subscribe link on the"),
        "fallback points to the Calendars tab: {body}"
    );
    assert!(
        body.contains("/frontend/user/user/calendar#cal-editablecal"),
        "tile anchor linked: {body}"
    );
    assert!(
        body.contains("https://public.example/caldav"),
        "CalDAV instructions still shown"
    );

    // Someone else's page → 401.
    let req = request(
        Method::GET,
        "/frontend/user/bob/calendar/personal",
        "user",
        "pass",
        None,
    );
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}
