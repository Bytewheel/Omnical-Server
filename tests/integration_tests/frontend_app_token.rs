//! Portal profile-page app-token tests: the Regenerate action rotates the
//! secret of an existing token in place — same id, same name, same FULL
//! access. The old secret stops validating immediately, the new one is
//! shown once on the profile page, and write access (full access, not just
//! read) is proven with a DAV PUT before and after the rotation.
use super::{ResponseExtractString, get_app};
use axum::body::Body;
use axum::extract::Request;
use headers::{Authorization, HeaderMapExt};
use http::{Method, StatusCode};
use rstest::rstest;
use rustical_store::auth::AuthenticationProvider;
use rustical_store_sqlite::tests::{TestStoreContext, test_store_context};
use tower::ServiceExt;

const ICS: &str = "BEGIN:VCALENDAR\r\n\
VERSION:2.0\r\n\
PRODID:-//Omnical//Test//EN\r\n\
BEGIN:VEVENT\r\n\
UID:regen-{uid}@test\r\n\
DTSTAMP:20260923T000000Z\r\n\
DTSTART:20260924T170000Z\r\n\
DTEND:20260924T180000Z\r\n\
SUMMARY:Regen test\r\n\
END:VEVENT\r\n\
END:VCALENDAR\r\n";

fn dav_request(
    method: Method,
    uri: String,
    user: &str,
    secret: &str,
    body: Option<String>,
) -> Request<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("host", "public.example");
    if body.is_some() {
        builder = builder
            .header("Content-Type", "text/calendar")
            .header("If-None-Match", "*");
    }
    let mut request = builder
        .body(body.map_or_else(Body::empty, Body::from))
        .unwrap();
    request
        .headers_mut()
        .typed_insert(Authorization::basic(user, secret));
    request
}

fn propfind(uri: &str, user: &str, secret: &str) -> Request<Body> {
    dav_request(
        Method::from_bytes(b"PROPFIND").unwrap(),
        uri.to_owned(),
        user,
        secret,
        Some(
            "<?xml version=\"1.0\" encoding=\"utf-8\"?>\
<propfind xmlns=\"DAV:\"><prop><resourcetype/></prop></propfind>"
                .to_owned(),
        ),
    )
}

/// PUT an event into the user's `personal` calendar — the full-access proof.
async fn put_event(app: &axum::Router, secret: &str, uid: &str) -> StatusCode {
    let request = dav_request(
        Method::PUT,
        format!("/caldav/principal/user/personal/{uid}.ics"),
        "user",
        secret,
        Some(ICS.replace("{uid}", uid)),
    );
    let response = app.clone().oneshot(request).await.unwrap();
    response.status()
}

#[rstest]
#[tokio::test]
async fn test_app_token_regenerate_keeps_full_access(
    #[from(test_store_context)]
    #[future]
    context: TestStoreContext,
) {
    let context = context.await;
    let app = get_app(context.clone());

    // The fixture provisions one app token for `user`: name "test",
    // secret "pass" (full account access).
    let tokens = context
        .principal_store
        .get_app_tokens("user")
        .await
        .unwrap();
    assert_eq!(tokens.len(), 1);
    let token_id = tokens[0].id.clone();

    // Full access with the ORIGINAL secret: MKCALENDAR (admin-level write)
    // then a PUT (event write).
    let mkcalendar_body = "\
<?xml version='1.0' encoding='UTF-8' ?>\
<CAL:mkcalendar xmlns=\"DAV:\" xmlns:CAL=\"urn:ietf:params:xml:ns:caldav\">\
<set><prop><resourcetype><collection /><CAL:calendar /></resourcetype>\
<displayname>Personal</displayname></prop></set></CAL:mkcalendar>";
    let mut request = Request::builder()
        .method(Method::from_bytes(b"MKCALENDAR").unwrap())
        .uri("/caldav/principal/user/personal")
        .header("host", "public.example")
        .body(Body::from(mkcalendar_body))
        .unwrap();
    request
        .headers_mut()
        .typed_insert(Authorization::basic("user", "pass"));
    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(put_event(&app, "pass", "1").await, StatusCode::CREATED);

    // Regenerate through the portal route (HTML forms are POSTs; no CSRF
    // token on this form, same as Delete). Authenticated with the current
    // token secret via Basic auth, like the other portal tests.
    let mut request = Request::builder()
        .method(Method::POST)
        .uri(format!(
            "/frontend/user/user/app_token/{token_id}/regenerate"
        ))
        .header("host", "public.example")
        .body(Body::empty())
        .unwrap();
    request
        .headers_mut()
        .typed_insert(Authorization::basic("user", "pass"));
    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let page = response.extract_string().await;

    // One-time banner: the new secret, the token's name, the full-access
    // note, and the once-only warning.
    let new_token = page
        .split("<code class=\"share-url\">")
        .nth(1)
        .and_then(|rest| rest.split("</code>").next())
        .expect("regenerated token in banner")
        .to_owned();
    assert_eq!(new_token.len(), 69, "4-char id prefix + '_' + 64 secret");
    assert!(new_token.starts_with(&token_id[..4]));
    assert!(page.contains("regenerated!"));
    assert!(page.contains("same token, same full access"));
    assert!(page.contains("shown only once"));

    // The old secret is dead everywhere — auth now 401s on a write.
    assert_eq!(put_event(&app, "pass", "2").await, StatusCode::UNAUTHORIZED);

    // The new secret keeps FULL access: read (PROPFIND) AND write (PUT).
    let response = app
        .clone()
        .oneshot(propfind("/caldav/principal/user", "user", &new_token))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::MULTI_STATUS);
    assert_eq!(put_event(&app, &new_token, "3").await, StatusCode::CREATED);

    // Same token row — same id, same name, no extra tokens minted.
    let tokens = context
        .principal_store
        .get_app_tokens("user")
        .await
        .unwrap();
    assert_eq!(tokens.len(), 1);
    assert_eq!(tokens[0].id, token_id);
    assert_eq!(tokens[0].name, "test");
}

#[rstest]
#[tokio::test]
async fn test_app_token_regenerate_rejects_unknown_and_foreign(
    #[from(test_store_context)]
    #[future]
    context: TestStoreContext,
) {
    let context = context.await;
    let app = get_app(context.clone());

    // A second user with their own token — regenerating it through the
    // first user's profile must not work.
    context
        .principal_store
        .insert_principal(
            rustical_store::auth::Principal {
                id: "other".to_owned(),
                displayname: None,
                memberships: vec![],
                password: None,
                principal_type: rustical_store::auth::PrincipalType::Individual,
                needs_password_change: false,
                privileges: Default::default(),
            },
            false,
        )
        .await
        .unwrap();
    context
        .principal_store
        .add_app_token("other", "foreign".to_owned(), "foreign-secret".to_owned())
        .await
        .unwrap();
    let foreign_id = context
        .principal_store
        .get_app_tokens("other")
        .await
        .unwrap()[0]
        .id
        .clone();

    // Authenticated as `user` (fixture token "pass"):
    // - unknown token id → 404
    // - the other user's token id → 404 (token lookup is scoped to the
    //   acting user, so a foreign id is indistinguishable from unknown)
    for id in ["00000000-0000-0000-0000-000000000000", &foreign_id] {
        let mut request = Request::builder()
            .method(Method::POST)
            .uri(format!("/frontend/user/user/app_token/{id}/regenerate"))
            .header("host", "public.example")
            .body(Body::empty())
            .unwrap();
        request
            .headers_mut()
            .typed_insert(Authorization::basic("user", "pass"));
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
    // The foreign user's secret still works — untouched by the attempts.
    let response = app
        .clone()
        .oneshot(propfind(
            "/caldav/principal/other",
            "other",
            "foreign-secret",
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::MULTI_STATUS);
}
