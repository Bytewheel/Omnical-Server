//! The HawkBook download (the DAVx⁵ fork the per-client instructions keep
//! naming): a signed-in-only route serving the configured APK plus the
//! sha256 the profile intro prints next to the link.
//!
//! The design contract under test: the checksum the page shows and the bytes
//! the route serves derive from ONE startup read of ONE configured file
//! (`[frontend] hawkbook_apk`), so a link that renders can always serve,
//! and what it serves always matches what the page claims. Unset (or
//! unreadable) config ⇒ no link and a 404 — never a link at a 404.
use super::{ResponseExtractString, get_app, get_app_with_frontend_config};
use axum::body::Body;
use axum::extract::Request;
use headers::{Authorization, HeaderMapExt};
use http::{StatusCode, header};
use rstest::rstest;
use rustical_frontend::FrontendConfig;
use rustical_store_sqlite::tests::{TestStoreContext, test_store_context};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use tower::ServiceExt;

/// A request builder with the fixture principal's Basic auth (`user:pass`,
/// provisioned by the store context like in `frontend_profile_intro.rs`).
fn with_auth(mut request: Request) -> Request {
    request
        .headers_mut()
        .typed_insert(Authorization::basic("user", "pass"));
    request
}

fn authed_get(path: &str) -> Request {
    with_auth(
        Request::builder()
            .uri(path)
            .header("host", "public.example")
            .body(Body::empty())
            .unwrap(),
    )
}

fn authed_get_no_auth(path: &str) -> Request {
    Request::builder()
        .uri(path)
        .header("host", "public.example")
        .body(Body::empty())
        .unwrap()
}

/// A temp APK with deterministic bytes (enough of them to be a file, not a
/// number: the point is identity through the route, not realism — the real
/// package is 18 MB and lives on the router, not in the test tree).
fn write_fake_apk() -> PathBuf {
    let path = std::env::temp_dir().join(format!("hawkbook-test-{}.apk", uuid::Uuid::new_v4()));
    std::fs::write(
        &path,
        "PK\u{3}\u{4}not a real zip, but a real file on a real path\ndeterministic.",
    )
    .unwrap();
    path
}

/// The page-intro and the download route must agree: the sha256 printed in
/// the New here? block is the ETag AND the sha256 of the served bytes, and
/// an unauthenticated hit never reaches the file.
#[rstest]
#[tokio::test]
async fn test_download_route_matches_the_intro_checksum(
    #[from(test_store_context)]
    #[future]
    context: TestStoreContext,
) {
    let apk_path = write_fake_apk();
    let app = get_app_with_frontend_config(
        context.await,
        FrontendConfig {
            hawkbook_apk: Some(apk_path.clone()),
            ..FrontendConfig::default()
        },
    );

    // 1. The profile intro links the download and prints the checksum.
    let page = app
        .clone()
        .oneshot(authed_get("/frontend/user/user"))
        .await
        .unwrap()
        .extract_string()
        .await;
    let sha256 = hex::encode(Sha256::digest(std::fs::read(&apk_path).unwrap()));
    assert!(
        page.contains(r#"href="/frontend/download/hawkbook.apk""#),
        "{page}"
    );
    assert!(
        page.contains(&format!("sha256sum</code>: <code>{sha256}</code>")),
        "{page}"
    );

    // 2. The route serves the exact file bytes with the APK content type.
    let response = app
        .clone()
        .oneshot(authed_get("/frontend/download/hawkbook.apk"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE).unwrap(),
        "application/vnd.android.package-archive"
    );
    assert_eq!(
        response.headers().get(header::ETAG).unwrap(),
        format!("\"{sha256}\"").as_str()
    );
    let body = response.extract_string().await;
    assert_eq!(body, std::fs::read_to_string(&apk_path).unwrap());

    // 3. Revalidation: `no-cache` means every re-download re-asks; a
    // matching If-None-Match must be a 304 (answered before the file is
    // even read), a non-matching one a full 200 — 18 MB over a
    // home-router uplink must not be re-sent just for a re-check.
    let revalidating = with_auth(
        Request::builder()
            .uri("/frontend/download/hawkbook.apk")
            .header("host", "public.example")
            .header(header::IF_NONE_MATCH, format!("\"{sha256}\""))
            .body(Body::empty())
            .unwrap(),
    );
    let response = app.clone().oneshot(revalidating).await.unwrap();
    assert_eq!(response.status(), StatusCode::NOT_MODIFIED);
    assert_eq!(
        response.headers().get(header::ETAG).unwrap(),
        format!("\"{sha256}\"").as_str()
    );
    assert!(response.extract_string().await.is_empty());

    let stale = with_auth(
        Request::builder()
            .uri("/frontend/download/hawkbook.apk")
            .header("host", "public.example")
            .header(header::IF_NONE_MATCH, "\"stale-deadbeef\"")
            .body(Body::empty())
            .unwrap(),
    );
    let response = app.clone().oneshot(stale).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(header::ETAG).unwrap(),
        format!("\"{sha256}\"").as_str()
    );

    // 4. Sessionless hits are bounced to the login form (with the way back),
    // never to the file — the package rides a home-router uplink.
    let response = app
        .clone()
        .oneshot(authed_get_no_auth("/frontend/download/hawkbook.apk"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body = response.extract_string().await;
    // redirect_uri is percent-encoded by the redirect builder; do not
    // over-specify the encoding, assert the way-back target instead.
    assert!(body.contains("/frontend/login?redirect_uri="), "{body}");

    std::fs::remove_file(&apk_path).unwrap();
}

/// Unconfigured ⇒ no link on the page and a 404 on the route, for the
/// authenticated user too: the intro never links at something this
/// deployment cannot serve.
#[rstest]
#[tokio::test]
async fn test_unconfigured_download_stays_hidden_and_absent(
    #[from(test_store_context)]
    #[future]
    context: TestStoreContext,
) {
    let app = get_app(context.await);

    let page = app
        .clone()
        .oneshot(authed_get("/frontend/user/user"))
        .await
        .unwrap()
        .extract_string()
        .await;
    assert!(!page.contains("/frontend/download/hawkbook.apk"), "{page}");

    let response = app
        .oneshot(authed_get("/frontend/download/hawkbook.apk"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}
