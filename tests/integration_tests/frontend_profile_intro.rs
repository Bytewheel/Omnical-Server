//! The profile page is the landing page of every signed-in session, so the
//! Omnical introduction ("no calendar on this website — your apps display,
//! this server stores") has to survive past the one-time onboarding page.
//! It renders collapsed in HTML and is expanded client-side on first sight
//! per browser, then dismissed by collapsing (`localStorage`, no server
//! state). Users who registered before the onboarding page existed — the
//! exact case that motivated it (2026-10-06: l.mari.222 registered under the
//! old credential card) — therefore see the introduction in full on their
//! next login.
use super::{ResponseExtractString, get_app};
use axum::body::Body;
use axum::extract::Request;
use headers::{Authorization, HeaderMapExt};
use http::StatusCode;
use rstest::rstest;
use rustical_store_sqlite::tests::{TestStoreContext, test_store_context};
use tower::ServiceExt;

#[rstest]
#[tokio::test]
async fn test_profile_page_carries_the_intro_and_its_dismiss_logic(
    #[from(test_store_context)]
    #[future]
    context: TestStoreContext,
) {
    let context = context.await;
    let app = get_app(context);

    // The fixture provisions one app token for `user`: secret "pass".
    let mut request = Request::builder()
        .uri("/frontend/user/user")
        .header("host", "public.example")
        .body(Body::empty())
        .unwrap();
    request
        .headers_mut()
        .typed_insert(Authorization::basic("user", "pass"));
    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let page = response.extract_string().await;

    // The introduction itself.
    assert!(page.contains("what-is-omnical"), "{page}");
    assert!(page.contains("New here? What is Omnical"), "{page}");
    assert!(
        page.contains("This website has no calendar on it"),
        "{page}"
    );

    // The expand-until-dismissed logic: a first visit (no localStorage key)
    // must open the details, and a collapse must be what remembers the
    // dismissal. Both live in the inline script, so the markers are the
    // storage key and the two toggle branches — enough to notice if the
    // script is dropped or the key renamed without the other.
    assert!(page.contains("omnical-intro-dismissed"), "{page}");
    assert!(page.contains("setAttribute('open', '')"), "{page}");
    assert!(page.contains("storage.setItem(KEY, '1')"), "{page}");

    // Not server-side-open: the details element itself ships closed, so the
    // expansion is purely the browser's decision (and private-mode browsers
    // that block storage still get the collapsed summary).
    assert!(!page.contains("<details class=\"client-help\" id=\"what-is-omnical\" open"));
}
