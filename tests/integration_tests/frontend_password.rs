//! Portal forced-password-change tests (Omnical sharing): the
//! `needs_password_change` gate redirects every portal page to the change
//! form until the user rotates their password; the form verifies the current
//! password, applies the new hash, and lifts the gate.
use super::{ResponseExtractString, get_app};
use argon2::password_hash::{PasswordHasher, SaltString};
use axum::body::Body;
use axum::extract::Request;
use headers::{Authorization, HeaderMapExt};
use http::{Method, StatusCode};
use rstest::rstest;
use rustical_store::Secret;
use rustical_store::auth::{AuthenticationProvider, Principal, PrincipalType};
use rustical_store_sqlite::tests::{TestStoreContext, test_store_context};
use tower::ServiceExt;

/// Minimum accepted password length (mirrors `FrontendConfig` default).
const MIN_PASSWORD_LENGTH: usize = 12;

fn hash_password(password: &str) -> String {
    let salt = SaltString::encode_b64(b"0123456789abcdef").unwrap();
    argon2::Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .unwrap()
        .to_string()
}

/// A real user (password stored, unconditional needs-password-change flag).
async fn insert_user_with_password(context: &TestStoreContext, id: &str, password: &str) {
    context
        .principal_store
        .insert_principal(
            Principal {
                id: id.to_owned(),
                displayname: Some(id.to_owned()),
                principal_type: PrincipalType::Individual,
                password: Some(Secret::from(hash_password(password))),
                memberships: vec![],
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
        builder = builder.header("content-type", "application/x-www-form-urlencoded");
    }
    let mut request = builder.body(body.unwrap_or_else(Body::empty)).unwrap();
    request
        .headers_mut()
        .typed_insert(Authorization::basic(user, pass));
    request
}

fn change_form(current: &str, new: &str, confirm: &str) -> Option<String> {
    Some(format!(
        "current_password={current}&new_password={new}&new_password_confirm={confirm}"
    ))
}

#[rstest]
#[tokio::test]
async fn test_password_gate_redirects_every_portal_page(
    #[from(test_store_context)]
    #[future]
    context: TestStoreContext,
) {
    let context = context.await;
    insert_user_with_password(&context, "pwduser", "oldpassword").await;
    context
        .principal_store
        .set_needs_password_change("pwduser", true)
        .await
        .unwrap();
    let app = get_app(context);

    let req = request(
        Method::GET,
        "/frontend/user/pwduser/share",
        "pwduser",
        "pwduser",
        None,
    );
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        resp.headers().get("location").unwrap(),
        "/frontend/user/pwduser/password"
    );
}

#[rstest]
#[tokio::test]
async fn test_password_gate_skips_users_without_a_password(
    #[from(test_store_context)]
    #[future]
    context: TestStoreContext,
) {
    // The shared fixture "user" has no stored password — even an explicit
    // flag must not dead-lock such accounts (OIDC-only users etc.).
    let context = context.await;
    context
        .principal_store
        .set_needs_password_change("user", true)
        .await
        .unwrap();
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
}

#[rstest]
#[tokio::test]
async fn test_password_page_renders_when_flagged(
    #[from(test_store_context)]
    #[future]
    context: TestStoreContext,
) {
    let context = context.await;
    insert_user_with_password(&context, "pwduser", "oldpassword").await;
    context
        .principal_store
        .set_needs_password_change("pwduser", true)
        .await
        .unwrap();
    let app = get_app(context);

    let req = request(
        Method::GET,
        "/frontend/user/pwduser/password",
        "pwduser",
        "pwduser",
        None,
    );
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.extract_string().await;
    assert!(body.contains("Change your password"));
    assert!(body.contains("current_password"));
    assert!(body.contains("new_password"));
    assert!(body.contains(&format!("minlength=\"{MIN_PASSWORD_LENGTH}\"")));
}

#[rstest]
#[tokio::test]
async fn test_change_password_success_clears_flag_and_lifts_gate(
    #[from(test_store_context)]
    #[future]
    context: TestStoreContext,
) {
    let context = context.await;
    insert_user_with_password(&context, "pwduser", "oldpassword").await;
    context
        .principal_store
        .set_needs_password_change("pwduser", true)
        .await
        .unwrap();
    let app = get_app(context.clone());

    let req = request(
        Method::POST,
        "/frontend/user/pwduser/password",
        "pwduser",
        "pwduser",
        change_form("oldpassword", "brandnewpassword", "brandnewpassword"),
    );
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        resp.headers().get("location").unwrap(),
        "/frontend/user/pwduser"
    );

    // Flag cleared, new password active, old password dead.
    assert!(
        !context
            .principal_store
            .get_needs_password_change("pwduser")
            .await
            .unwrap()
    );
    assert!(
        context
            .principal_store
            .validate_password("pwduser", "brandnewpassword")
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        context
            .principal_store
            .validate_password("pwduser", "oldpassword")
            .await
            .unwrap()
            .is_none()
    );

    // The gate is lifted: the Share page now renders instead of redirecting.
    let req = request(
        Method::GET,
        "/frontend/user/pwduser/share",
        "pwduser",
        "pwduser",
        None,
    );
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[rstest]
#[tokio::test]
async fn test_change_password_rejects_wrong_current_password(
    #[from(test_store_context)]
    #[future]
    context: TestStoreContext,
) {
    let context = context.await;
    insert_user_with_password(&context, "pwduser", "oldpassword").await;
    context
        .principal_store
        .set_needs_password_change("pwduser", true)
        .await
        .unwrap();
    let app = get_app(context.clone());

    let req = request(
        Method::POST,
        "/frontend/user/pwduser/password",
        "pwduser",
        "pwduser",
        change_form("wrongpassword", "brandnewpassword", "brandnewpassword"),
    );
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.extract_string().await;
    assert!(body.contains("Current password is incorrect."));
    assert!(
        context
            .principal_store
            .get_needs_password_change("pwduser")
            .await
            .unwrap()
    );
}

#[rstest]
#[tokio::test]
async fn test_change_password_rejects_short_new_password(
    #[from(test_store_context)]
    #[future]
    context: TestStoreContext,
) {
    let context = context.await;
    insert_user_with_password(&context, "pwduser", "oldpassword").await;
    context
        .principal_store
        .set_needs_password_change("pwduser", true)
        .await
        .unwrap();
    let app = get_app(context);

    let req = request(
        Method::POST,
        "/frontend/user/pwduser/password",
        "pwduser",
        "pwduser",
        change_form("oldpassword", "short", "short"),
    );
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.extract_string().await;
    assert!(body.contains(&format!(
        "Password must be at least {MIN_PASSWORD_LENGTH} characters"
    )));
}

#[rstest]
#[tokio::test]
async fn test_change_password_rejects_mismatched_confirm(
    #[from(test_store_context)]
    #[future]
    context: TestStoreContext,
) {
    let context = context.await;
    insert_user_with_password(&context, "pwduser", "oldpassword").await;
    context
        .principal_store
        .set_needs_password_change("pwduser", true)
        .await
        .unwrap();
    let app = get_app(context);

    let req = request(
        Method::POST,
        "/frontend/user/pwduser/password",
        "pwduser",
        "pwduser",
        change_form("oldpassword", "brandnewpassword", "differentnewpassword"),
    );
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.extract_string().await;
    assert!(body.contains("The new passwords do not match."));
}
