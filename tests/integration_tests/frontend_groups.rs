use super::{ResponseExtractString, get_app};
use axum::body::Body;
use axum::extract::Request;
use headers::{Authorization, HeaderMapExt};
use http::Method;
use http::StatusCode;
use rstest::rstest;
use rustical_store::auth::{AuthenticationProvider, Principal, PrincipalType};
use rustical_store_sqlite::tests::{TestStoreContext, test_store_context};
use tower::ServiceExt;

async fn setup_group(context: &TestStoreContext) {
    let group_id = "testgroup";
    if context
        .principal_store
        .get_principal(group_id)
        .await
        .unwrap()
        .is_none()
    {
        context
            .principal_store
            .insert_principal(
                Principal {
                    id: group_id.to_owned(),
                    displayname: Some("Test Group".to_owned()),
                    memberships: vec![],
                    password: None,
                    principal_type: PrincipalType::Group,
                },
                false,
            )
            .await
            .unwrap();
        context
            .principal_store
            .set_group_owner(group_id, "user")
            .await
            .unwrap();
        context
            .principal_store
            .add_membership("user", group_id)
            .await
            .unwrap();
    }
}

fn auth_get(uri: &str, user: &str) -> Request<Body> {
    let mut req = Request::builder()
        .method(Method::GET)
        .uri(uri)
        .body(Body::empty())
        .unwrap();
    req.headers_mut()
        .typed_insert(Authorization::basic(user, "pass"));
    req
}

#[rstest]
#[tokio::test]
async fn test_list_groups_empty(
    #[from(test_store_context)]
    #[future]
    context: TestStoreContext,
) {
    let context = context.await;
    let app = get_app(context);

    let req = auth_get("/frontend/user/user/groups", "user");
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.extract_string().await;
    assert!(body.contains("groups"));
    assert!(body.contains("are not a member of any groups") || !body.contains("testgroup"));
}

#[rstest]
#[tokio::test]
async fn test_list_groups_with_group(
    #[from(test_store_context)]
    #[future]
    context: TestStoreContext,
) {
    let context = context.await;
    setup_group(&context).await;
    let app = get_app(context);

    let req = auth_get("/frontend/user/user/groups", "user");
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.extract_string().await;
    assert!(body.contains("Test Group"));
    assert!(body.contains("testgroup"));
}

#[rstest]
#[tokio::test]
async fn test_list_groups_wrong_user(
    #[from(test_store_context)]
    #[future]
    context: TestStoreContext,
) {
    let context = context.await;
    let app = get_app(context);

    let req = auth_get("/frontend/user/user/groups", "otheruser");
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[rstest]
#[tokio::test]
async fn test_new_group_page(
    #[from(test_store_context)]
    #[future]
    context: TestStoreContext,
) {
    let context = context.await;
    let app = get_app(context);

    let req = auth_get("/frontend/user/user/groups/new", "user");
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.extract_string().await;
    assert!(body.contains("New Group"));
    assert!(body.contains("group-create-form"));
}

#[rstest]
#[tokio::test]
async fn test_new_group_page_wrong_user(
    #[from(test_store_context)]
    #[future]
    context: TestStoreContext,
) {
    let context = context.await;
    let app = get_app(context);

    let req = auth_get("/frontend/user/user/groups/new", "otheruser");
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[rstest]
#[tokio::test]
async fn test_group_detail(
    #[from(test_store_context)]
    #[future]
    context: TestStoreContext,
) {
    let context = context.await;
    setup_group(&context).await;
    let app = get_app(context);

    let req = auth_get("/frontend/user/user/groups/testgroup", "user");
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.extract_string().await;
    assert!(body.contains("Test Group"));
    assert!(body.contains("Members"));
}

#[rstest]
#[tokio::test]
async fn test_group_detail_not_found(
    #[from(test_store_context)]
    #[future]
    context: TestStoreContext,
) {
    let context = context.await;
    let app = get_app(context);

    let req = auth_get("/frontend/user/user/groups/nonexistent", "user");
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[rstest]
#[tokio::test]
async fn test_group_detail_wrong_user(
    #[from(test_store_context)]
    #[future]
    context: TestStoreContext,
) {
    let context = context.await;
    setup_group(&context).await;
    let app = get_app(context);

    let req = auth_get("/frontend/user/user/groups/testgroup", "otheruser");
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[rstest]
#[tokio::test]
async fn test_groups_nav_tab_present(
    #[from(test_store_context)]
    #[future]
    context: TestStoreContext,
) {
    let context = context.await;
    setup_group(&context).await;
    let app = get_app(context);

    let req = auth_get("/frontend/user/user/groups", "user");
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.extract_string().await;
    assert!(body.contains("/frontend/user/user/groups"));
    assert!(body.contains("Groups"));
}
