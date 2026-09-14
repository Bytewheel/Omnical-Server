use axum::body::Body;
use axum::extract::Request;
use headers::{Authorization, HeaderMapExt};
use http::header::CONTENT_TYPE;
use http::{Method, StatusCode};
use rstest::rstest;
use rustical_store::auth::{AuthenticationProvider, Principal, PrincipalType};
use rustical_store_sqlite::tests::{TestStoreContext, test_store_context};
use serde_json::json;
use tower::ServiceExt;

use super::get_app;

async fn setup_group(context: &TestStoreContext) -> (String, String) {
    let group_id = "testgroup";
    let member_id = "bob";
    let owner2_id = "carol";

    for &id in &[member_id, owner2_id] {
        if context
            .principal_store
            .get_principal(id)
            .await
            .unwrap()
            .is_none()
        {
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
    }

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
                    needs_password_change: false,
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

    (group_id.to_owned(), member_id.to_owned())
}

fn auth_request(
    method: Method,
    uri: &str,
    user: &str,
    pass: &str,
    body: Option<Body>,
) -> Request<Body> {
    let mut request_builder = Request::builder().method(method).uri(uri);
    if let Some(_) = &body {
        request_builder = request_builder.header(CONTENT_TYPE, "application/json");
    }
    let mut request = if let Some(body) = body {
        request_builder.body(body).unwrap()
    } else {
        request_builder.body(Body::empty()).unwrap()
    };
    request
        .headers_mut()
        .typed_insert(Authorization::basic(user, pass));
    request
}

#[rstest]
#[tokio::test]
async fn test_list_members_empty(
    #[from(test_store_context)]
    #[future]
    context: TestStoreContext,
) {
    let context = context.await;
    let (group_id, _) = setup_group(&context).await;
    let app = get_app(context);

    let request = auth_request(
        Method::GET,
        &format!("/frontend/api/v1/groups/{group_id}/members"),
        "user",
        "pass",
        None,
    );

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = String::from_utf8(
        axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    let members: Vec<serde_json::Value> = serde_json::from_str(&body).unwrap();
    assert_eq!(members.len(), 1);
    assert_eq!(members[0]["id"], "user");
}

#[rstest]
#[tokio::test]
async fn test_add_and_list_members(
    #[from(test_store_context)]
    #[future]
    context: TestStoreContext,
) {
    let context = context.await;
    let (group_id, member_id) = setup_group(&context).await;
    let app = get_app(context);

    let add_body = json!({"user_id": member_id});
    let request = auth_request(
        Method::POST,
        &format!("/frontend/api/v1/groups/{group_id}/members"),
        "user",
        "pass",
        Some(Body::from(add_body.to_string())),
    );

    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    let request = auth_request(
        Method::GET,
        &format!("/frontend/api/v1/groups/{group_id}/members"),
        "user",
        "pass",
        None,
    );

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = String::from_utf8(
        axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    let members: Vec<serde_json::Value> = serde_json::from_str(&body).unwrap();
    assert_eq!(members.len(), 2);
    let ids: Vec<&str> = members.iter().map(|m| m["id"].as_str().unwrap()).collect();
    assert!(ids.contains(&"user"));
    assert!(ids.contains(&member_id.as_str()));
}

#[rstest]
#[tokio::test]
async fn test_remove_member(
    #[from(test_store_context)]
    #[future]
    context: TestStoreContext,
) {
    let context = context.await;
    let (group_id, member_id) = setup_group(&context).await;
    let app = get_app(context.clone());

    let add_body = json!({"user_id": member_id});
    let request = auth_request(
        Method::POST,
        &format!("/frontend/api/v1/groups/{group_id}/members"),
        "user",
        "pass",
        Some(Body::from(add_body.to_string())),
    );
    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    let request = auth_request(
        Method::DELETE,
        &format!("/frontend/api/v1/groups/{group_id}/members/{member_id}"),
        "user",
        "pass",
        None,
    );
    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let request = auth_request(
        Method::GET,
        &format!("/frontend/api/v1/groups/{group_id}/members"),
        "user",
        "pass",
        None,
    );
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = String::from_utf8(
        axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    let members: Vec<serde_json::Value> = serde_json::from_str(&body).unwrap();
    assert_eq!(members.len(), 1);
    assert_eq!(members[0]["id"], "user");
}

#[rstest]
#[tokio::test]
async fn test_non_owner_cannot_add_member(
    #[from(test_store_context)]
    #[future]
    context: TestStoreContext,
) {
    let context = context.await;
    let (group_id, member_id) = setup_group(&context).await;
    let app = get_app(context);

    let add_body = json!({"user_id": member_id});
    let request = auth_request(
        Method::POST,
        &format!("/frontend/api/v1/groups/{group_id}/members"),
        &member_id,
        &member_id,
        Some(Body::from(add_body.to_string())),
    );

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[rstest]
#[tokio::test]
async fn test_non_owner_cannot_remove_member(
    #[from(test_store_context)]
    #[future]
    context: TestStoreContext,
) {
    let context = context.await;
    let (group_id, member_id) = setup_group(&context).await;
    let app = get_app(context.clone());

    let add_body = json!({"user_id": &member_id});
    let request = auth_request(
        Method::POST,
        &format!("/frontend/api/v1/groups/{group_id}/members"),
        "user",
        "pass",
        Some(Body::from(add_body.to_string())),
    );
    app.clone().oneshot(request).await.unwrap();

    let request = auth_request(
        Method::DELETE,
        &format!("/frontend/api/v1/groups/{group_id}/members/{member_id}"),
        &member_id,
        &member_id,
        None,
    );
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[rstest]
#[tokio::test]
async fn test_unauthenticated_requests(
    #[from(test_store_context)]
    #[future]
    context: TestStoreContext,
) {
    let context = context.await;
    let (group_id, _) = setup_group(&context).await;
    let app = get_app(context);

    let request = Request::builder()
        .method(Method::GET)
        .uri(format!("/frontend/api/v1/groups/{group_id}/members"))
        .body(Body::empty())
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[rstest]
#[tokio::test]
async fn test_search_users_match(
    #[from(test_store_context)]
    #[future]
    context: TestStoreContext,
) {
    let context = context.await;
    let (_, _) = setup_group(&context).await;
    let app = get_app(context);

    let request = auth_request(
        Method::GET,
        "/frontend/api/v1/users?q=bob",
        "user",
        "pass",
        None,
    );

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = String::from_utf8(
        axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    let users: Vec<serde_json::Value> = serde_json::from_str(&body).unwrap();
    assert!(!users.is_empty());
    let ids: Vec<&str> = users.iter().map(|u| u["id"].as_str().unwrap()).collect();
    assert!(ids.contains(&"bob"));
}

#[rstest]
#[tokio::test]
async fn test_search_users_no_match(
    #[from(test_store_context)]
    #[future]
    context: TestStoreContext,
) {
    let context = context.await;
    let app = get_app(context);

    let request = auth_request(
        Method::GET,
        "/frontend/api/v1/users?q=zzzznonexistent",
        "user",
        "pass",
        None,
    );

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = String::from_utf8(
        axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    let users: Vec<serde_json::Value> = serde_json::from_str(&body).unwrap();
    assert!(users.is_empty());
}

#[rstest]
#[tokio::test]
async fn test_search_users_missing_query(
    #[from(test_store_context)]
    #[future]
    context: TestStoreContext,
) {
    let context = context.await;
    let app = get_app(context);

    let request = auth_request(Method::GET, "/frontend/api/v1/users", "user", "pass", None);

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[rstest]
#[tokio::test]
async fn test_search_users_unauthenticated(
    #[from(test_store_context)]
    #[future]
    context: TestStoreContext,
) {
    let context = context.await;
    let app = get_app(context);

    let request = Request::builder()
        .method(Method::GET)
        .uri("/frontend/api/v1/users?q=bob")
        .body(Body::empty())
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[rstest]
#[tokio::test]
async fn test_create_collection_calendar(
    #[from(test_store_context)]
    #[future]
    context: TestStoreContext,
) {
    let context = context.await;
    let (group_id, _) = setup_group(&context).await;
    let app = get_app(context);

    let body = json!({
        "group_id": group_id,
        "type": "calendar",
        "displayname": "Extra Calendar",
        "color": "#ff0000"
    });

    let request = auth_request(
        Method::POST,
        "/frontend/api/v1/collections",
        "user",
        "pass",
        Some(Body::from(body.to_string())),
    );

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
}

#[rstest]
#[tokio::test]
async fn test_create_collection_addressbook(
    #[from(test_store_context)]
    #[future]
    context: TestStoreContext,
) {
    let context = context.await;
    let (group_id, _) = setup_group(&context).await;
    let app = get_app(context);

    let body = json!({
        "group_id": group_id,
        "type": "addressbook",
        "displayname": "Extra Contacts"
    });

    let request = auth_request(
        Method::POST,
        "/frontend/api/v1/collections",
        "user",
        "pass",
        Some(Body::from(body.to_string())),
    );

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
}

#[rstest]
#[tokio::test]
async fn test_create_collection_non_member(
    #[from(test_store_context)]
    #[future]
    context: TestStoreContext,
) {
    let context = context.await;
    let (group_id, _) = setup_group(&context).await;
    let app = get_app(context);

    let body = json!({
        "group_id": group_id,
        "type": "calendar",
        "displayname": "Outsider Calendar"
    });

    let request = auth_request(
        Method::POST,
        "/frontend/api/v1/collections",
        "bob",
        "bob",
        Some(Body::from(body.to_string())),
    );

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[rstest]
#[tokio::test]
async fn test_create_collection_bad_type(
    #[from(test_store_context)]
    #[future]
    context: TestStoreContext,
) {
    let context = context.await;
    let (group_id, _) = setup_group(&context).await;
    let app = get_app(context);

    let body = json!({
        "group_id": group_id,
        "type": "invalid",
        "displayname": "Bad Type"
    });

    let request = auth_request(
        Method::POST,
        "/frontend/api/v1/collections",
        "user",
        "pass",
        Some(Body::from(body.to_string())),
    );

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[rstest]
#[tokio::test]
async fn test_create_collection_unauthenticated(
    #[from(test_store_context)]
    #[future]
    context: TestStoreContext,
) {
    let context = context.await;
    let app = get_app(context);

    let body = json!({
        "group_id": "testgroup",
        "type": "calendar",
        "displayname": "No Auth Calendar"
    });

    let request = Request::builder()
        .method(Method::POST)
        .uri("/frontend/api/v1/collections")
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}
