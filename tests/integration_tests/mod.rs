use axum::extract::Request;
use axum::{body::Body, response::Response};
use rstest::rstest;
use rustical::{app::make_app, config::NextcloudLoginConfig};
use rustical_caldav::CalDavConfig;
use rustical_frontend::FrontendConfig;
use rustical_store_sqlite::tests::{TestStoreContext, test_store_context};
use rustical_store_sqlite::{
    SqliteCalendarSourceStore, SqliteCollectionShareStore, SqliteInviteStore,
    SqliteSubscriptionStore,
};
use std::sync::Arc;
use tower::ServiceExt;

pub fn get_app(context: TestStoreContext) -> axum::Router {
    let TestStoreContext {
        addr_store,
        cal_store,
        principal_store,
        dav_push_store,
        ..
    } = context;

    // The Share portal tests exercise the real subscription store end to
    // end (create → portal URL → public /export fetch), so the integration
    // app mounts the same extension as production.
    let subscription_store = Arc::new(SqliteSubscriptionStore::new(cal_store.clone()));
    let source_store = Arc::new(SqliteCalendarSourceStore::new(cal_store.clone()));
    let invite_store = Arc::new(SqliteInviteStore::new(cal_store.clone()));
    let share_store = Arc::new(SqliteCollectionShareStore::new(cal_store.clone()));

    make_app(
        Arc::new(addr_store),
        Arc::new(cal_store),
        Arc::new(dav_push_store),
        Arc::new(principal_store),
        FrontendConfig {
            enabled: true,
            allow_password_login: true,
            ..FrontendConfig::default()
        },
        None,
        CalDavConfig::default(),
        None,
        Some(subscription_store),
        None,
        &NextcloudLoginConfig { enabled: false },
        false,
        true,
        20,
        source_store,
        "https://public.example".to_owned(),
        invite_store,
        share_store,
        vec![],
    )
}

pub trait ResponseExtractString {
    #[allow(async_fn_in_trait)]
    async fn extract_string(self) -> String;
}

impl ResponseExtractString for Response {
    async fn extract_string(self) -> String {
        let bytes = axum::body::to_bytes(self.into_body(), usize::MAX)
            .await
            .unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }
}

#[rstest]
#[tokio::test]
async fn test_ping(
    #[from(test_store_context)]
    #[future]
    context: TestStoreContext,
) {
    let app = get_app(context.await);

    let response = app
        .oneshot(Request::builder().uri("/ping").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert!(response.status().is_success());
}

mod api;
mod caldav;
mod carddav;
mod frontend_calendars;
mod frontend_groups;
mod frontend_linked_platforms;
mod frontend_password;
mod frontend_share;
