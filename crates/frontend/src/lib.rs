#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
use axum::{
    Extension, RequestExt, Router,
    body::Body,
    extract::{OriginalUri, Request},
    middleware::{self, Next},
    response::{Redirect, Response},
    routing::{get, post},
};
use headers::{ContentType, HeaderMapExt};
use http::{Method, StatusCode};
use routes::{addressbooks::route_addressbooks, calendars::route_calendars};
use rustical_oidc::{OidcConfig, OidcServiceConfig, oidc_router};
use rustical_store::SubscriptionStore;
use rustical_store::{
    AddressbookStore, CalendarSourceStore, CalendarStore, PrefixedCalendarStore,
    auth::{AuthenticationProvider, middleware::AuthenticationLayer},
};
use std::sync::Arc;
use url::Url;

mod assets;
mod config;
pub mod nextcloud_login;
mod oidc_user_store;
pub(crate) mod pages;
mod routes;
pub mod url_builder;

pub use config::FrontendConfig;
use oidc_user_store::OidcUserStore;

use crate::routes::{
    addressbook::{route_addressbook, route_addressbook_restore},
    app_token::{route_delete_app_token, route_post_app_token},
    calendar::{route_calendar, route_calendar_restore},
    groups::{route_group_detail, route_group_new, route_groups},
    linked_platforms::{
        route_get_linked_platforms, route_post_linked_platforms_add,
        route_post_linked_platforms_refresh, route_post_linked_platforms_remove,
    },
    login::{route_get_login, route_post_login, route_post_logout},
    share::{route_get_share, route_share_create, route_share_revoke},
    timezones::route_timezones,
    user::{route_get_home, route_root, route_user_named},
};
#[cfg(not(feature = "dev"))]
use assets::{Assets, EmbedService};
use rustical_api::api_router;

#[allow(clippy::too_many_arguments)]
pub fn frontend_router<
    AP: AuthenticationProvider,
    CS: CalendarStore,
    AS: AddressbookStore + PrefixedCalendarStore,
>(
    prefix: &'static str,
    auth_provider: Arc<AP>,
    cal_store: Arc<CS>,
    addr_store: Arc<AS>,
    frontend_config: FrontendConfig,
    oidc_config: Option<OidcConfig>,
    sub_store: Option<Arc<dyn SubscriptionStore>>,
    source_store: Arc<dyn CalendarSourceStore>,
    subscriptions_public_url: String,
) -> Router {
    let user_router = Router::new()
        .route("/", get(route_get_home))
        .route("/{user}", get(route_user_named::<AP>))
        // App token management
        .route("/{user}/app_token", post(route_post_app_token::<AP>))
        .route(
            // POST because HTML5 forms don't support DELETE method
            "/{user}/app_token/{id}/delete",
            post(route_delete_app_token::<AP>),
        )
        // Calendar
        .route("/{user}/calendar", get(route_calendars::<CS>))
        .route("/{user}/calendar/{calendar}", get(route_calendar::<CS>))
        .route(
            "/{user}/calendar/{calendar}/restore",
            post(route_calendar_restore::<CS>),
        )
        // Addressbook
        .route("/{user}/addressbook", get(route_addressbooks::<AS>))
        .route(
            "/{user}/addressbook/{addressbook}",
            get(route_addressbook::<AS>),
        )
        .route(
            "/{user}/addressbook/{addressbook}/restore",
            post(route_addressbook_restore::<AS>),
        )
        // Linked platforms (Omnical §17.8)
        .route(
            "/{user}/linked-platforms",
            get(route_get_linked_platforms::<CS>),
        )
        .route(
            "/{user}/linked-platforms/add",
            post(route_post_linked_platforms_add::<CS>),
        )
        .route(
            "/{user}/linked-platforms/{id}/refresh",
            post(route_post_linked_platforms_refresh::<CS>),
        )
        .route(
            "/{user}/linked-platforms/{id}/remove",
            post(route_post_linked_platforms_remove),
        )
        // Share links (Omnical §17.7)
        .route("/{user}/share", get(route_get_share::<AP, CS, AS>))
        .route(
            "/{user}/share/create",
            post(route_share_create::<AP, CS, AS>),
        )
        .route("/{user}/share/{id}/revoke", post(route_share_revoke::<AP>))
        // Groups (Omnical §17.9)
        .route("/{user}/groups", get(route_groups::<AP, CS, AS>))
        .route("/{user}/groups/new", get(route_group_new))
        .route(
            "/{user}/groups/{group}",
            get(route_group_detail::<AP, CS, AS>),
        )
        .layer(middleware::from_fn(unauthorized_handler));

    let router = Router::new()
        .route("/", get(route_root))
        .nest("/user", user_router)
        .nest(
            "/api/v1",
            api_router(auth_provider.clone(), cal_store.clone(), addr_store.clone()),
        )
        .route("/login", get(route_get_login).post(route_post_login::<AP>))
        .route("/logout", post(route_post_logout))
        .route(
            "/_timezones.json",
            get(route_timezones).head(route_timezones),
        );

    #[cfg(not(feature = "dev"))]
    let mut router = router.route_service("/assets/{*file}", EmbedService::<Assets>::default());
    #[cfg(feature = "dev")]
    let mut router = router.nest_service(
        "/assets",
        tower_http::services::ServeDir::new(concat!(env!("CARGO_MANIFEST_DIR"), "/public/assets")),
    );

    if let Some(oidc_config) = oidc_config.clone() {
        router = router.nest(
            "/login/oidc",
            oidc_router(
                oidc_config,
                OidcServiceConfig {
                    default_redirect_path: "/frontend/user",
                    session_key_user_id: "user",
                    callback_path: "/frontend/login/oidc/callback",
                },
                OidcUserStore(auth_provider.clone()),
            ),
        );
    }

    router = router
        .layer(AuthenticationLayer::new(auth_provider.clone()))
        .layer(Extension(auth_provider))
        .layer(Extension(cal_store))
        .layer(Extension(addr_store))
        .layer(Extension(frontend_config))
        .layer(Extension(oidc_config))
        .layer(Extension(sub_store))
        .layer(Extension(source_store))
        .layer(Extension(subscriptions_public_url));

    Router::new()
        .nest(prefix, router)
        .route("/", get(async || Redirect::to(prefix)))
}

async fn unauthorized_handler(mut request: Request, next: Next) -> Response {
    let meth = request.method().clone();
    let OriginalUri(uri) = request.extract_parts().await.unwrap();
    let resp = next.run(request).await;
    if resp.status() == StatusCode::UNAUTHORIZED {
        // This is a dumb hack since parsed Urls cannot be relative
        let mut login_url: Url = "http://github.com/frontend/login".parse().unwrap();
        if meth == Method::GET {
            login_url
                .query_pairs_mut()
                .append_pair("redirect_uri", uri.path());
        }
        let path = login_url.path();
        let query = login_url
            .query()
            .map(|query| format!("?{query}"))
            .unwrap_or_default();
        let login_url = format!("{path}{query}");
        let mut resp = Response::builder().status(StatusCode::UNAUTHORIZED);
        let hdrs = resp.headers_mut().unwrap();
        hdrs.typed_insert(ContentType::html());
        return resp
            .body(Body::new(format!(
                r#"<!Doctype html>
<html>
    <head>
        <meta http-equiv="refresh" content="1; url={login_url}" />
    </head>
    <body>
        Unauthorized, redirecting to <a href="{login_url}">login page</a>
    </body>
</html>"#,
            )))
            .unwrap();
    }
    resp
}
