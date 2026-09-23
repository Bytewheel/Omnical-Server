use std::sync::Arc;

use crate::pages::user::{Section, UserPage};
use crate::routes::calendar::resolve_base_url;
use askama::Template;
use askama_web::WebTemplate;
use axum::{
    Extension,
    extract::Path,
    response::{IntoResponse, Redirect, Response},
};
use axum_extra::TypedHeader;
use headers::{HeaderMapExt, Host, UserAgent};
use http::{HeaderMap, StatusCode};
use rustical_store::auth::{AppToken, AuthenticationProvider, Principal};

impl Section for ProfileSection {
    fn name() -> &'static str {
        "profile"
    }
}

/// A just-regenerated app token shown once on the profile page: the token's
/// (unchanged) name plus the new secret — old one-time banner pattern, same
/// as the calendars credentials.
pub struct RegeneratedToken {
    pub name: String,
    pub token: String,
}

#[derive(Template, WebTemplate)]
#[template(path = "components/sections/profile_section.html")]
pub struct ProfileSection {
    pub user: Principal,
    pub app_tokens: Vec<AppToken>,
    pub davx5_hostname: Option<String>,
    /// `CalDAV` endpoint printed in the per-client instructions.
    pub caldav_url: String,
    /// `CardDAV` endpoint printed in the per-client instructions.
    pub carddav_url: String,
    /// One-time banner payload of a Regenerate action (`None` on a plain
    /// page load).
    pub regenerated: Option<RegeneratedToken>,
}

/// The shared profile-page renderer (same pattern as
/// `render_calendars_page`): the regenerate route re-renders the page with a
/// one-time banner after rotating a token secret.
pub async fn render_profile_page<AP: AuthenticationProvider>(
    auth_provider: &Arc<AP>,
    public_url: &str,
    host: &Host,
    headers: &HeaderMap,
    user: &Principal,
    regenerated: Option<RegeneratedToken>,
) -> Response {
    let ua = headers.typed_get::<UserAgent>();
    let davx5_hostname =
        ua.and_then(|ua| ua.as_str().contains("Android").then_some(host.to_string()));

    let base_url = resolve_base_url(public_url, host);

    UserPage {
        section: ProfileSection {
            user: user.clone(),
            app_tokens: auth_provider.get_app_tokens(&user.id).await.unwrap(),
            davx5_hostname,
            caldav_url: format!("{base_url}/caldav"),
            carddav_url: format!("{base_url}/carddav"),
            regenerated,
        },
        user: user.clone(),
    }
    .into_response()
}

pub async fn route_user_named<AP: AuthenticationProvider>(
    Path(user_id): Path<String>,
    Extension(auth_provider): Extension<Arc<AP>>,
    Extension(public_url): Extension<String>,
    TypedHeader(host): TypedHeader<Host>,
    user: Principal,
    headers: HeaderMap,
) -> impl IntoResponse {
    if user_id != user.id {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    render_profile_page(&auth_provider, &public_url, &host, &headers, &user, None).await
}

pub async fn route_get_home(user: Principal) -> Redirect {
    Redirect::to(&format!("/frontend/user/{}", user.id))
}

pub async fn route_root(user: Option<Principal>) -> Redirect {
    match user {
        Some(user) => route_get_home(user).await,
        None => Redirect::to("/frontend/login"),
    }
}
