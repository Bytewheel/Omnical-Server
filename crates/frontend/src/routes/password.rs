//! Portal password-change page (Omnical sharing: forced one-time change after
//! a user's first-ever calendar/group join).
//!
//! When `Principal::needs_password_change` is set (created on the first-ever
//! membership of a real user, seeded for the initial shared-calendar users,
//! cleared on password rotation), every portal page except this one redirects
//! here until the user rotates their password. The form requires the current
//! password (proving control beyond the session cookie), then stores the new
//! argon2 hash via `AuthenticationProvider::update_password`.

use crate::{FrontendConfig, pages::DefaultLayoutData};
use argon2::password_hash::{PasswordHasher, SaltString, rand_core::OsRng};
use askama::Template;
use askama_web::WebTemplate;
use axum::{
    Extension, Form,
    extract::Request,
    middleware::Next,
    response::{IntoResponse, Redirect, Response},
};
use http::StatusCode;
use rustical_store::auth::{AuthenticationProvider, Principal};
use serde::Deserialize;
use std::sync::Arc;
use tracing::instrument;

#[derive(Template, WebTemplate)]
#[template(path = "pages/password_change.html")]
pub struct PasswordChangePage {
    pub user: Principal,
    pub error: Option<String>,
    pub min_password_length: usize,
}

impl DefaultLayoutData for PasswordChangePage {
    fn get_user(&self) -> Option<&rustical_store::auth::Principal> {
        Some(&self.user)
    }
}

/// GET /frontend/user/{user}/password — the (force-able) change form.
#[instrument(skip(config))]
pub async fn route_get_password_change(
    user: Principal,
    Extension(config): Extension<FrontendConfig>,
) -> Response {
    if !config.allow_password_login {
        // No stored password exists to change — nothing to force.
        return Redirect::to(&format!("/frontend/user/{}", user.id)).into_response();
    }
    PasswordChangePage {
        user,
        error: None,
        min_password_length: config.min_password_length,
    }
    .into_response()
}

#[derive(Debug, Deserialize)]
pub struct ChangePasswordForm {
    current_password: String,
    new_password: String,
    new_password_confirm: String,
}

/// POST /frontend/user/{user}/password — verify the current password, store
/// the new hash, and clear the forced-change nudge.
#[instrument(skip(auth_provider, config))]
pub async fn route_post_password_change<AP: AuthenticationProvider>(
    user: Principal,
    Extension(auth_provider): Extension<Arc<AP>>,
    Extension(config): Extension<FrontendConfig>,
    Form(form): Form<ChangePasswordForm>,
) -> Response {
    if !config.allow_password_login {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    }

    let minlen = config.min_password_length;
    let render_error = |message: &str| {
        PasswordChangePage {
            user: user.clone(),
            error: Some(message.to_owned()),
            min_password_length: minlen,
        }
        .into_response()
    };

    if auth_provider
        .validate_password(&user.id, &form.current_password)
        .await
        .ok()
        .flatten()
        .is_none()
    {
        return render_error("Current password is incorrect.");
    }
    if form.new_password.len() < minlen {
        return render_error(&format!("Password must be at least {minlen} characters."));
    }
    if form.new_password != form.new_password_confirm {
        return render_error("The new passwords do not match.");
    }

    let salt = SaltString::generate(OsRng);
    let password_hash = argon2::Argon2::default()
        .hash_password(form.new_password.as_bytes(), &salt)
        .expect("argon2 hashing cannot fail for valid parameters")
        .to_string();

    if let Err(err) = auth_provider
        .update_password(&user.id, &password_hash)
        .await
    {
        return render_error(&format!("Could not update your password: {err}"));
    }

    tracing::info!(user = %user.id, "password changed (forced after first calendar join)");
    Redirect::to(&format!("/frontend/user/{}", user.id)).into_response()
}

/// Blocks every portal page except the password-change page itself (and the
/// logout route, which lives outside this sub-router anyway) while the
/// logged-in user still must change their password.
pub async fn password_change_gate(request: Request, next: Next) -> Response {
    let path = request.uri().path().to_owned();
    let needs_change = request
        .extensions()
        .get::<Principal>()
        .is_some_and(|user| user.needs_password_change && user.password.is_some());

    if needs_change
        && !path.ends_with("/password")
        && let Some(user) = request.extensions().get::<Principal>()
    {
        return Redirect::to(&format!("/frontend/user/{}/password", user.id)).into_response();
    }
    next.run(request).await
}
