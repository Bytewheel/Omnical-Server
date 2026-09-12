use super::{ApiState, error::ApiError};
use axum::Json;
use axum::Router;
use axum::extract::{Query, State};
use axum::response::IntoResponse;
use axum::routing::get;
use rustical_store::auth::{AuthenticationProvider, Principal};
use rustical_store::{AddressbookStore, CalendarStore, PrefixedCalendarStore};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct SearchQuery {
    pub q: String,
}

#[derive(Debug, Serialize)]
pub struct UserResponse {
    pub id: String,
    pub displayname: String,
}

pub fn users_router<
    AP: AuthenticationProvider,
    CS: CalendarStore,
    AS: AddressbookStore + PrefixedCalendarStore,
>() -> Router<ApiState<AP, CS, AS>> {
    Router::new().route("/users", get(search_users))
}

async fn search_users<
    AP: AuthenticationProvider,
    CS: CalendarStore,
    AS: AddressbookStore + PrefixedCalendarStore,
>(
    State(state): State<ApiState<AP, CS, AS>>,
    _principal: Principal,
    Query(query): Query<SearchQuery>,
) -> Result<impl IntoResponse, ApiError> {
    let users = state.auth_provider.search_users(&query.q).await?;

    let result: Vec<UserResponse> = users
        .into_iter()
        .map(|(id, displayname)| UserResponse { id, displayname })
        .collect();

    Ok(Json(result))
}
