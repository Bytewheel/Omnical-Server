use axum::Router;
use axum::extract::{Path, State};
use axum::response::IntoResponse;
use axum::{Json, routing::get};
use http::StatusCode;
use rustical_store::AddressbookStore;
use rustical_store::auth::{AuthenticationProvider, Principal};
use rustical_store::{CalendarStore, PrefixedCalendarStore};
use serde::Deserialize;

use super::{ApiState, error::ApiError};

#[derive(Debug, Deserialize)]
pub struct AddMemberRequest {
    pub user_id: String,
}

pub fn members_router<
    AP: AuthenticationProvider,
    CS: CalendarStore,
    AS: AddressbookStore + PrefixedCalendarStore,
>() -> Router<ApiState<AP, CS, AS>> {
    Router::new()
        .route(
            "/groups/{group_id}/members",
            get(list_members).post(add_member),
        )
        .route(
            "/groups/{group_id}/members/{member_id}",
            axum::routing::delete(remove_member),
        )
}

async fn list_members<
    AP: AuthenticationProvider,
    CS: CalendarStore,
    AS: AddressbookStore + PrefixedCalendarStore,
>(
    State(state): State<ApiState<AP, CS, AS>>,
    Path(group_id): Path<String>,
    _principal: Principal,
) -> Result<impl IntoResponse, ApiError> {
    let member_ids = state.auth_provider.list_members(&group_id).await?;
    let mut members = Vec::new();
    for id in member_ids {
        if let Some(p) = state.auth_provider.get_principal(&id).await? {
            members.push(p);
        }
    }

    Ok(Json(members))
}

async fn add_member<
    AP: AuthenticationProvider,
    CS: CalendarStore,
    AS: AddressbookStore + PrefixedCalendarStore,
>(
    State(state): State<ApiState<AP, CS, AS>>,
    Path(group_id): Path<String>,
    principal: Principal,
    Json(req): Json<AddMemberRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let owner = state
        .auth_provider
        .get_group_owner(&group_id)
        .await?
        .ok_or_else(|| ApiError::NotFound("Group not found".into()))?;

    if owner != principal.id {
        return Err(ApiError::Forbidden("Only the owner can add members".into()));
    }

    state
        .auth_provider
        .add_membership(&req.user_id, &group_id)
        .await?;

    Ok(StatusCode::CREATED)
}

async fn remove_member<
    AP: AuthenticationProvider,
    CS: CalendarStore,
    AS: AddressbookStore + PrefixedCalendarStore,
>(
    State(state): State<ApiState<AP, CS, AS>>,
    Path((group_id, member_id)): Path<(String, String)>,
    principal: Principal,
) -> Result<impl IntoResponse, ApiError> {
    let owner = state
        .auth_provider
        .get_group_owner(&group_id)
        .await?
        .ok_or_else(|| ApiError::NotFound("Group not found".into()))?;

    if owner != principal.id {
        return Err(ApiError::Forbidden(
            "Only the owner can remove members".into(),
        ));
    }

    state
        .auth_provider
        .remove_membership(&member_id, &group_id)
        .await?;

    Ok(StatusCode::NO_CONTENT)
}
