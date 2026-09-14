use axum::Router;
use axum::extract::{Path, State};
use axum::response::IntoResponse;
use axum::{Json, routing::get};
use http::StatusCode;
use rustical_store::AddressbookStore;
use rustical_store::auth::{AuthenticationProvider, Principal, Privilege};
use rustical_store::{CalendarStore, PrefixedCalendarStore};
use serde::Deserialize;

use super::{ApiState, error::ApiError};

#[derive(Debug, Deserialize)]
pub struct AddMemberRequest {
    pub user_id: String,
    /// Optional starting privilege; defaults to `edit` (the pre-privilege
    /// "full r/w" level).
    #[serde(default)]
    pub privilege: Option<Privilege>,
}

#[derive(Debug, Deserialize)]
pub struct SetMemberPrivilegeRequest {
    pub privilege: Privilege,
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
            axum::routing::delete(remove_member).put(set_member_privilege),
        )
}

/// The member list with per-member privileges (Omnical §17.9.2): an
/// authenticated member of the group can see it; only the ids are exposed
/// here, the full principals come from `GET /groups/{group_id}`.
async fn list_members<
    AP: AuthenticationProvider,
    CS: CalendarStore,
    AS: AddressbookStore + PrefixedCalendarStore,
>(
    State(state): State<ApiState<AP, CS, AS>>,
    Path(group_id): Path<String>,
    principal: Principal,
) -> Result<impl IntoResponse, ApiError> {
    if !principal.is_principal(&group_id) {
        return Err(ApiError::Forbidden(
            "You are not a member of this group".into(),
        ));
    }

    let members = state
        .auth_provider
        .list_members_with_privileges(&group_id)
        .await?;

    Ok(Json(
        members
            .into_iter()
            .map(|(id, privilege)| {
                serde_json::json!({
                    "id": id,
                    "privilege": privilege.as_str(),
                })
            })
            .collect::<Vec<_>>(),
    ))
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
    // Omnical §17.9.2: member management is admin-only (the owner is an
    // implicit admin via the `group_members` backfill).
    if !principal.is_admin(&group_id) {
        return Err(ApiError::Forbidden(
            "Only an admin can add members".into(),
        ));
    }

    state
        .auth_provider
        .add_membership(&req.user_id, &group_id)
        .await?;

    // A non-default starting privilege overwrites the `edit` default seeded
    // by `add_membership`.
    if let Some(privilege) = req.privilege
        && privilege != Privilege::Edit
    {
        state
            .auth_provider
            .set_privilege(&req.user_id, &group_id, privilege)
            .await?;
    }

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
    // Omnical §17.9.2: member management is admin-only; the store rejects
    // removing the last remaining admin.
    if !principal.is_admin(&group_id) {
        return Err(ApiError::Forbidden(
            "Only an admin can remove members".into(),
        ));
    }

    state
        .auth_provider
        .remove_membership(&member_id, &group_id)
        .await?;

    Ok(StatusCode::NO_CONTENT)
}

async fn set_member_privilege<
    AP: AuthenticationProvider,
    CS: CalendarStore,
    AS: AddressbookStore + PrefixedCalendarStore,
>(
    State(state): State<ApiState<AP, CS, AS>>,
    Path((group_id, member_id)): Path<(String, String)>,
    principal: Principal,
    Json(req): Json<SetMemberPrivilegeRequest>,
) -> Result<impl IntoResponse, ApiError> {
    // Omnical §17.9.2 invariants: only admins may change privileges, nobody
    // may change their own; the store upholds the last-admin and
    // owner-never-demotable rules.
    if !principal.is_admin(&group_id) {
        return Err(ApiError::Forbidden(
            "Only an admin can change member privileges".into(),
        ));
    }
    if member_id == principal.id {
        return Err(ApiError::Forbidden(
            "You cannot change your own privilege".into(),
        ));
    }

    state
        .auth_provider
        .set_privilege(&member_id, &group_id, req.privilege)
        .await?;

    Ok(StatusCode::NO_CONTENT)
}
