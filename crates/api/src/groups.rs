use axum::Json;
use axum::Router;
use axum::extract::{Path, State};
use axum::response::IntoResponse;
use axum::routing::get;
use http::StatusCode;
use rustical_ical::CalendarObjectType;
use rustical_store::CalendarMetadata;
use rustical_store::{
    AddressbookStore, CalendarStore, PrefixedCalendarStore,
    auth::{AuthenticationProvider, Principal, PrincipalType},
};
use serde::{Deserialize, Serialize};

use super::{ApiState, error::ApiError};

#[derive(Debug, Deserialize)]
pub struct CreateGroupRequest {
    pub id: String,
    pub displayname: String,
    #[serde(default)]
    pub members: Vec<String>,
    #[serde(default)]
    pub collections: CreateGroupCollections,
}

#[derive(Debug, Default, Deserialize)]
pub struct CreateGroupCollections {
    #[serde(default)]
    pub calendar: bool,
    #[serde(default)]
    pub tasks: bool,
    #[serde(default)]
    pub addressbook: bool,
}

#[derive(Debug, Serialize)]
pub struct GroupResponse {
    pub id: String,
    pub displayname: String,
    pub owner: bool,
    pub member_count: usize,
    pub collections: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct GroupDetailResponse {
    pub id: String,
    pub displayname: String,
    pub owner: bool,
    pub members: Vec<Principal>,
    pub collections: Vec<String>,
}

pub fn groups_router<
    AP: AuthenticationProvider,
    CS: CalendarStore,
    AS: AddressbookStore + PrefixedCalendarStore,
>() -> Router<ApiState<AP, CS, AS>> {
    Router::new()
        .route("/groups", get(list_groups).post(create_group))
        .route("/groups/{group_id}", get(get_group).delete(delete_group))
}

async fn list_groups<
    AP: AuthenticationProvider,
    CS: CalendarStore,
    AS: AddressbookStore + PrefixedCalendarStore,
>(
    State(state): State<ApiState<AP, CS, AS>>,
    principal: Principal,
) -> Result<impl IntoResponse, ApiError> {
    let groups = state
        .auth_provider
        .list_groups_for_user(&principal.id)
        .await?;

    let mut result = Vec::new();
    for (group_id, displayname) in groups {
        let owner = state
            .auth_provider
            .get_group_owner(&group_id)
            .await?
            .as_deref()
            == Some(&principal.id);
        let members = state.auth_provider.list_members(&group_id).await?;

        let calendars = state
            .cal_store
            .get_calendars(&group_id)
            .await
            .unwrap_or_default()
            .into_iter()
            .map(|c| format!("calendars/{}", c.id));
        let addressbooks = state
            .addr_store
            .get_addressbooks(&group_id)
            .await
            .unwrap_or_default()
            .into_iter()
            .map(|a| format!("addressbooks/{}", a.id));
        let collections: Vec<String> = calendars.chain(addressbooks).collect();

        result.push(GroupResponse {
            id: group_id,
            displayname,
            owner,
            member_count: members.len(),
            collections,
        });
    }

    Ok(Json(result))
}

async fn create_group<
    AP: AuthenticationProvider,
    CS: CalendarStore,
    AS: AddressbookStore + PrefixedCalendarStore,
>(
    State(state): State<ApiState<AP, CS, AS>>,
    principal: Principal,
    Json(req): Json<CreateGroupRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let group = Principal {
        id: req.id.clone(),
        displayname: Some(req.displayname.clone()),
        principal_type: PrincipalType::Group,
        password: None,
        memberships: vec![],
        needs_password_change: false,
        privileges: Default::default(),
    };

    state
        .auth_provider
        .insert_principal(group, false)
        .await
        .map_err(|e| ApiError::BadRequest(format!("Could not create group: {e}")))?;

    state
        .auth_provider
        .set_group_owner(&req.id, &principal.id)
        .await?;

    state
        .auth_provider
        .add_membership(&principal.id, &req.id)
        .await?;

    for member_id in &req.members {
        if let Err(e) = state.auth_provider.add_membership(member_id, &req.id).await {
            tracing::warn!(%e, %member_id, group_id=%req.id, "failed to add member");
        }
    }

    seed_group_collections(&state, &req).await?;

    let members = state.auth_provider.list_members(&req.id).await?;

    let calendars = state
        .cal_store
        .get_calendars(&req.id)
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|c| format!("calendars/{}", c.id));
    let addressbooks = state
        .addr_store
        .get_addressbooks(&req.id)
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|a| format!("addressbooks/{}", a.id));
    let collections: Vec<String> = calendars.chain(addressbooks).collect();

    let response = GroupResponse {
        id: req.id,
        displayname: req.displayname,
        owner: true,
        member_count: members.len(),
        collections,
    };

    Ok((StatusCode::CREATED, Json(response)))
}

async fn get_group<
    AP: AuthenticationProvider,
    CS: CalendarStore,
    AS: AddressbookStore + PrefixedCalendarStore,
>(
    State(state): State<ApiState<AP, CS, AS>>,
    Path(group_id): Path<String>,
    principal: Principal,
) -> Result<impl IntoResponse, ApiError> {
    let group = state
        .auth_provider
        .get_principal(&group_id)
        .await?
        .ok_or_else(|| ApiError::NotFound("Group not found".into()))?;

    let owner = state
        .auth_provider
        .get_group_owner(&group_id)
        .await?
        .as_deref()
        == Some(&principal.id);

    let member_ids = state.auth_provider.list_members(&group_id).await?;
    let mut members = Vec::new();
    for id in member_ids {
        if let Some(p) = state.auth_provider.get_principal(&id).await? {
            members.push(p);
        }
    }

    let calendars = state
        .cal_store
        .get_calendars(&group_id)
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|c| format!("calendars/{}", c.id));
    let addressbooks = state
        .addr_store
        .get_addressbooks(&group_id)
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|a| format!("addressbooks/{}", a.id));
    let collections: Vec<String> = calendars.chain(addressbooks).collect();

    Ok(Json(GroupDetailResponse {
        id: group_id,
        displayname: group.displayname.unwrap_or_default(),
        owner,
        members,
        collections,
    }))
}

async fn delete_group<
    AP: AuthenticationProvider,
    CS: Send + Sync + 'static,
    AS: Send + Sync + 'static,
>(
    State(state): State<ApiState<AP, CS, AS>>,
    Path(group_id): Path<String>,
    principal: Principal,
) -> Result<impl IntoResponse, ApiError> {
    if state
        .auth_provider
        .get_group_owner(&group_id)
        .await?
        .is_none()
    {
        return Err(ApiError::NotFound("Group not found".into()));
    }

    // Omnical §17.9.2: deleting a group is admin-only (the owner is an
    // implicit admin).
    if !principal.is_admin(&group_id) {
        return Err(ApiError::Forbidden(
            "Only an admin can delete this group".into(),
        ));
    }

    state.auth_provider.remove_principal(&group_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn seed_group_collections<
    AP: AuthenticationProvider,
    CS: CalendarStore,
    AS: AddressbookStore + PrefixedCalendarStore,
>(
    state: &ApiState<AP, CS, AS>,
    req: &CreateGroupRequest,
) -> Result<(), ApiError> {
    let gen_topic = || uuid::Uuid::new_v4().to_string();

    if req.collections.calendar {
        state
            .cal_store
            .insert_calendar(rustical_store::Calendar {
                id: req.id.clone(),
                principal: req.id.clone(),
                meta: CalendarMetadata {
                    displayname: Some(req.displayname.clone()),
                    order: 0,
                    description: None,
                    color: None,
                },
                timezone_id: None,
                deleted_at: None,
                synctoken: 0,
                subscription_url: None,
                push_topic: gen_topic(),
                components: vec![CalendarObjectType::Event, CalendarObjectType::Journal],
            })
            .await?;
    }

    if req.collections.tasks {
        state
            .cal_store
            .insert_calendar(rustical_store::Calendar {
                id: format!("{}-tasks", req.id),
                principal: req.id.clone(),
                meta: CalendarMetadata {
                    displayname: Some(format!("{} Tasks", req.displayname)),
                    order: 1,
                    description: None,
                    color: None,
                },
                timezone_id: None,
                deleted_at: None,
                synctoken: 0,
                subscription_url: None,
                push_topic: gen_topic(),
                components: vec![CalendarObjectType::Todo],
            })
            .await?;
    }

    if req.collections.addressbook {
        state
            .addr_store
            .insert_addressbook(rustical_store::Addressbook {
                id: format!("{}-contacts", req.id),
                principal: req.id.clone(),
                displayname: Some(format!("{} Contacts", req.displayname)),
                description: None,
                deleted_at: None,
                synctoken: 0,
                push_topic: gen_topic(),
            })
            .await?;
    }

    Ok(())
}
