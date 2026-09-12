use super::{ApiState, error::ApiError};
use axum::Json;
use axum::Router;
use axum::extract::State;
use axum::response::IntoResponse;
use axum::routing::post;
use http::StatusCode;
use rustical_ical::CalendarObjectType;
use rustical_store::CalendarMetadata;
use rustical_store::auth::{AuthenticationProvider, Principal, PrincipalType};
use rustical_store::{AddressbookStore, CalendarStore, PrefixedCalendarStore};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct CreateCollectionRequest {
    pub group_id: String,
    #[serde(rename = "type")]
    pub collection_type: String,
    pub displayname: String,
    #[serde(default)]
    pub color: Option<String>,
}

pub fn collections_router<
    AP: AuthenticationProvider,
    CS: CalendarStore,
    AS: AddressbookStore + PrefixedCalendarStore,
>() -> Router<ApiState<AP, CS, AS>> {
    Router::new().route("/collections", post(create_collection))
}

async fn create_collection<
    AP: AuthenticationProvider,
    CS: CalendarStore,
    AS: AddressbookStore + PrefixedCalendarStore,
>(
    State(state): State<ApiState<AP, CS, AS>>,
    principal: Principal,
    Json(req): Json<CreateCollectionRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let group = state
        .auth_provider
        .get_principal(&req.group_id)
        .await?
        .ok_or_else(|| ApiError::NotFound("Group not found".into()))?;

    if group.principal_type != PrincipalType::Group {
        return Err(ApiError::BadRequest("Not a group principal".into()));
    }

    let is_member = state
        .auth_provider
        .list_members(&req.group_id)
        .await?
        .iter()
        .any(|m| m == &principal.id);

    if !is_member {
        return Err(ApiError::Forbidden(
            "You are not a member of this group".into(),
        ));
    }

    let collection_id = uuid::Uuid::new_v4().to_string();
    let push_topic = uuid::Uuid::new_v4().to_string();

    match req.collection_type.as_str() {
        "calendar" => {
            state
                .cal_store
                .insert_calendar(rustical_store::Calendar {
                    id: collection_id.clone(),
                    principal: req.group_id.clone(),
                    meta: CalendarMetadata {
                        displayname: Some(req.displayname),
                        order: 0,
                        description: None,
                        color: req.color,
                    },
                    timezone_id: None,
                    deleted_at: None,
                    synctoken: 0,
                    subscription_url: None,
                    push_topic,
                    components: vec![CalendarObjectType::Event, CalendarObjectType::Journal],
                })
                .await?;
        }
        "addressbook" => {
            state
                .addr_store
                .insert_addressbook(rustical_store::Addressbook {
                    id: collection_id,
                    principal: req.group_id.clone(),
                    displayname: Some(req.displayname),
                    description: None,
                    deleted_at: None,
                    synctoken: 0,
                    push_topic,
                })
                .await?;
        }
        other => {
            return Err(ApiError::BadRequest(format!(
                "Unknown collection type: {other}. Expected 'calendar' or 'addressbook'"
            )));
        }
    }

    Ok(StatusCode::CREATED)
}
