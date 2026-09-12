use std::sync::Arc;

use crate::pages::user::UserPage;
use crate::pages::{DefaultLayoutData, user::Section};
use askama::Template;
use askama_web::WebTemplate;
use axum::{
    Extension,
    extract::Path,
    response::{IntoResponse, Response},
};
use http::StatusCode;
use rustical_store::{
    AddressbookStore, CalendarStore, PrefixedCalendarStore,
    auth::{AuthenticationProvider, Principal},
};

impl Section for GroupsSection {
    fn name() -> &'static str {
        "groups"
    }
}

pub struct GroupInfo {
    pub id: String,
    pub displayname: String,
    pub owner: bool,
    pub member_count: usize,
    pub collection_count: usize,
}

#[derive(Template, WebTemplate)]
#[template(path = "components/sections/groups_section.html")]
pub struct GroupsSection {
    pub user: Principal,
    pub groups: Vec<GroupInfo>,
}

pub async fn route_groups<
    AP: AuthenticationProvider,
    CS: CalendarStore,
    AS: AddressbookStore + PrefixedCalendarStore,
>(
    Path(user_id): Path<String>,
    Extension(auth_provider): Extension<Arc<AP>>,
    Extension(cal_store): Extension<Arc<CS>>,
    Extension(addr_store): Extension<Arc<AS>>,
    user: Principal,
) -> impl IntoResponse {
    if user_id != user.id {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    let raw_groups = auth_provider
        .list_groups_for_user(&user.id)
        .await
        .unwrap_or_default();

    let mut groups = Vec::new();
    for (group_id, displayname) in raw_groups {
        let owner = auth_provider
            .get_group_owner(&group_id)
            .await
            .unwrap_or(None)
            .as_deref()
            == Some(&user.id);

        let members = auth_provider
            .list_members(&group_id)
            .await
            .unwrap_or_default();

        let cal_count = cal_store
            .get_calendars(&group_id)
            .await
            .unwrap_or_default()
            .len();
        let addr_count = addr_store
            .get_addressbooks(&group_id)
            .await
            .unwrap_or_default()
            .len();

        groups.push(GroupInfo {
            id: group_id,
            displayname,
            owner,
            member_count: members.len(),
            collection_count: cal_count + addr_count,
        });
    }

    UserPage {
        section: GroupsSection {
            user: user.clone(),
            groups,
        },
        user,
    }
    .into_response()
}

#[derive(Template, WebTemplate)]
#[template(path = "pages/group_new.html")]
struct GroupNewPage {
    user: Principal,
}

impl DefaultLayoutData for GroupNewPage {
    fn get_user(&self) -> Option<&Principal> {
        Some(&self.user)
    }
}

pub async fn route_group_new(Path(user_id): Path<String>, user: Principal) -> impl IntoResponse {
    if user_id != user.id {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    GroupNewPage { user }.into_response()
}

#[derive(Template, WebTemplate)]
#[template(path = "pages/group_detail.html")]
struct GroupDetailPage {
    user: Principal,
    group_id: String,
    displayname: String,
    owner: bool,
    members: Vec<Principal>,
    collections: Vec<String>,
}

impl DefaultLayoutData for GroupDetailPage {
    fn get_user(&self) -> Option<&Principal> {
        Some(&self.user)
    }
}

pub async fn route_group_detail<
    AP: AuthenticationProvider,
    CS: CalendarStore,
    AS: AddressbookStore + PrefixedCalendarStore,
>(
    Path((user_id, group_id)): Path<(String, String)>,
    Extension(auth_provider): Extension<Arc<AP>>,
    Extension(cal_store): Extension<Arc<CS>>,
    Extension(addr_store): Extension<Arc<AS>>,
    user: Principal,
) -> Result<Response, StatusCode> {
    if user_id != user.id {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let group = auth_provider
        .get_principal(&group_id)
        .await
        .unwrap_or(None)
        .ok_or(StatusCode::NOT_FOUND)?;

    let owner = auth_provider
        .get_group_owner(&group_id)
        .await
        .unwrap_or(None)
        .as_deref()
        == Some(&user.id);

    let member_ids = auth_provider
        .list_members(&group_id)
        .await
        .unwrap_or_default();
    let mut members = Vec::new();
    for id in &member_ids {
        if let Some(p) = auth_provider.get_principal(id).await.unwrap_or(None) {
            members.push(p);
        }
    }

    let calendars = cal_store
        .get_calendars(&group_id)
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|c| format!("calendars/{}", c.id));
    let addressbooks = addr_store
        .get_addressbooks(&group_id)
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|a| format!("addressbooks/{}", a.id));
    let collections: Vec<String> = calendars.chain(addressbooks).collect();

    Ok(GroupDetailPage {
        user,
        displayname: group.displayname.unwrap_or_else(|| group_id.clone()),
        group_id,
        owner,
        members,
        collections,
    }
    .into_response())
}
