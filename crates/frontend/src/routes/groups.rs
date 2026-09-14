use std::sync::Arc;

use crate::pages::user::UserPage;
use crate::pages::{DefaultLayoutData, user::Section};
use askama::Template;
use askama_web::WebTemplate;
use axum::Form;
use axum::{
    Extension,
    extract::Path,
    response::{IntoResponse, Redirect, Response},
};
use http::StatusCode;
use rustical_store::{
    AddressbookStore, CalendarStore, PrefixedCalendarStore,
    auth::{AuthenticationProvider, Principal, Privilege},
};
use serde::Deserialize;

impl Section for GroupsSection {
    fn name() -> &'static str {
        "groups"
    }
}

pub struct GroupInfo {
    pub id: String,
    pub displayname: String,
    /// Whether the acting user may manage this group's members (Omnical
    /// §17.9.2: `admin` privilege; the owner is an implicit admin).
    pub admin: bool,
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
        let admin = user.is_admin(&group_id);

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
            admin,
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

/// One member row of the group detail page: the principal plus their
/// privilege (Omnical §17.9.2).
pub struct GroupMember {
    pub principal: Principal,
    pub privilege: Privilege,
}

#[derive(Template, WebTemplate)]
#[template(path = "pages/group_detail.html")]
struct GroupDetailPage {
    user: Principal,
    group_id: String,
    displayname: String,
    /// Whether the acting user may manage this group (delete, add/remove
    /// members, change privileges).
    admin: bool,
    members: Vec<GroupMember>,
    collections: Vec<String>,
    error: Option<String>,
}

impl DefaultLayoutData for GroupDetailPage {
    fn get_user(&self) -> Option<&Principal> {
        Some(&self.user)
    }
}

/// Shared builder for the group detail page; `error` renders an error banner
/// (used by the member-management POST routes).
async fn group_detail_page<
    AP: AuthenticationProvider,
    CS: CalendarStore,
    AS: AddressbookStore + PrefixedCalendarStore,
>(
    auth_provider: &Arc<AP>,
    cal_store: &Arc<CS>,
    addr_store: &Arc<AS>,
    user: &Principal,
    group_id: &str,
    error: Option<String>,
) -> Result<Response, StatusCode> {
    let group = auth_provider
        .get_principal(group_id)
        .await
        .unwrap_or(None)
        .ok_or(StatusCode::NOT_FOUND)?;

    let mut members = Vec::new();
    for (member_id, privilege) in auth_provider
        .list_members_with_privileges(group_id)
        .await
        .unwrap_or_default()
    {
        let Some(principal) = auth_provider
            .get_principal(&member_id)
            .await
            .unwrap_or(None)
        else {
            continue;
        };
        members.push(GroupMember {
            principal,
            privilege,
        });
    }

    let calendars = cal_store
        .get_calendars(group_id)
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|c| format!("calendars/{}", c.id));
    let addressbooks = addr_store
        .get_addressbooks(group_id)
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|a| format!("addressbooks/{}", a.id));
    let collections: Vec<String> = calendars.chain(addressbooks).collect();

    Ok(GroupDetailPage {
        user: user.clone(),
        displayname: group.displayname.unwrap_or_else(|| group_id.to_owned()),
        group_id: group_id.to_owned(),
        admin: user.is_admin(group_id),
        members,
        collections,
        error,
    }
    .into_response())
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
    group_detail_page(
        &auth_provider,
        &cal_store,
        &addr_store,
        &user,
        &group_id,
        None,
    )
    .await
}

#[derive(Debug, Deserialize)]
pub struct SetPrivilegeForm {
    pub privilege: String,
}

/// POST /{user}/groups/{group}/members/{member}/privilege — change a
/// member's privilege. Admin-only; the store upholds the last-admin and
/// owner-never-demotable invariants.
pub async fn route_group_member_privilege<AP: AuthenticationProvider>(
    Path((user_id, group_id, member_id)): Path<(String, String, String)>,
    Extension(auth_provider): Extension<Arc<AP>>,
    user: Principal,
    Form(form): Form<SetPrivilegeForm>,
) -> Response {
    if user_id != user.id {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    if !user.is_admin(&group_id) {
        return (
            StatusCode::FORBIDDEN,
            "Only an admin can change member privileges.",
        )
            .into_response();
    }
    if member_id == user.id {
        return (
            StatusCode::FORBIDDEN,
            "You cannot change your own privilege.",
        )
            .into_response();
    }
    let Ok(privilege) = form.privilege.parse::<Privilege>() else {
        return (
            StatusCode::BAD_REQUEST,
            "Invalid privilege — must be view, edit or admin.",
        )
            .into_response();
    };
    if let Err(err) = auth_provider
        .set_privilege(&member_id, &group_id, privilege)
        .await
    {
        return Redirect::to(&format!(
            "/frontend/user/{user_id}/groups/{group_id}?error={}",
            percent_encoding::utf8_percent_encode(
                &err.to_string(),
                percent_encoding::NON_ALPHANUMERIC
            )
        ))
        .into_response();
    }
    Redirect::to(&format!("/frontend/user/{user_id}/groups/{group_id}")).into_response()
}

/// POST /{user}/groups/{group}/members/{member}/remove — remove a member.
/// Admin-only; removing the last admin is rejected by the store.
pub async fn route_group_member_remove<AP: AuthenticationProvider>(
    Path((user_id, group_id, member_id)): Path<(String, String, String)>,
    Extension(auth_provider): Extension<Arc<AP>>,
    user: Principal,
) -> Response {
    if user_id != user.id {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    if !user.is_admin(&group_id) {
        return (StatusCode::FORBIDDEN, "Only an admin can remove members.").into_response();
    }
    if member_id == user.id {
        return (StatusCode::FORBIDDEN, "You cannot remove yourself.").into_response();
    }
    if let Err(err) = auth_provider.remove_membership(&member_id, &group_id).await {
        return Redirect::to(&format!(
            "/frontend/user/{user_id}/groups/{group_id}?error={}",
            percent_encoding::utf8_percent_encode(
                &err.to_string(),
                percent_encoding::NON_ALPHANUMERIC
            )
        ))
        .into_response();
    }
    Redirect::to(&format!("/frontend/user/{user_id}/groups/{group_id}")).into_response()
}
