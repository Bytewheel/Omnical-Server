use crate::Error;
use crate::privileges::UserPrivilege;
use crate::resource::Resource;
use crate::resource::ResourceService;
use axum::extract::{Path, State};
use axum_extra::TypedHeader;
use headers::{IfMatch, IfNoneMatch};
use http::HeaderMap;

pub async fn axum_route_delete<R: ResourceService>(
    Path(path): Path<R::PathComponents>,
    State(resource_service): State<R>,
    principal: R::Principal,
    mut if_match: Option<TypedHeader<IfMatch>>,
    mut if_none_match: Option<TypedHeader<IfNoneMatch>>,
    header_map: HeaderMap,
) -> Result<(), R::Error> {
    // https://github.com/hyperium/headers/issues/204
    if !header_map.contains_key("If-Match") {
        if_match = None;
    }
    if !header_map.contains_key("If-None-Match") {
        if_none_match = None;
    }
    let no_trash = header_map
        .get("X-No-Trashbin")
        .is_some_and(|val| matches!(val.to_str(), Ok("1")));
    let user_agent = header_map
        .get(http::header::USER_AGENT)
        .and_then(|val| val.to_str().ok());
    route_delete(
        &path,
        &principal,
        &resource_service,
        no_trash,
        if_match.map(|hdr| hdr.0),
        if_none_match.map(|hdr| hdr.0),
        user_agent,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn route_delete<R: ResourceService>(
    path_components: &R::PathComponents,
    principal: &R::Principal,
    resource_service: &R,
    no_trash: bool,
    if_match: Option<IfMatch>,
    if_none_match: Option<IfNoneMatch>,
    user_agent: Option<&str>,
) -> Result<(), R::Error> {
    let resource = resource_service.get_resource(path_components, true).await?;

    // Kind of a bodge since we don't get unbind from the parent
    let privileges = resource.get_user_privileges(principal)?;
    if !privileges.has(&UserPrivilege::WriteProperties) {
        // Omnical §17.9.2: an authenticated principal that can READ the
        // resource but lacks write privileges (a `view` member) gets a clean
        // 403 so read-only clients do not retry the write; principals with
        // no privileges at all are not members and keep the 401.
        return Err(if privileges.has(&UserPrivilege::Read) {
            Error::Forbidden
        } else {
            Error::Unauthorized
        }
        .into());
    }

    if let Some(if_match) = if_match
        && !resource.satisfies_if_match(&if_match)
    {
        // Precondition failed
        return Err(crate::Error::PreconditionFailed.into());
    }
    if let Some(if_none_match) = if_none_match
        && resource.satisfies_if_none_match(&if_none_match)
    {
        // Precondition failed
        return Err(crate::Error::PreconditionFailed.into());
    }
    resource_service
        .delete_resource(path_components, !no_trash)
        .await?;
    // Post-delete hook (fire-and-forget: the object is already gone, so a
    // hook failure must not turn the successful DELETE into an error).
    resource_service
        .on_resource_deleted(path_components, principal, &resource, user_agent)
        .await;
    Ok(())
}
