use super::{PrincipalUri, Resource};
use crate::Principal;
use crate::resource::{AxumMethods, AxumService};
use async_trait::async_trait;
use axum::Router;
use axum::extract::FromRequestParts;
use axum::response::IntoResponse;
use serde::Deserialize;
use std::borrow::Cow;

/// A `ResourceService` is responsible for handling operations on the resource at an endpoint
#[async_trait]
pub trait ResourceService: Clone + Sized + Send + Sync + AxumMethods + 'static {
    /// defines how the resource URI maps to parameters, i.e. /{principal}/{calendar} -> (String, String)
    type PathComponents: std::fmt::Debug
        + for<'de> Deserialize<'de>
        + Sized
        + Send
        + Sync
        + Clone
        + 'static;

    /// Type of a potential child resource
    type MemberType: Resource<Error = Self::Error, Principal = Self::Principal>
        + super::ResourceName;

    /// The resource type served by this service
    type Resource: Resource<Error = Self::Error, Principal = Self::Principal>;
    type Error: From<crate::Error> + Send + Sync + IntoResponse + 'static;
    type Principal: Principal + FromRequestParts<Self>;
    type PrincipalUri: PrincipalUri;

    const DAV_HEADER: &'static str;

    /// Instance-level `DAV` header advertised by `OPTIONS`.
    /// Services whose feature set depends on runtime state (e.g. the CalDAV
    /// scheduling extension) override this; the default is [`Self::DAV_HEADER`].
    fn dav_header(&self) -> Cow<'static, str> {
        Cow::Borrowed(Self::DAV_HEADER)
    }

    async fn get_members(
        &self,
        _path: &Self::PathComponents,
    ) -> Result<Vec<Self::MemberType>, Self::Error> {
        Ok(vec![])
    }

    async fn get_resource(
        &self,
        path: &Self::PathComponents,
        show_deleted: bool,
    ) -> Result<Self::Resource, Self::Error>;

    async fn save_resource(
        &self,
        _path: &Self::PathComponents,
        _file: Self::Resource,
    ) -> Result<(), Self::Error> {
        Err(crate::Error::Unauthorized.into())
    }

    async fn delete_resource(
        &self,
        _path: &Self::PathComponents,
        _use_trashbin: bool,
    ) -> Result<(), Self::Error> {
        Err(crate::Error::Unauthorized.into())
    }

    /// Hook invoked by the generic DELETE path after [`Self::delete_resource`]
    /// succeeded. `deleted_resource` was fetched *before* the deletion and
    /// carries the object's last contents; `user_agent` is the raw
    /// `User-Agent` header of the request. Failures are the implementor's to
    /// handle — the resource is already gone at this point, so an error must
    /// never fail the (already-successful) request.
    async fn on_resource_deleted(
        &self,
        _path: &Self::PathComponents,
        _principal: &Self::Principal,
        _deleted_resource: &Self::Resource,
        _user_agent: Option<&str>,
    ) {
    }

    // Returns whether an existing resource was overwritten
    async fn copy_resource(
        &self,
        _path: &Self::PathComponents,
        _destination: &Self::PathComponents,
        _user: &Self::Principal,
        _overwrite: bool,
    ) -> Result<bool, Self::Error> {
        Err(crate::Error::Forbidden.into())
    }

    // Returns whether an existing resource was overwritten
    async fn move_resource(
        &self,
        _path: &Self::PathComponents,
        _destination: &Self::PathComponents,
        _user: &Self::Principal,
        _overwrite: bool,
    ) -> Result<bool, Self::Error> {
        Err(crate::Error::Forbidden.into())
    }

    fn axum_service(self) -> AxumService<Self> {
        AxumService::new(self)
    }

    fn axum_router<S: Send + Sync + Clone + 'static>(self) -> Router<S> {
        Router::new().route_service("/", self.axum_service())
    }
}
