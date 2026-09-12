//! The per-principal schedule-inbox (RFC 6638 §4): a DB-backed collection
//! of iTIP messages (REQUEST/CANCEL/REPLY) delivered by the scheduler.

use crate::{CalDavPrincipalUri, Error, calendar_object::CalendarObjectPropWrapperName};
use async_trait::async_trait;
use axum::Router;
use axum::body::Body;
use axum::extract::{Path, State};
use axum::handler::Handler;
use axum::response::Response;
use futures_util::future::BoxFuture;
use headers::{ContentType, ETag, HeaderMapExt};
use hex::ToHex;
use http::{Method, StatusCode};
use rustical_dav::extensions::{
    CommonPropertiesExtension, CommonPropertiesProp, CommonPropertiesPropName,
};
use rustical_dav::namespace::{NS_CALDAV, NS_DAV};
use rustical_dav::privileges::UserPrivilegeSet;
use rustical_dav::resource::{AxumMethods, PrincipalUri, Resource, ResourceName, ResourceService};
use rustical_dav::resourcetype;
use rustical_dav::xml::Resourcetype;
use rustical_store::{InboxObject, SchedulingStore, auth::Principal};
use sha2::{Digest, Sha256};
use std::borrow::Cow;
use std::convert::Infallible;
use std::str::FromStr;
use std::sync::Arc;
use tower::Service;

use crate::calendar_object::{
    CalendarObjectProp, CalendarObjectPropName, CalendarObjectPropWrapper,
};

/// Strong entity tag for an inbox object (mirrors `CalendarObject::get_etag`).
pub(crate) fn inbox_etag(object: &InboxObject) -> String {
    let mut hasher = Sha256::new();
    hasher.update(&object.object_id);
    hasher.update(&object.ics);
    format!(
        "\"{}\"",
        hasher.finalize().as_slice().encode_hex::<String>()
    )
}

#[derive(Clone, Debug)]
pub struct InboxResource {
    principal: String,
}

impl Resource for InboxResource {
    type Prop = CommonPropertiesProp;
    type Error = Error;
    type Principal = Principal;

    fn is_collection(&self) -> bool {
        true
    }

    fn get_resourcetype(&self) -> Resourcetype {
        resourcetype!((NS_DAV, "collection"), (NS_CALDAV, "schedule-inbox"))
    }

    fn get_prop(
        &self,
        puri: &impl PrincipalUri,
        user: &Principal,
        prop: &CommonPropertiesPropName,
    ) -> Result<Self::Prop, Self::Error> {
        CommonPropertiesExtension::get_prop(self, puri, user, prop)
    }

    fn get_displayname(&self) -> Option<&str> {
        Some("Schedule Inbox")
    }

    fn get_owner(&self) -> Option<&str> {
        Some(&self.principal)
    }

    fn get_user_privileges(&self, user: &Principal) -> Result<UserPrivilegeSet, Self::Error> {
        Ok(UserPrivilegeSet::owner_only(
            user.is_principal(&self.principal),
        ))
    }
}

#[derive(Clone)]
pub struct InboxResourceService {
    pub(crate) store: Arc<dyn SchedulingStore>,
}

impl InboxResourceService {
    #[must_use]
    pub const fn new(store: Arc<dyn SchedulingStore>) -> Self {
        Self { store }
    }
}

#[async_trait]
impl ResourceService for InboxResourceService {
    type PathComponents = (String,);
    type MemberType = InboxObjectResource;
    type Resource = InboxResource;
    type Error = Error;
    type Principal = Principal;
    type PrincipalUri = CalDavPrincipalUri;

    const DAV_HEADER: &str = "1, 3, access-control, calendar-scheduling, calendar-auto-schedule";

    async fn get_resource(
        &self,
        (principal,): &Self::PathComponents,
        _show_deleted: bool,
    ) -> Result<Self::Resource, Self::Error> {
        Ok(InboxResource {
            principal: principal.clone(),
        })
    }

    async fn get_members(
        &self,
        (principal,): &Self::PathComponents,
    ) -> Result<Vec<Self::MemberType>, Self::Error> {
        Ok(self
            .store
            .get_inbox_objects(principal)
            .await?
            .into_iter()
            .map(|object| InboxObjectResource {
                object,
                principal: principal.clone(),
            })
            .collect())
    }

    fn axum_router<State: Send + Sync + Clone + 'static>(self) -> Router<State> {
        Router::new()
            .nest(
                "/{object_id}",
                InboxObjectResourceService {
                    store: self.store.clone(),
                }
                .axum_router(),
            )
            .route_service("/", self.axum_service())
    }
}

impl AxumMethods for InboxResourceService {}

#[derive(Clone, Debug)]
pub struct InboxObjectResource {
    pub(crate) object: InboxObject,
    pub(crate) principal: String,
}

impl ResourceName for InboxObjectResource {
    fn get_name(&self) -> Cow<'_, str> {
        Cow::from(&self.object.object_id)
    }
}

impl Resource for InboxObjectResource {
    type Prop = CalendarObjectPropWrapper;
    type Error = Error;
    type Principal = Principal;

    fn is_collection(&self) -> bool {
        false
    }

    fn get_resourcetype(&self) -> Resourcetype {
        resourcetype!()
    }

    fn get_prop(
        &self,
        puri: &impl PrincipalUri,
        user: &Principal,
        prop: &CalendarObjectPropWrapperName,
    ) -> Result<Self::Prop, Self::Error> {
        Ok(match prop {
            CalendarObjectPropWrapperName::CalendarObject(prop) => {
                CalendarObjectPropWrapper::CalendarObject(match prop {
                    CalendarObjectPropName::Getetag => {
                        CalendarObjectProp::Getetag(inbox_etag(&self.object))
                    }
                    CalendarObjectPropName::CalendarData(_) => {
                        CalendarObjectProp::CalendarData(self.object.ics.clone())
                    }
                    CalendarObjectPropName::Getcontenttype => {
                        CalendarObjectProp::Getcontenttype("text/calendar;charset=utf-8")
                    }
                })
            }
            CalendarObjectPropWrapperName::Common(prop) => CalendarObjectPropWrapper::Common(
                CommonPropertiesExtension::get_prop(self, puri, user, prop)?,
            ),
        })
    }

    fn get_displayname(&self) -> Option<&str> {
        None
    }

    fn get_owner(&self) -> Option<&str> {
        Some(&self.principal)
    }

    fn get_etag(&self) -> Option<String> {
        Some(inbox_etag(&self.object))
    }

    fn get_user_privileges(&self, user: &Principal) -> Result<UserPrivilegeSet, Self::Error> {
        Ok(UserPrivilegeSet::owner_only(
            user.is_principal(&self.principal),
        ))
    }
}

#[derive(Clone)]
pub struct InboxObjectResourceService {
    pub(crate) store: Arc<dyn SchedulingStore>,
}

#[async_trait]
impl ResourceService for InboxObjectResourceService {
    type PathComponents = (String, String); // principal, object_id
    type Resource = InboxObjectResource;
    type MemberType = InboxObjectResource;
    type Error = Error;
    type Principal = Principal;
    type PrincipalUri = CalDavPrincipalUri;

    const DAV_HEADER: &str = "1, 3, access-control, calendar-scheduling, calendar-auto-schedule";

    async fn get_resource(
        &self,
        (principal, object_id): &Self::PathComponents,
        _show_deleted: bool,
    ) -> Result<Self::Resource, Self::Error> {
        let object = self.store.get_inbox_object(principal, object_id).await?;
        Ok(InboxObjectResource {
            object,
            principal: principal.clone(),
        })
    }

    async fn delete_resource(
        &self,
        (principal, object_id): &Self::PathComponents,
        _use_trashbin: bool,
    ) -> Result<(), Self::Error> {
        self.store.delete_inbox_object(principal, object_id).await?;
        Ok(())
    }
}

impl AxumMethods for InboxObjectResourceService {
    fn get()
    -> Option<fn(Self, axum::extract::Request) -> BoxFuture<'static, Result<Response, Infallible>>>
    {
        Some(|state, req| {
            let mut service = Handler::with_state(get_inbox_object, state);
            Box::pin(Service::call(&mut service, req))
        })
    }
}

#[tracing::instrument(skip(store))]
pub async fn get_inbox_object(
    Path((principal, object_id)): Path<(String, String)>,
    State(InboxObjectResourceService { store }): State<InboxObjectResourceService>,
    user: Principal,
    method: Method,
) -> Result<Response, Error> {
    if !user.is_principal(&principal) {
        return Err(Error::Unauthorized);
    }

    let object = store.get_inbox_object(&principal, &object_id).await?;

    let mut resp = Response::builder().status(StatusCode::OK);
    let hdrs = resp.headers_mut().unwrap();
    hdrs.typed_insert(ETag::from_str(&inbox_etag(&object)).unwrap());
    hdrs.typed_insert(ContentType::from_str("text/calendar; charset=utf-8").unwrap());
    if matches!(method, Method::HEAD) {
        Ok(resp.body(Body::empty()).unwrap())
    } else {
        Ok(resp.body(Body::new(object.ics)).unwrap())
    }
}
