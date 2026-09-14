//! The per-principal schedule-outbox (RFC 6638 §8): a stub collection whose
//! POST endpoint performs explicit scheduling and answers with a
//! `schedule-response` document.

use crate::{CalDavPrincipalUri, Error};
use async_trait::async_trait;
use axum::Router;
use axum::body::Body;
use axum::extract::{Path, State};
use axum::handler::Handler;
use axum::response::{IntoResponse, Response};
use futures_util::future::BoxFuture;
use headers::{ContentType, HeaderMapExt};
use http::{StatusCode, Uri};
use rustical_dav::extensions::{
    CommonPropertiesExtension, CommonPropertiesProp, CommonPropertiesPropName,
};
use rustical_dav::namespace::{NS_CALDAV, NS_DAV};
use rustical_dav::privileges::UserPrivilegeSet;
use rustical_dav::resource::{AxumMethods, PrincipalUri, Resource, ResourceName, ResourceService};
use rustical_dav::resourcetype;
use rustical_dav::xml::Resourcetype;
use rustical_scheduling::Scheduler;
use rustical_store::auth::Principal;
use rustical_xml::{XmlRootTag, XmlSerialize};
use std::borrow::Cow;
use std::convert::Infallible;
use std::str::FromStr;
use std::sync::Arc;
use tower::Service;

#[derive(Clone, Debug)]
pub struct OutboxResource {
    principal: String,
}

impl ResourceName for OutboxResource {
    fn get_name(&self) -> Cow<'_, str> {
        Cow::from("outbox")
    }
}

impl Resource for OutboxResource {
    type Prop = CommonPropertiesProp;
    type Error = Error;
    type Principal = Principal;

    fn is_collection(&self) -> bool {
        true
    }

    fn get_resourcetype(&self) -> Resourcetype {
        resourcetype!((NS_DAV, "collection"), (NS_CALDAV, "schedule-outbox"))
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
        Some("Schedule Outbox")
    }

    fn get_owner(&self) -> Option<&str> {
        Some(&self.principal)
    }

    fn get_user_privileges(&self, user: &Principal) -> Result<UserPrivilegeSet, Self::Error> {
        // Omnical §17.9.2: `view` members read but cannot write.
        if !user.is_principal(&self.principal) {
            return Ok(UserPrivilegeSet::default());
        }
        if user.can_write(&self.principal) {
            Ok(UserPrivilegeSet::all())
        } else {
            Ok(UserPrivilegeSet::read_only())
        }
    }
}

#[derive(Clone)]
pub struct OutboxResourceService {
    pub(crate) scheduler: Arc<Scheduler>,
}

impl OutboxResourceService {
    #[must_use]
    pub const fn new(scheduler: Arc<Scheduler>) -> Self {
        Self { scheduler }
    }
}

#[async_trait]
impl ResourceService for OutboxResourceService {
    type PathComponents = (String,);
    type MemberType = OutboxResource;
    type Resource = OutboxResource;
    type Error = Error;
    type Principal = Principal;
    type PrincipalUri = CalDavPrincipalUri;

    const DAV_HEADER: &str = "1, 3, access-control, calendar-scheduling, calendar-auto-schedule";

    async fn get_resource(
        &self,
        (principal,): &Self::PathComponents,
        _show_deleted: bool,
    ) -> Result<Self::Resource, Self::Error> {
        Ok(OutboxResource {
            principal: principal.clone(),
        })
    }

    fn axum_router<State: Send + Sync + Clone + 'static>(self) -> Router<State> {
        Router::new().route_service("/", self.axum_service())
    }
}

impl AxumMethods for OutboxResourceService {
    fn post()
    -> Option<fn(Self, axum::extract::Request) -> BoxFuture<'static, Result<Response, Infallible>>>
    {
        Some(|state, req| {
            let mut service = Handler::with_state(post_outbox, state);
            Box::pin(Service::call(&mut service, req))
        })
    }
}

// RFC 6638 section 8: per-recipient status of one POSTed iTIP message
#[derive(XmlSerialize)]
pub struct ScheduleResponseRecipient {
    #[xml(ns = "rustical_dav::namespace::NS_DAV")]
    pub href: Uri,
}

#[derive(XmlSerialize)]
pub struct ScheduleResponseEntry {
    #[xml(ns = "rustical_dav::namespace::NS_CALDAV")]
    pub recipient: ScheduleResponseRecipient,
    #[xml(ns = "rustical_dav::namespace::NS_CALDAV", rename = "request-status")]
    pub request_status: String,
}

#[derive(XmlSerialize, XmlRootTag)]
#[xml(root = "schedule-response", ns = "rustical_dav::namespace::NS_CALDAV")]
pub struct ScheduleResponse {
    #[xml(rename = "response", flatten)]
    pub responses: Vec<ScheduleResponseEntry>,
}

impl IntoResponse for ScheduleResponse {
    fn into_response(self) -> Response {
        let Ok(output) = rustical_xml::XmlSerializeRoot::serialize_to_string(&self) else {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "IO error when serialising output",
            )
                .into_response();
        };

        let mut resp = Response::builder().status(StatusCode::OK);
        resp.headers_mut()
            .expect("this always works")
            .typed_insert(ContentType::xml());
        resp.body(Body::from(output))
            .expect("empty body always works")
    }
}

#[tracing::instrument(skip(scheduler, body))]
pub async fn post_outbox(
    Path((principal,)): Path<(String,)>,
    State(OutboxResourceService { scheduler }): State<OutboxResourceService>,
    user: Principal,
    body: String,
) -> Result<ScheduleResponse, Error> {
    if !user.is_principal(&principal) {
        return Err(Error::Unauthorized);
    }
    // Omnical §17.9.2: scheduling triggers are write operations — `view`
    // members cannot post to the outbox.
    if !user.can_write(&principal) {
        return Err(Error::DavError(rustical_dav::Error::Forbidden));
    }

    let statuses = scheduler
        .handle_outbox_post(&user.id, &body)
        .await
        .map_err(|err| Error::DavError(rustical_dav::Error::BadRequest(err)))?;

    Ok(ScheduleResponse {
        responses: statuses
            .into_iter()
            .map(|status| ScheduleResponseEntry {
                recipient: ScheduleResponseRecipient {
                    href: Uri::from_str(&format!("mailto:{}", status.recipient))
                        .expect("attendee addresses produce valid mailto URIs"),
                },
                request_status: if status.code < 300 {
                    "2.0;Success".to_owned()
                } else {
                    format!("5.0;{}", status.message)
                },
            })
            .collect(),
    })
}
