use crate::Error;
use crate::calendar_object::{CalendarObjectPathComponents, CalendarObjectResourceService};
use crate::error::Precondition;
use axum::body::Body;
use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use axum_extra::TypedHeader;
use caldata::parser::ParserOptions;
use headers::{ContentType, ETag, HeaderMapExt, IfMatch, IfNoneMatch};
use http::{HeaderMap, HeaderValue, Method, StatusCode};
use rustical_ical::CalendarObject;
use rustical_store::CalendarStore;
use rustical_store::auth::Principal;
use std::str::FromStr;
use tracing::{instrument, warn};

#[instrument(skip(cal_store))]
pub async fn get_event<C: CalendarStore>(
    Path(CalendarObjectPathComponents {
        principal,
        calendar_id,
        object_id,
    }): Path<CalendarObjectPathComponents>,
    State(CalendarObjectResourceService {
        cal_store,
        config: _,
        scheduler: _,
    }): State<CalendarObjectResourceService<C>>,
    user: Principal,
    method: Method,
) -> Result<Response, Error> {
    if !user.is_principal(&principal) {
        return Err(crate::Error::Unauthorized);
    }

    let calendar = cal_store
        .get_calendar(&principal, &calendar_id, false)
        .await?;
    if !user.is_principal(&calendar.principal) {
        return Err(crate::Error::Unauthorized);
    }

    let event = cal_store
        .get_object(&principal, &calendar_id, &object_id, false)
        .await?;

    let mut resp = Response::builder().status(StatusCode::OK);
    let hdrs = resp.headers_mut().unwrap();
    hdrs.typed_insert(ETag::from_str(&event.get_etag()).unwrap());
    hdrs.typed_insert(ContentType::from_str("text/calendar; charset=utf-8").unwrap());
    if matches!(method, Method::HEAD) {
        Ok(resp.body(Body::empty()).unwrap())
    } else {
        Ok(resp.body(Body::new(event.get_ics().to_owned())).unwrap())
    }
}

#[instrument(skip(cal_store, scheduler))]
pub async fn put_event<C: CalendarStore>(
    Path(CalendarObjectPathComponents {
        principal,
        calendar_id,
        object_id,
    }): Path<CalendarObjectPathComponents>,
    State(CalendarObjectResourceService {
        cal_store,
        config,
        scheduler,
    }): State<CalendarObjectResourceService<C>>,
    user: Principal,
    mut if_none_match: Option<TypedHeader<IfNoneMatch>>,
    mut if_match: Option<TypedHeader<IfMatch>>,
    header_map: HeaderMap,
    body: String,
) -> Result<Response, Error> {
    if !user.is_principal(&principal) {
        return Err(crate::Error::Unauthorized);
    }

    // https://github.com/hyperium/headers/issues/204
    if !header_map.contains_key("If-None-Match") {
        if_none_match = None;
    }
    if !header_map.contains_key("If-Match") {
        if_match = None;
    }

    let user_agent = header_map
        .get(http::header::USER_AGENT)
        .and_then(|val| val.to_str().ok());

    // Fetch the previous object for the precondition checks below and for
    // implicit scheduling (it compares old vs. new attendees)
    let existing = if if_match.is_some() || if_none_match.is_some() || scheduler.is_some() {
        match cal_store
            .get_object(&principal, &calendar_id, &object_id, false)
            .await
        {
            Ok(existing) => Some(existing),
            Err(rustical_store::Error::NotFound) => None,
            Err(err) => Err(err)?,
        }
    } else {
        None
    };

    if if_match.is_some() || if_none_match.is_some() {
        // There's an already existing object
        if let Some(existing) = &existing {
            let etag: Option<ETag> = existing.get_etag().parse().ok();

            if let Some(if_match) = if_match.as_ref()
                && etag
                    .as_ref()
                    // If ETag is None If-Match will also fail
                    .is_none_or(|etag| !if_match.precondition_passes(etag))
            {
                return Err(Error::DavError(rustical_dav::Error::PreconditionFailed));
            }

            if let Some(if_none_match) = if_none_match.as_ref()
                && etag
                    .as_ref()
                    // If ETag is None If-None-Match will succeed as it will not match
                    .is_some_and(|etag| !if_none_match.precondition_passes(etag))
            {
                return Err(Error::DavError(rustical_dav::Error::PreconditionFailed));
            }
        }
        // No existing object but we still expect a match
        // From https://datatracker.ietf.org/doc/html/rfc2616#section-14.24
        // ```
        // If none of the entity tags match, or if "*" is given and no current
        // entity exists, the server MUST NOT perform the requested method, and
        // MUST return a 412 (Precondition Failed) response. This behavior is
        // most useful when the client wants to prevent an updating method, such
        // as PUT, from modifying a resource that has changed since the client
        // last retrieved it.
        // ```
        else if if_match.is_some() {
            return Err(Error::DavError(rustical_dav::Error::PreconditionFailed));
        }
    }

    let object = match CalendarObject::import(
        &body,
        Some(ParserOptions {
            rfc7809: config.rfc7809,
        }),
    ) {
        Ok(object) => object,
        Err(err) => {
            warn!("invalid calendar data:\n{body}");
            warn!("{err}");
            return Err(Error::PreconditionFailed(Precondition::ValidCalendarData));
        }
    };
    let etag = object.get_etag();
    cal_store
        .put_object(&principal, &calendar_id, &object_id, object, true)
        .await?;

    // Implicit scheduling (RFC 6638 subset): fire-and-forget style — the
    // object is stored, a scheduling failure must not fail the PUT
    if let Some(scheduler) = scheduler.as_ref() {
        scheduler
            .handle_put(
                &user.id,
                (&principal, &calendar_id, &object_id),
                existing.as_ref().map(|obj| obj.get_ics()),
                &body,
                user_agent,
            )
            .await;
    }

    let mut headers = HeaderMap::new();
    headers.insert(
        "ETag",
        HeaderValue::from_str(&etag).expect("Contains no invalid characters"),
    );
    Ok((StatusCode::CREATED, headers).into_response())
}
