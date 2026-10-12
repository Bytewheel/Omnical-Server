use crate::Error;
use crate::calendar::CalendarResourceService;
use axum::body::Body;
use axum::extract::{Query, State};
use axum::{extract::Path, response::Response};
use caldata::component::IcalCalendar;
use caldata::generator::Emitter;
use caldata::parser::ContentLine;
use headers::{ContentType, HeaderMapExt};
use http::{HeaderValue, Method, StatusCode, header};
use rustical_dav::rfc_3986_percent_encode;
use rustical_dav_push::DavPushStore;
use rustical_ical::CalendarObject;
use rustical_store::{Calendar, CalendarStore, auth::Principal};
use serde::Deserialize;
use std::str::FromStr;
use tracing::instrument;

/// The `?dailyview=1` request of the owner export: the DailyView-shaped
/// variant (see `crate::dailyview`). `serde(default)` keeps unknown
/// parameters from rejecting the request.
#[derive(Debug, Default, Deserialize)]
pub struct DailyviewExportQuery {
    #[serde(default)]
    pub(crate) dailyview: Option<String>,
}

/// The `X-WR-*` calendar metadata properties of the export envelope.
pub(crate) fn calendar_x_wr_props(calendar: &Calendar) -> Vec<ContentLine> {
    let mut props = vec![];

    if let Some(displayname) = &calendar.meta.displayname {
        props.push(ContentLine {
            name: "X-WR-CALNAME".to_owned(),
            value: displayname.clone(),
            params: vec![].into(),
        });
    }
    if let Some(description) = &calendar.meta.description {
        props.push(ContentLine {
            name: "X-WR-CALDESC".to_owned(),
            value: description.clone(),
            params: vec![].into(),
        });
    }
    if let Some(color) = &calendar.meta.color {
        props.push(ContentLine {
            name: "X-WR-CALCOLOR".to_owned(),
            value: color.clone(),
            params: vec![].into(),
        });
    }
    if let Some(timezone_id) = &calendar.timezone_id {
        props.push(ContentLine {
            name: "X-WR-TIMEZONE".to_owned(),
            value: timezone_id.clone(),
            params: vec![].into(),
        });
    }

    props
}

/// Generate the full `.ics` export of a calendar: all objects wrapped in one
/// `VCALENDAR`, with `X-WR-CALNAME`/`X-WR-CALDESC`/`X-WR-CALCOLOR`/
/// `X-WR-TIMEZONE` props derived from the calendar metadata.
///
/// Shared between the owner-authenticated `route_get` export and the
/// unauthenticated subscription export routes (Omnical "share links",
/// PLAN.md §17.7), so both serve byte-identical payloads.
#[must_use]
pub fn build_export_ics(calendar: &Calendar, objects: Vec<(String, CalendarObject)>) -> String {
    let objects = objects
        .into_iter()
        .map(|(_, object)| object.into())
        .collect();

    IcalCalendar::from_objects(
        "RustiCal Export".to_owned(),
        objects,
        calendar_x_wr_props(calendar),
    )
    .generate()
}

#[instrument(skip(cal_store))]
#[allow(clippy::too_many_arguments)]
pub async fn route_get<C: CalendarStore, DP: DavPushStore>(
    Path((principal, calendar_id)): Path<(String, String)>,
    State(CalendarResourceService {
        cal_store, config, ..
    }): State<CalendarResourceService<C, DP>>,
    user: Principal,
    method: Method,
    Query(export_query): Query<DailyviewExportQuery>,
) -> Result<Response, Error> {
    if !user.is_principal(&principal) {
        return Err(crate::Error::Unauthorized);
    }

    let calendar = cal_store
        .get_calendar(&principal, &calendar_id, true)
        .await?;
    if !user.is_principal(&calendar.principal) {
        return Err(crate::Error::Unauthorized);
    }

    let objects = cal_store.get_objects(&principal, &calendar_id).await?;

    // Omnical §18.38: `?dailyview=1` serves the DailyView-shaped export (the
    // stock Punkt MP02 phone syncs aphy.io, not omnical — its only ingest is
    // a manual import of this download, so the file itself must be
    // phone-shaped: recurrences flattened to concrete instances, all-day
    // lines as local midnights). Armed by the same `[caldav]`
    // dailyview_timezone` as the wire shim; every other request — and an
    // unarmed config — gets the canonical export.
    let export_ics = if export_query.dailyview.is_some() {
        config.dailyview_timezone().map_or_else(
            || build_export_ics(&calendar, objects.clone()),
            |timezone| {
                crate::dailyview::build_export_ics_dailyview(
                    &calendar,
                    objects.clone(),
                    timezone,
                    chrono::Utc::now(),
                )
            },
        )
    } else {
        build_export_ics(&calendar, objects)
    };

    let mut resp = Response::builder().status(StatusCode::OK);
    let hdrs = resp.headers_mut().unwrap();
    hdrs.typed_insert(ContentType::from_str("text/calendar; charset=utf-8").unwrap());

    let filename = format!(
        "{}_{}{}.ics",
        calendar.principal,
        calendar.id,
        calendar
            .meta
            .displayname
            .as_deref()
            .map(|name| format!("_{name}"))
            .unwrap_or_default()
    );
    let filename = rfc_3986_percent_encode(&filename);
    hdrs.insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_str(&format!(
            "attachement; filename*=UTF-8''{filename}; filename={filename}",
        ))
        .unwrap(),
    );
    if matches!(method, Method::HEAD) {
        Ok(resp.body(Body::empty()).unwrap())
    } else {
        Ok(resp.body(Body::new(export_ics)).unwrap())
    }
}
