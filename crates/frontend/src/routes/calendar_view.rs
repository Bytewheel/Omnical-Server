use std::str::FromStr;

use askama::Template;
use askama_web::WebTemplate;
use axum::{
    Extension,
    extract::{Form, Path, Query},
    response::{IntoResponse, Redirect, Response},
};
use axum_extra::TypedHeader;
use caldata::component::{CalendarInnerData, Component, ComponentMut};
use caldata::component::{
    CalendarInnerDataBuilder, IcalCalendarObjectBuilder, IcalEvent, IcalEventBuilder,
};
use caldata::parser::{ContentLine, ParserOptions};
use caldata::property::{
    Calscale, IcalCALSCALEProperty, IcalDTENDProperty, IcalDTSTAMPProperty, IcalDTSTARTProperty,
    IcalPRODIDProperty, IcalSUMMARYProperty, IcalUIDProperty, IcalVERSIONProperty, IcalVersion,
};
use caldata::types::{CalDate, CalDateOrDateTime, CalDateTime, Tz as CalTz};
use chrono::{Datelike, NaiveDate, NaiveTime, TimeZone, Utc};
use chrono_tz::Tz as ChronoTz;
use headers::Cookie;
use http::StatusCode;
use rustical_ical::CalendarObject;
use rustical_store::{Calendar, CalendarStore, auth::Principal, calendar_store::CalendarQuery};
use serde::Deserialize;
use std::sync::Arc;
use uuid::Uuid;

use crate::pages::DefaultLayoutData;
use crate::pages::user::{Section, UserPage};

/// The month view rendered as the portal's "Calendar" section. All fields are
/// display strings cooked in Rust so the template stays presentation-only.
#[derive(Template, WebTemplate)]
#[template(path = "components/sections/calendar_grid_section.html")]
pub struct CalendarGridSection {
    /// "Calendar" (aggregate) or the single calendar's display name.
    pub heading: String,
    /// "October 2026".
    pub month_label: String,
    /// "YYYY-MM" of the previous month.
    pub prev: String,
    /// "YYYY-MM" of the next month.
    pub next: String,
    /// "YYYY-MM" of the current month (Today button).
    pub today: String,
    /// E.g. "Times shown in Europe/London".
    pub times_note: String,
    /// The create-event form URL.
    pub new_href: String,
    pub can_create: bool,
    pub weeks: Vec<CalendarGridWeek>,
    pub calendars: Vec<CalendarLegendChip>,
}

impl Section for CalendarGridSection {
    fn name() -> &'static str {
        "calendar"
    }
}

pub struct CalendarGridWeek {
    pub days: Vec<CalendarGridDay>,
}

pub struct CalendarGridDay {
    pub day_number: u32,
    pub in_month: bool,
    pub today: bool,
    pub events: Vec<CalendarGridEvent>,
}

pub struct CalendarGridEvent {
    pub summary: String,
    /// "09:00" or "09:00–10:00"; `None` for all-day events.
    pub time: Option<String>,
    pub all_day: bool,
    /// Calendar color for the left accent bar ("transparent" when unset).
    pub color: String,
    pub calendar_name: String,
    /// The edit form URL for this event's underlying object.
    pub href: String,
    /// False (rendered as a plain chip) when the user cannot write the
    /// owning principal or the calendar is a read-only mirror.
    pub editable: bool,
}

pub struct CalendarLegendChip {
    pub name: String,
    /// Calendar color for the legend swatch ("transparent" when unset).
    pub color: String,
}

/// One calendar offered by the new-event form's calendar picker.
pub struct CalendarFormOption {
    /// `principal|cal_id`.
    pub value: String,
    pub label: String,
}

const GRID_DAYS: i64 = 42;

/// Resolve the timezone used to display times: the browser's timezone from the
/// `tzid` cookie, falling back to UTC when absent or unknown. Floating times
/// are rendered as wall-clock in this zone.
#[must_use]
pub fn display_timezone(cookie_tzid: Option<&str>) -> ChronoTz {
    display_timezone_fallback(cookie_tzid, chrono_tz::UTC)
}

/// [`display_timezone`] with a caller-supplied fallback instead of UTC. The
/// single-calendar view falls back to the calendar's own `timezone_id`
/// (`PLAN_NEXT_AGENT_WEB_CALENDAR_UI.md` §1.1 Limit B — UTC instances map into
/// the calendar zone when the browser zone is unknown).
#[must_use]
pub fn display_timezone_fallback(cookie_tzid: Option<&str>, fallback: ChronoTz) -> ChronoTz {
    cookie_tzid
        .map(str::trim)
        .filter(|tzid| !tzid.is_empty() && tzid.len() <= 64)
        .and_then(|tzid| ChronoTz::from_str(tzid).ok())
        .unwrap_or(fallback)
}

#[must_use]
fn parse_month(date: Option<&str>, today: NaiveDate) -> NaiveDate {
    date.and_then(|d| NaiveDate::parse_from_str(&format!("{d}-01"), "%Y-%m-%d").ok())
        .or_else(|| NaiveDate::from_ymd_opt(today.year(), today.month(), 1))
        .unwrap_or(today)
}

/// Shift a first-of-month date by `delta` months.
#[must_use]
fn shift_month(first: NaiveDate, delta: i32) -> NaiveDate {
    let total =
        first.year() * 12 + i32::try_from(first.month()).expect("month is 1-12") - 1 + delta;
    let (year, month0) = (total.div_euclid(12), total.rem_euclid(12));
    NaiveDate::from_ymd_opt(year, u32::try_from(month0 + 1).unwrap_or(1), 1).unwrap_or(first)
}

/// The first day shown on the grid (the Monday on or before the 1st).
#[must_use]
fn grid_start(first_of_month: NaiveDate) -> NaiveDate {
    let offset = i64::from(first_of_month.weekday().num_days_from_monday());
    first_of_month - chrono::Duration::days(offset)
}

/// Read a TEXT property (case-insensitive) from the raw content lines.
pub(super) fn text_prop<'a>(props: &'a [ContentLine], name: &str) -> Option<&'a str> {
    props
        .iter()
        .find(|p| p.name.eq_ignore_ascii_case(name))
        .map(|p| p.value.as_str())
}

/// "09:00" wall-clock for a DATE-TIME, rendered in the display timezone.
/// Floating times (no zone) keep their wall clock unchanged.
#[must_use]
pub(super) fn format_time(dt: &CalDateTime, display_tz: ChronoTz) -> String {
    if dt.timezone().is_local() {
        dt.utc().format("%H:%M").to_string()
    } else {
        dt.utc()
            .with_timezone(&display_tz)
            .format("%H:%M")
            .to_string()
    }
}

/// The grid column (local date) an event start occupies.
#[must_use]
pub(super) fn bucket_date(cdt: &CalDateOrDateTime, display_tz: ChronoTz) -> NaiveDate {
    match cdt {
        CalDateOrDateTime::Date(date) => date.naive_date().to_owned(),
        CalDateOrDateTime::DateTime(dt) => {
            if dt.timezone().is_local() {
                dt.date_floor()
            } else {
                dt.utc().with_timezone(&display_tz).date_naive()
            }
        }
    }
}

fn can_create_any<CS: CalendarStore>(store: &CS, user: &Principal, calendars: &[Calendar]) -> bool {
    calendars
        .iter()
        .any(|c| user.can_write(&c.principal) && !store.is_read_only(&c.id))
}

/// Build the 6-week grid view model for one or many calendars.
#[allow(clippy::too_many_lines)]
async fn build_grid<CS: CalendarStore>(
    store: &CS,
    user: &Principal,
    calendars: &[Calendar],
    month: NaiveDate,
    display_tz: ChronoTz,
    today: NaiveDate,
    single_calendar: bool,
) -> Result<CalendarGridSection, rustical_store::Error> {
    let start = grid_start(month);
    let end = start + chrono::Duration::days(GRID_DAYS);
    let expand_start = start.and_time(NaiveTime::MIN).and_utc();
    let expand_end = end.and_time(NaiveTime::MIN).and_utc();

    let mut events_by_day: Vec<Vec<CalendarGridEvent>> =
        (0..GRID_DAYS).map(|_| Vec::new()).collect();
    let mut chips = Vec::new();

    for calendar in calendars {
        let cal_name = calendar
            .meta
            .displayname
            .clone()
            .unwrap_or_else(|| calendar.id.clone());
        chips.push(CalendarLegendChip {
            name: if single_calendar {
                cal_name.clone()
            } else {
                format!("{}/{}", calendar.principal, cal_name)
            },
            color: calendar
                .meta
                .color
                .clone()
                .unwrap_or_else(|| "transparent".to_owned()),
        });

        let query = CalendarQuery {
            time_start: Some(start),
            time_end: Some(end),
        };
        let objects = store
            .calendar_query(&calendar.principal, &calendar.id, query)
            .await?;

        let editable = user.can_write(&calendar.principal) && !store.is_read_only(&calendar.id);
        for (object_id, object) in objects {
            let href = format!(
                "/frontend/user/{}/calendar/{}/events/{object_id}/edit",
                calendar.principal, calendar.id
            );
            let expanded = object
                .get_inner()
                .expand_recurrence(Some(expand_start), Some(expand_end));
            let CalendarInnerData::Event(main, rest) = expanded.get_inner() else {
                // VTODO / VJOURNAL belong to the tasks view; skip here.
                continue;
            };
            for event in std::iter::once(main).chain(rest) {
                let summary = text_prop(event.get_properties(), "SUMMARY")
                    .map_or_else(|| "(no title)".to_owned(), ToOwned::to_owned);

                let all_day = event.dtstart.0.is_date();
                let start_label = match &event.dtstart.0 {
                    CalDateOrDateTime::DateTime(dt) => Some(format_time(dt, display_tz)),
                    CalDateOrDateTime::Date(_) => None,
                };
                let end_label = event.dtend.as_ref().and_then(|dtend| match &dtend.0 {
                    CalDateOrDateTime::DateTime(dt) if !all_day => {
                        Some(format_time(dt, display_tz))
                    }
                    _ => None,
                });
                let time = start_label.as_ref().map(|start| {
                    end_label.map_or_else(|| start.clone(), |end| format!("{start}–{end}"))
                });
                let bucket = bucket_date(&event.dtstart.0, display_tz);
                let day_offset = (bucket - start).num_days();
                if !(0..GRID_DAYS).contains(&day_offset) {
                    continue;
                }
                events_by_day[usize::try_from(day_offset).expect("day offset is non-negative")]
                    .push(CalendarGridEvent {
                        summary,
                        time,
                        all_day,
                        color: calendar
                            .meta
                            .color
                            .clone()
                            .unwrap_or_else(|| "transparent".to_owned()),
                        calendar_name: cal_name.clone(),
                        href: href.clone(),
                        editable,
                    });
            }
        }
    }

    // All-day first, then by start time (HH:MM sorts lexically).
    for day in &mut events_by_day {
        day.sort_by_key(|e| (!e.all_day, e.time.clone().unwrap_or_default()));
    }

    let weeks = (0..6)
        .map(|week| CalendarGridWeek {
            days: (0..7)
                .map(|day| {
                    let offset = week * 7 + day;
                    let date = start + chrono::Duration::days(offset);
                    CalendarGridDay {
                        day_number: date.day(),
                        in_month: date.month() == month.month() && date.year() == month.year(),
                        today: date == today,
                        events: std::mem::take(
                            &mut events_by_day
                                [usize::try_from(offset).expect("weekly offset is non-negative")],
                        ),
                    }
                })
                .collect(),
        })
        .collect();

    let can_create = can_create_any(store, user, calendars);
    let new_href = if single_calendar {
        // The single-calendar grid is owner-scoped in the URL (the path
        // `{user}` segment is the owning principal, same as the Calendars
        // tab), so the create form must keep that segment intact — group
        // calendars are fetched under the group principal.
        let principal = calendars
            .first()
            .map(|c| c.principal.as_str())
            .unwrap_or_default();
        let cal_id = calendars.first().map(|c| c.id.as_str()).unwrap_or_default();
        format!("/frontend/user/{principal}/calendar/{cal_id}/events/new")
    } else {
        format!("/frontend/user/{}/events/new", user.id)
    };

    Ok(CalendarGridSection {
        heading: if single_calendar {
            calendars
                .first()
                .and_then(|c| c.meta.displayname.clone())
                .unwrap_or_else(|| "Calendar".to_owned())
        } else {
            "Calendar".to_owned()
        },
        month_label: month.format("%B %Y").to_string(),
        prev: shift_month(month, -1).format("%Y-%m").to_string(),
        next: shift_month(month, 1).format("%Y-%m").to_string(),
        today: today.format("%Y-%m").to_string(),
        times_note: format!("Times shown in {display_tz}"),
        new_href,
        can_create,
        weeks,
        calendars: chips,
    })
}

/// Fetch every calendar the user can see (their own plus memberships and
/// guest shares), mirroring the Calendars tab's listing rule.
async fn user_calendars<CS: CalendarStore>(
    store: &Arc<CS>,
    user: &Principal,
) -> Result<Vec<Calendar>, rustical_store::Error> {
    let mut calendars = Vec::new();
    for group in user.memberships() {
        calendars.extend(store.get_calendars(group).await?);
    }
    Ok(calendars)
}

#[derive(Debug, Default, Deserialize)]
pub struct GridQuery {
    #[serde(default)]
    pub date: Option<String>,
}

pub async fn route_events<CS: CalendarStore>(
    Path(user_id): Path<String>,
    Extension(store): Extension<Arc<CS>>,
    Query(query): Query<GridQuery>,
    TypedHeader(cookie): TypedHeader<Cookie>,
    user: Principal,
) -> Result<Response, rustical_store::Error> {
    if user_id != user.id {
        return Ok(StatusCode::UNAUTHORIZED.into_response());
    }
    let today = Utc::now().date_naive();
    let display_tz = display_timezone(cookie.get("tzid"));
    let month = parse_month(query.date.as_deref(), today);
    let calendars = user_calendars(&store, &user).await?;
    let section = build_grid(
        store.as_ref(),
        &user,
        &calendars,
        month,
        display_tz,
        today,
        false,
    )
    .await?;
    Ok(UserPage { user, section }.into_response())
}

pub async fn route_calendar_events<CS: CalendarStore>(
    Path((owner, cal_id)): Path<(String, String)>,
    Extension(store): Extension<Arc<CS>>,
    Query(query): Query<GridQuery>,
    TypedHeader(cookie): TypedHeader<Cookie>,
    user: Principal,
) -> Result<Response, rustical_store::Error> {
    if !user.is_principal(&owner) {
        return Ok(StatusCode::UNAUTHORIZED.into_response());
    }
    let calendar = store.get_calendar(&owner, &cal_id, true).await?;
    let today = Utc::now().date_naive();
    let display_tz = display_timezone_fallback(
        cookie.get("tzid"),
        calendar.get_timezone().unwrap_or(chrono_tz::UTC),
    );
    let month = parse_month(query.date.as_deref(), today);
    let section = build_grid(
        store.as_ref(),
        &user,
        &[calendar],
        month,
        display_tz,
        today,
        true,
    )
    .await?;
    Ok(UserPage { user, section }.into_response())
}

// ---------------------------------------------------------------------------
// Event create / edit / delete.
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Deserialize)]
pub struct EventForm {
    /// `principal|cal_id` for the aggregate form; scoped by the URL otherwise.
    #[serde(default)]
    pub calendar: Option<String>,
    pub summary: String,
    #[serde(default)]
    pub location: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    /// Present only when the all-day checkbox is ticked.
    #[serde(default)]
    pub all_day: Option<String>,
    pub start_date: String,
    #[serde(default)]
    pub start_time: Option<String>,
    #[serde(default)]
    pub end_date: Option<String>,
    #[serde(default)]
    pub end_time: Option<String>,
    #[serde(default)]
    pub timezone: Option<String>,
}

#[derive(Template, WebTemplate)]
#[template(path = "pages/event_form.html")]
pub struct EventFormPage {
    pub title: String,
    pub action: String,
    pub calendars: Vec<CalendarFormOption>,
    pub summary: String,
    pub location: String,
    pub description: String,
    pub all_day: bool,
    pub start_date: String,
    pub start_time: String,
    pub end_date: String,
    pub end_time: String,
    /// The currently selected IANA timezone (defaults to the browser's).
    pub timezone: String,
    /// Every IANA timezone id, for the datalist suggestions.
    pub timezones: Vec<String>,
}

impl DefaultLayoutData for EventFormPage {
    fn get_user(&self) -> Option<&Principal> {
        None
    }
}

/// Split a `"principal|cal_id"` selector value.
#[must_use]
pub(super) fn split_calendar_value(value: &str) -> Option<(&str, &str)> {
    value.split_once('|')
}

/// The user-selected timezone for a submitted form, with a UTC fallback.
#[must_use]
pub(super) fn form_timezone(tzid: Option<&str>, default: ChronoTz) -> ChronoTz {
    tzid.and_then(|tzid| ChronoTz::from_str(tzid).ok())
        .unwrap_or(default)
}

/// Interpret the form's wall-clock date(+time) in the chosen zone and store
/// it as an unambiguous UTC DATE-TIME (or an all-day DATE). Shared by the
/// event and task forms.
pub(super) fn form_datetime(
    date_str: &str,
    time_str: Option<&str>,
    all_day: bool,
    tzid: Option<&str>,
    default: ChronoTz,
) -> Option<CalDateOrDateTime> {
    let date = NaiveDate::parse_from_str(date_str, "%Y-%m-%d").ok()?;
    if all_day {
        return Some(CalDateOrDateTime::Date(CalDate(date, CalTz::Local)));
    }
    let time = time_str
        .and_then(|t| NaiveTime::parse_from_str(t, "%H:%M").ok())
        .unwrap_or(NaiveTime::MIN);
    let tz = form_timezone(tzid, default);
    let utc = tz
        .from_local_datetime(&date.and_time(time))
        .earliest()
        .map_or_else(
            || date.and_time(time).and_utc(),
            |dt| dt.with_timezone(&Utc),
        );
    Some(CalDateOrDateTime::DateTime(CalDateTime::from(utc)))
}

/// Interpret the form's wall-clock start in the chosen zone and store it as an
/// unambiguous UTC DATE-TIME (or an all-day DATE).
fn form_start(form: &EventForm, default: ChronoTz) -> Option<CalDateOrDateTime> {
    form_datetime(
        &form.start_date,
        form.start_time.as_deref(),
        form.all_day.as_deref() == Some("on"),
        form.timezone.as_deref(),
        default,
    )
}

/// The event's end: a UTC DATE-TIME strictly after start, or an all-day DATE.
fn form_end(form: &EventForm, default: ChronoTz) -> Option<CalDateOrDateTime> {
    let start = form_start(form, default)?;
    if form.all_day.as_deref() == Some("on") {
        // All-day DTEND is exclusive: the stored end is last day + 1.
        let last = form
            .end_date
            .as_deref()
            .and_then(|d| NaiveDate::parse_from_str(d, "%Y-%m-%d").ok());
        let end = last.and_then(|d| d.succ_opt()).or_else(|| match &start {
            CalDateOrDateTime::Date(date) => date.0.succ_opt(),
            CalDateOrDateTime::DateTime(_) => None,
        })?;
        return Some(CalDateOrDateTime::Date(CalDate(end, CalTz::Local)));
    }
    let CalDateOrDateTime::DateTime(_) = start else {
        return None;
    };
    let end_date = NaiveDate::parse_from_str(form.end_date.as_deref()?, "%Y-%m-%d").ok()?;
    let end_time = form
        .end_time
        .as_deref()
        .and_then(|t| NaiveTime::parse_from_str(t, "%H:%M").ok())
        .unwrap_or(NaiveTime::MIN);
    let tz = form_timezone(form.timezone.as_deref(), default);
    let end_utc = tz
        .from_local_datetime(&end_date.and_time(end_time))
        .earliest()
        .map_or_else(
            || end_date.and_time(end_time).and_utc(),
            |dt| dt.with_timezone(&Utc),
        );
    let end = CalDateOrDateTime::DateTime(CalDateTime::from(end_utc));
    (end.utc() > start.utc()).then_some(end)
}

/// Build a `CalendarObject` for the form, reusing `uid` when updating an
/// existing event (edit keeps the resource's identity across clients).
fn build_event_object(form: &EventForm, default: ChronoTz, uid: String) -> Option<CalendarObject> {
    let start = form_start(form, default)?;
    let mut props: Vec<ContentLine> = vec![
        IcalDTSTARTProperty(start, vec![].into()).into(),
        IcalDTSTAMPProperty(CalDateTime::from(Utc::now()), vec![].into()).into(),
        IcalUIDProperty(uid, vec![].into()).into(),
        IcalSUMMARYProperty(form.summary.clone(), vec![].into()).into(),
    ];
    if let Some(end) = form_end(form, default) {
        props.push(IcalDTENDProperty(end, vec![].into()).into());
    }
    if let Some(location) = form.location.as_deref().filter(|s| !s.is_empty()) {
        props.push(ContentLine {
            name: "LOCATION".to_owned(),
            value: location.to_owned(),
            ..Default::default()
        });
    }
    if let Some(description) = form.description.as_deref().filter(|s| !s.is_empty()) {
        props.push(ContentLine {
            name: "DESCRIPTION".to_owned(),
            value: description.to_owned(),
            ..Default::default()
        });
    }

    let object = IcalCalendarObjectBuilder {
        properties: vec![
            IcalVERSIONProperty(IcalVersion::Version2_0, vec![].into()).into(),
            IcalCALSCALEProperty(Calscale::Gregorian, vec![].into()).into(),
            IcalPRODIDProperty(
                "-//github.com/Bytewheel/Omnical web calendar//EN".to_owned(),
                vec![].into(),
            )
            .into(),
        ],
        inner: Some(CalendarInnerDataBuilder::Event(vec![IcalEventBuilder {
            properties: props,
            alarms: vec![],
        }])),
        vtimezones: std::collections::BTreeMap::default(),
    }
    .build(&ParserOptions::default(), None)
    .ok()?
    .into();

    Some(object)
}

/// The calendars offered by the aggregate form's picker (writable, not
/// read-only mirrors).
fn calendar_options<CS: CalendarStore>(
    store: &CS,
    user: &Principal,
    calendars: &[Calendar],
) -> Vec<CalendarFormOption> {
    calendars
        .iter()
        .filter(|c| user.can_write(&c.principal) && !store.is_read_only(&c.id))
        .map(|c| CalendarFormOption {
            value: format!("{}|{}", c.principal, c.id),
            label: c.meta.displayname.clone().unwrap_or_else(|| c.id.clone()),
        })
        .collect()
}

async fn render_event_form<CS: CalendarStore>(
    store: &Arc<CS>,
    user: &Principal,
    title: String,
    action: String,
    default_tz: ChronoTz,
    fixed: Option<(&str, &str)>,
    defaults: &EventForm,
) -> Result<Response, rustical_store::Error> {
    let calendars = if let Some((principal, cal_id)) = fixed {
        vec![CalendarFormOption {
            value: format!("{principal}|{cal_id}"),
            label: cal_id.to_owned(),
        }]
    } else {
        calendar_options(store.as_ref(), user, &user_calendars(store, user).await?)
    };
    let timezone = defaults
        .timezone
        .clone()
        .unwrap_or_else(|| default_tz.to_string());
    // Same source and ordering as the portal's /_timezones.json endpoint —
    // the form datalist and the JSON API share the one vtimezones-rs map.
    let mut timezones: Vec<String> = vtimezones_rs::VTIMEZONES
        .keys()
        .map(|k| (*k).to_owned())
        .collect();
    timezones.sort_unstable();
    Ok(EventFormPage {
        title,
        action,
        calendars,
        summary: defaults.summary.clone(),
        location: defaults.location.clone().unwrap_or_default(),
        description: defaults.description.clone().unwrap_or_default(),
        all_day: defaults.all_day.as_deref() == Some("on"),
        start_date: defaults.start_date.clone(),
        start_time: defaults.start_time.clone().unwrap_or_default(),
        end_date: defaults.end_date.clone().unwrap_or_default(),
        end_time: defaults.end_time.clone().unwrap_or_default(),
        timezone,
        timezones,
    }
    .into_response())
}

pub async fn route_events_new<CS: CalendarStore>(
    Path(user_id): Path<String>,
    Extension(store): Extension<Arc<CS>>,
    TypedHeader(cookie): TypedHeader<Cookie>,
    user: Principal,
) -> Result<Response, rustical_store::Error> {
    if user_id != user.id {
        return Ok(StatusCode::UNAUTHORIZED.into_response());
    }
    let display_tz = display_timezone(cookie.get("tzid"));
    render_event_form(
        &store,
        &user,
        "New event".to_owned(),
        format!("/frontend/user/{user_id}/events"),
        display_tz,
        None,
        &EventForm::default(),
    )
    .await
}

pub async fn route_calendar_events_new<CS: CalendarStore>(
    Path((owner, cal_id)): Path<(String, String)>,
    Extension(store): Extension<Arc<CS>>,
    TypedHeader(cookie): TypedHeader<Cookie>,
    user: Principal,
) -> Result<Response, rustical_store::Error> {
    if !user.is_principal(&owner) || !user.can_write(&owner) || store.is_read_only(&cal_id) {
        return Ok(StatusCode::FORBIDDEN.into_response());
    }
    let calendar = store.get_calendar(&owner, &cal_id, true).await?;
    let display_tz = display_timezone_fallback(
        cookie.get("tzid"),
        calendar.get_timezone().unwrap_or(chrono_tz::UTC),
    );
    render_event_form(
        &store,
        &user,
        "New event".to_owned(),
        format!("/frontend/user/{owner}/calendar/{cal_id}/events"),
        display_tz,
        Some((&owner, &cal_id)),
        &EventForm::default(),
    )
    .await
}

/// Resolve the owning principal + calendar id the form acts on.
#[must_use]
fn form_target<'a>(form: &'a EventForm, fixed: (&'a str, &'a str)) -> (&'a str, &'a str) {
    form.calendar
        .as_deref()
        .and_then(split_calendar_value)
        .unwrap_or(fixed)
}

pub async fn route_event_create<CS: CalendarStore>(
    Path(user_id): Path<String>,
    Extension(store): Extension<Arc<CS>>,
    TypedHeader(cookie): TypedHeader<Cookie>,
    user: Principal,
    Form(form): Form<EventForm>,
) -> Result<Response, rustical_store::Error> {
    if user_id != user.id {
        return Ok(StatusCode::UNAUTHORIZED.into_response());
    }
    let display_tz = display_timezone(cookie.get("tzid"));
    let (principal, cal_id) = form_target(&form, (&user.id, ""));
    if cal_id.is_empty() || !user.can_write(principal) || store.is_read_only(cal_id) {
        return Ok(StatusCode::FORBIDDEN.into_response());
    }
    let object_id = Uuid::new_v4().to_string();
    let uid = format!("{object_id}@omnical");
    let Some(object) = build_event_object(&form, display_tz, uid) else {
        return Ok(StatusCode::BAD_REQUEST.into_response());
    };
    store
        .put_object(principal, cal_id, &object_id, object, false)
        .await?;
    Ok(Redirect::to(&format!(
        "/frontend/user/{user_id}/calendar/{cal_id}/events"
    ))
    .into_response())
}

pub async fn route_calendar_event_create<CS: CalendarStore>(
    Path((owner, cal_id)): Path<(String, String)>,
    Extension(store): Extension<Arc<CS>>,
    TypedHeader(cookie): TypedHeader<Cookie>,
    user: Principal,
    Form(form): Form<EventForm>,
) -> Result<Response, rustical_store::Error> {
    if !user.is_principal(&owner) || !user.can_write(&owner) || store.is_read_only(&cal_id) {
        return Ok(StatusCode::FORBIDDEN.into_response());
    }
    let display_tz = display_timezone(cookie.get("tzid"));
    let object_id = Uuid::new_v4().to_string();
    let uid = format!("{object_id}@omnical");
    let Some(object) = build_event_object(&form, display_tz, uid) else {
        return Ok(StatusCode::BAD_REQUEST.into_response());
    };
    store
        .put_object(&owner, &cal_id, &object_id, object, false)
        .await?;
    Ok(Redirect::to(&format!("/frontend/user/{owner}/calendar/{cal_id}/events")).into_response())
}

fn event_form_defaults(event: &IcalEvent, display_tz: ChronoTz) -> EventForm {
    let (start_date, start_time, all_day) = match &event.dtstart.0 {
        CalDateOrDateTime::Date(date) => (
            date.naive_date().format("%Y-%m-%d").to_string(),
            String::new(),
            true,
        ),
        CalDateOrDateTime::DateTime(dt) => {
            let local = if dt.timezone().is_local() {
                dt.utc().naive_utc()
            } else {
                dt.utc().with_timezone(&display_tz).naive_utc()
            };
            (
                local.format("%Y-%m-%d").to_string(),
                local.format("%H:%M").to_string(),
                false,
            )
        }
    };
    let end = event.dtend.as_ref().map(|dtend| match &dtend.0 {
        CalDateOrDateTime::Date(date) => {
            let last = date
                .naive_date()
                .pred_opt()
                .unwrap_or_else(|| date.naive_date().to_owned());
            (Some(last.format("%Y-%m-%d").to_string()), None)
        }
        CalDateOrDateTime::DateTime(dt) => {
            let local = if dt.timezone().is_local() {
                dt.utc().naive_utc()
            } else {
                dt.utc().with_timezone(&display_tz).naive_utc()
            };
            (
                Some(local.format("%Y-%m-%d").to_string()),
                Some(local.format("%H:%M").to_string()),
            )
        }
    });
    let (end_date, end_time) = end.unwrap_or((None, None));
    EventForm {
        calendar: None,
        summary: text_prop(event.get_properties(), "SUMMARY")
            .unwrap_or_default()
            .to_owned(),
        location: text_prop(event.get_properties(), "LOCATION").map(ToOwned::to_owned),
        description: text_prop(event.get_properties(), "DESCRIPTION").map(ToOwned::to_owned),
        all_day: all_day.then(|| "on".to_owned()),
        start_date,
        start_time: (!all_day).then_some(start_time),
        end_date,
        end_time,
        timezone: None,
    }
}

pub async fn route_event_edit<CS: CalendarStore>(
    Path((owner, cal_id, object_id)): Path<(String, String, String)>,
    Extension(store): Extension<Arc<CS>>,
    TypedHeader(cookie): TypedHeader<Cookie>,
    user: Principal,
) -> Result<Response, rustical_store::Error> {
    if !user.is_principal(&owner) {
        return Ok(StatusCode::UNAUTHORIZED.into_response());
    }
    if !user.can_write(&owner) || store.is_read_only(&cal_id) {
        return Ok(StatusCode::FORBIDDEN.into_response());
    }
    let object = store.get_object(&owner, &cal_id, &object_id, false).await?;
    let calendar = store.get_calendar(&owner, &cal_id, true).await?;
    let display_tz = display_timezone_fallback(
        cookie.get("tzid"),
        calendar.get_timezone().unwrap_or(chrono_tz::UTC),
    );
    let CalendarInnerData::Event(main, _) = object.get_inner().get_inner() else {
        return Ok(StatusCode::BAD_REQUEST.into_response());
    };
    let defaults = event_form_defaults(main, display_tz);
    render_event_form(
        &store,
        &user,
        "Edit event".to_owned(),
        format!("/frontend/user/{owner}/calendar/{cal_id}/events/{object_id}"),
        display_tz,
        Some((&owner, &cal_id)),
        &defaults,
    )
    .await
}

pub async fn route_event_update<CS: CalendarStore>(
    Path((owner, cal_id, object_id)): Path<(String, String, String)>,
    Extension(store): Extension<Arc<CS>>,
    TypedHeader(cookie): TypedHeader<Cookie>,
    user: Principal,
    Form(form): Form<EventForm>,
) -> Result<Response, rustical_store::Error> {
    if !user.is_principal(&owner) || !user.can_write(&owner) || store.is_read_only(&cal_id) {
        return Ok(StatusCode::FORBIDDEN.into_response());
    }
    let display_tz = display_timezone(cookie.get("tzid"));
    let original = store.get_object(&owner, &cal_id, &object_id, false).await?;
    let uid = original.get_uid().to_owned();
    let Some(object) = build_event_object(&form, display_tz, uid) else {
        return Ok(StatusCode::BAD_REQUEST.into_response());
    };
    store
        .put_object(&owner, &cal_id, &object_id, object, true)
        .await?;
    Ok(Redirect::to(&format!("/frontend/user/{owner}/calendar/{cal_id}/events")).into_response())
}

pub async fn route_event_delete<CS: CalendarStore>(
    Path((owner, cal_id, object_id)): Path<(String, String, String)>,
    Extension(store): Extension<Arc<CS>>,
    user: Principal,
) -> Result<Response, rustical_store::Error> {
    if !user.is_principal(&owner) || !user.can_write(&owner) || store.is_read_only(&cal_id) {
        return Ok(StatusCode::FORBIDDEN.into_response());
    }
    store
        .delete_object(&owner, &cal_id, &object_id, true)
        .await?;
    Ok(Redirect::to(&format!("/frontend/user/{owner}/calendar/{cal_id}/events")).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_timezone_falls_back_to_utc() {
        assert_eq!(display_timezone(None), chrono_tz::UTC);
        assert_eq!(display_timezone(Some("")), chrono_tz::UTC);
        assert_eq!(display_timezone(Some("Not/AZone")), chrono_tz::UTC);
        assert_eq!(
            display_timezone(Some("Europe/London")),
            chrono_tz::Europe::London
        );
    }

    #[test]
    fn display_timezone_rejects_overlong_ids() {
        let long = "x".repeat(200);
        assert_eq!(display_timezone(Some(&long)), chrono_tz::UTC);
    }

    #[test]
    fn parse_month_reads_ym_and_falls_back() {
        let today = NaiveDate::from_ymd_opt(2026, 10, 11).unwrap();
        assert_eq!(
            parse_month(Some("2026-03"), today),
            NaiveDate::from_ymd_opt(2026, 3, 1).unwrap()
        );
        assert_eq!(
            parse_month(Some("garbage"), today),
            NaiveDate::from_ymd_opt(2026, 10, 1).unwrap()
        );
        assert_eq!(
            parse_month(None, today),
            NaiveDate::from_ymd_opt(2026, 10, 1).unwrap()
        );
    }

    #[test]
    fn shift_month_wraps_years() {
        let dec = NaiveDate::from_ymd_opt(2026, 12, 1).unwrap();
        assert_eq!(
            shift_month(dec, 1),
            NaiveDate::from_ymd_opt(2027, 1, 1).unwrap()
        );
        assert_eq!(
            shift_month(dec, -11),
            NaiveDate::from_ymd_opt(2026, 1, 1).unwrap()
        );
    }

    #[test]
    fn grid_start_is_the_monday_on_or_before_the_first() {
        // 2026-10-01 is a Thursday, so the grid starts on Monday 2026-09-28.
        let first = NaiveDate::from_ymd_opt(2026, 10, 1).unwrap();
        assert_eq!(
            grid_start(first),
            NaiveDate::from_ymd_opt(2026, 9, 28).unwrap()
        );
    }
}
