use askama::Template;
use askama_web::WebTemplate;
use axum::{
    Extension,
    extract::{Form, Path, Query},
    response::{IntoResponse, Redirect, Response},
};
use axum_extra::TypedHeader;
use caldata::component::{
    CalendarInnerData, CalendarInnerDataBuilder, Component, ComponentMut,
    IcalCalendarObjectBuilder, IcalTodoBuilder,
};
use caldata::parser::{ContentLine, ParserOptions};
use caldata::property::{
    Calscale, IcalCALSCALEProperty, IcalDTSTAMPProperty, IcalDUEProperty, IcalPRODIDProperty,
    IcalUIDProperty, IcalVERSIONProperty, IcalVersion,
};
use caldata::types::{CalDateOrDateTime, CalDateTime};
use chrono::Utc;
use chrono_tz::Tz as ChronoTz;
use headers::Cookie;
use http::StatusCode;
use rustical_ical::{CalendarObject, CalendarObjectType};
use rustical_store::{Calendar, CalendarStore, auth::Principal};
use serde::Deserialize;
use std::sync::Arc;
use uuid::Uuid;

use crate::pages::DefaultLayoutData;
use crate::pages::user::{Section, UserPage};
use crate::routes::calendar_view::{
    display_timezone, form_datetime, split_calendar_value, text_prop,
};

/// The tasks list shown as the portal's "Tasks" tab. Recurring VTODO are not
/// expanded (see `PLAN_NEXT_AGENT_WEB_CALENDAR_UI.md` §1.1 Limit A) — the
/// master is rendered once.
#[derive(Template, WebTemplate)]
#[template(path = "components/sections/tasks_section.html")]
pub struct TasksSection {
    pub tasks: Vec<TaskItem>,
    pub show_all_href: String,
    pub hide_completed_href: String,
    /// The new-task form URL — always present (the form itself gates).
    pub new_href: String,
    pub can_create: bool,
}

impl Section for TasksSection {
    fn name() -> &'static str {
        "tasks"
    }
}

pub struct TaskItem {
    pub summary: String,
    /// "YYYY-MM-DD" (all-day) or "HH:MM" (timed).
    pub due: Option<String>,
    pub status: String,
    pub completed: bool,
    pub calendar_name: String,
    pub color: String,
    /// The edit form URL for this task's underlying object.
    pub href: String,
    /// The delete POST URL.
    pub delete_href: String,
    /// False (no controls rendered) when the user cannot write the owning
    /// principal or the calendar is a read-only mirror.
    pub editable: bool,
    /// True when the task carries a recurrence ruleset — the list renders
    /// the master once (caldata expands events only, PLAN §1.1 Limit A).
    pub recurring: bool,
}

#[derive(Debug, Default, Deserialize)]
pub struct TasksQuery {
    #[serde(default)]
    pub hide_completed: Option<String>,
}

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

pub async fn route_tasks<CS: CalendarStore>(
    Path(user_id): Path<String>,
    Extension(store): Extension<Arc<CS>>,
    Query(query): Query<TasksQuery>,
    TypedHeader(cookie): TypedHeader<Cookie>,
    user: Principal,
) -> Result<Response, rustical_store::Error> {
    if user_id != user.id {
        return Ok(StatusCode::UNAUTHORIZED.into_response());
    }
    let display_tz = display_timezone(cookie.get("tzid"));
    let hide_completed = query.hide_completed.as_deref() == Some("on");
    let calendars = user_calendars(&store, &user).await?;

    let mut can_create = false;
    let mut tasks = Vec::new();
    for calendar in calendars {
        if !calendar.components.contains(&CalendarObjectType::Todo) {
            continue;
        }
        let cal_name = calendar
            .meta
            .displayname
            .clone()
            .unwrap_or_else(|| calendar.id.clone());
        let color = calendar
            .meta
            .color
            .clone()
            .unwrap_or_else(|| "transparent".to_owned());
        let editable = user.can_write(&calendar.principal) && !store.is_read_only(&calendar.id);
        can_create |= editable;
        for (object_id, object) in store.get_objects(&calendar.principal, &calendar.id).await? {
            let CalendarInnerData::Todo(main, _) = object.get_inner().get_inner() else {
                continue;
            };
            let props = main.get_properties();
            let summary = text_prop(props, "SUMMARY")
                .map_or_else(|| "(no title)".to_owned(), ToOwned::to_owned);
            let status = text_prop(props, "STATUS")
                .map_or_else(|| "NEEDS-ACTION".to_owned(), ToOwned::to_owned);
            let completed = status.eq_ignore_ascii_case("COMPLETED")
                || text_prop(props, "PERCENT-COMPLETE") == Some("100");
            if hide_completed && completed {
                continue;
            }
            let due = main.due.as_ref().map(|due| match &due.0 {
                CalDateOrDateTime::Date(date) => date.naive_date().format("%Y-%m-%d").to_string(),
                CalDateOrDateTime::DateTime(dt) => format_time_short(dt, display_tz),
            });
            tasks.push(TaskItem {
                summary,
                due,
                status,
                completed,
                calendar_name: cal_name.clone(),
                color: color.clone(),
                href: format!(
                    "/frontend/user/{}/calendar/{}/tasks/{object_id}/edit",
                    calendar.principal, calendar.id
                ),
                delete_href: format!(
                    "/frontend/user/{}/calendar/{}/tasks/{object_id}/delete",
                    calendar.principal, calendar.id
                ),
                editable,
                recurring: main.has_rruleset(),
            });
        }
    }

    tasks.sort_by(|a, b| {
        a.completed.cmp(&b.completed).then_with(|| {
            a.due
                .as_deref()
                .unwrap_or_default()
                .cmp(b.due.as_deref().unwrap_or_default())
        })
    });

    Ok(UserPage {
        user,
        section: TasksSection {
            tasks,
            show_all_href: format!("/frontend/user/{user_id}/tasks"),
            hide_completed_href: format!("/frontend/user/{user_id}/tasks?hide_completed=on"),
            new_href: format!("/frontend/user/{user_id}/tasks/new"),
            can_create,
        },
    }
    .into_response())
}

/// "HH:MM" wall-clock for a DATE-TIME, rendered in the display timezone.
/// Floating times (no zone) keep their wall clock unchanged.
pub(super) fn format_time_short(dt: &CalDateTime, display_tz: ChronoTz) -> String {
    if dt.timezone().is_local() {
        dt.utc().format("%H:%M").to_string()
    } else {
        dt.utc()
            .with_timezone(&display_tz)
            .format("%H:%M")
            .to_string()
    }
}

// ---------------------------------------------------------------------------
// Task create / edit / delete.
// ---------------------------------------------------------------------------

/// The task statuses offered by the form, in the order they are offered.
const TASK_STATUSES: [&str; 4] = ["NEEDS-ACTION", "IN-PROCESS", "COMPLETED", "CANCELLED"];

#[derive(Debug, Default, Deserialize)]
pub struct TaskForm {
    /// `principal|cal_id` for the aggregate form; scoped by the URL otherwise.
    #[serde(default)]
    pub calendar: Option<String>,
    pub summary: String,
    /// One of `TASK_STATUSES`; anything else falls back to NEEDS-ACTION.
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub all_day: Option<String>,
    #[serde(default)]
    pub due_date: Option<String>,
    #[serde(default)]
    pub due_time: Option<String>,
    #[serde(default)]
    pub timezone: Option<String>,
}

#[derive(Template, WebTemplate)]
#[template(path = "pages/task_form.html")]
pub struct TaskFormPage {
    pub title: String,
    pub action: String,
    pub calendars: Vec<TaskFormOption>,
    pub summary: String,
    pub description: String,
    /// `(status, selected)` pairs — exactly one selected.
    pub statuses: Vec<(&'static str, bool)>,
    pub all_day: bool,
    pub due_date: String,
    pub due_time: String,
    /// The currently selected IANA timezone (defaults to the browser's).
    pub timezone: String,
    /// Every IANA timezone id, for the datalist suggestions.
    pub timezones: Vec<String>,
}

impl DefaultLayoutData for TaskFormPage {
    fn get_user(&self) -> Option<&Principal> {
        None
    }
}

/// One calendar offered by the task form's calendar picker.
pub struct TaskFormOption {
    /// `principal|cal_id`.
    pub value: String,
    pub label: String,
}

/// The calendars offered by the aggregate form's picker: writable, not
/// read-only, and carrying the `VTODO` component.
fn todo_calendar_options<CS: CalendarStore>(
    store: &CS,
    user: &Principal,
    calendars: &[Calendar],
) -> Vec<TaskFormOption> {
    calendars
        .iter()
        .filter(|c| {
            c.components.contains(&CalendarObjectType::Todo)
                && user.can_write(&c.principal)
                && !store.is_read_only(&c.id)
        })
        .map(|c| TaskFormOption {
            value: format!("{}|{}", c.principal, c.id),
            label: c.meta.displayname.clone().unwrap_or_else(|| c.id.clone()),
        })
        .collect()
}

async fn render_task_form<CS: CalendarStore>(
    store: &Arc<CS>,
    user: &Principal,
    title: String,
    action: String,
    default_tz: ChronoTz,
    fixed: Option<(&str, &str)>,
    defaults: &TaskForm,
) -> Result<Response, rustical_store::Error> {
    let calendars = if let Some((principal, cal_id)) = fixed {
        vec![TaskFormOption {
            value: format!("{principal}|{cal_id}"),
            label: cal_id.to_owned(),
        }]
    } else {
        todo_calendar_options(store.as_ref(), user, &user_calendars(store, user).await?)
    };
    let selected = defaults
        .status
        .as_deref()
        .map_or(TASK_STATUSES[0], |status| {
            TASK_STATUSES
                .iter()
                .find(|s| s.eq_ignore_ascii_case(status))
                .copied()
                .unwrap_or(TASK_STATUSES[0])
        });
    let statuses = TASK_STATUSES
        .iter()
        .map(|status| (*status, *status == selected))
        .collect();
    let timezone = defaults
        .timezone
        .clone()
        .unwrap_or_else(|| default_tz.to_string());
    // Same source and ordering as the portal's /_timezones.json endpoint.
    let mut timezones: Vec<String> = vtimezones_rs::VTIMEZONES
        .keys()
        .map(|k| (*k).to_owned())
        .collect();
    timezones.sort_unstable();
    Ok(TaskFormPage {
        title,
        action,
        calendars,
        summary: defaults.summary.clone(),
        statuses,
        description: defaults.description.clone().unwrap_or_default(),
        all_day: defaults.all_day.as_deref() == Some("on"),
        due_date: defaults.due_date.clone().unwrap_or_default(),
        due_time: defaults.due_time.clone().unwrap_or_default(),
        timezone,
        timezones,
    }
    .into_response())
}

/// Build a task `CalendarObject` for the form, reusing `uid` when updating.
fn build_todo_object(form: &TaskForm, default: ChronoTz, uid: String) -> Option<CalendarObject> {
    let mut props: Vec<ContentLine> = vec![
        IcalDTSTAMPProperty(CalDateTime::from(Utc::now()), vec![].into()).into(),
        IcalUIDProperty(uid, vec![].into()).into(),
    ];
    // SUMMARY may be empty; keep the object valid.
    props.push(ContentLine {
        name: "SUMMARY".to_owned(),
        value: if form.summary.trim().is_empty() {
            "(no title)".to_owned()
        } else {
            form.summary.clone()
        },
        ..Default::default()
    });
    if let Some(due) = build_due(form, default) {
        props.push(IcalDUEProperty(due, vec![].into()).into());
    }
    let status = form
        .status
        .as_deref()
        .filter(|s| TASK_STATUSES.iter().any(|t| t.eq_ignore_ascii_case(s)))
        .unwrap_or("NEEDS-ACTION");
    props.push(ContentLine {
        name: "STATUS".to_owned(),
        value: status.to_uppercase(),
        ..Default::default()
    });
    if status.eq_ignore_ascii_case("COMPLETED") {
        props.push(ContentLine {
            name: "PERCENT-COMPLETE".to_owned(),
            value: "100".to_owned(),
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

    IcalCalendarObjectBuilder {
        properties: vec![
            IcalVERSIONProperty(IcalVersion::Version2_0, vec![].into()).into(),
            IcalCALSCALEProperty(Calscale::Gregorian, vec![].into()).into(),
            IcalPRODIDProperty(
                "-//github.com/Bytewheel/Omnical web calendar//EN".to_owned(),
                vec![].into(),
            )
            .into(),
        ],
        inner: Some(CalendarInnerDataBuilder::Todo(vec![IcalTodoBuilder {
            properties: props,
            alarms: vec![],
        }])),
        vtimezones: std::collections::BTreeMap::default(),
    }
    .build(&ParserOptions::default(), None)
    .ok()
    .map(Into::into)
}

/// The due DATE/TIME of a submitted form (`None` when the form left the due
/// fields empty).
fn build_due(form: &TaskForm, default: ChronoTz) -> Option<CalDateOrDateTime> {
    let due_date = form.due_date.as_deref()?;
    if due_date.is_empty() {
        return None;
    }
    form_datetime(
        due_date,
        form.due_time.as_deref(),
        form.all_day.as_deref() == Some("on"),
        form.timezone.as_deref(),
        default,
    )
}

fn submit_redirect(user: &Principal) -> Response {
    Redirect::to(&format!("/frontend/user/{}/tasks", user.id)).into_response()
}

pub async fn route_tasks_new<CS: CalendarStore>(
    Path(user_id): Path<String>,
    Extension(store): Extension<Arc<CS>>,
    TypedHeader(cookie): TypedHeader<Cookie>,
    user: Principal,
) -> Result<Response, rustical_store::Error> {
    if user_id != user.id {
        return Ok(StatusCode::UNAUTHORIZED.into_response());
    }
    let display_tz = display_timezone(cookie.get("tzid"));
    render_task_form(
        &store,
        &user,
        "New task".to_owned(),
        format!("/frontend/user/{user_id}/tasks"),
        display_tz,
        None,
        &TaskForm::default(),
    )
    .await
}

pub async fn route_tasks_create<CS: CalendarStore>(
    Path(user_id): Path<String>,
    Extension(store): Extension<Arc<CS>>,
    TypedHeader(cookie): TypedHeader<Cookie>,
    user: Principal,
    Form(form): Form<TaskForm>,
) -> Result<Response, rustical_store::Error> {
    if user_id != user.id {
        return Ok(StatusCode::UNAUTHORIZED.into_response());
    }
    let display_tz = display_timezone(cookie.get("tzid"));
    let Some((principal, cal_id)) = form.calendar.as_deref().and_then(split_calendar_value) else {
        return Ok(StatusCode::BAD_REQUEST.into_response());
    };
    create_task(store, user, principal, cal_id, &form, display_tz).await
}

/// Share of `route_tasks_create` — also used when a fixed calendar is known.
async fn create_task<CS: CalendarStore>(
    store: Arc<CS>,
    user: Principal,
    principal: &str,
    cal_id: &str,
    form: &TaskForm,
    display_tz: ChronoTz,
) -> Result<Response, rustical_store::Error> {
    if !user.is_principal(principal) || !user.can_write(principal) || store.is_read_only(cal_id) {
        return Ok(StatusCode::FORBIDDEN.into_response());
    }
    let calendar = store.get_calendar(principal, cal_id, true).await?;
    if !calendar.components.contains(&CalendarObjectType::Todo) {
        return Ok(StatusCode::BAD_REQUEST.into_response());
    }
    let object_id = Uuid::new_v4().to_string();
    let uid = format!("{object_id}@omnical");
    let Some(object) = build_todo_object(form, display_tz, uid) else {
        return Ok(StatusCode::BAD_REQUEST.into_response());
    };
    store
        .put_object(principal, cal_id, &object_id, object, false)
        .await?;
    Ok(submit_redirect(&user))
}

/// The due form defaults for an existing task (mirrors the event form's
/// round-trip: values are re-displayed in the browser's zone).
fn due_defaults(
    due: Option<&IcalDUEProperty>,
    display_tz: ChronoTz,
) -> (Option<String>, Option<String>, bool) {
    due.map_or((None, None, false), |d| match &d.0 {
        CalDateOrDateTime::Date(date) => (
            Some(date.naive_date().format("%Y-%m-%d").to_string()),
            None,
            true,
        ),
        CalDateOrDateTime::DateTime(dt) => {
            let local = if dt.timezone().is_local() {
                dt.utc().naive_utc()
            } else {
                dt.utc().with_timezone(&display_tz).naive_utc()
            };
            (
                Some(local.format("%Y-%m-%d").to_string()),
                Some(local.format("%H:%M").to_string()),
                false,
            )
        }
    })
}

pub async fn route_task_edit<CS: CalendarStore>(
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
    let display_tz = display_timezone(cookie.get("tzid"));
    let CalendarInnerData::Todo(main, _) = object.get_inner().get_inner() else {
        return Ok(StatusCode::BAD_REQUEST.into_response());
    };
    let props = main.get_properties();
    let (due_date, due_time, all_day) = due_defaults(main.due.as_ref(), display_tz);
    let defaults = TaskForm {
        summary: text_prop(props, "SUMMARY").unwrap_or_default().to_owned(),
        status: text_prop(props, "STATUS").map(ToOwned::to_owned),
        description: text_prop(props, "DESCRIPTION").map(ToOwned::to_owned),
        all_day: all_day.then(|| "on".to_owned()),
        due_date,
        due_time,
        ..Default::default()
    };
    render_task_form(
        &store,
        &user,
        "Edit task".to_owned(),
        format!("/frontend/user/{owner}/calendar/{cal_id}/tasks/{object_id}"),
        display_tz,
        Some((&owner, &cal_id)),
        &defaults,
    )
    .await
}

pub async fn route_task_update<CS: CalendarStore>(
    Path((owner, cal_id, object_id)): Path<(String, String, String)>,
    Extension(store): Extension<Arc<CS>>,
    TypedHeader(cookie): TypedHeader<Cookie>,
    user: Principal,
    Form(form): Form<TaskForm>,
) -> Result<Response, rustical_store::Error> {
    if !user.is_principal(&owner) || !user.can_write(&owner) || store.is_read_only(&cal_id) {
        return Ok(StatusCode::FORBIDDEN.into_response());
    }
    let display_tz = display_timezone(cookie.get("tzid"));
    let original = store.get_object(&owner, &cal_id, &object_id, false).await?;
    let uid = original.get_uid().to_owned();
    let Some(object) = build_todo_object(&form, display_tz, uid) else {
        return Ok(StatusCode::BAD_REQUEST.into_response());
    };
    store
        .put_object(&owner, &cal_id, &object_id, object, true)
        .await?;
    Ok(submit_redirect(&user))
}

pub async fn route_task_delete<CS: CalendarStore>(
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
    Ok(submit_redirect(&user))
}
