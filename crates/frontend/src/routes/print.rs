//! The portal's print pages — physical calendars (`PLAN_NEXT_AGENT_PRINTING.md`).
//!
//! Every tab that lists calendar or addressbook data can be printed onto
//! 8.5×11 paper or onto sticker sheets that get cut apart and stuck onto a
//! wall calendar. The two layouts are one data set (`?format=` selects only
//! the layout, plan D2); the data set itself is filtered by `?scope=`:
//!
//! - `scope=new` (the default) renders everything **not yet marked printed**
//!   — "new" means *previously unprinted* (the user's words), tracked in the
//!   [`PrintStore`] table.
//! - marking is an **explicit POST** on the page ("Mark these N printed"),
//!   never a side effect of rendering: a preview nobody prints must not
//!   silently empty the next "new" run (plan D5).
//!
//! Events are tracked per **concrete instance** (plan D4): a weekly series
//! printed for October comes back as new in November, because next month's
//! instances are next month's stickers. Tasks and contacts carry no
//! recurrence expansion, so their instance key is empty — the whole object.
//!
//! Sticker sheets are chunked **server-side** into pages of 20 (4×5 of
//! 1.75×1.9 in inside `@page { size: letter }` margins, plan D3): flex/grid
//! page-breaking across browser print pages is exactly the kind of thing
//! that looks right in one browser and eats stickers in another.

use std::sync::Arc;

use askama::Template;
use askama_web::WebTemplate;
use axum::{
    Extension,
    extract::{Form, Path, Query},
    response::{IntoResponse, Redirect, Response},
};
use axum_extra::TypedHeader;
use caldata::component::{CalendarInnerData, Component};
use caldata::types::CalDateOrDateTime;
use chrono::{NaiveDate, NaiveTime, Utc};
use chrono_tz::Tz as ChronoTz;
use headers::Cookie;
use http::StatusCode;
use rustical_ical::CalendarObjectType;
use rustical_store::{
    Addressbook, AddressbookStore, Calendar, CalendarStore, PrintCollectionKind, PrintMark,
    PrintStore, auth::Principal, calendar_store::CalendarQuery,
};
use serde::Deserialize;

use crate::pages::DefaultLayoutData;
use crate::routes::addressbook::{contact_item, user_addressbooks};
use crate::routes::calendar_view::{
    bucket_date, display_timezone, display_timezone_fallback, format_time, parse_month,
    shift_month, text_prop, user_calendars,
};
use crate::routes::tasks::format_time_short;

/// Separator inside one hidden mark input: `principal`, `collection_id`,
/// `object_id`, `instance_key` — the segments are UUIDs, ids and timestamps,
/// never user text, so one ASCII control character is unambiguous.
const MARK_SEP: char = '\u{1f}';

/// Sticker cells per sheet: 4 columns × 5 rows of 1.75×1.9 in inside the
/// 7.5×10 in printable area of a letter page with 0.5 in margins (plan D3).
const STICKERS_PER_SHEET: usize = 20;

#[derive(Debug, Default, Deserialize)]
pub struct PrintQuery {
    /// `paper` | `stickers` — anything else (incl. absent) is stickers.
    #[serde(default)]
    pub format: Option<String>,
    /// `new` | `all` — anything else (incl. absent) is new.
    #[serde(default)]
    pub scope: Option<String>,
    /// Events pages only: `YYYY-MM`, defaulting to the current month.
    #[serde(default)]
    pub date: Option<String>,
    /// One-time "Marked N as printed" banner, set by the POST redirect.
    #[serde(default)]
    pub marked: Option<usize>,
}

/// The mark form's parts: the `mark0`… inputs' values, plus the `format`
/// and (events pages) `date` hidden inputs.
///
/// Parsed out of a flat `BTreeMap<String, String>` because axum's form
/// deserializer (`serde_urlencoded`) is flat: it cannot collect repeated
/// keys into a `Vec`, nor fill a map field beside scalar fields. Indexed
/// input names into a top-level map is what it *can* carry, so that is what
/// the mark form renders (`name="markN"`).
#[must_use]
fn mark_form_parts(
    form: &std::collections::BTreeMap<String, String>,
) -> (Vec<String>, Option<&str>, Option<&str>) {
    let marks = form
        .iter()
        .filter(|(name, _)| name.starts_with("mark"))
        .map(|(_, value)| value.as_str())
        .map(str::to_owned)
        .collect();
    let format = form.get("format").map(String::as_str);
    let date = form.get("date").map(String::as_str);
    (marks, format, date)
}

fn format_is_stickers(query: &PrintQuery) -> bool {
    query.format.as_deref() != Some("paper")
}

fn scope_is_new(query: &PrintQuery) -> bool {
    query.scope.as_deref() != Some("all")
}

/// One cooked sticker/paper row. `title` is the sticker's headline (the date
/// for events, the summary for tasks, the name for contacts) and doubles as
/// the paper row's label; `lines` are the body lines; `color` is the owning
/// calendar's color for the accent bar; `mark` is the hidden-input value.
struct PrintItem {
    title: String,
    lines: Vec<String>,
    color: String,
    mark: String,
}

/// One sticker cell (template-facing).
pub struct Sticker {
    pub title: String,
    pub lines: Vec<String>,
    pub color: String,
}

/// One paper list row (template-facing).
pub struct PaperRow {
    pub label: String,
    pub lines: Vec<String>,
    pub color: String,
}

#[derive(Template, WebTemplate)]
#[template(path = "pages/print.html")]
pub struct PrintPage {
    pub title: String,
    pub subtitle: String,
    pub format_stickers: bool,
    pub sticker_sheets: Vec<Vec<Sticker>>,
    pub sheet_count: usize,
    pub paper_rows: Vec<PaperRow>,
    /// Layout/scope toggle links, params preserved (plan D2).
    pub stickers_href: String,
    pub paper_href: String,
    pub new_href: String,
    pub all_href: String,
    /// The mark form's target: this page's own path.
    pub post_action: String,
    /// The events page's `YYYY-MM` (hidden input on the mark form, so the
    /// redirect returns to the printed month). `None` on tasks/contacts.
    pub print_date: Option<String>,
    pub marks: Vec<String>,
    pub mark_count: usize,
    pub marked_banner: Option<usize>,
    pub nothing_new: bool,
}

impl DefaultLayoutData for PrintPage {
    fn get_user(&self) -> Option<&Principal> {
        // The layout's `header` block is emptied by the template — no logout
        // form is rendered — and a printout must not depend on a session.
        None
    }
}

/// Build one toggle link preserving the page's other params.
fn print_href(path: &str, date: Option<&str>, scope: &str, format: &str) -> String {
    let mut url = format!("{path}?scope={scope}&format={format}");
    if let Some(date) = date.filter(|d| !d.is_empty()) {
        url.push_str("&date=");
        url.push_str(date);
    }
    url
}

/// The mark value for one rendered item.
fn mark_value(principal: &str, collection_id: &str, object_id: &str, instance_key: &str) -> String {
    format!("{principal}{MARK_SEP}{collection_id}{MARK_SEP}{object_id}{MARK_SEP}{instance_key}")
}

/// Parse a mark value back into its four segments.
fn parse_mark(raw: &str) -> Option<(&str, &str, &str, &str)> {
    let (principal, rest) = raw.split_once(MARK_SEP)?;
    let (collection_id, rest) = rest.split_once(MARK_SEP)?;
    let (object_id, instance_key) = rest.split_once(MARK_SEP)?;
    if principal.is_empty() || collection_id.is_empty() || object_id.is_empty() {
        return None;
    }
    Some((principal, collection_id, object_id, instance_key))
}

/// Assemble the page around a cooked, scope-filtered, sorted item list.
fn render_print_page(
    title: String,
    items: Vec<PrintItem>,
    format_stickers: bool,
    scope_new: bool,
    path: &str,
    date_param: Option<&str>,
    marked_banner: Option<usize>,
) -> Response {
    let format = if format_stickers { "stickers" } else { "paper" };
    let scope = if scope_new { "new" } else { "all" };
    let nothing_new = scope_new && items.is_empty();
    let subtitle = if scope_new {
        format!("{} new (not yet printed)", items.len())
    } else {
        format!("all {}", items.len())
    };

    // The mark form mirrors exactly what is rendered (either scope), so
    // "Mark these N printed" can never drift from the stickers on the page.
    let marks: Vec<String> = items.iter().map(|item| item.mark.clone()).collect();
    let mark_count = marks.len();

    let (sticker_sheets, paper_rows) = if format_stickers {
        (
            items
                .chunks(STICKERS_PER_SHEET)
                .map(|chunk| {
                    chunk
                        .iter()
                        .map(|item| Sticker {
                            title: item.title.clone(),
                            lines: item.lines.clone(),
                            color: item.color.clone(),
                        })
                        .collect()
                })
                .collect::<Vec<Vec<Sticker>>>(),
            Vec::new(),
        )
    } else {
        (
            Vec::new(),
            items
                .into_iter()
                .map(|item| PaperRow {
                    label: item.title,
                    lines: item.lines,
                    color: item.color,
                })
                .collect(),
        )
    };
    let sheet_count = sticker_sheets.len();

    PrintPage {
        title,
        subtitle,
        format_stickers,
        stickers_href: print_href(path, date_param, scope, "stickers"),
        paper_href: print_href(path, date_param, scope, "paper"),
        new_href: print_href(path, date_param, "new", format),
        all_href: print_href(path, date_param, "all", format),
        post_action: path.to_owned(),
        print_date: date_param
            .map(str::to_owned)
            .filter(|date| !date.is_empty()),
        marks,
        mark_count,
        marked_banner,
        nothing_new,
        sticker_sheets,
        sheet_count,
        paper_rows,
    }
    .into_response()
}

/// The mark POST shared by all five routes: parse the hidden inputs, validate
/// them against the route's own (principal, collection) policy, upsert, and
/// redirect back to the page with the one-time banner.
async fn mark_and_redirect(
    print_store: &dyn PrintStore,
    marks: Vec<PrintMark>,
    format: Option<&str>,
    date: Option<&str>,
    path: &str,
) -> Result<Response, rustical_store::Error> {
    print_store.mark_printed(&marks).await?;
    let format = if format == Some("paper") {
        "paper"
    } else {
        "stickers"
    };
    // Redirect back at scope=new: the just-marked are gone from it, and that
    // emptiness next to the banner is the confirmation (plan D5).
    let mut url = format!("{path}?scope=new&format={format}&marked={}", marks.len());
    if let Some(date) = date.filter(|d| !d.is_empty()) {
        url.push_str("&date=");
        url.push_str(date);
    }
    Ok(Redirect::to(&url).into_response())
}

/// Turn parsed mark strings into [`PrintMark`]s for collections the user can
/// see — the aggregate routes' policy: `(principal, collection)` comes from
/// the body (the aggregate spans many collections), but only pairs the
/// user's own listing would have rendered are accepted.
fn visible_marks(
    user: &Principal,
    visible: &[(String, String)],
    kind: PrintCollectionKind,
    raw_marks: &[String],
) -> Vec<PrintMark> {
    raw_marks
        .iter()
        .filter_map(|raw| parse_mark(raw))
        .filter(|(principal, collection_id, _, _)| {
            visible
                .iter()
                .any(|(p, c)| p.as_str() == *principal && c.as_str() == *collection_id)
        })
        .map(
            |(principal, collection_id, object_id, instance_key)| PrintMark {
                principal: principal.to_owned(),
                collection_id: collection_id.to_owned(),
                kind,
                object_id: object_id.to_owned(),
                instance_key: instance_key.to_owned(),
                printed_by: user.id.clone(),
            },
        )
        .collect()
}

// ---------------------------------------------------------------------------
// Events (the Calendar tab and the Profile → Calendars tile).
// ---------------------------------------------------------------------------

/// Cook one month of event stickers/paper rows across the given calendars.
/// Instances are filed at their **start** (same semantics as the grid: a
/// multi-day event lives on the day it starts) and keyed per instance.
#[allow(clippy::too_many_lines)]
async fn cook_events<CS: CalendarStore>(
    store: &CS,
    print_store: &dyn PrintStore,
    calendars: &[Calendar],
    month: NaiveDate,
    display_tz: ChronoTz,
    scope_new: bool,
) -> Result<Vec<PrintItem>, rustical_store::Error> {
    let next_month = shift_month(month, 1);
    let expand_start = month.and_time(NaiveTime::MIN).and_utc();
    let expand_end = next_month.and_time(NaiveTime::MIN).and_utc();

    // (chronological start, calendar index, summary) — stable, readable order.
    let mut cooked: Vec<(chrono::DateTime<Utc>, usize, String, PrintItem)> = Vec::new();
    for (cal_index, calendar) in calendars.iter().enumerate() {
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

        let objects = store
            .calendar_query(
                &calendar.principal,
                &calendar.id,
                CalendarQuery {
                    time_start: Some(month),
                    time_end: Some(next_month),
                },
            )
            .await?;
        let printed = print_store
            .printed_keys(
                &calendar.principal,
                PrintCollectionKind::Calendar,
                &calendar.id,
            )
            .await?;

        for (object_id, object) in objects {
            let expanded = object
                .get_inner()
                .expand_recurrence(Some(expand_start), Some(expand_end));
            let CalendarInnerData::Event(main, rest) = expanded.get_inner() else {
                // VTODO / VJOURNAL belong to the tasks view; skip here.
                continue;
            };
            for event in std::iter::once(main).chain(rest) {
                let props = event.get_properties();
                let summary = text_prop(props, "SUMMARY")
                    .map_or_else(|| "(no title)".to_owned(), ToOwned::to_owned);
                let location = text_prop(props, "LOCATION").map(ToOwned::to_owned);

                let dtstart = &event.dtstart.0;
                let all_day = dtstart.is_date();
                // Per-instance key (plan D4): the concrete start, so a series
                // printed for October is new again in November.
                let (instance_key, start_utc) = match dtstart {
                    CalDateOrDateTime::Date(date) => (
                        date.naive_date().format("%Y%m%d").to_string(),
                        date.naive_date().and_time(NaiveTime::MIN).and_utc(),
                    ),
                    CalDateOrDateTime::DateTime(dt) => {
                        (dt.utc().format("%Y%m%dT%H%M%SZ").to_string(), dt.utc())
                    }
                };
                if scope_new && printed.contains(&(object_id.clone(), instance_key.clone())) {
                    continue;
                }

                let bucket = bucket_date(dtstart, display_tz);
                if !(bucket >= month && bucket < next_month) {
                    continue;
                }

                let mut lines = Vec::new();
                if all_day {
                    lines.push("All day".to_owned());
                } else if let CalDateOrDateTime::DateTime(dt) = dtstart {
                    let end_label = event.dtend.as_ref().and_then(|dtend| match &dtend.0 {
                        CalDateOrDateTime::DateTime(dt) if !all_day => {
                            Some(format_time(dt, display_tz))
                        }
                        _ => None,
                    });
                    let start_label = format_time(dt, display_tz);
                    lines.push(match end_label {
                        Some(end) if end != start_label => format!("{start_label}–{end}"),
                        _ => start_label,
                    });
                }
                // A multi-day event on a wall calendar needs its range on the
                // sticker, not just its first day.
                if let Some(dtend) = event.dtend.as_ref() {
                    let end_bucket = bucket_date(&dtend.0, display_tz);
                    if end_bucket != bucket {
                        lines.push(format!("until {}", end_bucket.format("%a %d %b")));
                    }
                }
                lines.push(summary.clone());
                if let Some(location) = location {
                    lines.push(location);
                }
                lines.push(cal_name.clone());

                cooked.push((
                    start_utc,
                    cal_index,
                    summary,
                    PrintItem {
                        title: bucket.format("%a %d %b").to_string(),
                        lines,
                        color: color.clone(),
                        mark: mark_value(
                            &calendar.principal,
                            &calendar.id,
                            &object_id,
                            &instance_key,
                        ),
                    },
                ));
            }
        }
    }
    // Chronological by the instance's own start, calendars in tab order, then
    // summary — the order the wall calendar will be stickered in.
    cooked.sort_by_key(|(start, cal_index, summary, _)| (*start, *cal_index, summary.clone()));
    Ok(cooked.into_iter().map(|(_, _, _, item)| item).collect())
}
pub async fn route_events_print<CS: CalendarStore>(
    Path(user_id): Path<String>,
    Extension(store): Extension<Arc<CS>>,
    Extension(print_store): Extension<Arc<dyn PrintStore>>,
    Query(query): Query<PrintQuery>,
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
    let items = cook_events(
        store.as_ref(),
        print_store.as_ref(),
        &calendars,
        month,
        display_tz,
        scope_is_new(&query),
    )
    .await?;
    let path = format!("/frontend/user/{user_id}/events/print");
    let page = render_print_page(
        format!("Events — {}", month.format("%B %Y")),
        items,
        format_is_stickers(&query),
        scope_is_new(&query),
        &path,
        query.date.as_deref(),
        query.marked,
    );
    Ok(page)
}

/// `POST /{user}/events/print` — mark the rendered event stickers printed.
pub async fn route_events_print_mark<CS: CalendarStore>(
    Path(user_id): Path<String>,
    Extension(store): Extension<Arc<CS>>,
    Extension(print_store): Extension<Arc<dyn PrintStore>>,
    user: Principal,
    Form(form): Form<std::collections::BTreeMap<String, String>>,
) -> Result<Response, rustical_store::Error> {
    if user_id != user.id {
        return Ok(StatusCode::UNAUTHORIZED.into_response());
    }
    let calendars = user_calendars(&store, &user).await?;
    let visible: Vec<(String, String)> = calendars
        .iter()
        .map(|c| (c.principal.clone(), c.id.clone()))
        .collect();
    let (raw_marks, format, date) = mark_form_parts(&form);
    let marks = visible_marks(&user, &visible, PrintCollectionKind::Calendar, &raw_marks);
    mark_and_redirect(
        print_store.as_ref(),
        marks,
        format,
        date,
        &format!("/frontend/user/{user_id}/events/print"),
    )
    .await
}

/// `GET /{user}/calendar/{calendar}/events/print` — one calendar's print page
/// (the per-calendar grid and the Profile → Calendars tile both link here).
pub async fn route_calendar_events_print<CS: CalendarStore>(
    Path((owner, cal_id)): Path<(String, String)>,
    Extension(store): Extension<Arc<CS>>,
    Extension(print_store): Extension<Arc<dyn PrintStore>>,
    Query(query): Query<PrintQuery>,
    TypedHeader(cookie): TypedHeader<Cookie>,
    user: Principal,
) -> Result<Response, rustical_store::Error> {
    if !user.is_principal(&owner) {
        return Ok(StatusCode::UNAUTHORIZED.into_response());
    }
    let calendar = store.get_calendar(&owner, &cal_id, true).await?;
    let display_tz = display_timezone_fallback(
        cookie.get("tzid"),
        calendar.get_timezone().unwrap_or(chrono_tz::UTC),
    );
    let heading = calendar
        .meta
        .displayname
        .clone()
        .unwrap_or_else(|| cal_id.clone());
    let today = Utc::now().date_naive();
    let month = parse_month(query.date.as_deref(), today);
    let items = cook_events(
        store.as_ref(),
        print_store.as_ref(),
        std::slice::from_ref(&calendar),
        month,
        display_tz,
        scope_is_new(&query),
    )
    .await?;
    let path = format!("/frontend/user/{owner}/calendar/{cal_id}/events/print");
    Ok(render_print_page(
        format!("{} — {}", heading, month.format("%B %Y")),
        items,
        format_is_stickers(&query),
        scope_is_new(&query),
        &path,
        query.date.as_deref(),
        query.marked,
    ))
}

/// `POST /{user}/calendar/{calendar}/events/print` — mark this calendar's
/// rendered stickers printed. `(principal, collection)` comes from the URL
/// and the body may only repeat it (plan §2: never move).
pub async fn route_calendar_events_print_mark(
    Path((owner, cal_id)): Path<(String, String)>,
    Extension(print_store): Extension<Arc<dyn PrintStore>>,
    user: Principal,
    Form(form): Form<std::collections::BTreeMap<String, String>>,
) -> Result<Response, rustical_store::Error> {
    if !user.is_principal(&owner) {
        return Ok(StatusCode::UNAUTHORIZED.into_response());
    }
    let (raw_marks, format, date) = mark_form_parts(&form);
    let marks: Vec<PrintMark> = raw_marks
        .iter()
        .filter_map(|raw| parse_mark(raw))
        .filter(|(principal, collection_id, _, _)| {
            // The URL is the authority on which collection this POST marks.
            *principal == owner.as_str() && *collection_id == cal_id.as_str()
        })
        .map(
            |(principal, collection_id, object_id, instance_key)| PrintMark {
                principal: principal.to_owned(),
                collection_id: collection_id.to_owned(),
                kind: PrintCollectionKind::Calendar,
                object_id: object_id.to_owned(),
                instance_key: instance_key.to_owned(),
                printed_by: user.id.clone(),
            },
        )
        .collect();
    mark_and_redirect(
        print_store.as_ref(),
        marks,
        format,
        date,
        &format!("/frontend/user/{owner}/calendar/{cal_id}/events/print"),
    )
    .await
}

// ---------------------------------------------------------------------------
// Tasks (the Tasks tab).
// ---------------------------------------------------------------------------

/// Cook the tasks list across every calendar carrying `VTODO` — masters only
/// (recurring VTODO are never expanded, the same Limit A the tab documents).
async fn cook_tasks<CS: CalendarStore>(
    store: &CS,
    print_store: &dyn PrintStore,
    calendars: &[Calendar],
    display_tz: ChronoTz,
    scope_new: bool,
) -> Result<Vec<PrintItem>, rustical_store::Error> {
    // (completed, due, summary) — the tab's order: open tasks by due date,
    // completed last.
    let mut cooked: Vec<(bool, String, String, PrintItem)> = Vec::new();
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
        let objects = store.get_objects(&calendar.principal, &calendar.id).await?;
        let printed = print_store
            .printed_keys(
                &calendar.principal,
                PrintCollectionKind::Calendar,
                &calendar.id,
            )
            .await?;
        for (object_id, object) in objects {
            let CalendarInnerData::Todo(main, _) = object.get_inner().get_inner() else {
                continue;
            };
            // Tasks and contacts are whole-object marks: instance key "".
            if scope_new && printed.contains(&(object_id.clone(), String::new())) {
                continue;
            }
            let props = main.get_properties();
            let summary = text_prop(props, "SUMMARY")
                .map_or_else(|| "(no title)".to_owned(), ToOwned::to_owned);
            let status = text_prop(props, "STATUS")
                .map_or_else(|| "NEEDS-ACTION".to_owned(), ToOwned::to_owned);
            let completed = status.eq_ignore_ascii_case("COMPLETED")
                || text_prop(props, "PERCENT-COMPLETE") == Some("100");
            let due = main.due.as_ref().map(|due| match &due.0 {
                CalDateOrDateTime::Date(date) => date.naive_date().format("%a %d %b").to_string(),
                CalDateOrDateTime::DateTime(dt) => format_time_short(dt, display_tz),
            });
            let mut lines = Vec::new();
            if let Some(due) = due.clone() {
                lines.push(format!("due {due}"));
            }
            lines.push(status.clone());
            lines.push(cal_name.clone());
            cooked.push((
                completed,
                due.unwrap_or_default(),
                summary.to_lowercase(),
                PrintItem {
                    title: summary.clone(),
                    lines,
                    color: color.clone(),
                    mark: mark_value(&calendar.principal, &calendar.id, &object_id, ""),
                },
            ));
        }
    }
    // The tab's order: open tasks by due date, completed last (route_tasks
    // sorts the same way).
    cooked.sort_by_key(|(completed, due, summary, _)| (*completed, due.clone(), summary.clone()));
    Ok(cooked.into_iter().map(|(_, _, _, item)| item).collect())
}

/// `GET /{user}/tasks/print` — the Tasks tab's print page.
pub async fn route_tasks_print<CS: CalendarStore>(
    Path(user_id): Path<String>,
    Extension(store): Extension<Arc<CS>>,
    Extension(print_store): Extension<Arc<dyn PrintStore>>,
    Query(query): Query<PrintQuery>,
    TypedHeader(cookie): TypedHeader<Cookie>,
    user: Principal,
) -> Result<Response, rustical_store::Error> {
    if user_id != user.id {
        return Ok(StatusCode::UNAUTHORIZED.into_response());
    }
    let display_tz = display_timezone(cookie.get("tzid"));
    let calendars = user_calendars(&store, &user).await?;
    let items = cook_tasks(
        store.as_ref(),
        print_store.as_ref(),
        &calendars,
        display_tz,
        scope_is_new(&query),
    )
    .await?;
    let path = format!("/frontend/user/{user_id}/tasks/print");
    Ok(render_print_page(
        "Tasks".to_owned(),
        items,
        format_is_stickers(&query),
        scope_is_new(&query),
        &path,
        None,
        query.marked,
    ))
}

/// `POST /{user}/tasks/print` — mark the rendered task stickers printed.
pub async fn route_tasks_print_mark<CS: CalendarStore>(
    Path(user_id): Path<String>,
    Extension(store): Extension<Arc<CS>>,
    Extension(print_store): Extension<Arc<dyn PrintStore>>,
    user: Principal,
    Form(form): Form<std::collections::BTreeMap<String, String>>,
) -> Result<Response, rustical_store::Error> {
    if user_id != user.id {
        return Ok(StatusCode::UNAUTHORIZED.into_response());
    }
    let calendars = user_calendars(&store, &user).await?;
    let visible: Vec<(String, String)> = calendars
        .iter()
        .map(|c| (c.principal.clone(), c.id.clone()))
        .collect();
    let (raw_marks, format, date) = mark_form_parts(&form);
    let marks = visible_marks(&user, &visible, PrintCollectionKind::Calendar, &raw_marks);
    mark_and_redirect(
        print_store.as_ref(),
        marks,
        format,
        date,
        &format!("/frontend/user/{user_id}/tasks/print"),
    )
    .await
}

// ---------------------------------------------------------------------------
// Contacts (the Contacts tab and the Profile → Addressbooks tile).
// ---------------------------------------------------------------------------

/// Cook the contacts list across the given addressbooks.
async fn cook_contacts<AS: AddressbookStore>(
    store: &AS,
    print_store: &dyn PrintStore,
    addressbooks: &[Addressbook],
    scope_new: bool,
) -> Result<Vec<PrintItem>, rustical_store::Error> {
    let mut cooked: Vec<(String, PrintItem)> = Vec::new();
    for addressbook in addressbooks {
        let ab_name = addressbook
            .displayname
            .clone()
            .unwrap_or_else(|| addressbook.id.clone());
        let printed = print_store
            .printed_keys(
                &addressbook.principal,
                PrintCollectionKind::Addressbook,
                &addressbook.id,
            )
            .await?;
        for (object_id, object) in store
            .get_objects(&addressbook.principal, &addressbook.id)
            .await?
        {
            if scope_new && printed.contains(&(object_id.clone(), String::new())) {
                continue;
            }
            // `contact_item` does the vCard cooking (name / email / phone);
            // its edit/delete hrefs are unused on a printout — pass
            // `editable = false`.
            let contact = contact_item(
                &ab_name,
                &addressbook.principal,
                &addressbook.id,
                &object_id,
                &object,
                false,
            );
            let mut lines = Vec::new();
            if let Some(phone) = contact.phone.clone() {
                lines.push(phone);
            }
            if let Some(email) = contact.email.clone() {
                lines.push(email);
            }
            lines.push(ab_name.clone());
            cooked.push((
                contact.name.to_lowercase(),
                PrintItem {
                    title: contact.name.clone(),
                    lines,
                    // No calendar color to carry; the accent bar is neutral.
                    color: "transparent".to_owned(),
                    mark: mark_value(&addressbook.principal, &addressbook.id, &object_id, ""),
                },
            ));
        }
    }
    // Alphabetical, same as both Contacts pages.
    cooked.sort_by_key(|(name, _)| name.clone());
    Ok(cooked.into_iter().map(|(_, item)| item).collect())
}

/// `GET /{user}/contacts/print` — the aggregate Contacts tab's print page.
pub async fn route_contacts_print<AS: AddressbookStore>(
    Path(user_id): Path<String>,
    Extension(store): Extension<Arc<AS>>,
    Extension(print_store): Extension<Arc<dyn PrintStore>>,
    Query(query): Query<PrintQuery>,
    user: Principal,
) -> Result<Response, rustical_store::Error> {
    if user_id != user.id {
        return Ok(StatusCode::UNAUTHORIZED.into_response());
    }
    let addressbooks = user_addressbooks(&store, &user).await?;
    let items = cook_contacts(
        store.as_ref(),
        print_store.as_ref(),
        &addressbooks,
        scope_is_new(&query),
    )
    .await?;
    let path = format!("/frontend/user/{user_id}/contacts/print");
    Ok(render_print_page(
        "Contacts".to_owned(),
        items,
        format_is_stickers(&query),
        scope_is_new(&query),
        &path,
        None,
        query.marked,
    ))
}

/// `POST /{user}/contacts/print` — mark the rendered contact stickers printed.
pub async fn route_contacts_print_mark<AS: AddressbookStore>(
    Path(user_id): Path<String>,
    Extension(store): Extension<Arc<AS>>,
    Extension(print_store): Extension<Arc<dyn PrintStore>>,
    user: Principal,
    Form(form): Form<std::collections::BTreeMap<String, String>>,
) -> Result<Response, rustical_store::Error> {
    if user_id != user.id {
        return Ok(StatusCode::UNAUTHORIZED.into_response());
    }
    let addressbooks = user_addressbooks(&store, &user).await?;
    let visible: Vec<(String, String)> = addressbooks
        .iter()
        .map(|a| (a.principal.clone(), a.id.clone()))
        .collect();
    let (raw_marks, format, date) = mark_form_parts(&form);
    let marks = visible_marks(
        &user,
        &visible,
        PrintCollectionKind::Addressbook,
        &raw_marks,
    );
    mark_and_redirect(
        print_store.as_ref(),
        marks,
        format,
        date,
        &format!("/frontend/user/{user_id}/contacts/print"),
    )
    .await
}

/// `GET /{user}/addressbook/{addressbook}/contacts/print` — one addressbook's
/// print page (the Profile → Addressbooks tile links here).
pub async fn route_addressbook_contacts_print<AS: AddressbookStore>(
    Path((owner, addrbook_id)): Path<(String, String)>,
    Extension(store): Extension<Arc<AS>>,
    Extension(print_store): Extension<Arc<dyn PrintStore>>,
    Query(query): Query<PrintQuery>,
    user: Principal,
) -> Result<Response, rustical_store::Error> {
    if !user.is_principal(&owner) {
        return Ok(StatusCode::UNAUTHORIZED.into_response());
    }
    let addressbook = store.get_addressbook(&owner, &addrbook_id, true).await?;
    let heading = addressbook
        .displayname
        .clone()
        .unwrap_or_else(|| addrbook_id.clone());
    let items = cook_contacts(
        store.as_ref(),
        print_store.as_ref(),
        std::slice::from_ref(&addressbook),
        scope_is_new(&query),
    )
    .await?;
    let path = format!("/frontend/user/{owner}/addressbook/{addrbook_id}/contacts/print");
    Ok(render_print_page(
        format!("Contacts — {heading}"),
        items,
        format_is_stickers(&query),
        scope_is_new(&query),
        &path,
        None,
        query.marked,
    ))
}

/// `POST /{user}/addressbook/{addressbook}/contacts/print` — mark this
/// addressbook's rendered stickers printed.
pub async fn route_addressbook_contacts_print_mark(
    Path((owner, addrbook_id)): Path<(String, String)>,
    Extension(print_store): Extension<Arc<dyn PrintStore>>,
    user: Principal,
    Form(form): Form<std::collections::BTreeMap<String, String>>,
) -> Result<Response, rustical_store::Error> {
    if !user.is_principal(&owner) {
        return Ok(StatusCode::UNAUTHORIZED.into_response());
    }
    let (raw_marks, format, date) = mark_form_parts(&form);
    let marks: Vec<PrintMark> = raw_marks
        .iter()
        .filter_map(|raw| parse_mark(raw))
        .filter(|(principal, collection_id, _, _)| {
            // The URL is the authority on which collection this POST marks.
            *principal == owner.as_str() && *collection_id == addrbook_id.as_str()
        })
        .map(
            |(principal, collection_id, object_id, instance_key)| PrintMark {
                principal: principal.to_owned(),
                collection_id: collection_id.to_owned(),
                kind: PrintCollectionKind::Addressbook,
                object_id: object_id.to_owned(),
                instance_key: instance_key.to_owned(),
                printed_by: user.id.clone(),
            },
        )
        .collect();
    mark_and_redirect(
        print_store.as_ref(),
        marks,
        format,
        date,
        &format!("/frontend/user/{owner}/addressbook/{addrbook_id}/contacts/print"),
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_mark_round_trips_mark_value() {
        let value = mark_value("user", "personal", "object-1", "20261014T180000Z");
        assert_eq!(
            parse_mark(&value),
            Some(("user", "personal", "object-1", "20261014T180000Z"))
        );
        // Empty segments are rejected (a malformed or hand-crafted input).
        assert_eq!(parse_mark("user\u{1f}personal\u{1f}\u{1f}"), None);
    }

    #[test]
    fn parse_mark_rejects_short_values() {
        assert_eq!(parse_mark("user\u{1f}personal\u{1f}object"), None);
        assert_eq!(parse_mark(""), None);
    }

    #[test]
    fn defaults_are_stickers_and_new() {
        let query = PrintQuery::default();
        assert!(format_is_stickers(&query));
        assert!(scope_is_new(&query));
        let paper = PrintQuery {
            format: Some("paper".to_owned()),
            scope: Some("all".to_owned()),
            ..Default::default()
        };
        assert!(!format_is_stickers(&paper));
        assert!(!scope_is_new(&paper));
    }

    #[test]
    fn print_href_preserves_date_for_events() {
        assert_eq!(
            print_href(
                "/frontend/user/user/events/print",
                Some("2026-10"),
                "new",
                "paper"
            ),
            "/frontend/user/user/events/print?scope=new&format=paper&date=2026-10"
        );
        assert_eq!(
            print_href("/frontend/user/user/tasks/print", None, "all", "stickers"),
            "/frontend/user/user/tasks/print?scope=all&format=stickers"
        );
    }
}
