//! Omnical "linked platforms" portal section (PLAN.md §17.8.3): import a
//! foreign HTTPS .ics feed into one of the user's own calendars, then keep it
//! in sync via an explicit Refresh. Removed sources leave the materialized
//! data behind — a linked source is a copy by design.
//!
//! Import engine: HTTPS-only fetch with an SSRF guard (private-range refusal +
//! DNS-rebind resistance via per-request host resolution), parse via
//! `caldata`, materialize into the target calendar, diff-by-UID refresh with a
//! mass-delete abort.
//!
//! Routes are owner-scoped and mount under the user-router inside
//! `frontend_router`, so they inherit the session/auth cookie handling.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::Arc;

use crate::pages::user::{Section, UserPage};
use askama::Template;
use askama_web::WebTemplate;
use axum::{
    Extension, Form,
    extract::Path,
    response::{IntoResponse, Redirect, Response},
};
use caldata::component::IcalCalendar;
use caldata::component::ical::IcalParser;
use caldata::parser::{BytesLines, ParserOptions};
use http::StatusCode;
use rustical_ical::CalendarObject;
use rustical_store::{
    Calendar, CalendarSource, CalendarSourceStore, CalendarStore, Error, auth::Principal,
};
use tracing::{error, info, warn};
use url::Url;

// --- SSRF guard -------------------------------------------------------------

fn is_private_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(o) => {
            let b = o.octets();
            if b[0] == 127 || b[0] == 255 {
                return true;
            }
            if b[0] == 169 && b[1] == 254 {
                return true;
            }
            if b[0] == 10 {
                return true;
            }
            if b[0] == 172 && (16..=31).contains(&b[1]) {
                return true;
            }
            if b[0] == 192 && b[1] == 168 {
                return true;
            }
            if b[0] == 100 && (b[1] & 0xc0) == 0x40 {
                return true;
            }
            if b[0] == 0 {
                return true;
            }
            b[0] >= 224
        }
        IpAddr::V6(a) => {
            let b = a.octets();
            (b[0] & 0xfe) == 0xfc
                || b[0] == 0xfe && (b[1] & 0xc0) == 0x80
                || a.is_loopback()
                || b[0] == 0xff
        }
    }
}

fn refused_if_private(ip: &IpAddr) -> Result<(), &'static str> {
    if is_private_ip(ip) {
        Err("Refused: private-range address")
    } else {
        Ok(())
    }
}

/// Resolve `source_url`'s host and refuse private/loopback/link-local/ULA/
/// multicast/reserved IPs. Re-resolves on every call (DNS-rebind resistance).
fn ssrf_guard(source_url: &str) -> Result<(), &'static str> {
    let url = Url::parse(source_url).map_err(|_| "Invalid URL")?;
    if url.scheme() != "https" {
        return Err("Only HTTPS URLs are allowed");
    }
    let ip = match url.host() {
        // Literal addresses need no DNS and cannot be rebound.
        Some(url::Host::Ipv4(v4)) => IpAddr::V4(v4),
        Some(url::Host::Ipv6(v6)) => IpAddr::V6(v6),
        Some(url::Host::Domain(host)) => {
            let addrs = host
                .to_socket_addrs()
                .map_err(|_| "DNS resolution failed")?;
            addrs
                .map(|sa| sa.ip())
                .find(|ip| !ip.is_unspecified())
                .ok_or("No resolved address")?
        }
        None => return Err("No host"),
    };
    refused_if_private(&ip)
}

// --- Import engine ----------------------------------------------------------

const FETCH_TIMEOUT_SEC: u64 = 20;
const MAX_RESPONSE_BYTES: u64 = 25 * 1024 * 1024;
const MASS_DELETE_RATIO: f64 = 0.5;

async fn fetch_and_parse(source_url: &str) -> Result<Vec<CalendarObject>, &'static str> {
    ssrf_guard(source_url)?;
    let host = Url::parse(source_url)
        .ok()
        .and_then(|u| u.host_str().map(ToOwned::to_owned))
        .ok_or("Invalid URL")?;
    let addrs: Vec<SocketAddr> = host
        .to_socket_addrs()
        .map_err(|_| "DNS resolution failed")?
        .collect();

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(FETCH_TIMEOUT_SEC))
        .https_only(true)
        .resolve_to_addrs(&host, &addrs)
        .redirect(reqwest::redirect::Policy::custom(|attempt| {
            if ssrf_guard(attempt.url().as_str()).is_err() {
                attempt.stop()
            } else {
                attempt.follow()
            }
        }))
        .build()
        .map_err(|_| "client build failed")?;

    let resp = client
        .get(source_url)
        .send()
        .await
        .map_err(|_| "fetch failed")?;
    let bytes = resp.bytes().await.map_err(|_| "fetch body failed")?;
    if bytes.len() as u64 > MAX_RESPONSE_BYTES {
        return Err("Response too large");
    }
    let ics = std::str::from_utf8(&bytes).map_err(|_| "not UTF-8")?;
    let calendar: IcalCalendar = IcalParser::<BytesLines>::from_slice(ics.as_bytes())
        .with_options(ParserOptions::default())
        .expect_one()
        .map_err(|_| "parse failed")?;
    calendar
        .into_objects()
        .map_err(|_| "into_objects failed")
        .map(|v| v.into_iter().map(CalendarObject::from).collect())
}

/// The diff the refresh wants to apply. Pure split of the fetch/materialize
/// halves so the UID-diff + mass-delete heuristic stay unit-testable offline.
struct RefreshPlan {
    to_delete: Vec<String>,
    to_update: Vec<(String, CalendarObject)>,
    to_add: Vec<(String, CalendarObject)>,
    mass_delete_abort: bool,
}

fn plan_refresh(existing: &[(String, CalendarObject)], remote: &[CalendarObject]) -> RefreshPlan {
    let remote_by_uid: HashMap<String, CalendarObject> = remote
        .iter()
        .map(|o| (o.get_uid().to_owned(), o.clone()))
        .collect();
    let mut to_delete = Vec::new();
    let mut to_update = Vec::new();
    for (obj_id, obj) in existing {
        match remote_by_uid.get(obj_id) {
            None => to_delete.push(obj_id.clone()),
            Some(remote_obj) => {
                if remote_obj.get_ics() != obj.get_ics() {
                    to_update.push((obj_id.clone(), remote_obj.clone()));
                }
            }
        }
    }
    let mut to_add = Vec::new();
    for (uid, remote_obj) in &remote_by_uid {
        if existing.iter().all(|(id, _)| id != uid) {
            to_add.push((uid.clone(), remote_obj.clone()));
        }
    }
    // Providers that omit old events on later fetches are common — a refresh
    // deleting more than half a calendar's rows aborts instead of wiping.
    #[allow(clippy::cast_precision_loss)]
    let mass_delete_abort = !existing.is_empty()
        && (to_delete.len() as f64) > (existing.len() as f64) * MASS_DELETE_RATIO;
    RefreshPlan {
        to_delete,
        to_update,
        to_add,
        mass_delete_abort,
    }
}

async fn apply_refresh(
    cal_store: &Arc<dyn CalendarStore>,
    principal: &str,
    calendar_id: &str,
    plan: RefreshPlan,
) -> Result<(), String> {
    if plan.mass_delete_abort {
        warn!(
            deleted = plan.to_delete.len(),
            "refresh aborted: mass-delete heuristic"
        );
        return Err("mass-delete aborted".into());
    }
    for obj_id in &plan.to_delete {
        cal_store
            .delete_object(principal, calendar_id, obj_id, false)
            .await
            .map_err(|e| e.to_string())?;
    }
    if !plan.to_update.is_empty() {
        cal_store
            .put_objects(principal, calendar_id, plan.to_update, true)
            .await
            .map_err(|e| e.to_string())?;
    }
    if !plan.to_add.is_empty() {
        cal_store
            .put_objects(principal, calendar_id, plan.to_add, true)
            .await
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// Insert the initial import's objects into the target calendar (a copy).
async fn materialize_objects(
    cal_store: &Arc<dyn CalendarStore>,
    principal: &str,
    calendar_id: &str,
    objects: Vec<CalendarObject>,
) -> Result<(), String> {
    let batch: Vec<(String, CalendarObject)> = objects
        .into_iter()
        .map(|o| (o.get_uid().to_owned(), o))
        .collect();
    cal_store
        .put_objects(principal, calendar_id, batch, true)
        .await
        .map_err(|e| e.to_string())
}

/// Re-fetch a source, diff by UID against what is already materialized, and
/// apply adds/updates/removes. Stamps `last_fetch_at` on success.
async fn refresh_source(
    cal_store: &Arc<dyn CalendarStore>,
    source_store: &Arc<dyn CalendarSourceStore>,
    source: &CalendarSource,
) -> Result<(), String> {
    let objects = fetch_and_parse(&source.source_url)
        .await
        .inspect_err(|e| warn!(source = %source.id, error = %e, "refresh fetch failed"))?;
    let existing = cal_store
        .get_objects(&source.principal, &source.calendar_id)
        .await
        .map_err(|e| e.to_string())?;
    let plan = plan_refresh(&existing, &objects);
    apply_refresh(cal_store, &source.principal, &source.calendar_id, plan).await?;

    let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let _ = source_store
        .update_calendar_source_fetch(&source.principal, &source.id, &now, true)
        .await;
    info!(source = %source.id, "refresh completed");
    Ok(())
}

// --- Portal section ---------------------------------------------------------

impl Section for LinkedPlatformsSection {
    fn name() -> &'static str {
        "linked-platforms"
    }
}

#[derive(Template, WebTemplate)]
#[template(path = "components/sections/linked_platforms_section.html")]
pub struct LinkedPlatformsSection {
    pub user: Principal,
    pub sources: Vec<CalendarSource>,
    pub calendars: Vec<Calendar>,
    pub calendar_display_names: Vec<String>,
    pub error: Option<String>,
}

impl LinkedPlatformsSection {
    fn display_name(cal: &Calendar) -> String {
        cal.meta
            .displayname
            .clone()
            .unwrap_or_else(|| cal.id.clone())
    }
}

async fn linked_platforms_page<CS: CalendarStore>(
    cal_store: &Arc<CS>,
    source_store: &Arc<dyn CalendarSourceStore>,
    user: &Principal,
    error: Option<String>,
) -> Response {
    let sources = source_store
        .get_calendar_sources(&user.id)
        .await
        .unwrap_or_default();
    let calendars = cal_store.get_calendars(&user.id).await.unwrap_or_default();
    let calendar_display_names = calendars
        .iter()
        .map(LinkedPlatformsSection::display_name)
        .collect();
    UserPage {
        section: LinkedPlatformsSection {
            user: user.clone(),
            sources,
            calendars,
            calendar_display_names,
            error,
        },
        user: user.clone(),
    }
    .into_response()
}

/// Fetch the owning principal's source with an `id` (404 if none/mismatched).
async fn owned_source(
    source_store: &Arc<dyn CalendarSourceStore>,
    user_id: &str,
    id: &str,
) -> Option<CalendarSource> {
    source_store
        .get_calendar_source(user_id, id)
        .await
        .ok()
        .filter(|s| s.principal == user_id)
}

pub async fn route_get_linked_platforms<CS: CalendarStore>(
    Path(user_id): Path<String>,
    Extension(cal_store): Extension<Arc<CS>>,
    Extension(source_store): Extension<Arc<dyn CalendarSourceStore>>,
    user: Principal,
) -> Response {
    if user_id != user.id {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    linked_platforms_page(&cal_store, &source_store, &user, None).await
}

/// POST add — fetch + SSRF-guard the feed first, then record the mapping and
/// materialize a copy into the chosen calendar. A failed/refused fetch never
/// leaves a dead mapping behind.
pub async fn route_post_linked_platforms_add<CS: CalendarStore>(
    Path(user_id): Path<String>,
    Extension(cal_store): Extension<Arc<CS>>,
    Extension(source_store): Extension<Arc<dyn CalendarSourceStore>>,
    user: Principal,
    Form(form): Form<AddSourceForm>,
) -> Response {
    if user_id != user.id {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    if form.source_url.trim().is_empty() {
        return linked_platforms_page(
            &cal_store,
            &source_store,
            &user,
            Some("A source URL is required.".to_owned()),
        )
        .await;
    }

    if cal_store
        .get_calendar(&user.id, &form.calendar_id, false)
        .await
        .is_err()
    {
        return linked_platforms_page(
            &cal_store,
            &source_store,
            &user,
            Some(format!("No such calendar '{}'.", form.calendar_id)),
        )
        .await;
    }

    let provider_host = Url::parse(&form.source_url)
        .ok()
        .and_then(|u| u.host_str().map(ToOwned::to_owned))
        .unwrap_or_default();

    let objects = match fetch_and_parse(&form.source_url).await {
        Ok(objects) => objects,
        Err(e) => {
            return linked_platforms_page(
                &cal_store,
                &source_store,
                &user,
                Some(format!(
                    "Could not fetch '{}': {e}. Only public HTTPS .ics feeds are allowed.",
                    form.source_url
                )),
            )
            .await;
        }
    };

    let source_id = match source_store
        .add_calendar_source(
            &user.id,
            &form.calendar_id,
            &form.source_url,
            &provider_host,
        )
        .await
    {
        Ok(id) => id,
        Err(Error::AlreadyExists) => {
            return linked_platforms_page(
                &cal_store,
                &source_store,
                &user,
                Some("This calendar is already linked to that URL.".to_owned()),
            )
            .await;
        }
        Err(e) => {
            error!(%e, "add calendar source failed");
            return linked_platforms_page(
                &cal_store,
                &source_store,
                &user,
                Some(format!("Could not record the linked source: {e}.")),
            )
            .await;
        }
    };

    let cal_dyn: Arc<dyn CalendarStore> = cal_store.clone();
    if let Err(e) = materialize_objects(&cal_dyn, &user.id, &form.calendar_id, objects).await {
        warn!(%e, "materialize failed after fetch");
        return linked_platforms_page(
            &cal_store,
            &source_store,
            &user,
            Some(format!(
                "Fetched the feed but could not import its events: {e}."
            )),
        )
        .await;
    }

    let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let _ = source_store
        .update_calendar_source_fetch(&user.id, &source_id, &now, true)
        .await;
    info!(source = %source_id, "linked platform added and materialized");

    Redirect::to(&format!("/frontend/user/{}/linked-platforms", user.id)).into_response()
}

/// POST refresh — re-fetch + diff by UID. Mass-delete heuristic aborts with an
/// error banner rather than wiping the calendar.
pub async fn route_post_linked_platforms_refresh<CS: CalendarStore>(
    Path((user_id, id)): Path<(String, String)>,
    Extension(cal_store): Extension<Arc<CS>>,
    Extension(source_store): Extension<Arc<dyn CalendarSourceStore>>,
    user: Principal,
) -> Response {
    if user_id != user.id {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let Some(source) = owned_source(&source_store, &user.id, &id).await else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let cal_dyn: Arc<dyn CalendarStore> = cal_store.clone();
    match refresh_source(&cal_dyn, &source_store, &source).await {
        Ok(()) => {
            Redirect::to(&format!("/frontend/user/{}/linked-platforms", user.id)).into_response()
        }
        Err(e) => {
            warn!(%id, %e, "refresh failed");
            linked_platforms_page(
                &cal_store,
                &source_store,
                &user,
                Some(format!("Refresh failed: {e}.")),
            )
            .await
        }
    }
}

/// POST remove — unlink the mapping, leave the materialized data intact.
pub async fn route_post_linked_platforms_remove(
    Path((user_id, id)): Path<(String, String)>,
    Extension(source_store): Extension<Arc<dyn CalendarSourceStore>>,
    user: Principal,
) -> Response {
    if user_id != user.id {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    if owned_source(&source_store, &user.id, &id).await.is_none() {
        return StatusCode::NOT_FOUND.into_response();
    }
    if let Err(e) = source_store.delete_calendar_source(&user.id, &id).await {
        error!(%e, "delete calendar source failed");
    }
    info!(source = %id, "linked platform removed (data kept)");
    Redirect::to(&format!("/frontend/user/{}/linked-platforms", user.id)).into_response()
}

#[derive(Clone, serde::Deserialize)]
pub struct AddSourceForm {
    pub source_url: String,
    pub calendar_id: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(uid: &str, summary: &str) -> CalendarObject {
        CalendarObject::from_ics(format!(
            "BEGIN:VCALENDAR\n\
             PRODID:-//test//EN\n\
             VERSION:2.0\n\
             BEGIN:VEVENT\n\
             UID:{uid}\n\
             DTSTAMP:20260726T112617Z\n\
             DTSTART:20260806T100000Z\n\
             SUMMARY:{summary}\n\
             END:VEVENT\n\
             END:VCALENDAR"
        ))
        .unwrap()
    }

    #[test]
    fn private_ranges_are_flagged() {
        for ip in [
            "127.0.0.1",
            "127.25.0.1",
            "10.0.0.1",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "169.254.0.1",
            "100.64.0.1",
            "100.127.255.255",
            "0.0.0.0",
            "224.0.0.1",
            "255.255.255.255",
            "::1",
            "fd12::1",
            "fe80::1",
            "ff02::1",
        ] {
            assert!(
                is_private_ip(&ip.parse().unwrap()),
                "{ip} should be refused"
            );
        }
    }

    #[test]
    fn public_ranges_are_allowed() {
        for ip in [
            "8.8.8.8",
            "1.1.1.1",
            "172.32.0.1",
            "192.169.0.1",
            "100.128.0.1",
            "2001:4860:4860::8888",
            "2600:1900::1",
        ] {
            assert!(
                !is_private_ip(&ip.parse().unwrap()),
                "{ip} should be allowed"
            );
        }
    }

    #[test]
    fn ssrf_guard_rejects_non_https() {
        assert_eq!(
            ssrf_guard("http://example.com/x.ics"),
            Err("Only HTTPS URLs are allowed")
        );
        assert_eq!(
            ssrf_guard("ftp://example.com/x.ics"),
            Err("Only HTTPS URLs are allowed")
        );
    }

    #[test]
    fn ssrf_guard_rejects_literal_private_ips() {
        assert_eq!(
            ssrf_guard("https://192.168.1.1/x.ics"),
            Err("Refused: private-range address")
        );
        assert_eq!(
            ssrf_guard("https://10.0.0.5/x.ics"),
            Err("Refused: private-range address")
        );
        assert_eq!(
            ssrf_guard("https://127.0.0.1/x.ics"),
            Err("Refused: private-range address")
        );
        assert_eq!(
            ssrf_guard("https://[::1]/x.ics"),
            Err("Refused: private-range address")
        );
    }

    #[test]
    fn ssrf_guard_allows_literal_public_ip() {
        assert!(ssrf_guard("https://8.8.8.8/x.ics").is_ok());
        assert!(ssrf_guard("https://1.1.1.1/x.ics").is_ok());
    }

    #[test]
    fn refused_error_message_covers_private_ranges() {
        for ip in [
            "127.0.0.1",
            "10.0.0.1",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.0.1",
            "100.64.0.1",
            "0.0.0.0",
            "224.0.0.1",
            "::1",
            "fd12::1",
            "fe80::1",
        ] {
            assert_eq!(
                refused_if_private(&ip.parse().unwrap()),
                Err("Refused: private-range address"),
                "{ip} should be refused"
            );
        }
        for ip in ["8.8.8.8", "1.1.1.1", "172.32.0.1", "2001:4860:4860::8888"] {
            assert!(
                refused_if_private(&ip.parse().unwrap()).is_ok(),
                "{ip} should be allowed"
            );
        }
    }

    #[test]
    fn refresh_plan_adds_updates_leaves_unchanged() {
        let a = event("a", "first");
        let a_changed = event("a", "changed");
        let b = event("b", "b");
        let c = event("c", "c");

        let existing = vec![
            (a.get_uid().to_owned(), a),
            (b.get_uid().to_owned(), b.clone()),
        ];
        let remote = vec![a_changed.clone(), b, c.clone()];

        let plan = plan_refresh(&existing, &remote);

        assert!(!plan.mass_delete_abort);
        assert!(plan.to_delete.is_empty());
        assert_eq!(plan.to_update.len(), 1);
        assert_eq!(plan.to_update[0].0, "a");
        assert_eq!(plan.to_update[0].1.get_ics(), a_changed.get_ics());
        assert_eq!(plan.to_add.len(), 1);
        assert_eq!(plan.to_add[0].0, "c");
        assert_eq!(plan.to_add[0].1.get_ics(), c.get_ics());
    }

    #[test]
    fn refresh_plan_deletes_gone_uids() {
        let keep = event("keep", "k");
        let gone = event("gone", "g");
        let existing = vec![
            (keep.get_uid().to_owned(), keep.clone()),
            (gone.get_uid().to_owned(), gone),
        ];
        let remote = vec![keep];

        let plan = plan_refresh(&existing, &remote);

        assert!(!plan.mass_delete_abort);
        assert_eq!(plan.to_delete, vec!["gone"]);
        assert!(plan.to_update.is_empty());
        assert!(plan.to_add.is_empty());
    }

    #[test]
    fn refresh_plan_aborts_mass_delete() {
        let a = event("a", "a");
        let b = event("b", "b");
        let c = event("c", "c");
        let remote_only = event("remote-only", "r");
        let existing = vec![
            (a.get_uid().to_owned(), a),
            (b.get_uid().to_owned(), b),
            (c.get_uid().to_owned(), c),
        ];
        let remote = vec![remote_only];

        let plan = plan_refresh(&existing, &remote);
        // deletion of 3/3 exceeds the 50% threshold → abort
        assert!(plan.mass_delete_abort);
    }

    #[test]
    fn refresh_plan_tolerates_half_deletion() {
        let a = event("a", "a");
        let b = event("b", "b");
        let c = event("c", "c");
        let remote = vec![a.clone(), b.clone()];
        let existing = vec![
            (a.get_uid().to_owned(), a),
            (b.get_uid().to_owned(), b),
            (c.get_uid().to_owned(), c),
        ];

        let plan = plan_refresh(&existing, &remote);
        // deletion of 1/3 stays under the 50% threshold → no abort
        assert!(!plan.mass_delete_abort);
        assert_eq!(plan.to_delete, vec!["c"]);
    }
}
/// Offline (no network) verification of the materialize + refresh-diff
/// pipeline against the real SQLite stores — the same code path
/// `route_post_linked_platforms_add` / `refresh` drive, minus the fetch.
#[cfg(test)]
mod store_pipeline {
    use super::*;
    use rustical_ical::CalendarObjectType;
    use rustical_store::{CalendarMetadata, CalendarWriteStore};
    use rustical_store_sqlite::{SqliteCalendarSourceStore, tests::test_store_context};

    fn event(uid: &str, summary: &str) -> CalendarObject {
        CalendarObject::from_ics(format!(
            "BEGIN:VCALENDAR\n\
             PRODID:-//test//EN\n\
             VERSION:2.0\n\
             BEGIN:VEVENT\n\
             UID:{uid}\n\
             DTSTAMP:20260726T112617Z\n\
             DTSTART:20260806T100000Z\n\
             SUMMARY:{summary}\n\
             END:VEVENT\n\
             END:VCALENDAR"
        ))
        .unwrap()
    }

    async fn fixture() -> (Arc<dyn CalendarStore>, SqliteCalendarSourceStore, String) {
        let context = test_store_context().await;
        context
            .cal_store
            .insert_calendar(Calendar {
                id: "imported".to_owned(),
                principal: "user".to_owned(),
                meta: CalendarMetadata {
                    displayname: Some("Imported".to_owned()),
                    order: 0,
                    description: None,
                    color: None,
                },
                timezone_id: None,
                deleted_at: None,
                synctoken: 0,
                subscription_url: None,
                push_topic: "linked-pipeline".to_owned(),
                components: vec![CalendarObjectType::Event],
            })
            .await
            .unwrap();
        let source_store = SqliteCalendarSourceStore::new(context.cal_store.clone());
        let cal_dyn: Arc<dyn CalendarStore> = Arc::new(context.cal_store);
        (cal_dyn, source_store, "imported".to_owned())
    }

    #[tokio::test]
    async fn materialize_imports_uid_preserving_copies() {
        let (cal_dyn, _source_store, cal_id) = fixture().await;
        let events = vec![event("u1", "one"), event("u2", "two")];
        materialize_objects(&cal_dyn, "user", &cal_id, events)
            .await
            .unwrap();

        let objects = cal_dyn.get_objects("user", &cal_id).await.unwrap();
        assert_eq!(objects.len(), 2, "both events landed in the calendar");
        let uids: Vec<&str> = objects.iter().map(|(id, _)| id.as_str()).collect();
        assert!(uids.contains(&"u1") && uids.contains(&"u2"));
    }

    #[tokio::test]
    async fn apply_refresh_diffs_by_uid_in_real_store() {
        let (cal_dyn, _source_store, cal_id) = fixture().await;
        let a = event("a", "first");
        let b = event("b", "keep");
        let c = event("c", "gone");
        let d = event("d", "fresh");
        materialize_objects(
            &cal_dyn,
            "user",
            &cal_id,
            vec![a.clone(), b.clone(), c.clone()],
        )
        .await
        .unwrap();

        let existing = cal_dyn.get_objects("user", &cal_id).await.unwrap();
        let remote = vec![event("a", "changed"), b.clone(), d.clone()];
        let plan = plan_refresh(&existing, &remote);
        assert!(!plan.mass_delete_abort);
        apply_refresh(&cal_dyn, "user", &cal_id, plan)
            .await
            .unwrap();

        let objects = cal_dyn.get_objects("user", &cal_id).await.unwrap();
        assert_eq!(objects.len(), 3, "changed a + kept b + fresh d");
        let by_uid: HashMap<String, String> = objects
            .iter()
            .map(|(id, o)| (id.clone(), o.get_ics().to_owned()))
            .collect();
        assert!(by_uid.contains_key("d"), "new upstream uid added");
        assert!(!by_uid.contains_key("c"), "gone upstream uid removed");
        assert_eq!(
            by_uid.get("a").unwrap(),
            event("a", "changed").get_ics(),
            "changed upstream uid updated in place"
        );
    }

    #[tokio::test]
    async fn apply_refresh_aborts_mass_delete_without_touching_rows() {
        let (cal_dyn, _, cal_id) = fixture().await;
        let five = vec![
            event("a", "a"),
            event("b", "b"),
            event("c", "c"),
            event("d", "d"),
            event("e", "e"),
        ];
        materialize_objects(&cal_dyn, "user", &cal_id, five)
            .await
            .unwrap();

        let existing = cal_dyn.get_objects("user", &cal_id).await.unwrap();
        let remote = vec![event("z", "only-survivor")];
        let plan = plan_refresh(&existing, &remote);
        assert!(
            plan.mass_delete_abort,
            "5/5 deletion must trip the heuristic"
        );
        let before: HashMap<String, String> = existing
            .iter()
            .map(|(id, o)| (id.clone(), o.get_ics().to_owned()))
            .collect();

        let err = apply_refresh(&cal_dyn, "user", &cal_id, plan).await;
        assert!(err.is_err(), "mass-delete abort surfaces as an error");

        let after = cal_dyn.get_objects("user", &cal_id).await.unwrap();
        assert_eq!(after.len(), before.len(), "no rows were deleted on abort");
    }
}
