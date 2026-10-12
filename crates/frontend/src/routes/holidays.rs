//! Omnical holiday sets: the "add holidays" dropdown of the create-calendar
//! modal. A deployment stages `.ics` files plus a `holidays.toml` manifest on
//! the router (`[frontend] holidays_dir`); the modal lists the manifest's
//! groups and sets, and a selection is merged into the freshly created
//! calendar as a copy — the same semantics as a linked platform. A
//! `holidays://{set}` source row is recorded per selected set so the
//! existing linked-platforms Refresh (§17.8.3) keeps the copy updatable by
//! UID when the `.ics` files are regenerated (new years, better dates).
//!
//! Files are read from disk at import/refresh time, never fetched over HTTP:
//! the linked-platform engine's fetch is HTTPS-only *with an SSRF guard on
//! private ranges* (rightly), and the router serving its own flash back to
//! itself over TLS would be a certificate dance for bytes it already has.
//! The manifest is re-read per request — it is a few hundred bytes — so a
//! regeneration is picked up without a restart.
//!
//! Paths are traversal-safe by construction: a set id is resolved to its
//! manifest entry first, and only the manifest's own `file` names are ever
//! joined onto the configured directory. An id that is not in the manifest
//! names no path at all.

use std::{collections::HashSet, path::PathBuf, sync::Arc};

use crate::routes::linked_platforms::{materialize_objects, parse_ics};
use crate::routes::user::ProfileDeps;
use axum::{
    Extension, Form,
    extract::Path,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use rustical_ical::CalendarObject;
use rustical_store::{
    AddressbookStore, CalendarStore, Error, PrefixedCalendarStore,
    auth::{AuthenticationProvider, Principal},
};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

/// `holidays.toml` — the groups the modal offers, each with its sets.
#[derive(Debug, Deserialize)]
pub struct HolidaysManifest {
    #[serde(default)]
    pub groups: Vec<HolidayGroup>,
}

#[derive(Debug, Deserialize)]
pub struct HolidayGroup {
    pub id: String,
    pub label: String,
    #[serde(default)]
    pub sets: Vec<HolidaySetEntry>,
}

#[derive(Debug, Deserialize)]
pub struct HolidaySetEntry {
    pub id: String,
    pub label: String,
    pub file: String,
}

#[derive(Serialize)]
struct HolidaysGroupJson {
    id: String,
    label: String,
    sets: Vec<HolidaysSetJson>,
}

#[derive(Serialize)]
struct HolidaysSetJson {
    id: String,
    label: String,
}

#[derive(Serialize)]
struct HolidaysListJson {
    groups: Vec<HolidaysGroupJson>,
}

/// The deployment's holiday catalog: the configured directory plus a
/// per-request manifest read. `None` (unconfigured) disables every arm —
/// the list answers empty and imports answer "no holiday sets".
#[derive(Clone, Default)]
pub struct HolidaysCatalog {
    dir: Option<PathBuf>,
}

impl HolidaysCatalog {
    pub fn from_config(path: Option<&PathBuf>) -> Self {
        Self { dir: path.cloned() }
    }

    /// The parsed manifest, or an error string naming what is wrong.
    fn manifest(&self) -> Result<HolidaysManifest, String> {
        let dir = self.dir.as_ref().ok_or("no holiday sets on this server")?;
        let text = std::fs::read_to_string(dir.join("holidays.toml"))
            .map_err(|e| format!("holidays manifest unreadable: {e}"))?;
        toml::from_str(&text).map_err(|e| format!("holidays manifest unparsable: {e}"))
    }

    /// The `.ics` path of a manifest set. Traversal-safe by construction:
    /// only the id is user input, and it must match a manifest entry first.
    fn set_path(&self, manifest: &HolidaysManifest, set_id: &str) -> Result<PathBuf, String> {
        let set = manifest
            .groups
            .iter()
            .flat_map(|group| &group.sets)
            .find(|set| set.id == set_id)
            .ok_or_else(|| format!("unknown holiday set '{set_id}'"))?;
        Ok(self
            .dir
            .as_ref()
            .expect("a loaded manifest implies a configured dir")
            .join(&set.file))
    }

    /// Load + parse one set's `.ics` from disk — the disk arm of the import
    /// engine's fetch. Used by the import route and by the refresh of a
    /// `holidays://{set}` source.
    ///
    /// # Errors
    /// Names the set and what is wrong with it.
    pub fn load_set(&self, set_id: &str) -> Result<Vec<CalendarObject>, String> {
        let manifest = self.manifest()?;
        let path = self.set_path(&manifest, set_id)?;
        let ics = std::fs::read_to_string(&path)
            .map_err(|e| format!("holiday set '{set_id}' unreadable: {e}"))?;
        parse_ics(&ics).map_err(|e| format!("holiday set '{set_id}' unparsable: {e}"))
    }
}

/// The section tile's title for a holidays source: the set's manifest label,
/// falling back to the id when the manifest is gone (a retired set still
/// deserves a readable tile, not a raw URL).
pub fn holiday_set_label(holidays: &HolidaysCatalog, set_id: &str) -> String {
    let label = holidays
        .manifest()
        .ok()
        .and_then(|manifest| {
            manifest
                .groups
                .iter()
                .flat_map(|group| &group.sets)
                .find(|set| set.id == set_id)
                .map(|set| set.label.clone())
        })
        .unwrap_or_else(|| set_id.to_owned());
    format!("Holidays · {label}")
}

/// `GET /_holidays.json` — the manifest as the create-calendar modal reads
/// it: groups with their sets. Public metadata (names of holiday sets), the
/// same trust level as the timezone list — nothing here is user data, and
/// the dialog needs it before any calendar exists.
///
/// Unconfigured, or a manifest that will not read, answers an empty list
/// (with a warn): the modal shows nothing to select, which is honest.
pub async fn route_holidays_json(Extension(holidays): Extension<HolidaysCatalog>) -> Response {
    let list = match holidays.manifest() {
        Ok(manifest) => HolidaysListJson {
            groups: manifest
                .groups
                .into_iter()
                .map(|group| HolidaysGroupJson {
                    id: group.id,
                    label: group.label,
                    sets: group
                        .sets
                        .into_iter()
                        .map(|set| HolidaysSetJson {
                            id: set.id,
                            label: set.label,
                        })
                        .collect(),
                })
                .collect(),
        },
        Err(_) if holidays.dir.is_none() => HolidaysListJson { groups: vec![] },
        Err(e) => {
            warn!("{e} — the add-holidays dropdown stays empty");
            HolidaysListJson { groups: vec![] }
        }
    };
    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, "application/json".parse().unwrap());
    (headers, serde_json::to_string(&list).unwrap()).into_response()
}

#[derive(Deserialize)]
pub struct HolidaysImportForm {
    /// The owning principal of the target calendar. Holiday sources are
    /// per-principal rows like every linked source, and the linked-platforms
    /// section lists and refreshes them under the acting user — so holidays
    /// import into the user's own calendars only, not a group's.
    pub principal: String,
    /// Comma-separated set ids (`us,judaism,rc-1962`) — the modal submits
    /// its checkbox list as one field.
    pub sets: String,
}

/// The submitted set ids: split, trimmed, de-duplicated, order-preserved.
fn parse_set_ids(raw: &str) -> Vec<String> {
    let mut seen = HashSet::new();
    raw.split(',')
        .map(str::trim)
        .filter(|id| !id.is_empty())
        .filter(|id| seen.insert((*id).to_owned()))
        .map(ToOwned::to_owned)
        .collect()
}

/// Load + validate every selected set before any row is written: a bad id
/// must not leave a half-imported calendar behind. `load_set` resolves each
/// id via the manifest (unknown id, unreadable or unparsable file all
/// named); an empty set is as useless as a missing one.
fn load_holiday_sets<'a>(
    holidays: &HolidaysCatalog,
    set_ids: &'a [String],
) -> Result<Vec<(&'a String, Vec<CalendarObject>)>, String> {
    set_ids
        .iter()
        .map(|set_id| {
            let objects = holidays.load_set(set_id)?;
            if objects.is_empty() {
                return Err(format!("Holiday set '{set_id}' has no events."));
            }
            Ok((set_id, objects))
        })
        .collect()
}

/// `POST /{user}/calendar/{calendar_id}/holidays` — import the selected sets
/// into the named calendar as a copy, recording a `holidays://{set}` source
/// row per set so the linked-platforms Refresh keeps them updatable.
///
/// Idempotent per set: a set already recorded for this calendar is skipped
/// (re-selecting it re-materializes the same UIDs — an overwrite, not a
/// duplicate), so a failed half-import can simply be retried.
pub async fn route_post_holidays_add<
    AP: AuthenticationProvider,
    CS: CalendarStore,
    AS: AddressbookStore + PrefixedCalendarStore,
>(
    Path((user_id, calendar_id)): Path<(String, String)>,
    deps: ProfileDeps<AP, CS, AS>,
    Extension(holidays): Extension<HolidaysCatalog>,
    user: Principal,
    Form(form): Form<HolidaysImportForm>,
) -> Response {
    if user_id != user.id {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    if form.principal != user.id {
        return error_response(
            StatusCode::BAD_REQUEST,
            "Holidays can only be added to your own calendars, not a group's.",
        );
    }
    if deps
        .cal_store
        .get_calendar(&form.principal, &calendar_id, false)
        .await
        .is_err()
    {
        return error_response(
            StatusCode::NOT_FOUND,
            &format!("No such calendar '{calendar_id}'."),
        );
    }

    // Validate everything before writing a single row: a bad id must not
    // leave a half-imported calendar behind. `load_set` resolves the id via
    // the manifest (unknown id, unreadable or unparsable file all named).
    let set_ids = parse_set_ids(&form.sets);
    if set_ids.is_empty() {
        return error_response(StatusCode::BAD_REQUEST, "No holiday sets selected.");
    }
    let set_objects = match load_holiday_sets(&holidays, &set_ids) {
        Ok(set_objects) => set_objects,
        Err(e) => return error_response(StatusCode::BAD_REQUEST, &e),
    };

    // Import per set: each set's events materialize under a `holidays://{set}`
    // source row that owns exactly those UIDs, so a later Refresh of one set
    // (or of a sibling set in the same calendar) diffs only its own events —
    // the combined calendar is N sources, not one blob.
    let cal_dyn: Arc<dyn CalendarStore> = deps.cal_store.clone();
    let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let known_sources = deps
        .source_store
        .get_calendar_sources(&form.principal)
        .await
        .unwrap_or_default();
    for (set_id, objects) in set_objects {
        let source_url = format!("holidays://{set_id}");
        let source_id = match deps
            .source_store
            .add_calendar_source(&form.principal, &calendar_id, &source_url, "holidays")
            .await
        {
            // A re-import keeps its source row (the retried import then only
            // re-materializes: put_objects is keyed by UID, so a set's
            // events overwrite in place and never duplicate).
            Ok(source_id) => source_id,
            Err(Error::AlreadyExists) => {
                let Some(source) = known_sources.iter().find(|source| {
                    source.source_url == source_url && source.calendar_id == calendar_id
                }) else {
                    return error_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        &format!(
                            "holiday set '{set_id}' is already linked but its source row is missing"
                        ),
                    );
                };
                source.id.clone()
            }
            Err(e) => {
                warn!(%e, set_id = %set_id, "holiday source row failed");
                return error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &format!("Could not record holiday set '{set_id}': {e}."),
                );
            }
        };
        let imported: Vec<String> = objects.iter().map(|o| o.get_uid().to_owned()).collect();
        if let Err(e) = materialize_objects(&cal_dyn, &form.principal, &calendar_id, objects).await
        {
            warn!(%e, "holiday materialize failed");
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("Could not import the holiday events: {e}."),
            );
        }
        if let Err(e) = deps
            .source_store
            .record_source_objects(&form.principal, &source_id, &imported)
            .await
        {
            warn!(%e, set_id = %set_id, "record holiday source objects failed");
        }
        let _ = deps
            .source_store
            .update_calendar_source_fetch(&form.principal, &source_id, &now, true)
            .await;
        info!(user = %user.id, calendar = %calendar_id, set_id = %set_id, "holiday set imported");
    }

    (
        StatusCode::OK,
        format!("{{\"imported\":{}}}", set_ids.len()),
    )
        .into_response()
}

/// A machine-readable error for the modal's `fetch`: it alerts the body
/// text, so the message is one short sentence a user can act on.
fn error_response(status: StatusCode, message: &str) -> Response {
    let mut response = (status, format!("{{\"error\":\"{message}\"}}")).into_response();
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, "application/json".parse().unwrap());
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest_text() -> &'static str {
        r#"
[[groups]]
id = "countries"
label = "Countries"

[[groups.sets]]
id = "us"
label = "United States (federal)"
file = "us.ics"

[[groups]]
id = "christianity"
label = "Christianity"

[[groups.sets]]
id = "rc-1962"
label = "Roman Catholic (1962 Missal)"
file = "christianity/rc-1962.ics"
"#
    }

    #[test]
    fn manifest_parses_groups_and_sets() {
        let manifest: HolidaysManifest = toml::from_str(manifest_text()).unwrap();
        assert_eq!(manifest.groups.len(), 2);
        assert_eq!(manifest.groups[0].sets[0].id, "us");
        assert_eq!(manifest.groups[1].sets[0].file, "christianity/rc-1962.ics");
    }

    #[test]
    fn unconfigured_catalog_names_itself() {
        let catalog = HolidaysCatalog::from_config(None);
        assert!(catalog.manifest().unwrap_err().contains("no holiday sets"));
    }

    #[test]
    fn set_path_only_resolves_manifest_files() {
        let catalog = HolidaysCatalog::from_config(Some(&PathBuf::from("/srv/holidays")));
        let manifest: HolidaysManifest = toml::from_str(manifest_text()).unwrap();
        let path = catalog.set_path(&manifest, "rc-1962").unwrap();
        assert_eq!(
            path,
            PathBuf::from("/srv/holidays/christianity/rc-1962.ics")
        );
        assert!(catalog.set_path(&manifest, "../etc/passwd").is_err());
        assert!(catalog.set_path(&manifest, "nope").is_err());
    }
}
