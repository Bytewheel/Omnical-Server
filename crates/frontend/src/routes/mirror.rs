//! The §18.42 push-mirror UI: what the profile page's Calendars section
//! shows per calendar tile (the configured targets that mirror it, and
//! when each last ran), and the "Sync now" button that runs the same
//! engine (`rustical_caldav::mirror::sync_target`) the background loop
//! and the CLI run — from the crate that owns it, which is why the
//! engine lives in `caldav` and not the root (see its module doc).
//!
//! ## What the button is and is not
//!
//! It is a manual trigger for the same sync the cron line or the
//! background loop performs. It is **not** gated on `[mirror] enabled`
//! — that switch arms the background loop only, and `rustical mirror
//! sync` ignores it for the same reason: a mirror is tested by hand
//! before it is turned on.
//!
//! ## Why the targets come from the context, never the form
//!
//! The form carries `principal` + `calendar_id` only — an identity of
//! *what to sync*, not *how*. The how (URL, credentials, phone-feed
//! shape) is deployment config, and letting a form pick a target by
//! name would let any signed-in user push any calendar to any
//! configured remote. The gates that matter are on the calendar, not
//! the target.

use std::collections::HashSet;
use std::sync::{Arc, Mutex, PoisonError};

use axum::{
    Extension,
    extract::{Form, Path},
    response::{IntoResponse, Response},
};
use chrono::DateTime;
use http::StatusCode;
use rustical_caldav::mirror::{MirrorTargetConfig, resolve_timezone, sync_target};
use rustical_store::{MirrorStore, auth::AuthenticationProvider};
use serde::Deserialize;

use crate::routes::user::{ProfileDeps, ProfileExtras, ProfileRequest, render_profile_page};

/// Everything the mirror UI needs, built once per router (per tenant).
///
/// The run-history store, the configured targets, the deployment
/// timezone (the cascade's second rung), and the in-flight guard that
/// keeps a second click from stacking a run on one already going.
///
/// **Not** a bare `Extension<String>` for the timezone: that type is
/// already taken by the subscriptions public URL layered a few lines
/// down in `frontend_router`, and a second one would silently shadow
/// the first.
pub struct MirrorUiContext {
    pub store: Arc<dyn MirrorStore>,
    pub targets: Vec<MirrorTargetConfig>,
    pub deployment_timezone: String,
    /// Per-target in-flight guard: a second click while a sync runs
    /// answers "already syncing" instead of stacking runs.
    pub in_flight: Mutex<HashSet<String>>,
}

/// One mirror target as a calendar tile shows it: the name, a
/// human-readable label of the remote, what kind of feed it is, and when
/// it last ran.
pub struct MirrorTargetUi {
    pub name: String,
    /// `host · last-path-segment` of the target URL — "dav.aphy.app ·
    /// Default" — the remote's identity without the credentials or the
    /// full path.
    pub remote_label: String,
    /// "web calendar" (canonical), "phone feed" (`phone_feed_only`), or
    /// "web calendar + phone feed" (`phone_instances`).
    pub kind_label: &'static str,
    /// The newest recorded run (one `last_mirror_run` query per target).
    pub last_run: Option<rustical_store::MirrorRun>,
    /// The same run as a relative phrase ("2 hours ago") —
    /// chrono-humanize, so timezone-independent (the app-tokens pattern).
    pub last_run_relative: Option<String>,
}

/// The remote label of a target: host + last path segment. The full URL
/// never renders (it carries no secret today, but a URL is an
/// identifier, and the label is what a person reads).
pub fn remote_label(url: &str) -> String {
    let host = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .map_or("", |rest| rest.split(['/', '?']).next().unwrap_or(rest));
    let last_segment = url
        .trim_end_matches('/')
        .rsplit('/')
        .next()
        .filter(|segment| !segment.is_empty() && !segment.contains(':'))
        .unwrap_or("");
    if host.is_empty() {
        url.to_owned()
    } else if last_segment.is_empty() || last_segment == host {
        host.to_owned()
    } else {
        format!("{host} · {last_segment}")
    }
}

/// What kind of feed a target is, in the §18.41 two-calendar vocabulary.
#[must_use]
pub const fn kind_label(target: &MirrorTargetConfig) -> &'static str {
    if target.phone_feed_only {
        "phone feed"
    } else if target.phone_instances {
        "web calendar + phone feed"
    } else {
        "web calendar"
    }
}

/// The relative form of a run's `ran_at` ("3 hours ago") — the same
/// chrono-humanize rendering the app-tokens table uses, so the two
/// "when" columns on one page read the same way.
fn relative(ran_at: &str) -> Option<String> {
    DateTime::parse_from_rfc3339(ran_at)
        .ok()
        .map(|dt| chrono_humanize::HumanTime::from(dt).to_string())
}

/// The [`MirrorTargetUi`] list of one calendar tile: every configured
/// target whose `(principal, calendar)` matches, newest-run row read
/// per target. `None` context ⇒ empty — an unconfigured deployment
/// shows no mirror block at all.
pub async fn mirror_targets_for(
    ctx: Option<&Arc<MirrorUiContext>>,
    calendar_principal: &str,
    calendar_id: &str,
) -> Vec<MirrorTargetUi> {
    let Some(ctx) = ctx else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for target in &ctx.targets {
        if target.principal != calendar_principal || target.calendar != calendar_id {
            continue;
        }
        let last_run = ctx.store.last_mirror_run(&target.name).await.ok().flatten();
        let last_run_relative = last_run.as_ref().and_then(|run| relative(&run.ran_at));
        out.push(MirrorTargetUi {
            name: target.name.clone(),
            remote_label: remote_label(&target.url),
            kind_label: kind_label(target),
            last_run,
            last_run_relative,
        });
    }
    out
}

#[derive(Debug, Clone, Deserialize)]
pub struct MirrorSyncForm {
    /// The owner principal of the calendar (`user`'s own id, or a group
    /// the user admins).
    pub principal: String,
    pub calendar_id: String,
}

/// POST `/{user}/calendar/mirror-sync` — the "Sync now" button: run the
/// configured targets of one calendar now, then re-render the profile
/// with a per-target result banner.
///
/// Gates: `user_id == user.id`; `form.principal == user.id ||
/// user.is_admin(&form.principal)` (the credentials rule — a member
/// without admin may read a group calendar but may not push it); the
/// calendar exists (fail fast like the share routes); the targets come
/// from the config, never the form.
///
/// No CSRF token: profile POSTs don't carry one (session `SameSite=Lax`
/// plus these auth gates — the credentials/subscribe pattern).
///
/// **Never log the target struct** — its `Debug` carries the remote
/// password (§18.41's own lesson, encoded in the engine already).
#[allow(clippy::too_many_lines)] // the gates, the in-flight guard, the per-target loop, the re-render
pub async fn route_post_mirror_sync<
    AP: AuthenticationProvider,
    CS: rustical_store::CalendarStore,
    AS: rustical_store::AddressbookStore + rustical_store::PrefixedCalendarStore,
>(
    Path(user_id): Path<String>,
    deps: ProfileDeps<AP, CS, AS>,
    req: ProfileRequest,
    user: rustical_store::auth::Principal,
    Extension(mirror): Extension<Option<Arc<MirrorUiContext>>>,
    Form(form): Form<MirrorSyncForm>,
) -> Response {
    if user_id != user.id {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    // The context's absence is a wiring fact, not a user error: 404
    // (the password-reset endpoints' pattern for an unconfigured
    // surface), not a banner.
    let Some(ctx) = mirror else {
        return StatusCode::NOT_FOUND.into_response();
    };

    let page_mirror_error = |deps: &ProfileDeps<AP, CS, AS>,
                             req: &ProfileRequest,
                             user: &rustical_store::auth::Principal,
                             error: String| {
        let deps = deps.clone();
        let req = req.clone();
        let user = user.clone();
        async move {
            render_profile_page(
                &deps,
                &req,
                &user,
                ProfileExtras {
                    calendars: crate::routes::calendar::CalendarsExtras {
                        mirror_synced: Some(vec![format!("Sync failed: {error}")]),
                        ..crate::routes::calendar::CalendarsExtras::default()
                    },
                    ..ProfileExtras::default()
                },
            )
            .await
        }
    };

    // Ownership: the user's own calendar, or a group they admin (the
    // credentials rule — pushing a member's calendar is member
    // management).
    if form.principal != user.id && !user.is_admin(&form.principal) {
        return (
            StatusCode::FORBIDDEN,
            "You can only sync your own or your groups' calendars.",
        )
            .into_response();
    }

    if form.calendar_id.is_empty() {
        return page_mirror_error(&deps, &req, &user, "No calendar specified.".to_owned()).await;
    }

    // Fail fast on a wrong calendar id (the share routes' discipline).
    if deps
        .cal_store
        .get_calendar(&form.principal, &form.calendar_id, false)
        .await
        .is_err()
    {
        return page_mirror_error(
            &deps,
            &req,
            &user,
            format!(
                "No such calendar '{}' for '{}'.",
                form.calendar_id, form.principal
            ),
        )
        .await;
    }

    // The targets of this calendar, from the config.
    let targets: Vec<&MirrorTargetConfig> = ctx
        .targets
        .iter()
        // Two axes, bound to locals: `suspicious_operation_groupings`
        // reads `target.principal == form.principal &&
        // target.calendar == form.calendar_id` as a possible
        // transposition of a tuple comparison — it is not one, but the
        // locals say so without an allow.
        .filter(|target| {
            let same_principal = target.principal == form.principal;
            let same_calendar = target.calendar == form.calendar_id;
            same_principal && same_calendar
        })
        .collect();
    if targets.is_empty() {
        return page_mirror_error(
            &deps,
            &req,
            &user,
            "No mirrors are configured for this calendar.".to_owned(),
        )
        .await;
    }

    let mut results: Vec<String> = Vec::new();
    for target in targets {
        // The in-flight guard: try-insert, and `insert` returning
        // `false` means the name was already there — a run is going,
        // so report it, do not stack another (`true` means this click
        // claimed the name). A poisoned lock means some other run
        // panicked mid-flight; taking the guard anyway (the set is
        // still consistent — a panicked run leaked its insert) is
        // safer than blocking this one forever.
        let claimed = ctx
            .in_flight
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(target.name.clone());
        if !claimed {
            results.push(format!(
                "{}: already syncing — try again in a minute.",
                target.name
            ));
            continue;
        }

        // §18.42 cascade, per run: the calendar OWNER's setting (never
        // the acting admin's), then the deployment rung, then UTC. A
        // missing owner row degrades rather than fails.
        let owner_timezone = deps
            .auth_provider
            .get_principal(&target.principal)
            .await
            .ok()
            .flatten()
            .map(|owner| owner.timezone)
            .unwrap_or_default();
        let timezone = resolve_timezone(&owner_timezone, &ctx.deployment_timezone);

        let outcome = sync_target(
            target,
            deps.cal_store.as_ref(),
            ctx.store.as_ref(),
            &timezone,
            chrono::Utc::now(),
        )
        .await;

        // Release the guard whatever happened: the button's next click
        // starts fresh. Same poisoned-lock treatment as the insert.
        ctx.in_flight
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&target.name);

        match outcome {
            Ok(stats) => results.push(format!(
                "{}: {} put, {} deleted, {} unchanged.",
                target.name, stats.put, stats.deleted, stats.unchanged
            )),
            Err(error) => results.push(format!("{name}: failed — {error}", name = target.name)),
        }
    }

    render_profile_page(
        &deps,
        &req,
        &user,
        ProfileExtras {
            calendars: crate::routes::calendar::CalendarsExtras {
                mirror_synced: Some(results),
                ..crate::routes::calendar::CalendarsExtras::default()
            },
            ..ProfileExtras::default()
        },
    )
    .await
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::routes::test_rig::{Rig, mirror_context, stub_caldav_server, target_config};
    use axum::body::Body as AxBody;
    use headers::HeaderMapExt as _;
    use http::{Method, Request, StatusCode};

    /// The profile GET renders a "Mirrors" block per configured calendar,
    /// with the last-sync line from the seeded `mirror_runs` row — and
    /// none at all for a calendar no target names.
    #[tokio::test]
    async fn profile_shows_mirror_block_with_last_sync_for_configured_calendars() {
        let rig = Rig::new().await;
        rig.insert_calendar_with_object("user", "personal").await;
        rig.insert_calendar_with_object("user", "unmirrored").await;
        let (url, _remote) = stub_caldav_server().await;
        let mirror = mirror_context(
            rig.mirror_store(),
            vec![target_config(
                "personal-to-omnical",
                "user",
                "personal",
                &url,
            )],
            "UTC",
        );
        let router = rig.router_with(Some(mirror)).await;

        // Seed a finished run so the last-sync line has something to say.
        sqlx::query(
            "INSERT INTO mirror_runs (mirror, ran_at, put, deleted, unchanged, error) \
             VALUES ('personal-to-omnical', '2026-10-13T14:30:00Z', 0, 0, 1, NULL)",
        )
        .execute(&rig.db)
        .await
        .unwrap();

        let mut req = Request::builder()
            .uri("/frontend/user/user")
            .body(AxBody::empty())
            .unwrap();
        req.headers_mut()
            .typed_insert(headers::Authorization::basic("user", "pass"));
        let resp = router.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let page = String::from_utf8(bytes.to_vec()).unwrap();

        assert!(page.contains("Mirrors (copies on other servers)"), "{page}");
        assert!(page.contains("personal-to-omnical"), "{page}");
        assert!(
            page.contains("personal-to-omnical</option>") || page.contains("personal-to-omnical"),
            "{page}"
        );
        // The last-sync line: relative, tz-independent, and the stats.
        assert!(
            page.contains("last sync"),
            "the tile shows when the target last ran: {page}"
        );
        assert!(
            page.contains("0 copied, 0 removed, 1 unchanged"),
            "the last run's counts: {page}"
        );
        // The remote label: host + last path segment, never the full URL.
        assert!(
            page.contains("127.0.0.1"),
            "the remote's host renders: {page}"
        );
        // One Sync button per mirrored tile — the unmirrored calendar
        // shows none.
        assert_eq!(
            page.matches("Sync now").count(),
            1,
            "exactly the configured calendar carries a sync button: {page}"
        );
    }

    /// POST sync end to end: the button runs the same engine against a
    /// real local `CalDAV` stub, re-renders the banner with the stats, and
    /// leaves the `mirror_objects` + `mirror_runs` rows the next render
    /// reads.
    #[tokio::test]
    async fn sync_button_runs_the_engine_against_a_stub_remote() {
        let rig = Rig::new().await;
        rig.insert_calendar_with_object("user", "personal").await;
        let (url, remote) = stub_caldav_server().await;
        let mirror = mirror_context(
            rig.mirror_store(),
            vec![target_config(
                "personal-to-omnical",
                "user",
                "personal",
                &url,
            )],
            "UTC",
        );
        let router = rig.router_with(Some(mirror)).await;

        let (status, body) = router_post_form(
            &router,
            "/frontend/user/user/calendar/mirror-sync",
            &[("principal", "user"), ("calendar_id", "personal")],
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(
            body.contains("Mirror sync finished"),
            "the banner renders: {body}"
        );
        assert!(
            body.contains("personal-to-omnical: 1 put, 0 deleted, 0 unchanged."),
            "one event PUT to the stub: {body}"
        );

        // The engine's own receipts: state and run rows.
        let objects: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM mirror_objects WHERE mirror = 'personal-to-omnical'",
        )
        .fetch_one(&rig.db)
        .await
        .unwrap();
        assert_eq!(objects, 1, "the state records the one written object");
        let runs: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM mirror_runs WHERE mirror = 'personal-to-omnical'",
        )
        .fetch_one(&rig.db)
        .await
        .unwrap();
        assert_eq!(runs, 1, "the run is recorded");
        // The stub saw the PUT.
        assert_eq!(remote.lock().unwrap().len(), 1, "the stub received the PUT");

        // A second click converges: unchanged, counted as such.
        let (_, body) = router_post_form(
            &router,
            "/frontend/user/user/calendar/mirror-sync",
            &[("principal", "user"), ("calendar_id", "personal")],
        )
        .await;
        assert!(
            body.contains("personal-to-omnical: 0 put, 0 deleted, 1 unchanged."),
            "a converged run reports unchanged: {body}"
        );
    }

    /// The gates: another user's calendar 403s, and a calendar with no
    /// configured targets answers the banner — never a silent no-op.
    #[tokio::test]
    async fn sync_gates_forbidden_and_unconfigured() {
        let rig = Rig::new().await;
        rig.insert_user("other").await;
        rig.insert_calendar_with_object("user", "personal").await;
        rig.insert_calendar_with_object("user", "noTargets").await;
        let (url, _remote) = stub_caldav_server().await;
        let mirror = mirror_context(
            rig.mirror_store(),
            vec![target_config(
                "personal-to-omnical",
                "user",
                "personal",
                &url,
            )],
            "UTC",
        );
        let router = rig.router_with(Some(mirror)).await;

        // A calendar the acting user does not own nor admin: 403.
        let (status, _) = router_post_form(
            &router,
            "/frontend/user/user/calendar/mirror-sync",
            &[("principal", "other"), ("calendar_id", "personal")],
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        // A real calendar of the user's with no configured targets: the
        // error banner, and no run recorded for anything.
        let (status, body) = router_post_form(
            &router,
            "/frontend/user/user/calendar/mirror-sync",
            &[("principal", "user"), ("calendar_id", "noTargets")],
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(
            body.contains("No mirrors are configured for this calendar."),
            "{body}"
        );
        let runs: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM mirror_runs")
            .fetch_one(&rig.db)
            .await
            .unwrap();
        assert_eq!(runs, 0, "no run is recorded for an unconfigured calendar");
    }

    /// A gate-failure POST answers 401 before any gate runs (the wrong
    /// session-user path).
    #[tokio::test]
    async fn sync_rejects_a_mismatched_session_user() {
        let rig = Rig::new().await;
        rig.insert_calendar_with_object("user", "personal").await;
        let (url, _remote) = stub_caldav_server().await;
        let mirror = mirror_context(
            rig.mirror_store(),
            vec![target_config(
                "personal-to-omnical",
                "user",
                "personal",
                &url,
            )],
            "UTC",
        );
        let router = rig.router_with(Some(mirror)).await;

        // The path names another user: the session user is `user`, so
        // `user_id != user.id` 401s before the form is even read.
        let body = "principal=user&calendar_id=personal";
        let mut req = Request::builder()
            .method(Method::POST)
            .uri("/frontend/user/other/calendar/mirror-sync")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(AxBody::from(body))
            .unwrap();
        req.headers_mut()
            .typed_insert(headers::Authorization::basic("user", "pass"));
        let resp = router.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    /// An authenticated POST helper against a router the rig does not
    /// own (the `router_with` rebuild) — the rig's own methods target
    /// `self.router`, which these tests deliberately do not use.
    async fn router_post_form(
        router: &axum::Router,
        path: &str,
        fields: &[(&str, &str)],
    ) -> (StatusCode, String) {
        let body = fields
            .iter()
            .map(|(k, v)| format!("{k}={}", crate::routes::test_rig::urlencode(v)))
            .collect::<Vec<_>>()
            .join("&");
        let mut req = Request::builder()
            .method(Method::POST)
            .uri(path)
            .header("content-type", "application/x-www-form-urlencoded")
            .body(AxBody::from(body))
            .unwrap();
        req.headers_mut()
            .typed_insert(headers::Authorization::basic("user", "pass"));
        let resp = router.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        (status, String::from_utf8(bytes.to_vec()).unwrap())
    }

    use tower::ServiceExt;

    /// §18.42, the timezone half: the profile renders the section with
    /// every IANA name; a save POST persists the zone (validator
    /// first), re-renders with it selected and the banner expanded; a
    /// garbage zone answers the banner and stores nothing.
    #[tokio::test]
    async fn timezone_section_saves_validates_and_renders_selected() {
        let rig = Rig::new().await;
        let router = rig.router_with(None).await;

        // The plain GET carries the section, sorted names, nothing selected.
        let (status, page) = get(&router, "/frontend/user/user").await;
        assert_eq!(status, StatusCode::OK);
        assert!(page.contains("id=\"timezone-section\""), "{page}");
        assert!(page.contains("America/New_York"), "{page}");
        assert!(
            page.contains("value=\"America/New_York\">America/New_York</option>"),
            "{page}"
        );
        assert!(
            !page.contains("value=\"America/New_York\" selected"),
            "nothing is selected while unset: {page}"
        );

        // Save: re-rendered page shows the banner and the selection.
        let (status, page) = router_post_form(
            &router,
            "/frontend/user/user/timezone",
            &[("timezone", "America/New_York")],
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{page}");
        assert!(page.contains("Timezone saved: America/New_York"), "{page}");
        assert!(
            page.contains("value=\"America/New_York\" selected"),
            "the saved zone renders selected: {page}"
        );
        // …and the store has it (the render's `user` came from the
        // provider, so this is also the persistence proof).
        assert_eq!(
            rig.principal_store
                .get_principal("user")
                .await
                .unwrap()
                .unwrap()
                .timezone,
            "America/New_York"
        );

        // Garbage: rejected with the banner, the old value kept.
        let (status, page) = router_post_form(
            &router,
            "/frontend/user/user/timezone",
            &[("timezone", "Mars/Olympus_Mons")],
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{page}");
        assert!(
            page.contains("is not a timezone this server recognises"),
            "{page}"
        );
        assert_eq!(
            rig.principal_store
                .get_principal("user")
                .await
                .unwrap()
                .unwrap()
                .timezone,
            "America/New_York",
            "a rejected save must not clear the stored zone"
        );

        // Clear ("Server default"): back to empty.
        let (status, page) =
            router_post_form(&router, "/frontend/user/user/timezone", &[("timezone", "")]).await;
        assert_eq!(status, StatusCode::OK, "{page}");
        assert!(page.contains("Timezone cleared"), "{page}");
        assert_eq!(
            rig.principal_store
                .get_principal("user")
                .await
                .unwrap()
                .unwrap()
                .timezone,
            ""
        );
    }

    async fn get(router: &axum::Router, path: &str) -> (StatusCode, String) {
        let mut req = Request::builder().uri(path).body(AxBody::empty()).unwrap();
        req.headers_mut()
            .typed_insert(headers::Authorization::basic("user", "pass"));
        let resp = router.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        (status, String::from_utf8(bytes.to_vec()).unwrap())
    }
}
