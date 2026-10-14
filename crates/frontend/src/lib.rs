#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
use axum::{
    Extension, RequestExt, Router,
    body::Body,
    extract::{OriginalUri, Request},
    middleware::{self, Next},
    response::{Redirect, Response},
    routing::{get, post},
};
use headers::{ContentType, HeaderMapExt};
use http::{Method, StatusCode};
use routes::addressbooks::route_addressbooks;
use routes::calendar::route_calendars;
use rustical_oidc::{OidcConfig, OidcServiceConfig, oidc_router};
use rustical_scheduling::SmtpAccount;
use rustical_store::SubscriptionStore;
use rustical_store::{
    AddressbookStore, CalendarSourceStore, CalendarStore, CollectionShareStore, InviteStore,
    PasswordResetStore, PrefixedCalendarStore, PrintStore,
    auth::{AuthenticationProvider, middleware::AuthenticationLayer},
};
// §18.42: the mirror UI context is the seam `make_app_for` hands the
// frontend (the routes stay private; the context is the contract).
pub use routes::mirror::MirrorUiContext;
use std::sync::Arc;
use url::Url;

mod assets;
pub mod client_ip;
mod config;
pub mod nextcloud_login;
mod oidc_user_store;
pub(crate) mod pages;
mod routes;
pub mod url_builder;

pub use config::FrontendConfig;
use oidc_user_store::OidcUserStore;
pub use routes::admin::{
    ADMIN_SESSION_COOKIE, AdminPanel, AdminRateLimiter, normalise_host as admin_normalise_host,
};
// The appliance panel's seam. `routes` is private, so the `rustical` crate —
// which is the only thing that implements `ApplianceService` — could not name
// the trait or the view types without these. Re-exported rather than the module
// made public, so the *contract* is visible from outside the crate and the
// handlers are not.
pub use routes::appliance::{
    AddressView, AppliancePanel, ApplianceService, DataView, FirmwareView, ImageView, NetworkView,
    PendingView, ReportView, RestorePointView, StagedView,
};

use crate::routes::{
    addressbook::{
        route_addressbook, route_addressbook_contacts, route_addressbook_contacts_create,
        route_addressbook_contacts_new, route_addressbook_restore, route_contact_delete,
        route_contact_edit, route_contact_update, route_contacts, route_contacts_create,
        route_contacts_new,
    },
    addressbooks::{
        route_addressbook_credentials, route_addressbook_credentials_revoke,
        route_post_contacts_import,
    },
    app_token::{route_delete_app_token, route_post_app_token, route_regenerate_app_token},
    calendar::{
        route_calendar, route_calendar_credentials, route_calendar_credentials_revoke,
        route_calendar_restore, route_calendar_subscribe,
    },
    calendar_view::{
        route_calendar_event_create, route_calendar_events, route_calendar_events_new,
        route_event_create, route_event_delete, route_event_edit, route_event_update, route_events,
        route_events_new,
    },
    download::{HawkBookApk, route_download_hawkbook},
    groups::{
        route_group_detail, route_group_member_privilege, route_group_member_remove,
        route_group_new, route_groups,
    },
    holidays::{HolidaysCatalog, route_holidays_json, route_post_holidays_add},
    linked_platforms::{
        route_get_linked_platforms, route_post_linked_platforms_add,
        route_post_linked_platforms_refresh, route_post_linked_platforms_remove,
    },
    login::{route_get_login, route_post_login, route_post_logout},
    mirror::route_post_mirror_sync,
    password::{password_change_gate, route_get_password_change, route_post_password_change},
    password_reset::{
        ResetRateLimiter, route_get_forgot_password, route_get_reset_password,
        route_post_forgot_password, route_post_reset_password,
    },
    print::{
        route_addressbook_contacts_print, route_addressbook_contacts_print_mark,
        route_calendar_events_print, route_calendar_events_print_mark, route_contacts_print,
        route_contacts_print_mark, route_events_print, route_events_print_mark, route_tasks_print,
        route_tasks_print_mark,
    },
    share::{
        route_share_create, route_share_guest_invite, route_share_guest_revoke, route_share_invite,
        route_share_invite_revoke, route_share_revoke,
    },
    tasks::{
        route_task_delete, route_task_edit, route_task_update, route_tasks, route_tasks_create,
        route_tasks_new,
    },
    timezones::route_timezones,
    user::{route_get_home, route_post_timezone_save, route_root, route_user_named},
};
#[cfg(not(feature = "dev"))]
use assets::{Assets, EmbedService};
use rustical_api::api_router;

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub fn frontend_router<
    AP: AuthenticationProvider,
    CS: CalendarStore,
    AS: AddressbookStore + PrefixedCalendarStore,
>(
    prefix: &'static str,
    auth_provider: Arc<AP>,
    cal_store: Arc<CS>,
    addr_store: Arc<AS>,
    frontend_config: FrontendConfig,
    oidc_config: Option<OidcConfig>,
    sub_store: Option<Arc<dyn SubscriptionStore>>,
    source_store: Arc<dyn CalendarSourceStore>,
    subscriptions_public_url: String,
    invite_store: Arc<dyn InviteStore>,
    share_store: Arc<dyn CollectionShareStore>,
    password_reset_store: Arc<dyn PasswordResetStore>,
    print_store: Arc<dyn PrintStore>,
    // §18.42: the profile page's mirror UI context — `None` (no
    // `[mirror.targets]` configured) mounts no mirror block and no
    // sync button; the sync handler 404s like the password-reset
    // endpoints do when unconfigured.
    mirror: Option<Arc<MirrorUiContext>>,
    smtp_accounts: Vec<SmtpAccount>,
) -> Router {
    // Shared sliding-window limiter for the public password-reset POSTs
    // (per client IP plus a global bucket, like the registration flow).
    let reset_limiter = Arc::new(ResetRateLimiter::new());
    // Read once: `frontend_config` is moved into its own `Extension` a few
    // layers down, and this list is needed for a second one.
    let frontend_trusted_proxies = frontend_config.trusted_proxies.clone();
    // HawkBook download (the DAVx⁵ fork): read + hash the configured package
    // once HERE, at router construction, so the route's ETag, the sha256 the
    // profile intro prints and the file the route can serve are all derived
    // from one read — see `HawkBookApk::from_config`. `None` (unconfigured,
    // or unreadable) keeps the route a 404 and omits the intro sentence.
    let hawkbook_apk = HawkBookApk::from_config(frontend_config.hawkbook_apk.as_ref());
    // Holiday sets (create-calendar modal's "add holidays" dropdown): the
    // configured directory is read per request (import/refresh/list), so a
    // regenerated `holidays.toml` + `.ics` set is picked up without a restart.
    let holidays = HolidaysCatalog::from_config(frontend_config.holidays_dir.as_ref());

    let user_router = Router::new()
        .route("/", get(route_get_home))
        .route("/{user}", get(route_user_named::<AP, CS, AS>))
        // App token management
        .route("/{user}/app_token", post(route_post_app_token::<AP>))
        .route(
            // POST because HTML5 forms don't support DELETE method
            "/{user}/app_token/{id}/delete",
            post(route_delete_app_token::<AP>),
        )
        // Regenerate — rotate the secret of an existing token in place (the
        // "lost token" retrieval path; shown once, full access unchanged)
        .route(
            "/{user}/app_token/{id}/regenerate",
            post(route_regenerate_app_token::<AP, CS, AS>),
        )
        // Calendar
        .route("/{user}/calendar", get(route_calendars::<AP, CS, AS>))
        .route(
            "/{user}/calendar/credentials",
            post(route_calendar_credentials::<AP, CS, AS>),
        )
        .route(
            "/{user}/calendar/credentials/{id}/revoke",
            post(route_calendar_credentials_revoke),
        )
        .route(
            "/{user}/calendar/subscribe",
            post(route_calendar_subscribe::<AP, CS, AS>),
        )
        // §18.42: the calendar tile's "Sync now" button — runs the
        // configured push-mirror targets of one calendar on demand.
        .route(
            "/{user}/calendar/mirror-sync",
            post(route_post_mirror_sync::<AP, CS, AS>),
        )
        // §18.42: the per-user timezone save (the profile's Timezone
        // section).
        .route(
            "/{user}/timezone",
            post(route_post_timezone_save::<AP, CS, AS>),
        )
        .route("/{user}/calendar/{calendar}", get(route_calendar::<CS>))
        .route(
            "/{user}/calendar/{calendar}/restore",
            post(route_calendar_restore::<CS>),
        )
        // Calendar view (Omnical: Roundcube-style web grid)
        .route(
            "/{user}/calendar/{calendar}/events",
            get(route_calendar_events::<CS>).post(route_calendar_event_create::<CS>),
        )
        .route(
            "/{user}/calendar/{calendar}/events/new",
            get(route_calendar_events_new::<CS>),
        )
        .route(
            "/{user}/calendar/{calendar}/events/{object}/edit",
            get(route_event_edit::<CS>),
        )
        .route(
            "/{user}/calendar/{calendar}/events/{object}",
            post(route_event_update::<CS>),
        )
        .route(
            "/{user}/calendar/{calendar}/events/{object}/delete",
            post(route_event_delete::<CS>),
        )
        // Aggregate calendar view
        .route(
            "/{user}/events",
            get(route_events::<CS>).post(route_event_create::<CS>),
        )
        .route("/{user}/events/new", get(route_events_new::<CS>))
        // Tasks view
        .route(
            "/{user}/tasks",
            get(route_tasks::<CS>).post(route_tasks_create::<CS>),
        )
        .route("/{user}/tasks/new", get(route_tasks_new::<CS>))
        .route(
            "/{user}/calendar/{calendar}/tasks/{object}/edit",
            get(route_task_edit::<CS>),
        )
        .route(
            "/{user}/calendar/{calendar}/tasks/{object}",
            post(route_task_update::<CS>),
        )
        .route(
            "/{user}/calendar/{calendar}/tasks/{object}/delete",
            post(route_task_delete::<CS>),
        )
        // Contacts view (the contacts counterpart of the Tasks tab)
        .route(
            "/{user}/contacts",
            get(route_contacts::<AS>).post(route_contacts_create::<AS>),
        )
        .route("/{user}/contacts/new", get(route_contacts_new::<AS>))
        // Print pages (physical calendars — PLAN_NEXT_AGENT_PRINTING.md §2):
        // every tab that lists calendar or addressbook data can be printed
        // onto 8.5×11 paper or sticker sheets, `scope=new|all` filtered by the
        // print-state table, and every page POSTs back to itself to mark what
        // was printed. Mounted beside their tabs, same view gates.
        .route(
            "/{user}/events/print",
            get(route_events_print::<CS>).post(route_events_print_mark::<CS>),
        )
        .route(
            "/{user}/calendar/{calendar}/events/print",
            get(route_calendar_events_print::<CS>).post(route_calendar_events_print_mark),
        )
        .route(
            "/{user}/tasks/print",
            get(route_tasks_print::<CS>).post(route_tasks_print_mark::<CS>),
        )
        .route(
            "/{user}/contacts/print",
            get(route_contacts_print::<AS>).post(route_contacts_print_mark::<AS>),
        )
        .route(
            "/{user}/addressbook/{addressbook}/contacts/print",
            get(route_addressbook_contacts_print::<AS>).post(route_addressbook_contacts_print_mark),
        )
        // Addressbook
        .route("/{user}/addressbook", get(route_addressbooks::<AP, CS, AS>))
        .route(
            "/{user}/addressbook/credentials",
            post(route_addressbook_credentials::<AP, CS, AS>),
        )
        // §18.43: contacts import — a `.vcf` (vCard, the format every
        // contacts app can export) or a contacts CSV (Google's or
        // Outlook's export), posted as the raw file body by the
        // `import-contacts-form` Lit component. The verb sits on a
        // STATIC path segment next to `credentials` on purpose: the
        // book-object POST route
        // (`/{user}/addressbook/{addressbook}/contacts/{object}`) owns
        // the literal `contacts` at the position a
        // `…/{principal}/{addressbook_id}/import` shape would need
        // dynamic, and matchit prefers the static one — so an import
        // into the default `contacts` book would have answered the
        // contact-edit form's 415 instead of this handler.
        .route(
            "/{user}/addressbook/import/{principal}/{addressbook_id}",
            post(route_post_contacts_import::<AS>),
        )
        .route(
            "/{user}/addressbook/credentials/{id}/revoke",
            post(route_addressbook_credentials_revoke),
        )
        .route(
            "/{user}/addressbook/{addressbook}",
            get(route_addressbook::<AS>),
        )
        .route(
            "/{user}/addressbook/{addressbook}/contacts",
            get(route_addressbook_contacts::<AS>).post(route_addressbook_contacts_create::<AS>),
        )
        .route(
            "/{user}/addressbook/{addressbook}/contacts/new",
            get(route_addressbook_contacts_new::<AS>),
        )
        .route(
            "/{user}/addressbook/{addressbook}/contacts/{object}/edit",
            get(route_contact_edit::<AS>),
        )
        .route(
            "/{user}/addressbook/{addressbook}/contacts/{object}",
            post(route_contact_update::<AS>),
        )
        .route(
            "/{user}/addressbook/{addressbook}/contacts/{object}/delete",
            post(route_contact_delete::<AS>),
        )
        .route(
            "/{user}/addressbook/{addressbook}/restore",
            post(route_addressbook_restore::<AS>),
        )
        // Linked platforms (Omnical §17.8)
        .route(
            "/{user}/linked-platforms",
            get(route_get_linked_platforms::<AP, CS, AS>),
        )
        // Holiday import from the create-calendar modal's "add holidays"
        // dropdown (Omnical §17.8.3 semantics: a copy + refresh-by-UID).
        .route(
            "/{user}/calendar/{calendar_id}/holidays",
            post(route_post_holidays_add::<AP, CS, AS>),
        )
        .route(
            "/{user}/linked-platforms/add",
            post(route_post_linked_platforms_add::<AP, CS, AS>),
        )
        .route(
            "/{user}/linked-platforms/{id}/refresh",
            post(route_post_linked_platforms_refresh::<AP, CS, AS>),
        )
        .route(
            "/{user}/linked-platforms/{id}/remove",
            post(route_post_linked_platforms_remove),
        )
        // Share links (Omnical §17.7) — the Share tab is gone (§17.15); these
        // internal form actions render on / redirect to the Calendars and
        // Addressbooks tabs.
        .route(
            "/{user}/share/create",
            post(route_share_create::<AP, CS, AS>),
        )
        .route("/{user}/share/{id}/revoke", post(route_share_revoke))
        // Send invite (Omnical registration extension)
        .route(
            "/{user}/share/invite",
            post(route_share_invite::<AP, CS, AS>),
        )
        .route(
            "/{user}/share/invite/{code}/revoke",
            post(route_share_invite_revoke),
        )
        // Guest shares (Omnical §17.10)
        .route(
            "/{user}/share/guest-invite",
            post(route_share_guest_invite::<AP, CS, AS>),
        )
        .route(
            "/{user}/share/guest-invite/{id}/revoke",
            post(route_share_guest_revoke),
        )
        // Groups (Omnical §17.9)
        .route("/{user}/groups", get(route_groups::<AP, CS, AS>))
        .route("/{user}/groups/new", get(route_group_new))
        .route(
            "/{user}/groups/{group}",
            get(route_group_detail::<AP, CS, AS>),
        )
        .route(
            "/{user}/groups/{group}/members/{member}/privilege",
            post(route_group_member_privilege::<AP>),
        )
        .route(
            "/{user}/groups/{group}/members/{member}/remove",
            post(route_group_member_remove::<AP>),
        )
        // Forced password change (Omnical sharing: first-ever calendar/group
        // join until the password is rotated)
        .route(
            "/{user}/password",
            get(route_get_password_change).post(route_post_password_change::<AP>),
        )
        .layer(middleware::from_fn(unauthorized_handler))
        // Innermost-first mounting, so this one is applied outermost: it
        // short-circuits every portal page (except the password page itself)
        // to the change form while the user still must rotate their password.
        .layer(middleware::from_fn(password_change_gate));

    let router = Router::new()
        .route("/", get(route_root))
        .nest("/user", user_router)
        .nest(
            "/api/v1",
            api_router(auth_provider.clone(), cal_store.clone(), addr_store.clone()),
        )
        .route("/login", get(route_get_login).post(route_post_login::<AP>))
        .route("/logout", post(route_post_logout))
        // Public forgot-/reset-password flow (Omnical extension): mounted
        // next to /login; the emailed token is the only credential, the
        // handlers never read the session `user`.
        .route(
            "/forgot-password",
            get(route_get_forgot_password).post(route_post_forgot_password::<AP>),
        )
        .route(
            "/reset-password/{token}",
            get(route_get_reset_password).post(route_post_reset_password::<AP>),
        )
        .route(
            "/_timezones.json",
            get(route_timezones).head(route_timezones),
        )
        // The add-holidays dropdown's group/set list — public metadata in
        // the same trust class as the timezone list (names of holiday sets
        // staged on this deployment, nothing user-specific).
        .route("/_holidays.json", get(route_holidays_json))
        // HawkBook download: sibling of /login, not under /user — it is not
        // user-scoped state, it is this deployment's client package. Served
        // UNAUTHENTICATED by design (see `route_download_hawkbook`): the
        // phone that needs it cannot form-login to the portal, `wget`/`curl`
        // for the printed sha256 need a plain URL, and the package is a
        // build artifact, not user data. The URL is printed only inside the
        // authenticated intro, and a deploy-restart killing the profile
        // session must not take the download with it.
        .route("/download/hawkbook.apk", get(route_download_hawkbook));

    #[cfg(not(feature = "dev"))]
    let mut router = router.route_service("/assets/{*file}", EmbedService::<Assets>::default());
    #[cfg(feature = "dev")]
    let mut router = router.nest_service(
        "/assets",
        tower_http::services::ServeDir::new(concat!(env!("CARGO_MANIFEST_DIR"), "/public/assets")),
    );

    if let Some(oidc_config) = oidc_config.clone() {
        router = router.nest(
            "/login/oidc",
            oidc_router(
                oidc_config,
                OidcServiceConfig {
                    default_redirect_path: "/frontend/user",
                    session_key_user_id: "user",
                    callback_path: "/frontend/login/oidc/callback",
                },
                OidcUserStore(auth_provider.clone()),
            ),
        );
    }

    router = router
        .layer(AuthenticationLayer::new(auth_provider.clone()))
        .layer(Extension(auth_provider))
        .layer(Extension(cal_store))
        .layer(Extension(addr_store))
        .layer(Extension(frontend_config))
        .layer(Extension(oidc_config))
        .layer(Extension(sub_store))
        .layer(Extension(source_store))
        .layer(Extension(subscriptions_public_url))
        .layer(Extension(invite_store))
        .layer(Extension(share_store))
        .layer(Extension(password_reset_store))
        .layer(Extension(print_store))
        .layer(Extension(mirror))
        .layer(Extension(reset_limiter))
        .layer(Extension(frontend_trusted_proxies))
        .layer(Extension(hawkbook_apk))
        .layer(Extension(holidays))
        .layer(Extension(smtp_accounts));

    Router::new()
        .nest(prefix, router)
        .route("/", get(async || Redirect::to(prefix)))
}

async fn unauthorized_handler(mut request: Request, next: Next) -> Response {
    let meth = request.method().clone();
    let OriginalUri(uri) = request.extract_parts().await.unwrap();
    let resp = next.run(request).await;
    if resp.status() == StatusCode::UNAUTHORIZED {
        // This is a dumb hack since parsed Urls cannot be relative
        let mut login_url: Url = "http://github.com/frontend/login".parse().unwrap();
        if meth == Method::GET {
            login_url
                .query_pairs_mut()
                .append_pair("redirect_uri", uri.path());
        }
        let path = login_url.path();
        let query = login_url
            .query()
            .map(|query| format!("?{query}"))
            .unwrap_or_default();
        let login_url = format!("{path}{query}");
        let mut resp = Response::builder().status(StatusCode::UNAUTHORIZED);
        let hdrs = resp.headers_mut().unwrap();
        hdrs.typed_insert(ContentType::html());
        return resp
            .body(Body::new(format!(
                r#"<!Doctype html>
<html>
    <head>
        <meta http-equiv="refresh" content="1; url={login_url}" />
    </head>
    <body>
        Unauthorized, redirecting to <a href="{login_url}">login page</a>
    </body>
</html>"#,
            )))
            .unwrap();
    }
    resp
}
