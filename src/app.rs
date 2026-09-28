use crate::config::NextcloudLoginConfig;
use crate::export::export_router;
use crate::register::{RegistrationContext, register_router};
use crate::rsvp::rsvp_router;
use axum::Router;
use axum::body::{Body, HttpBody};
use axum::extract::{DefaultBodyLimit, Extension, Request};
use axum::middleware::Next;
use axum::response::{Redirect, Response};
use axum::routing::{any, options};
use axum_extra::TypedHeader;
use headers::{HeaderMapExt, UserAgent};
use http::header::CONNECTION;
use http::{HeaderValue, StatusCode};
use rustical_caldav::{CalDavConfig, caldav_router};
use rustical_carddav::carddav_router;
use rustical_dav_push::DavPushStore;
use rustical_frontend::nextcloud_login::nextcloud_login_router;
use rustical_frontend::{FrontendConfig, frontend_router};
use rustical_oidc::OidcConfig;
use rustical_scheduling::Scheduler;
use rustical_store::SubscriptionStore;
use rustical_store::Tenant;
use rustical_store::auth::AuthenticationProvider;
use rustical_store::{
    AddressbookStore, CalendarSourceStore, CalendarStore, CombinedCalendarStore,
    PrefixedCalendarStore,
};
use std::sync::Arc;
use std::time::Duration;
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::classify::ServerErrorsFailureClass;
use tower_http::trace::TraceLayer;
use tower_sessions::cookie::SameSite;
use tower_sessions::{Expiry, MemoryStore, SessionManagerLayer};
use tracing::Span;
use tracing::field::display;

/// The decisions `make_app` makes about **which** routers to mount.
///
/// This exists because the two halves of building a server are different kinds
/// of work and get confused for it. Deciding is a function of configuration;
/// mounting is a function of the stores. Per-tenant config overrides (§6.3)
/// need those to be separable, because *one* `make_app_for` has to serve N
/// tenants that disagree about decisions while sharing the shape of the
/// mounting — a single `Config` → `Router` function cannot express that, since
/// every tenant would overwrite the last.
///
/// It is deliberately **not** `crate::config::Config`. The integration suite
/// builds a partial configuration by hand — no `[data_store]`, no `[tracing]`,
/// no `[maintenance]` — and §6.1's gate is that the refactor passes the 98-test
/// baseline with **zero test edits**. Bundling to `Config` would force every
/// test to construct a whole one, which is a test edit by another name.
#[derive(Clone)]
pub struct AppConfig {
    pub frontend: FrontendConfig,
    pub oidc: Option<OidcConfig>,
    pub caldav: CalDavConfig,
    /// `None` disables scheduling entirely; `Some` with `rsvp_links_enabled()`
    /// false still disables the public RSVP router but keeps the scheduler.
    pub scheduler: Option<Arc<Scheduler>>,
    pub subscriptions: Option<Arc<dyn SubscriptionStore>>,
    pub registration: Option<Arc<RegistrationContext>>,
    pub nextcloud_login: NextcloudLoginConfig,
    pub dav_push_enabled: bool,
    pub session_cookie_samesite_strict: bool,
    pub payload_limit_mb: usize,
    /// `[subscriptions] public_url` with the HTTP-bind fallback already applied.
    pub subscriptions_public_url: String,
    pub smtp_accounts: Vec<rustical_scheduling::SmtpAccount>,
}

/// The stores a router is mounted over.
///
/// Split from [`AppConfig`] for the same reason: the stores are per-tenant and
/// the decisions are per-tenant, but they are not the same axis, and §6.2's
/// construction path needs to hand one `AppConfig` to a router built over a
/// different `AppStores` per tenant without either knowing about the other.
pub struct AppStores<AS, CS, DP, AP> {
    pub addr_store: Arc<AS>,
    pub cal_store: Arc<CS>,
    pub dav_push_store: Arc<DP>,
    /// **Sized, not `Arc<dyn AuthenticationProvider>`.** The DAV and frontend
    /// routers are generic over a concrete `AP` (`caldav_router<AP: …>`,
    /// `frontend_router<AP: …>`), so erasing the provider to a trait object here
    /// would not compile. The stores that *are* already trait objects upstream
    /// — `source_store`, `invite_store`, `share_store`, `password_reset_store` —
    /// stay erased, because that is how the callers already hold them.
    pub auth_provider: Arc<AP>,
    pub source_store: Arc<dyn CalendarSourceStore>,
    pub invite_store: Arc<dyn rustical_store::InviteStore>,
    pub share_store: Arc<dyn rustical_store::CollectionShareStore>,
    pub password_reset_store: Arc<dyn rustical_store::PasswordResetStore>,
}

/// Hand the tenant to every handler in `router`, as an `Extension`.
///
/// This is what makes the tenant parameter useful rather than decorative.
/// Exactly one thing consumes it today, and that consumer is the point: the
/// `export_`, `rsvp_` and `register_` routers are mounted **outside** the
/// `AuthenticationLayer` (§6.4) and resolve ownership from a *token* rather than
/// a principal, which makes them the only three routes where a tenant check can
/// be silently absent. Rows 26-28 are what enforce it; this is what they assert
/// against.
///
/// **Call it last.** axum's `Router::layer` wraps only the routes registered
/// before the call, so an extension installed before the DAV routers or the
/// public token routers would leave them without it — and a missing extension is
/// a `500` in a handler that expected one, which is exactly the kind of failure
/// that only appears under a second tenant.
pub fn with_tenant(router: Router, tenant: Tenant) -> Router {
    router.layer(Extension(tenant))
}

/// The single-tenant entry point, and the **unchanged** public signature of
/// this module since before the tenancy work.
///
/// Its argument list is long and positional because two callers depend on it —
/// `cmd_serve` in `lib.rs` and `get_app` in the integration suite — and §6.1's
/// gate is that the 98-test baseline passes with zero test edits. It is kept
/// exactly as it was for that reason and no other: it is a compatibility shim
/// over [`make_app_for`], and the moment both callers are on the bundle it can
/// go.
#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::cognitive_complexity,
    clippy::missing_panics_doc
)]
pub fn make_app<
    AS: AddressbookStore + PrefixedCalendarStore,
    CS: CalendarStore,
    DP: DavPushStore,
>(
    addr_store: Arc<AS>,
    cal_store: Arc<CS>,
    dav_push_store: Arc<DP>,
    auth_provider: Arc<impl AuthenticationProvider>,
    frontend_config: FrontendConfig,
    oidc_config: Option<OidcConfig>,
    caldav_config: CalDavConfig,
    scheduler: Option<Arc<Scheduler>>,
    subscriptions: Option<Arc<dyn SubscriptionStore>>,
    registration: Option<Arc<RegistrationContext>>,
    nextcloud_login_config: &NextcloudLoginConfig,
    dav_push_enabled: bool,
    session_cookie_samesite_strict: bool,
    payload_limit_mb: usize,
    source_store: Arc<dyn CalendarSourceStore>,
    subscriptions_public_url: String,
    invite_store: Arc<dyn rustical_store::InviteStore>,
    share_store: Arc<dyn rustical_store::CollectionShareStore>,
    password_reset_store: Arc<dyn rustical_store::PasswordResetStore>,
    smtp_accounts: Vec<rustical_scheduling::SmtpAccount>,
) -> Router<()> {
    make_app_for(
        // `None` is the N=1 case and must stay indistinguishable from today:
        // §3.6 requires `enabled = false` to produce the same router, and the
        // 98-test baseline is the proof. No dispatch layer, no tenant extension,
        // nothing a handler can observe.
        None,
        AppConfig {
            frontend: frontend_config,
            oidc: oidc_config,
            caldav: caldav_config,
            scheduler,
            subscriptions,
            registration,
            nextcloud_login: nextcloud_login_config.clone(),
            dav_push_enabled,
            session_cookie_samesite_strict,
            payload_limit_mb,
            subscriptions_public_url,
            smtp_accounts,
        },
        AppStores {
            addr_store,
            cal_store,
            dav_push_store,
            auth_provider,
            source_store,
            invite_store,
            share_store,
            password_reset_store,
        },
    )
}

/// Mount one server. Pure construction: every "should this router exist"
/// decision was made by the caller and arrived in [`AppConfig`], so there is
/// nothing left here to interpret.
///
/// The body below is `make_app`'s body as it stood before §6.1, moved here
/// unchanged — same routes, same order of merges, same layers. That verbatim
/// move is the whole claim of this refactor and the only thing its gate checks,
/// which is why the one pre-existing `redundant clone` down there is still there
/// and is not being fixed: removing it would edit the body this commit promises
/// not to have touched.
#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::cognitive_complexity,
    clippy::missing_panics_doc
)]
pub fn make_app_for<AS, CS, DP, AP>(
    tenant: Option<Tenant>,
    config: AppConfig,
    stores: AppStores<AS, CS, DP, AP>,
) -> Router<()>
where
    AS: AddressbookStore + PrefixedCalendarStore,
    CS: CalendarStore,
    DP: DavPushStore,
    AP: AuthenticationProvider,
{
    let AppConfig {
        frontend: frontend_config,
        oidc: oidc_config,
        caldav: caldav_config,
        scheduler,
        subscriptions,
        registration,
        nextcloud_login: nextcloud_login_config,
        dav_push_enabled,
        session_cookie_samesite_strict,
        payload_limit_mb,
        subscriptions_public_url,
        smtp_accounts,
    } = config;
    let AppStores {
        addr_store,
        cal_store,
        dav_push_store,
        auth_provider,
        source_store,
        invite_store,
        share_store,
        password_reset_store,
    } = stores;

    let birthday_store = addr_store.clone();
    let combined_cal_store =
        Arc::new(CombinedCalendarStore::new(cal_store.clone()).with_store(birthday_store));

    let caldav_config = Arc::new(caldav_config);

    let mut router = Router::new()
        // endpoint to be used by healthcheck to see if rustical is online
        .route("/ping", axum::routing::get(async || "Pong!"))
        .merge(caldav_router(
            "/caldav",
            auth_provider.clone(),
            combined_cal_store.clone(),
            dav_push_store.clone(),
            false,
            caldav_config.clone(),
            scheduler.clone(),
        ))
        .merge(caldav_router(
            "/caldav-compat",
            auth_provider.clone(),
            combined_cal_store.clone(),
            dav_push_store.clone(),
            true,
            caldav_config,
            scheduler.clone(),
        ))
        .route(
            "/.well-known/caldav",
            any(async |TypedHeader(ua): TypedHeader<UserAgent>| {
                // This would be a use case for Aho Corasick :)
                // For user agents see https://github.com/lennart-k/rustical/issues/180
                if ua.as_str().contains("accountsd")
                    || ua.as_str().contains("remindd")
                    || ua.as_str().contains("dataaccessd")
                {
                    // remindd is an Apple Calendar User Agent
                    // Even when explicitly configuring a principal URL in Apple Calendar Apple
                    // will not respect that configuration but call /.well-known/caldav,
                    // so sadly we have to do this user-agent filtering. :(
                    // (I should have never gotten an Apple device)
                    return Redirect::permanent("/caldav-compat");
                }
                Redirect::permanent("/caldav")
            }),
        )
        .merge(carddav_router(
            "/carddav",
            auth_provider.clone(),
            addr_store.clone(),
            dav_push_store.clone(),
        ));

    // GNOME Accounts needs to discover a WebDAV Files endpoint to complete the setup
    // It looks at / as well as /remote.php/dav (Nextcloud)
    // This is not nice but we offer this as a sacrificial route to ensure the CalDAV/CardDAV setup
    // works.
    // See:
    // https://github.com/GNOME/gnome-online-accounts/blob/master/src/goabackend/goadavclient.c
    // https://github.com/GNOME/gnome-online-accounts/blob/master/src/goabackend/goawebdavprovider.c
    router = router.route(
        "/remote.php/dav",
        options(async || {
            let mut resp = Response::builder().status(StatusCode::OK);
            resp.headers_mut()
                .expect("this always works")
                .insert("DAV", HeaderValue::from_static("1"));
            resp.body(Body::empty()).expect("empty body always works")
        }),
    );

    let session_store = MemoryStore::default();

    // Omnical share-links extension (§17.7): public token export URLs, mounted
    // OUTSIDE the DAV `AuthenticationLayer` — the token in the URL is the
    // only credential. Merging before the frontend block keeps
    // `combined_cal_store` available; the combined store preserves
    // owner-export parity and keeps `_birthdays_*` collections feed-capable.
    if let Some(sub_store) = subscriptions.clone() {
        router = router.merge(export_router(
            addr_store.clone(),
            combined_cal_store.clone(),
            sub_store,
        ));
    }

    // Omnical RSVP-links extension (PLAN_SHARING.md §9 item 3): public
    // one-click response page for the tokens carried in iMIP invitation
    // emails. Like the export router it mounts OUTSIDE the DAV
    // `AuthenticationLayer` (the token is the only credential) and only
    // exists while fully configured, so a disabled config has zero
    // public footprint. `scheduler` was cloned into the second
    // caldav_router above, so it is still available here.
    if let Some(sched) = scheduler.as_ref().filter(|s| s.rsvp_links_enabled()) {
        router = router.merge(rsvp_router(sched.clone()));
    }

    // Omnical registration extension (§17.8): public invite-gated
    // self-service registration, mounted OUTSIDE the DAV `AuthenticationLayer`
    // like the export router. Only present while `[registration] enabled`, so
    // a disabled config has zero registration footprint.
    if let Some(registration) = registration {
        let auth: Arc<dyn AuthenticationProvider> = auth_provider.clone();
        router = router.merge(register_router(
            addr_store.clone(),
            combined_cal_store.clone(),
            auth,
            registration,
        ));
    }

    if frontend_config.enabled {
        router = router.merge(frontend_router(
            "/frontend",
            auth_provider.clone(),
            cal_store,
            addr_store,
            frontend_config,
            oidc_config,
            subscriptions.clone(),
            source_store,
            subscriptions_public_url,
            invite_store,
            share_store,
            password_reset_store,
            smtp_accounts,
        ));
    }

    if nextcloud_login_config.enabled {
        router = router.nest("/index.php/login/v2", nextcloud_login_router(auth_provider));
    }

    if dav_push_enabled {
        router = router.merge(rustical_dav_push::subscription_service(dav_push_store));
    }

    // Every span this router creates is attributable to its tenant. Under
    // tenancy the process is shared, so without this a log line cannot be
    // answered with "whose calendar is erroring" — which is the question §7.4's
    // OTel work exists to make answerable.
    //
    // `Arc<str>`, not `String`: the `TraceLayer` closures are `'static`, so the
    // label has to be *owned* by them, and a `String` would mean an allocation
    // per request. Cloning an `Arc` is a refcount bump.
    //
    // Taken *before* the tenant is moved into the extension below.
    let tenant_label: Option<Arc<str>> = tenant.as_ref().map(|t| Arc::from(t.slug.as_str()));

    // MUST be the last thing applied to `router`: axum's `Router::layer` covers
    // only the routes registered *before* it, so an extension installed any
    // earlier would miss the DAV routers and the three public token routers.
    // See `with_tenant`.
    router = match tenant {
        Some(tenant) => with_tenant(router, tenant),
        None => router,
    };

    router
        .layer(
            SessionManagerLayer::new(session_store)
                .with_name("rustical_session")
                .with_secure(true)
                .with_same_site(if session_cookie_samesite_strict {
                    SameSite::Strict
                } else {
                    SameSite::Lax
                })
                .with_expiry(Expiry::OnInactivity(
                    tower_sessions::cookie::time::Duration::hours(2),
                )),
        )
        .layer(CatchPanicLayer::new())
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(|request: &Request| {
                    tracing::info_span!(
                        "http-request",
                        status = tracing::field::Empty,
                        otel.name = tracing::field::display(format!(
                            "{} {}",
                            request.method(),
                            request.uri()
                        )),
                        ua = tracing::field::Empty,
                        // `Empty` in a single-tenant install: the field is
                        // absent rather than empty, so a filter on it cannot
                        // accidentally match the N=1 case.
                        tenant = tracing::field::Empty,
                    )
                })
                .on_request(move |req: &Request, span: &Span| {
                    span.record("method", display(req.method()));
                    span.record("path", display(req.uri()));
                    if let Some(label) = &tenant_label {
                        span.record("tenant", display(label.as_ref()));
                    }
                    if let Some(ua) = req.headers().typed_get::<UserAgent>() {
                        span.record("ua", display(ua));
                    }
                })
                .on_response(|response: &Response, _latency: Duration, span: &Span| {
                    span.record("status", display(response.status()));
                    if response.status().is_server_error() {
                        tracing::error!("server error");
                    } else if response.status().is_client_error() {
                        match response.status() {
                            StatusCode::UNAUTHORIZED => {
                                // The iOS client always tries an unauthenticated request first so
                                // logging 401's as errors would clog up our logs
                                tracing::debug!("unauthorized");
                            }
                            StatusCode::NOT_FOUND
                            | StatusCode::PRECONDITION_FAILED
                            | StatusCode::CONFLICT => {
                                // Clients like GNOME Calendar will try to reach /remote.php/webdav
                                // quite often clogging up the logs
                                tracing::info!("client error");
                            }
                            _ => {
                                tracing::error!("client error");
                            }
                        }
                    }
                })
                .on_failure(
                    |_error: ServerErrorsFailureClass, _latency: Duration, _span: &Span| {
                        tracing::error!("something went wrong");
                    },
                ),
        )
        .layer(axum::middleware::from_fn(
            async |req: Request, next: Next| {
                // Closes the connection if the request body might've not been fully consumed
                // Otherwise subsequent requests reusing the connection might fail.
                // See https://github.com/lennart-k/rustical/issues/77
                let body_empty = req.body().is_end_stream();
                let mut response = next.run(req).await;
                if !body_empty
                    && (response.status().is_server_error() || response.status().is_client_error())
                {
                    response
                        .headers_mut()
                        .insert(CONNECTION, HeaderValue::from_static("close"));
                }
                response
            },
        ))
        .layer(DefaultBodyLimit::max(payload_limit_mb * 1000 * 1000))
}
