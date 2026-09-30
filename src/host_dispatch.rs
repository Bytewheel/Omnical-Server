//! `Host` → tenant → `Router`. The new chokepoint — `PLAN_DEPLOYMENTS.md` §3.3.
//!
//! ## What this file decides, and in what order
//!
//! One request, five steps, in this order (§3.3):
//!
//! 1. read the `Host` header (or HTTP/2's `:authority`), strip the port, lowercase;
//! 2. resolve it to an **active** tenant — exact host claim, then
//!    `{slug}.{base_domain}`, then the whole host as a slug, then
//!    `default_tenant`;
//! 3. return a clone of that tenant's `Arc<Router>`;
//! 4. build the tenant's stores and router **only on a cache miss**;
//! 5. hand the request to it.
//!
//! ## Step 2's order is not arbitrary, and neither is its failure mode
//!
//! An exact host claim wins because it is the only one an operator sets
//! deliberately. `{slug}.{base_domain}` is derived, so it is tried second —
//! before the bare-slug match — because a tenant with an explicit claim for
//! `acme.t3.gg` must not be shadowed by a *different* tenant whose slug happens
//! to be `acme`. The bare-slug match is host-per-tenant, the shape `acme.t3.gg`
//! takes when there is no `base_domain` at all.
//!
//! `default_tenant` is last, and last matters: it is the N=1 escape hatch for an
//! appliance where the `Host` is whatever the LAN called the box. If it were
//! first, a typo in one tenant's DNS would silently serve that tenant's data to
//! everyone.
//!
//! **An unknown host, a suspended tenant, and a claimed-but-suspended host all
//! produce the same `404` with the same body.** Not for tidiness: three distinct
//! bodies would let anyone enumerate which hostnames are claimed, which tenants
//! exist, and which have been suspended, by comparing response bodies. §3.4
//! keeps the control plane free of other tenants' data for the same reason.
//!
//! ## The one thing this must never do
//!
//! Resolve a tenant **from the cache**. The cache is reached only after the
//! control plane has returned an active [`TenantId`]. See
//! [`crate::store_bundle`] for why, and for what it buys.
//!
//! ## `Host` is the *raw* header, and that is a known limitation
//!
//! The `Host` read here is not `X-Forwarded-Host`, and behind a reverse proxy
//! that rewrites it this service would resolve the wrong tenant. That is C5 /
//! §7.3.4's job, along with the `trusted_proxies` list — neither of which is in
//! this tree, deliberately (see `TenancyConfig`'s docs). For the direct
//! connections an appliance and a LAN self-host make, the raw header is exactly
//! right, which is why §3.6's "MUST be set for hosted" is about the hosted
//! commit and not this one.

use axum::Router;
use axum::http::{StatusCode, header::HOST};
use axum::response::IntoResponse;
use futures_util::future::BoxFuture;
use rustical_store::tenant::Tenant;
use rustical_store::tenant_store::TenantStore;
use rustical_store_sqlite::SqliteTenantStore;
use std::boxed::Box;
use std::sync::Arc;
use std::task::{Context, Poll};
use tower::Service;
use tracing::{debug, info, warn};

use crate::config::TenancyConfig;
use crate::store_bundle::{CachedTenant, StoreBundle, StoreBundleCache};

/// The request and response types this service speaks.
///
/// Spelled once because a bare `Response` does not compile in
/// `tower::Service` position on `http` 1.x: it needs its body type, and there
/// are three signatures to keep in step.
type HttpRequest = axum::http::Request<axum::body::Body>;
type HttpResponse = axum::http::Response<axum::body::Body>;

/// A health endpoint that runs **before** tenant resolution — and only in
/// tenancy mode.
///
/// The asymmetry is the point. With tenancy off, `/ping` already answers for
/// every host — §3.6's requirement — so a health check has something to hit and
/// adding a second unauthenticated route would only widen the default
/// single-tenant surface. With tenancy on, `/ping` becomes tenant-scoped and no
/// longer answers on the instance's own address, which is what makes the extra
/// path necessary rather than nice to have.
///
/// This exists because of a bug the end-to-end test found, and the shape of the
/// problem is worth recording: with tenancy on, a load balancer that health
/// checks `GET /ping` on the instance's own address gets a **404**, because that
/// address (`10.0.3.17:8080`, say) is not a tenant's host and there is no
/// `default_tenant` on a hosted deployment. The instance looks unhealthy, the LB
/// takes it out of rotation, and every tenant goes down — the health check is
/// what caused the outage it was meant to detect.
///
/// So the health answer is "is this process serving?", which is a question about
/// the process and not about any tenant. It is answered here, ahead of
/// [`HostDispatch`], and it deliberately does **not** consult the control plane:
/// a control-plane outage should not mark every instance unhealthy and cause the
/// thundering herd that a dependency-aware health check provokes.
///
/// `/ping` is untouched and remains a real application route, so it is
/// tenant-scoped like everything else.
pub const HEALTH_PATH: &str = "/healthz";

/// Readiness, which answers a different question and is a different endpoint.
///
/// §7.4: *"Add `/readyz` that checks the control plane + the tenant pool, so the
/// LB does not route to a process that cannot serve."* See
/// [`crate::readiness`] for why the two must not be merged, and for what this one
/// deliberately does not check.
pub const READY_PATH: &str = "/readyz";

/// The AGPL §13 source offer (§10.1, item 19).
///
/// Unauthenticated, on every host, and mounted ahead of tenant resolution. The
/// obligation is to *every user interacting with a modified version over a
/// network*, so gating it behind an account would defeat it.
pub const SOURCE_PATH: &str = "/frontend/source";

/// The liveness router. Deliberately a separate `Router` rather than a special
/// case inside the dispatch loop, so it cannot be reached by a path that
/// dispatch also handles and the two can never disagree about which is which.
fn health_router() -> Router {
    Router::new().route(
        HEALTH_PATH,
        axum::routing::get(|| async {
            (
                StatusCode::OK,
                [(
                    axum::http::header::CONTENT_TYPE,
                    "text/plain; charset=utf-8",
                )],
                "ok",
            )
        }),
    )
}

/// The response body for every "no tenant" outcome.
///
/// One constant for all three cases on purpose — see this module's docs. It
/// names no tenant, no host, and no setting, because each of those is
/// information a prober should not get.
const NO_TENANT_BODY: &str = "Not found. This server hosts several organisations; \
                               address it by your own subdomain.";

/// What a tenant's stores and router are built from.
///
/// A closure rather than a hard-coded call so this module does not care whether
/// a tenant is built from the global config or from a config with §3.6's
/// overrides merged in — that merge is item 10, and it belongs behind this
/// argument rather than inside the dispatch loop.
pub type TenantBuilder = Arc<
    dyn Fn(
            Tenant,
        ) -> BoxFuture<
            'static,
            Result<
                (
                    StoreBundle<rustical_store_sqlite::SqlitePrincipalStore>,
                    Router,
                ),
                String,
            >,
        > + Send
        + Sync,
>;

/// Resolves a `Host` header to a tenant and serves that tenant's router.
pub struct HostDispatch {
    control_plane: SqliteTenantStore,
    cache: Arc<StoreBundleCache>,
    builder: TenantBuilder,
    config: TenancyConfig,
}

impl HostDispatch {
    /// A dispatcher over an open control plane.
    ///
    /// Takes the control plane by value rather than by trait object: the whole
    /// point of the split is that the control plane is a *small, separate* store,
    /// so there is no second implementation to erase for. That will change when
    /// hosted moves it to Postgres (§7 wave 3), and this is the line that moves
    /// with it.
    #[must_use]
    pub fn new(
        control_plane: SqliteTenantStore,
        cache: Arc<StoreBundleCache>,
        builder: TenantBuilder,
        config: TenancyConfig,
    ) -> Self {
        Self {
            control_plane,
            cache,
            builder,
            config,
        }
    }

    /// The cache, for the admin view and for tests.
    #[must_use]
    pub const fn cache(&self) -> &Arc<StoreBundleCache> {
        &self.cache
    }

    /// §3.3 step 1: the request's host, normalised.
    ///
    /// Prefers the `Host` header and falls back to the URI authority, because
    /// HTTP/2 carries the authority in `:authority` and some proxies drop the
    /// header. A host with a port is stripped — `:8443` is not part of a
    /// hostname, and `acme.test:8443` would otherwise never match the stored
    /// `acme.test`.
    ///
    /// Returns `None` when the request names no host at all, which is HTTP/1.0
    /// without `Host` and a protocol violation rather than a tenant question.
    #[must_use]
    pub fn request_host(request: &HttpRequest) -> Option<String> {
        let raw = request
            .headers()
            .get(HOST)
            .and_then(|v| v.to_str().ok())
            .or_else(|| {
                request
                    .uri()
                    .authority()
                    .map(axum::http::uri::Authority::as_str)
            })?;
        Some(normalise_host(raw))
    }

    /// §3.3 step 2: resolve a normalised host to an **active** tenant.
    ///
    /// Every branch filters on `status = 'active'` inside SQL (see
    /// `TenantStore`), so a suspended tenant returns `None` at every step and
    /// cannot be reached by a later, more permissive rule.
    /// Which §3.3 match rule fired, or `None` for "no active tenant".
    ///
    /// Returned rather than logged-and-forgotten because the rule is the first
    /// thing anyone debugging a misrouted host wants, and a `debug!` line only
    /// says `resolved`.
    async fn resolve(&self, host: &str) -> Result<Option<(Tenant, &'static str)>, String> {
        // 1. An explicit claim, which is the only one an operator set on purpose.
        if let Some(tenant) = self
            .control_plane
            .get_tenant_by_host(host)
            .await
            .map_err(|e| format!("control plane lookup by host failed: {e}"))?
        {
            debug!(host, tenant = %tenant.slug, "resolved by explicit host claim");
            return Ok(Some((tenant, "explicit-host")));
        }

        // **A claimed host is owned.** If the host has a claim but no *active*
        // tenant behind it, the answer is `None` — full stop — rather than
        // "keep matching".
        //
        // This is the fix for a real bug, and the test that found it is
        // `a_suspended_tenant_is_not_papered_over_by_the_default_tenant`: with a
        // host claim and a `default_tenant` both configured, a suspended
        // tenant's hostname failed the active-only lookup above and then fell
        // through to `default_tenant`, which served **the default tenant's data
        // under the suspended tenant's URL**. One customer seeing another
        // customer's calendar is a worse failure than a 404, and it is exactly
        // what §3.3's "removed from the map" is supposed to prevent.
        if self
            .control_plane
            .is_host_claimed(host)
            .await
            .map_err(|e| format!("control plane host-claim check failed: {e}"))?
        {
            debug!(host, "host is claimed by a tenant that is not active");
            return Ok(None);
        }

        // 2. `{slug}.{base_domain}`. Tried before the bare-slug rule so an
        //    explicitly-claimed host is never shadowed by a same-named tenant.
        let base = self.config.base_domain.trim().trim_end_matches('.');
        if !base.is_empty()
            && let Some(slug) = host
                .strip_suffix(base)
                .and_then(|prefix| prefix.strip_suffix('.'))
                .filter(|slug| !slug.is_empty() && !slug.contains('.'))
        {
            if let Some(tenant) = self
                .control_plane
                .get_tenant_by_slug(slug)
                .await
                .map_err(|e| format!("control plane lookup by slug failed: {e}"))?
            {
                debug!(host, tenant = %tenant.slug, "resolved by base_domain");
                return Ok(Some((tenant, "base-domain")));
            }
            // The same fall-through hazard as above, one rule later: if that
            // slug exists but is suspended, stop rather than trying `default_tenant`.
            if self
                .control_plane
                .get_any_tenant_by_slug(slug)
                .await
                .map_err(|e| format!("control plane lookup by slug failed: {e}"))?
                .is_some()
            {
                debug!(host, slug, "slug exists but is not active");
                return Ok(None);
            }
        }

        // 3. Host-per-tenant: the whole host is the slug (`acme.t3.gg`).
        if let Ok(slug) = host.parse::<rustical_store::TenantId>() {
            if let Some(tenant) = self
                .control_plane
                .get_tenant_by_slug(slug.as_str())
                .await
                .map_err(|e| format!("control plane lookup by slug failed: {e}"))?
            {
                debug!(host, tenant = %tenant.slug, "resolved by host-as-slug");
                return Ok(Some((tenant, "host-as-slug")));
            }
            if self
                .control_plane
                .get_any_tenant_by_slug(slug.as_str())
                .await
                .map_err(|e| format!("control plane lookup by slug failed: {e}"))?
                .is_some()
            {
                debug!(
                    host,
                    slug = slug.as_str(),
                    "host is a suspended tenant's slug"
                );
                return Ok(None);
            }
        }

        // 4. The N=1 escape hatch, last, so a DNS typo can never be papered over
        //    by the default tenant.
        let default = self.config.default_tenant.trim();
        if !default.is_empty() {
            if let Some(tenant) = self
                .control_plane
                .get_tenant_by_slug(default)
                .await
                .map_err(|e| format!("control plane lookup of default_tenant failed: {e}"))?
            {
                debug!(host, tenant = %tenant.slug, "resolved by default_tenant");
                return Ok(Some((tenant, "default-tenant")));
            }
            // A *suspended* default tenant is an operator error, and the useful
            // behaviour is a 404 for every request plus a loud log — not a
            // server that answers nobody and looks merely idle.
            if self
                .control_plane
                .get_any_tenant_by_slug(default)
                .await
                .map_err(|e| format!("control plane lookup of default_tenant failed: {e}"))?
                .is_some()
            {
                warn!(
                    default_tenant = default,
                    "default_tenant is suspended; every request will 404 until it is resumed"
                );
            }
        }

        Ok(None)
    }

    /// The router for a tenant, from the cache or by building it.
    async fn router_for(&self, tenant: &Tenant) -> Result<Arc<Router>, String> {
        if let Some(router) = self.cache.get(&tenant.id) {
            debug!(tenant = %tenant.slug, "cache hit");
            return Ok(router);
        }
        debug!(tenant = %tenant.slug, "cache miss, building");
        let (bundle, router) = (self.builder)(tenant.clone()).await?;
        // A cold start with N tenants does N constructions. That is the
        // documented behaviour of the cache (§3.5) and is why this is `info!`
        // rather than `debug!`: an operator watching a slow first request needs
        // to see why.
        info!(tenant = %tenant.slug, "built tenant router");

        // The bundle is moved into an `Arc` **only** so the cache can hold a
        // `Weak` to it; the stores stay alive through the router's own `Arc`s.
        // A strong reference here would mean evicting a tenant from the LRU
        // failed to release its pools, and §7.2's memory bound would be a
        // fiction.
        let bundle = Arc::new(bundle);
        let router = Arc::new(router);
        if let Some(evicted) = self.cache.insert(
            tenant.id.clone(),
            CachedTenant {
                bundle: Arc::downgrade(&bundle),
                router: Arc::clone(&router),
            },
        ) {
            // Dropping the evicted entry is what closes that tenant's pool once
            // its last in-flight request finishes. See `StoreBundleCache::insert`
            // for why `LruCache::put` would have leaked it.
            debug!("evicted one cached tenant to make room");
            drop(evicted);
        }
        // The bundle's own `Arc` dies here; from now on the router holds the
        // stores. That is the intended ownership, and `CachedTenant::bundle_is_gone`
        // is the observable form of it.
        Ok(router)
    }

    /// Handle one request.
    /// Handle one request: resolve, then serve.
    ///
    /// Public because [`TenancyAwareApp`] and the tests both need to reach it,
    /// and it takes `self: Arc<Self>` so the future it returns is `'static`.
    /// [`TenancyAwareApp`] is what a caller should normally hold.
    pub async fn handle(self: Arc<Self>, request: HttpRequest) -> HttpResponse {
        let Some(host) = Self::request_host(&request) else {
            warn!("request arrived with no Host header or URI authority");
            return not_found();
        };

        let tenant = match self.resolve(&host).await {
            Ok(Some((tenant, rule))) => {
                // `let _ =` deliberately: these are side-effecting span
                // recorders that warn on their own if no span declared the
                // fields, and a `must_use` on the return would only add a second
                // way to be ignored.
                let _ = crate::tenant_telemetry::tag_dispatch(rule);
                let _ = crate::tenant_telemetry::tag_span(&tenant);
                tenant
            }
            Ok(None) => {
                // Unknown host, suspended tenant, and unclaimed host all land
                // here identically — deliberately.
                debug!(host, "no active tenant for this host");
                return not_found();
            }
            Err(e) => {
                // A control-plane failure is *our* fault, not the client's, so
                // this is a 500 and it says so. Swallowing it into the shared
                // 404 would turn a database outage into "your tenant does not
                // exist", which is both a lie and impossible to debug.
                error_500(&e);
                return server_error();
            }
        };

        let router = match self.router_for(&tenant).await {
            Ok(router) => router,
            Err(e) => {
                error_500(&e);
                return server_error();
            }
        };

        // `Service::call` takes `&mut self`, and an `Arc` cannot hand out a
        // mutable reference to what it points at — so the `Router` itself is
        // cloned, not the `Arc`. That is still the cheap pointer copy §3.3
        // step 3 promises: an axum `Router` is Arc-backed internally, so
        // cloning one bumps a refcount and shares every route. It is *not* a
        // deep copy of the routing table.
        let mut inner = (*router).clone();
        inner.call(request).await.unwrap_or_else(|e| {
            // `Router`'s error type is `Infallible`, so this arm is unreachable
            // in practice. It exists because "unreachable" should still produce
            // a response rather than a panic inside a serve loop.
            error_500(&format!("the tenant router returned an error: {e}"));
            server_error()
        })
    }
}

/// The one body every "no tenant" outcome returns.
fn not_found() -> HttpResponse {
    (
        StatusCode::NOT_FOUND,
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; charset=utf-8",
        )],
        NO_TENANT_BODY,
    )
        .into_response()
}

/// A 500 for a failure that is ours, not the client's.
///
/// The detail goes to the log and the body says nothing: a control-plane error
/// string can contain a database path, and this is a public-facing body. Called
/// as `server_error()` because [`error_500`] has already logged the detail by
/// the time a response is built — keeping the two in step at every call site is
/// the point, so the signature takes nothing.
fn server_error() -> HttpResponse {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; charset=utf-8",
        )],
        "Internal server error.",
    )
        .into_response()
}

fn error_500(detail: &str) {
    tracing::error!(error = %detail, "tenant dispatch failed");
}

/// Lowercase, strip the port, strip a trailing dot.
///
/// Exposed for tests and for any future caller that has a host in hand.
#[must_use]
pub fn normalise_host(raw: &str) -> String {
    let host = raw.trim();
    // A bracketed IPv6 literal keeps its brackets and its colons, so only an
    // *unbracketed* host is split on `:`.
    // Keep an IPv6 literal's brackets: `[::1]` is the host as it appears in a
    // `Host` header and as it would have to be stored. Dropping them turns
    // `[::1]:8443` into `[::1`, which matches nothing and fails silently.
    let host = host.find(']').map_or_else(
        || host.split(':').next().unwrap_or(host),
        |close| &host[..=close],
    );
    host.trim_end_matches('.').to_ascii_lowercase()
}

// `HostDispatch` deliberately does **not** implement `tower::Service`, and the
// reason is the orphan rule: the only way to hand a `'static` future to
// `Service::call(&mut self, ..)` is to own the dispatcher, and
// `impl Service for Arc<HostDispatch>` is forbidden because neither the trait
// nor `Arc` is local. So [`TenancyAwareApp`] — a local type holding the
// `Arc` — is the one that is a `Service`, and it calls
// [`HostDispatch::handle`] directly. It is also the type `cmd_serve` needs, so
// nothing is lost but a layer that would have existed only to satisfy a
// signature.

/// The outer app, so `cmd_serve` has one concrete type on both serve paths.
///
/// `enabled = false` must produce "exactly as today" (§3.6). A `match` here
/// would give the two `axum::serve` call sites two different types, so instead
/// one type carries both arms — and the `Single` arm is literally the old code
/// path with no dispatch layer in front of it.
pub enum TenancyAwareApp {
    Single(Router),
    Hosted(Arc<Tenancy>),
}

/// A tenancy-enabled install: the tenant dispatcher, plus the admin panel
/// mounted **in front of it** (§6.6.1).
///
/// The ordering is the whole design, so it lives in one struct rather than
/// being spread across call sites:
///
/// ```text
/// TenancyAwareApp::call(request):
///     host == admin_host  ->  panel router   (zero tenant content, ever)
///     path == /healthz    ->  health
///     otherwise           ->  HostDispatch   (unchanged)
/// ```
///
/// `panel` is `None` when `admin_host` is unset, and `admin_host` is the
/// **normalised** form the panel was matched on, so the comparison here cannot
/// disagree with the one that built the panel.
pub struct Tenancy {
    dispatch: Arc<HostDispatch>,
    /// Built in `serve_dispatch` and carried here so the readiness route can be
    /// served from the same place `/healthz` is, ahead of tenant resolution.
    /// `None` only if a caller constructs `Tenancy` by hand without one, in
    /// which case `/readyz` answers 503 rather than pretending to be ready.
    readiness: Option<Arc<crate::readiness::ReadinessProbe>>,
    /// `None` means **there is no panel** — not a panel on a default path, and
    /// not a panel on every host. §6.6.2: absence has to mean absence, or a
    /// self-hosted install acquires a cross-tenant control surface by upgrading
    /// and nothing announces it.
    panel: Option<Router>,
    admin_host: String,
}

impl Tenancy {
    /// The dispatcher plus an optional panel.
    ///
    /// # Panics
    /// Never. Takes the admin host already normalised so that this decision and
    /// the one that selected the panel use the same string; a mismatch would
    /// mean a panel nothing can reach, which §6.6.2 makes a startup refusal's
    /// job to prevent rather than a panic's.
    #[must_use]
    pub fn new(dispatch: Arc<HostDispatch>, panel: Option<Router>, admin_host: &str) -> Self {
        Self {
            dispatch,
            panel,
            admin_host: normalise_host(admin_host),
            readiness: None,
        }
    }

    /// The same, with a readiness probe. [`TenancyAwareApp::build`] uses it;
    /// [`Self::new`] stays for the tests that only exercise dispatch.
    #[must_use]
    pub fn with_readiness(
        dispatch: Arc<HostDispatch>,
        panel: Option<Router>,
        admin_host: &str,
        readiness: Arc<crate::readiness::ReadinessProbe>,
    ) -> Self {
        Self {
            readiness: Some(readiness),
            ..Self::new(dispatch, panel, admin_host)
        }
    }

    /// The tenant dispatcher, for tests and for the builder's own use.
    #[must_use]
    pub const fn dispatch(&self) -> &Arc<HostDispatch> {
        &self.dispatch
    }

    /// Is there a panel at all? `admin_host` unset, so no.
    #[must_use]
    pub const fn has_panel(&self) -> bool {
        self.panel.is_some()
    }
}

impl TenancyAwareApp {
    /// Is an admin panel configured? `false` for a single-tenant install and for
    /// a tenancy install with no `admin_host`.
    ///
    /// Exists because the "no panel" state is guarded in **two** places —
    /// `serve_dispatch` does not build one, and `call` refuses to use one — and
    /// without this the redundancy is untestable: mutating either guard alone
    /// changes no observable behaviour, because the other one covers for it.
    /// A diagnostic that can ask the question is also the thing a confused
    /// operator should be able to ask.
    #[must_use]
    pub fn has_admin_panel(&self) -> bool {
        match self {
            Self::Single(_) => false,
            Self::Hosted(tenancy) => tenancy.has_panel(),
        }
    }
}

impl Clone for TenancyAwareApp {
    fn clone(&self) -> Self {
        match self {
            Self::Single(r) => Self::Single(r.clone()),
            Self::Hosted(t) => Self::Hosted(t.clone()),
        }
    }
}

impl Service<HttpRequest> for TenancyAwareApp {
    type Response = HttpResponse;
    type Error = std::convert::Infallible;
    type Future = BoxFuture<'static, Result<HttpResponse, Self::Error>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: HttpRequest) -> Self::Future {
        match self {
            Self::Single(router) => {
                let mut router = router.clone();
                Box::pin(async move { router.call(request).await })
            }
            Self::Hosted(tenancy) => {
                // ── Ahead of dispatch, deliberately ──
                //
                // Two things are checked before a request can reach a tenant
                // router, and the order between them is chosen rather than
                // incidental:
                //
                // 1. **`/healthz` first.** It answers on *every* host, admin
                //    included, because a health check that 404s on one hostname
                //    is a load balancer that marks a healthy node down.
                // 2. **Then the panel.** It is selected by normalised host, so a
                //    `Host: ADMIN.EXAMPLE.COM:8443` claim still reaches it
                //    (§6.6.1).
                //
                // A panel request is *answered* here and never forwarded down. No
                // `fallback` to the dispatcher, no pass-through: there is no
                // path from an admin session to tenant content, by
                // construction rather than by review.
                if request.uri().path() == HEALTH_PATH {
                    let mut health = health_router();
                    return Box::pin(async move { health.call(request).await });
                }
                // `/readyz` is served here for the same structural reason as
                // `/healthz` — it is a question about the *process*, so it must
                // not be tenant-scoped — but with the opposite dependency rule.
                // §7.4: the LB must not route to a process that cannot serve.
                if request.uri().path() == READY_PATH {
                    let Some(probe) = &tenancy.readiness else {
                        return Box::pin(async move {
                            Ok(axum::http::Response::builder()
                                .status(axum::http::StatusCode::SERVICE_UNAVAILABLE)
                                .header(axum::http::header::CONTENT_TYPE, "text/plain")
                                .body(axum::body::Body::from(
                                    "not ready\nreadiness: not configured\n",
                                ))
                                .expect("a static response"))
                        });
                    };
                    let probe = Arc::clone(probe);
                    return Box::pin(async move {
                        Ok(crate::readiness::readyz(axum::extract::State(probe)).await)
                    });
                }
                // §10 (item 19): the AGPL §13 source offer. Unauthenticated and
                // ahead of `HostDispatch` on **every** host, unlike the panel —
                // a compliance obligation a prospective customer cannot read
                // without an account is not met by existing. It serves no tenant
                // data: a static page over build-time constants.
                if request.uri().path() == SOURCE_PATH {
                    return Box::pin(async move { Ok(crate::source_offer::source_offer().await) });
                }
                if let Some(panel) = &tenancy.panel
                    && !tenancy.admin_host.is_empty()
                {
                    let host = request
                        .headers()
                        .get(axum::http::header::HOST)
                        .and_then(|h| h.to_str().ok())
                        .unwrap_or_default();
                    if normalise_host(host) == tenancy.admin_host {
                        let mut panel = panel.clone();
                        return Box::pin(async move { panel.call(request).await });
                    }
                }
                let dispatch = Arc::clone(&tenancy.dispatch);
                Box::pin(async move { Ok(dispatch.handle(request).await) })
            }
        }
    }
}
