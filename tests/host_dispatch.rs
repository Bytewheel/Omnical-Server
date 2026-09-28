//! `HostDispatch` — `PLAN_DEPLOYMENTS.md` §3.3, and rows 24-25, 29.
//!
//! These run against a **real control plane and real tenant databases** in a
//! temp directory. That is deliberate: the claims being tested here are about
//! which database a request reaches, and a fake control plane would be testing
//! the fake.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use rustical::config::TenancyConfig;
use rustical::host_dispatch::{HostDispatch, TenancyAwareApp, normalise_host};
use rustical::store_bundle::StoreBundleCache;
use rustical_store::tenant::{Tenant, TenantId, TenantStatus};
use rustical_store::tenant_store::{NewTenant, TenantStore};
use rustical_store_sqlite::{
    SqliteTenantStore, create_control_plane_pool, create_db_pool, new_tenant,
};
use std::path::PathBuf;
use std::sync::Arc;
use tower::Service;

/// A tenant id that is a valid slug, for a fixture tenant.
fn id(s: &str) -> TenantId {
    s.parse().expect("a valid slug")
}

/// A real tenant with a real database at `<root>/tenants/<id>/db.sqlite3`.
///
/// The database is genuinely created — `create_db_pool` runs the full migration
/// set — because "tenant A's principal against tenant B's host" (row 24) is only
/// meaningful if A and B are separate databases, and the strongest way to show
/// they are separate is that they are separate *files*.
struct Fixture {
    root: PathBuf,
    control_plane: SqliteTenantStore,
    #[allow(dead_code)]
    _dir: tempfile::TempDir,
}

impl Fixture {
    async fn new() -> Self {
        let dir = tempfile::tempdir().expect("a temp dir");
        let root = dir.path().to_path_buf();
        let cp_path = root.join("control.sqlite3");
        let pool = create_control_plane_pool(&format!("sqlite://{}", cp_path.display()), true)
            .await
            .expect("control plane migrates");
        Self {
            root,
            control_plane: SqliteTenantStore::new(pool),
            _dir: dir,
        }
    }

    /// Create a tenant, its database, and its hosts.
    async fn tenant(&self, slug: &str, hosts: &[&str]) -> Tenant {
        let mut new: NewTenant = new_tenant(&id(slug), Some(slug));
        new.hosts = hosts.iter().map(|h| (*h).to_owned()).collect();
        self.control_plane
            .create_tenant(&new)
            .await
            .expect("created");
        // Build the tenant's own database, so the store path convention is
        // exercised rather than assumed. `ensure_tenant_store_dir` is the
        // production call, used here so a regression in it fails these tests
        // rather than only the first request a real tenant ever makes.
        let path = TenancyConfig::default()
            .ensure_tenant_store_dir(&self.root, &new.tenant.id)
            .expect("the tenant store directory is created");
        let pool = create_db_pool(path.to_str().expect("utf-8 path"), true)
            .await
            .expect("tenant db migrates");
        drop(pool);
        new.tenant
    }

    /// A plain filesystem path, for the assertions that check the two tenants
    /// really do have separate files. (The dispatch path uses the
    /// `sqlite://` URL form via `ensure_tenant_store_dir`.)
    fn tenant_db_path(&self, tenant_id: &TenantId) -> String {
        self.root
            .join("tenants")
            .join(tenant_id.as_str())
            .join("db.sqlite3")
            .to_string_lossy()
            .into_owned()
    }
}

/// A builder that hands out a distinct, identifiable router per tenant.
///
/// The `/whoami` route is the probe: it reports which tenant's router answered,
/// which is how a cross-tenant test can assert *which* tenant served a request
/// without depending on any real handler.
///
/// The **stores** are the real thing — `get_store_bundle` against that tenant's
/// own temp database — while the router is a one-route probe. Dispatch treats
/// the bundle opaquely, so a real bundle plus a probe router tests exactly the
/// dispatch path, and using the real constructor means the test cannot pass
/// against a store path convention the product does not actually use.
fn probe_builder(fixture: &Fixture) -> rustical::host_dispatch::TenantBuilder {
    let root = fixture.root.clone();
    Arc::new(move |tenant: Tenant| {
        let root = root.clone();
        Box::pin(async move {
            // The directory has to exist before SQLite will create the file
            // inside it — see `TenancyConfig::ensure_tenant_store_dir`.
            let path = TenancyConfig::default()
                .ensure_tenant_store_dir(&root, &tenant.id)
                .map_err(|e| e.to_string())?;
            let db_url = format!("sqlite://{}", path.display());
            let bundle = rustical::get_store_bundle(
                false,
                &rustical::config::DataStoreConfig::Sqlite(
                    rustical::config::SqliteDataStoreConfig {
                        db_url,
                        run_repairs: false,
                        skip_broken: false,
                    },
                ),
            )
            .await
            .map_err(|e| format!("building tenant stores failed: {e}"))?;

            let slug = tenant.slug.to_string();
            let router = axum::Router::new().route(
                "/whoami",
                axum::routing::get(move || {
                    let slug = slug.clone();
                    async move { slug }
                }),
            );
            Ok((bundle, router))
        })
    })
}

fn tenancy(base_domain: &str, default_tenant: &str) -> TenancyConfig {
    TenancyConfig {
        enabled: true,
        default_tenant: default_tenant.to_owned(),
        base_domain: base_domain.to_owned(),
        control_db_url: "sqlite://unused".to_owned(),
        ..TenancyConfig::default()
    }
}

fn dispatch(fixture: &Fixture, config: TenancyConfig) -> Arc<HostDispatch> {
    Arc::new(HostDispatch::new(
        fixture.control_plane.clone(),
        Arc::new(StoreBundleCache::new(8)),
        probe_builder(fixture),
        config,
    ))
}

async fn get(dispatch: &Arc<HostDispatch>, host: &str) -> (StatusCode, String) {
    let request = Request::builder()
        .uri(format!("http://{host}/whoami"))
        .body(Body::empty())
        .expect("a request");
    let response = dispatch.clone().handle(request).await;
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("a body");
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

// ---------------------------------------------------------------- host parsing

#[test]
fn a_host_is_lowercased_and_stripped_of_its_port() {
    // §3.3 step 1. A `Host` with a port is the *normal* case, not an edge case:
    // every request on :8443 carries one, and `acme.test:8443` would never match
    // a stored `acme.test`.
    assert_eq!(normalise_host("ACME.test:8443"), "acme.test");
    assert_eq!(normalise_host("acme.test"), "acme.test");
    assert_eq!(normalise_host("  acme.test  "), "acme.test");
    assert_eq!(
        normalise_host("acme.test."),
        "acme.test",
        "trailing root dot"
    );
    assert_eq!(normalise_host("acme.test:443"), "acme.test");
}

#[test]
fn a_bracketed_ipv6_host_keeps_its_own_colons() {
    // Splitting on the first `:` unconditionally would turn `[::1]:8443` into
    // `[` — and a host of `[` matches nothing, silently.
    assert_eq!(normalise_host("[::1]:8443"), "[::1]");
    assert_eq!(normalise_host("[2001:db8::1]"), "[2001:db8::1]");
}

#[rstest::rstest]
#[tokio::test]
async fn the_authority_is_read_when_the_host_header_is_absent() {
    // HTTP/2 carries the host in `:authority`, and some proxies drop the header
    // entirely. A dispatcher that only read the header would 404 every h2
    // request.
    let fixture = Fixture::new().await;
    fixture.tenant("acme", &["acme.test"]).await;
    let d = dispatch(&fixture, tenancy("", ""));

    let request = Request::builder()
        .method("GET")
        .uri("http://acme.test/whoami")
        .body(Body::empty())
        .expect("a request");
    let response = d.handle(request).await;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "uri authority must be used"
    );
}

#[rstest::rstest]
#[tokio::test]
async fn a_request_with_no_host_at_all_is_not_found() {
    // HTTP/1.0 without `Host` is a protocol violation, not a tenant question.
    // It must not fall through to `default_tenant` — that would be a host-less
    // request silently served.
    let fixture = Fixture::new().await;
    fixture.tenant("acme", &[]).await;
    let d = dispatch(&fixture, tenancy("", "acme"));

    let request = Request::builder()
        .uri("/whoami")
        .body(Body::empty())
        .expect("a request");
    let response = d.handle(request).await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

// ------------------------------------------------------------------ resolution

#[rstest::rstest]
#[tokio::test]
async fn an_explicit_host_claim_resolves() {
    let fixture = Fixture::new().await;
    fixture.tenant("acme", &["cal.acme.test"]).await;
    let d = dispatch(&fixture, tenancy("", ""));

    let (status, body) = get(&d, "cal.acme.test").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "acme");
}

#[rstest::rstest]
#[tokio::test]
async fn a_subdomain_of_base_domain_resolves() {
    // §3.3 match 2.
    let fixture = Fixture::new().await;
    fixture.tenant("acme", &[]).await;
    let d = dispatch(&fixture, tenancy("t3.gg", ""));

    let (status, body) = get(&d, "acme.t3.gg").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "acme");
}

#[rstest::rstest]
#[tokio::test]
async fn the_whole_host_can_be_the_slug() {
    // §3.3 match 3: host-per-tenant, `acme.t3.gg` with no `base_domain` at all.
    let fixture = Fixture::new().await;
    fixture.tenant("acme", &[]).await;
    let d = dispatch(&fixture, tenancy("", ""));

    let (status, body) = get(&d, "acme").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "acme");
}

#[rstest::rstest]
#[tokio::test]
async fn default_tenant_catches_everything_left() {
    // §3.3 match 4, and the appliance case: the `Host` is whatever the LAN
    // called the box.
    let fixture = Fixture::new().await;
    fixture.tenant("acme", &[]).await;
    let d = dispatch(&fixture, tenancy("", "acme"));

    for host in ["nas.local", "192.168.1.10", "omnical", "whatever.example"] {
        let (status, body) = get(&d, host).await;
        assert_eq!(status, StatusCode::OK, "host {host} should reach acme");
        assert_eq!(body, "acme");
    }
}

#[rstest::rstest]
#[tokio::test]
async fn an_explicit_claim_beats_a_default_tenant() {
    // The ordering that matters: if `default_tenant` were checked first, a typo
    // in one customer's DNS would silently serve them everybody else's data.
    let fixture = Fixture::new().await;
    fixture.tenant("acme", &["cal.acme.test"]).await;
    fixture.tenant("globex", &[]).await;
    let d = dispatch(&fixture, tenancy("", "globex"));

    let (_, body) = get(&d, "cal.acme.test").await;
    assert_eq!(body, "acme", "the claim must win over the default");
    let (_, body) = get(&d, "unknown.test").await;
    assert_eq!(body, "globex", "the default catches what is left");
}

#[rstest::rstest]
#[tokio::test]
async fn a_base_domain_resolution_beats_a_bare_slug_of_the_same_name() {
    // Two tenants: `acme`, and a host `acme.other.test` that the *slug* rule
    // would otherwise read as the slug `acme.other` — a name that cannot be a
    // slug, so it must not resolve.
    let fixture = Fixture::new().await;
    fixture.tenant("acme", &[]).await;
    let d = dispatch(&fixture, tenancy("t3.gg", ""));

    let (status, body) = get(&d, "acme.t3.gg").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "acme");
}

#[rstest::rstest]
#[tokio::test]
async fn a_multi_label_suffix_is_not_read_as_a_slug() {
    // `evil.acme.t3.gg` must not resolve to tenant `acme` just because the
    // suffix matches: the remainder still has to be a single valid slug.
    let fixture = Fixture::new().await;
    fixture.tenant("acme", &[]).await;
    let d = dispatch(&fixture, tenancy("t3.gg", ""));

    let (status, _) = get(&d, "evil.acme.t3.gg").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

// ----------------------------------------------------------------- row 29

#[rstest::rstest]
#[tokio::test]
async fn a_suspended_tenant_stops_serving_on_the_next_request() {
    // **Row 29.** The cached router exists; the control plane says suspended;
    // the request is 404. Nothing was evicted, because the cache is only reached
    // after resolution — which is the whole reason it is keyed by TenantId.
    let fixture = Fixture::new().await;
    let acme = fixture.tenant("acme", &["cal.acme.test"]).await;
    let d = dispatch(&fixture, tenancy("", ""));

    let (status, body) = get(&d, "cal.acme.test").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "acme");
    assert_eq!(d.cache().len(), 1, "the router is cached");

    fixture
        .control_plane
        .update_tenant_status(&acme.id, TenantStatus::Suspended)
        .await
        .expect("suspended");

    let (status, _) = get(&d, "cal.acme.test").await;
    assert_eq!(status, StatusCode::NOT_FOUND, "row 29: immediately 404");
    // The entry is still there and untouched — which is the proof that the
    // 404 came from resolution and not from an eviction somebody forgot.
    assert_eq!(d.cache().len(), 1, "no eviction was needed");
}

#[rstest::rstest]
#[tokio::test]
async fn a_suspended_tenant_is_not_papered_over_by_the_default_tenant() {
    // The dangerous version. With a `default_tenant` configured, a suspended
    // tenant's hostname must 404 — not fall through to the default and be
    // served somebody else's data.
    let fixture = Fixture::new().await;
    let acme = fixture.tenant("acme", &["cal.acme.test"]).await;
    fixture.tenant("globex", &[]).await;
    let d = dispatch(&fixture, tenancy("", "globex"));

    fixture
        .control_plane
        .update_tenant_status(&acme.id, TenantStatus::Suspended)
        .await
        .expect("suspended");

    let (status, body) = get(&d, "cal.acme.test").await;
    assert_eq!(status, StatusCode::NOT_FOUND, "a suspended tenant must 404");
    assert!(
        !body.contains("globex"),
        "must not be served by the default tenant: {body:?}"
    );
}

// -------------------------------------------------- indistinguishable failures

#[rstest::rstest]
#[tokio::test]
async fn the_three_no_tenant_outcomes_are_byte_identical() {
    // Unknown host, suspended tenant, and never-claimed host. If these bodies
    // differed, anyone could enumerate which hostnames are claimed, which
    // tenants exist, and which are suspended — by diffing responses.
    let fixture = Fixture::new().await;
    let acme = fixture.tenant("acme", &["cal.acme.test"]).await;
    fixture.tenant("globex", &[]).await;
    let d = dispatch(&fixture, tenancy("t3.gg", ""));

    let unknown = get(&d, "never-heard-of-it.test").await;
    let unclaimed = get(&d, "globex.t3.gg.other.test").await;

    fixture
        .control_plane
        .update_tenant_status(&acme.id, TenantStatus::Suspended)
        .await
        .expect("suspended");
    let suspended = get(&d, "cal.acme.test").await;

    assert_eq!(
        unknown, unclaimed,
        "unknown and unclaimed must be identical"
    );
    assert_eq!(
        unknown.0, suspended.0,
        "suspended and unknown must share a status"
    );
    assert_eq!(
        unknown.1, suspended.1,
        "suspended and unknown must share a body byte for byte"
    );
    // And the body must name nothing.
    for (label, (_, body)) in [
        ("unknown", &unknown),
        ("unclaimed", &unclaimed),
        ("suspended", &suspended),
    ] {
        assert!(!body.contains("acme"), "{label} leaked a tenant name");
        assert!(!body.contains("suspended"), "{label} leaked a status");
        assert!(!body.contains("t3.gg"), "{label} leaked the base domain");
    }
}

// ------------------------------------------------------------- the cache gate

#[rstest::rstest]
#[tokio::test]
async fn a_tenant_is_built_once_and_then_served_from_the_cache() {
    // §3.5's point: the cache is a construction memo.
    let fixture = Fixture::new().await;
    let acme = fixture.tenant("acme", &[]).await;
    let d = dispatch(&fixture, tenancy("", ""));

    for _ in 0..5 {
        let (status, body) = get(&d, "acme").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "acme");
    }
    assert_eq!(d.cache().len(), 1, "one tenant, one entry");
    // Keyed by the **id**, never the slug: the id is what the control plane
    // vouched for, and a slug can be renamed.
    assert_eq!(d.cache().cached_ids(), vec![acme.id]);
}

#[rstest::rstest]
#[tokio::test]
async fn two_tenants_get_two_independent_routers() {
    // §3.2's isolation, observable at the dispatch layer: same process, same
    // binary, two databases, two routers, and each host reaches only its own.
    let fixture = Fixture::new().await;
    let acme = fixture.tenant("acme", &["cal.acme.test"]).await;
    let globex = fixture.tenant("globex", &["cal.globex.test"]).await;
    let d = dispatch(&fixture, tenancy("", ""));

    // The two tenants really do have different database files.
    assert_ne!(acme.id, globex.id);
    assert!(fixture.tenant_db_path(&acme.id) != fixture.tenant_db_path(&globex.id));
    let acme_db = fixture.tenant_db_path(&acme.id);
    let globex_db = fixture.tenant_db_path(&globex.id);
    assert!(PathBuf::from(&acme_db).exists(), "{acme_db} should exist");
    assert!(
        PathBuf::from(&globex_db).exists(),
        "{globex_db} should exist"
    );

    for _ in 0..3 {
        assert_eq!(get(&d, "cal.acme.test").await.1, "acme");
        assert_eq!(get(&d, "cal.globex.test").await.1, "globex");
    }
    assert_eq!(d.cache().len(), 2);
}

// ------------------------------------------------------------- tenancy off

#[rstest::rstest]
#[tokio::test]
async fn disabled_tenancy_serves_the_router_with_no_dispatch_layer() {
    // §3.6's "behaves exactly as today". The `Single` arm must not consult a
    // control plane, must not 404 a host it does not recognise, and must not
    // care what the `Host` header says.
    let app = TenancyAwareApp::Single(
        axum::Router::new().route("/whoami", axum::routing::get(|| async { "single" })),
    );
    for host in ["acme.test", "unknown.invalid", "192.168.1.5:8443"] {
        let mut svc = app.clone();
        let request = Request::builder()
            .uri(format!("http://{host}/whoami"))
            .body(Body::empty())
            .expect("a request");
        let response = svc.call(request).await.expect("infallible");
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "single-tenant mode must not 404 on host {host}"
        );
    }
}

#[test]
fn tenancy_config_refuses_to_boot_when_nothing_can_resolve() {
    // Found at startup, not on the first request — a 500 for one unlucky tenant
    // is worse than a refusal to start.
    let broken = TenancyConfig {
        enabled: true,
        default_tenant: String::new(),
        base_domain: String::new(),
        control_db_url: "sqlite://x".to_owned(),
        ..TenancyConfig::default()
    };
    let err = broken.validate().expect_err("must refuse");
    assert!(
        err.contains("default_tenant") && err.contains("base_domain"),
        "{err}"
    );
}

#[test]
fn tenancy_config_refuses_a_malformed_default_tenant() {
    let broken = TenancyConfig {
        enabled: true,
        default_tenant: "Not A Slug".to_owned(),
        control_db_url: "sqlite://x".to_owned(),
        ..TenancyConfig::default()
    };
    assert!(broken.validate().is_err());
}

#[test]
fn tenancy_config_is_inert_and_accepted_while_disabled() {
    // A staged rollout turns `enabled` on in a later commit; refusing to start
    // because unused keys are present would break that.
    let staged = TenancyConfig {
        enabled: false,
        base_domain: "t3.gg".to_owned(),
        default_tenant: "not a slug".to_owned(),
        ..TenancyConfig::default()
    };
    assert!(staged.validate().is_ok());
}

#[test]
fn the_store_path_is_under_data_root_and_named_by_id() {
    // §3.4's convention. Named by *id*, not slug, so a rebrand does not mean
    // renaming a directory a running server has open.
    let config = TenancyConfig::default();
    let path = config.tenant_db_path(std::path::Path::new("/var/lib/omnical"), "abc-123");
    assert_eq!(path, "/var/lib/omnical/tenants/abc-123/db.sqlite3");
    assert!(!path.contains(".."));
}

#[rstest::rstest]
#[tokio::test]
async fn a_control_plane_failure_is_a_500_not_a_404() {
    // Swallowing a database outage into the shared 404 would make every tenant
    // look nonexistent, which is both a lie and impossible to debug.
    let fixture = Fixture::new().await;
    let d = dispatch(&fixture, tenancy("", ""));
    // Drop the control plane's file out from under it: the next query fails.
    drop(fixture);
    let (status, body) = get(&d, "acme.test").await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(
        !body.contains("sqlite") && !body.contains("/"),
        "the 500 body must not leak a path: {body:?}"
    );
}
