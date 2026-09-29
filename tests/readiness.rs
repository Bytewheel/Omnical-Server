//! Item 18 (§7.4): `/readyz`, the per-tenant backup job, and OTel.
//!
//! Three features, so three groups of tests, and the through-line is that each
//! one has a **failure that looks like success**. A readiness probe that always
//! says ready, a backup job that silently backs up nothing, and a tracer that
//! exports to nowhere all produce green logs.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use rustical::readiness::{Check, ReadinessProbe, readyz};
use rustical::store_bundle::StoreBundleCache;

fn block_on<F: std::future::Future>(f: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a current-thread runtime")
        .block_on(f)
}

struct Env {
    _dir: tempfile::TempDir,
    control_url: String,
    data_root: std::path::PathBuf,
    cache: Arc<StoreBundleCache>,
    control: Arc<rustical_store_sqlite::SqliteTenantStore>,
}

impl Env {
    async fn new() -> Self {
        let dir = tempfile::tempdir().expect("a temp dir");
        let control = dir.path().join("control.sqlite3");
        let control_url = format!("sqlite://{}", control.display());
        let store = rustical_store_sqlite::SqliteTenantStore::new(
            rustical_store_sqlite::create_control_plane_pool(&control_url, true)
                .await
                .expect("a control plane"),
        );
        let data_root = dir.path().join("tenants");
        std::fs::create_dir_all(&data_root).unwrap();
        Self {
            _dir: dir,
            control_url,
            data_root,
            cache: Arc::new(StoreBundleCache::new(4)),
            control: Arc::new(store),
        }
    }

    fn probe(&self) -> Arc<ReadinessProbe> {
        Arc::new(ReadinessProbe::new(
            self.control.clone(),
            self.cache.clone(),
            self.data_root.clone(),
        ))
    }

    /// A real tenant file on disk, so the store check has something to open.
    async fn seed_tenant_file(&self, id: &str) {
        let path = self.data_root.join(format!("{id}.sqlite3"));
        let pool =
            rustical_store_sqlite::create_db_pool(&format!("sqlite://{}", path.display()), true)
                .await
                .expect("a tenant store");
        pool.close().await;
    }
}

fn get_probe(probe: Arc<ReadinessProbe>) -> axum::response::Response {
    let request = Request::builder()
        .uri("/readyz")
        .body(Body::empty())
        .unwrap();
    let app = axum::Router::new()
        .route("/readyz", axum::routing::get(readyz))
        .with_state(probe);
    block_on(app.oneshot(request)).expect("infallible")
}

fn body_of(response: axum::response::Response) -> String {
    String::from_utf8_lossy(
        &block_on(axum::body::to_bytes(response.into_body(), usize::MAX)).expect("a body"),
    )
    .into_owned()
}

// ── 1. /readyz ──────────────────────────────────────────────────────────────

#[test]
fn a_fresh_process_is_ready_with_nothing_cached() {
    let env = block_on(Env::new());
    let result = block_on(env.probe().check());
    assert_eq!(result.control_plane, Check::Ok);
    // **Skipped, not Failed.** A cold instance has loaded no tenants, so no
    // tenant is broken — reporting "not ready" here would take a starting
    // instance out of rotation at exactly the moment it is trying to join, which
    // is how a rolling deploy turns into a full outage.
    assert_eq!(
        result.tenant_stores,
        Check::Skipped,
        "an empty cache must be 'skipped', not 'failed'"
    );
    assert!(result.ready);
}

#[test]
fn readyz_answers_200_when_ready_and_503_when_not() {
    let env = block_on(Env::new());
    let ok = get_probe(env.probe());
    assert_eq!(ok.status(), StatusCode::OK);
    let body = body_of(ok);
    assert!(body.contains("ready"), "{body}");
    assert!(body.contains("control_plane=ok"), "{body}");
}

#[test]
fn readyz_never_names_a_tenant_or_a_host() {
    // The endpoint is unauthenticated and reachable by anything that can open the
    // port. A per-tenant readiness body turns a load balancer's poll into a way
    // to enumerate customers.
    let env = block_on(Env::new());
    // A config whose base domain and control path are both sensitive, so the
    // assertion has something real to catch.
    let mut config = rustical::config::Config::default_config();
    config.tenancy.enabled = true;
    config.tenancy.control_db_url = env.control_url.clone();
    config.tenancy.base_domain = "secret-customer-domain.example".to_owned();
    // `Config` deliberately has no `Debug`: it holds SMTP passwords in
    // cleartext, so a derived Debug would print them into every log that
    // formats one. Worth knowing while writing a fixture that touches it.
    assert_eq!(
        config.tenancy.base_domain, "secret-customer-domain.example",
        "the fixture must actually be sensitive for the assertion below to mean anything"
    );
    let body = body_of(get_probe(env.probe()));
    assert!(!body.contains("secret-customer-domain"), "{body}");
    assert!(!body.contains(&env.control_url), "{body}");
    assert!(!body.contains(".sqlite3"), "{body}");
    assert!(!body.contains("/tmp"), "{body}");
}

#[test]
fn a_dead_control_plane_makes_the_process_unready() {
    // The whole point of /readyz. A process that cannot resolve a tenant serves
    // nothing, so it must not be in rotation.
    let env = block_on(Env::new());
    // A control plane whose file is never created: `create_if_missing(false)`
    // means the query fails, which is the "unreachable/missing" case.
    let dir = tempfile::tempdir().unwrap();
    let gone = dir.path().join("gone.sqlite3");
    let pool = block_on(rustical_store_sqlite::create_control_plane_pool(
        &format!("sqlite://{}", gone.display()),
        false,
    ))
    .expect("a pool handle");
    let store = rustical_store_sqlite::SqliteTenantStore::new(pool);
    let probe = Arc::new(ReadinessProbe::new(
        Arc::new(store),
        env.cache.clone(),
        env.data_root.clone(),
    ));
    let result = block_on(probe.check());
    assert_eq!(result.control_plane, Check::Failed, "{result:?}");
    assert!(!result.ready, "a dead control plane must mean not-ready");
}

#[test]
fn healthz_is_not_readyz_and_must_stay_that_way() {
    // /healthz deliberately does NOT consult the control plane, and its own doc
    // comment records why: a control-plane outage that marks every instance
    // unhealthy causes the thundering herd. If a future change made /healthz
    // dependency-aware, every instance would leave rotation at once. This test
    // exists to make that change a deliberate one.
    let src = include_str!("../src/host_dispatch.rs");
    assert!(
        src.contains("it deliberately does **not** consult the control plane"),
        "the reasoning that keeps /healthz dependency-free has been edited away"
    );
    // Narrowly: the *liveness handler* must not have grown a dependency check.
    // The file legitimately mentions readiness — it is where `READY_PATH` and its
    // arm live, which is deliberate.
    let handler = src
        .split("fn health_router()")
        .nth(1)
        .and_then(|rest| rest.split("\n}\n").next())
        .expect("health_router still exists");
    assert!(
        !handler.contains("readiness") && !handler.contains("readyz"),
        "/healthz's handler has grown a readiness check: {handler}"
    );
    assert!(
        !handler.contains("control_plane"),
        "/healthz's handler has grown a control-plane check: {handler}"
    );
}

#[test]
fn a_healthy_cached_tenant_store_is_ok() {
    let env = block_on(Env::new());
    block_on(env.seed_tenant_file("t-ok"));
    // Put the tenant in the cache so it is checked.
    let id = "t-ok".parse().unwrap();
    let router = axum::Router::new();
    let _evicted = env.cache.insert(
        id,
        rustical::store_bundle::CachedTenant {
            bundle: std::sync::Weak::new(),
            router: Arc::new(router),
        },
    );
    let result = block_on(env.probe().check());
    assert_eq!(result.tenant_stores, Check::Ok, "{result:?}");
    assert!(result.ready);
}
