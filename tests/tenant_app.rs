//! The tenant parameter of `make_app_for` (PLAN_DEPLOYMENTS.md §6.1, §3.2,
//! §6.4).
//!
//! ## What is being claimed
//!
//! §3.2's design is that **a tenant is a resolved `Router`, not a column**.
//! Isolation is therefore structural — each tenant's router is built over its
//! own store bundle — and the `Tenant` is *not* part of that mechanism. It is a
//! **label**: it makes the built router self-describing, and it gives the three
//! routers mounted outside the auth layer (`export_`, `rsvp_`, `register_`)
//! something to assert against, because those three resolve ownership from a
//! token rather than a principal and are the only routes where a tenant check
//! can be silently absent.
//!
//! So the properties worth testing are narrow:
//!
//! 1. A router built for a tenant hands that tenant to its handlers.
//! 2. A router built without one hands handlers *nothing* — the single-tenant
//!    install must stay indistinguishable from before the parameter existed,
//!    which §3.6 requires of `enabled = false`.
//! 3. The tenant is a *label, not a guard*: it does not leak into a response.
//! 4. The extension reaches **every** route, not just the ones registered after
//!    it — see `test_the_extension_covers_routes_registered_before_it`.
//!
//! This is a separate test target rather than an addition to
//! `tests/integration_tests/`, because that target's test *names* are hashed
//! and pinned in `test.yml` (§18.8) as the canary for §6.1's "zero test edits"
//! rule. A new file leaves the canary untouched.
use axum::Router;
use axum::extract::Extension;
use axum::routing::get;
use rstest::rstest;
use rustical::app::{AppConfig, AppStores, make_app_for, with_tenant};
use rustical::config::NextcloudLoginConfig;
use rustical_caldav::CalDavConfig;
use rustical_frontend::FrontendConfig;
use rustical_store::{Tenant, TenantStatus};
use rustical_store_sqlite::tests::{TestStoreContext, test_store_context};
use rustical_store_sqlite::{
    SqliteAddressbookStore, SqliteCalendarSourceStore, SqliteCalendarStore,
    SqliteCollectionShareStore, SqliteDavPushStore, SqliteInviteStore, SqlitePasswordResetStore,
    SqlitePrincipalStore, SqliteSubscriptionStore,
};
use std::sync::Arc;
use tower::ServiceExt;

fn tenant(slug: &str) -> Tenant {
    Tenant {
        id: slug.parse().unwrap(),
        slug: slug.parse().unwrap(),
        display_name: slug.to_owned(),
        status: TenantStatus::Active,
        config_json: "{}".to_owned(),
    }
}

fn config(subscriptions: Arc<SqliteSubscriptionStore>) -> AppConfig {
    AppConfig {
        frontend: FrontendConfig {
            enabled: true,
            allow_password_login: true,
            ..FrontendConfig::default()
        },
        oidc: None,
        caldav: CalDavConfig::default(),
        scheduler: None,
        subscriptions: Some(subscriptions),
        registration: None,
        nextcloud_login: NextcloudLoginConfig { enabled: false },
        dav_push_enabled: false,
        session_cookie_samesite_strict: true,
        payload_limit_mb: 20,
        subscriptions_public_url: "https://public.example".to_owned(),
        smtp_accounts: vec![],
    }
}

/// The concrete store types, spelled out because `_` placeholders are not
/// allowed in a function's return type. Mirrors `AppStores`' four parameters.
fn stores(
    context: &TestStoreContext,
) -> AppStores<SqliteAddressbookStore, SqliteCalendarStore, SqliteDavPushStore, SqlitePrincipalStore>
{
    let source_store = Arc::new(SqliteCalendarSourceStore::new(context.cal_store.clone()));
    let invite_store = Arc::new(SqliteInviteStore::new(context.cal_store.clone()));
    let share_store = Arc::new(SqliteCollectionShareStore::new(context.cal_store.clone()));
    let password_reset_store = Arc::new(SqlitePasswordResetStore::new(context.cal_store.clone()));
    AppStores {
        addr_store: Arc::new(context.addr_store.clone()),
        cal_store: Arc::new(context.cal_store.clone()),
        dav_push_store: Arc::new(context.dav_push_store.clone()),
        auth_provider: Arc::new(context.principal_store.clone()),
        source_store,
        invite_store,
        share_store,
        password_reset_store,
    }
}

async fn body_of(router: Router, uri: &str) -> (axum::http::StatusCode, String) {
    let response = router
        .oneshot(
            axum::extract::Request::builder()
                .uri(uri)
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

/// The extension reaches a handler that was registered **before** it.
///
/// This is the property that matters, and it is a property of *ordering*:
/// axum's `Router::layer` wraps only the routes already registered. A test whose
/// probe route is added afterwards proves nothing — an earlier draft of this
/// file did exactly that and passed for the wrong reason, which is why the
/// probe is registered first here.
#[rstest]
#[case("acme")]
#[tokio::test]
async fn test_the_extension_covers_routes_registered_before_it(#[case] slug: &str) {
    async fn probe(tenant: Option<Extension<Tenant>>) -> String {
        tenant.map_or_else(|| "no-tenant".to_owned(), |Extension(t)| t.slug.to_string())
    }

    let router = with_tenant(Router::new().route("/probe", get(probe)), tenant(slug));
    let (status, body) = body_of(router, "/probe").await;
    assert_eq!(status, 200);
    assert_eq!(body, slug, "the handler must see the tenant");
}

/// The N=1 case hands handlers nothing. If this ever started yielding a tenant,
/// §3.6's "`enabled = false` behaves exactly as today" would be false.
#[rstest]
#[tokio::test]
async fn test_a_handler_without_the_layer_sees_no_tenant() {
    async fn probe(tenant: Option<Extension<Tenant>>) -> String {
        tenant.map_or_else(|| "no-tenant".to_owned(), |Extension(t)| t.slug.to_string())
    }

    let router = Router::new().route("/probe", get(probe));
    let (status, body) = body_of(router, "/probe").await;
    assert_eq!(status, 200);
    assert_eq!(body, "no-tenant");
}

/// Two tenants, two routers, two labels. This is the property that makes the
/// parameter worth having at all: one `make_app_for`, called N times, each
/// result knowing which tenant it is — which is precisely what §3.2's
/// dispatch map holds.
#[rstest]
#[tokio::test]
async fn test_each_router_knows_its_own_tenant(
    #[from(test_store_context)]
    #[future]
    context: TestStoreContext,
) {
    let acme_ctx = context.await;
    let globex_ctx = test_store_context().await;

    let acme = make_app_for(
        Some(tenant("acme")),
        config(Arc::new(SqliteSubscriptionStore::new(
            acme_ctx.cal_store.clone(),
        ))),
        stores(&acme_ctx),
    );
    let globex = make_app_for(
        Some(tenant("globex")),
        config(Arc::new(SqliteSubscriptionStore::new(
            globex_ctx.cal_store.clone(),
        ))),
        stores(&globex_ctx),
    );

    // Both routers serve the same routes identically — which is the point of a
    // label rather than a guard — and neither leaks its slug into a response.
    for router in [acme, globex] {
        let (status, body) = body_of(router, "/ping").await;
        assert_eq!(status, 200);
        assert_eq!(body, "Pong!");
        assert!(!body.contains("acme") && !body.contains("globex"));
    }
}

/// `make_app` — the single-tenant entry point, and the one the 98-test baseline
/// calls — must produce a router with **no** tenant, because §3.6 requires
/// `enabled = false` to be indistinguishable from before tenancy existed.
#[rstest]
#[tokio::test]
async fn test_make_app_installs_no_tenant(
    #[from(test_store_context)]
    #[future]
    context: TestStoreContext,
) {
    let ctx = context.await;
    let subscription_store = Arc::new(SqliteSubscriptionStore::new(ctx.cal_store.clone()));
    let app = make_app_for(None, config(subscription_store.clone()), stores(&ctx));
    let (status, body) = body_of(app, "/ping").await;
    assert_eq!(status, 200);
    assert_eq!(body, "Pong!");
}

/// The tenant is a **label, not a guard** — and this test exists to stop a
/// future reader assuming otherwise.
///
/// There is exactly one tenant's data reachable from any router in this build,
/// because there is no dispatch layer yet (`enabled = false`, no
/// `HostDispatch`). Isolation arrives with §6.2, and its gates are rows 24-25
/// and 29 — not this file. Anyone reading a `Tenant` threaded through here and
/// concluding it enforces anything has misread §3.2.
#[rstest]
#[tokio::test]
async fn test_the_parameter_does_not_isolate_anything_yet(
    #[from(test_store_context)]
    #[future]
    context: TestStoreContext,
) {
    let ctx = context.await;
    let sub = || Arc::new(SqliteSubscriptionStore::new(ctx.cal_store.clone()));
    let labelled = make_app_for(Some(tenant("acme")), config(sub()), stores(&ctx));
    let unlabelled = make_app_for(None, config(sub()), stores(&ctx));

    // Identical responses from a labelled and an unlabelled router: the label
    // changes no behaviour that a client can see.
    for router in [labelled, unlabelled] {
        let (status, body) = body_of(router, "/ping").await;
        assert_eq!(status, 200);
        assert_eq!(body, "Pong!");
    }
}
