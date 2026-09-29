//! Wiring for the tenancy-enabled serve path — `PLAN_DEPLOYMENTS.md` §3.6.
//!
//! This is the only place that turns `[tenancy]` configuration into a running
//! dispatcher. It lives in its own module rather than in `cmd_serve` because
//! `cmd_serve` is already 130 lines of sequential startup and §18.11's rule is
//! that a commit whose claim is "this path is unchanged" should not edit the
//! thing it claims to leave alone. The `enabled = false` arm of `cmd_serve`
//! touches nothing in this file.
//!
//! ## What is built here, in order
//!
//! 1. the **control plane** — a second SQLite file, opened and migrated;
//! 2. the **store cache** — an LRU sized by `max_cached_tenants`;
//! 3. a **builder closure** that turns one [`Tenant`] into its stores and router.
//!
//! Step 3 is a closure rather than a function so that the per-tenant config
//! merge (§3.6's `config_json`, item 10) can be added *inside* it without
//! touching the dispatch loop. The dispatch code has no idea a tenant can carry
//! configuration, which is what keeps it honest.
//!
//! ## Two failures this refuses to paper over
//!
//! - A **`data_root` that does not exist** is created, because §3.4's
//!   `create_if_missing` creates a file and not the two directories above it.
//! - A **missing `default_tenant` on an appliance-style install** is a refusal
//!   to boot, from [`TenancyConfig::validate`], not a 404 on every request.

use rustical_frontend::AdminPanel;
use rustical_store::admin_store::AdminCredentialStore;
use rustical_store::tenant_store::TenantStore;
use rustical_store_sqlite::{SqliteTenantStore, create_control_plane_pool};
use std::sync::Arc;
use tracing::info;

use crate::app::AppConfig;
use crate::config::Config;
use crate::host_dispatch::{HostDispatch, Tenancy, TenancyAwareApp, TenantBuilder};
use crate::store_bundle::StoreBundleCache;

/// Build the serving app for a tenancy-enabled install.
///
/// # Errors
/// Anything [`TenancyConfig::validate`](crate::config::TenancyConfig::validate)
/// rejects, plus a failure to open or migrate the control plane. Both are
/// startup failures: a server that boots and then 404s everybody is worse than
/// one that refuses to start and says why.
pub async fn serve_dispatch(config: &Config) -> anyhow::Result<TenancyAwareApp> {
    config.tenancy.validate().map_err(anyhow::Error::msg)?;

    let control_plane = open_control_plane(&config.tenancy.control_db_url).await?;

    // §6.6.2: `admin_host` is a **reserved** name, checked before anything is
    // served. The panel is selected ahead of `HostDispatch`, so a collision does
    // not error at the point of collision — it makes the tenant silently
    // unreachable, which is why this is a startup refusal and not a 404.
    //
    // It needs the control plane, which is why it lives here and not in
    // `TenancyConfig::validate`: the derivable-collision half of the question is
    // "does a tenant with this slug exist", and that is a database read.
    crate::admin::assert_admin_host_unclaimed(&control_plane, &config.tenancy).await?;

    // A warning rather than a refusal — see the function's doc comment. An
    // allowlist that leads the table is how bootstrap works, so this reports
    // the gap and names the command that closes it.
    crate::admin::warn_about_allowlist_gaps(&control_plane, &config.tenancy).await;

    let cache = Arc::new(StoreBundleCache::new(config.tenancy.max_cached_tenants));

    info!(
        enabled = config.tenancy.enabled,
        base_domain = %config.tenancy.base_domain,
        default_tenant = %config.tenancy.default_tenant,
        max_cached_tenants = config.tenancy.max_cached_tenants,
        admin_host = %config.tenancy.normalised_admin_host(),
        "tenancy enabled: requests will be dispatched by Host"
    );

    let builder = tenant_builder(config, &control_plane, &cache);
    let dispatch = Arc::new(HostDispatch::new(
        control_plane.clone(),
        cache,
        builder,
        config.tenancy.clone(),
    ));

    // §6.6.1: the panel is mounted **in front of** `HostDispatch`, on exactly
    // one host. `None` when `admin_host` is unset, and `None` means *absent*:
    // no panel on a default path, no panel on every host.
    //
    // It is built from the same `control_plane` Arc the dispatcher holds, so
    // the panel and the CLI audit into the same database — and it is the only
    // thing in the process that can be handed the panel's stores, which is how
    // "the panel never opens a tenant's database" stays true: `AdminPanel`
    // holds two control-plane trait objects and has no path to a `StoreBundle`.
    let admin_host = config.tenancy.normalised_admin_host();
    let panel = if admin_host.is_empty() {
        info!("no admin_host configured, so there is no admin panel");
        None
    } else {
        // A **clone of the same store**, not a second `open_control_plane`. The
        // pool inside is refcounted, so a clone is the same two connections
        // under a different `Arc` — a second call would open a second pool
        // against the same file, which is the exact thing
        // `store_sqlite`'s module doc argues against for the tenant stores and
        // which the control plane's own two-connection cap depends on.
        let panel: Arc<dyn TenantStore> = Arc::new(control_plane.clone());
        let admins: Arc<dyn AdminCredentialStore> = Arc::new(control_plane.clone());
        Some(
            Arc::new(AdminPanel::new(
                panel,
                admins,
                config.tenancy.platform_admins.clone(),
                &admin_host,
            ))
            .router(),
        )
    };

    Ok(TenancyAwareApp::Hosted(Arc::new(Tenancy::new(
        dispatch,
        panel,
        &admin_host,
    ))))
}

/// Open and migrate the control plane — a **different file** from any tenant
/// store (§3.4).
async fn open_control_plane(url: &str) -> anyhow::Result<SqliteTenantStore> {
    let pool = create_control_plane_pool(url, true)
        .await
        .map_err(|e| anyhow::anyhow!("could not open the control plane at {url}: {e}"))?;
    Ok(SqliteTenantStore::new(pool))
}

/// The closure that turns one tenant into `(stores, router)`.
///
/// Everything a tenant needs is inside the closure, so the dispatch loop stays a
/// pure "resolve then serve".
fn tenant_builder(
    config: &Config,
    _control_plane: &SqliteTenantStore,
    _cache: &Arc<StoreBundleCache>,
) -> TenantBuilder {
    let config = config.clone();
    Arc::new(move |tenant| {
        let config = config.clone();
        Box::pin(async move {
            // This closure's error type is `String` (it is boxed into a
            // `TenantBuilder`), so the anyhow error is flattened back to a
            // message here rather than converted.
            let root = config
                .tenancy
                .data_root(&config.data_store)
                .map_err(|e: String| e)?;

            // The store directory, created before SQLite is asked for the file:
            // `create_if_missing(true)` creates a *file*, not the two
            // directories above it, so without this every brand-new tenant
            // would 500 on its first request.
            let db_path = config.tenancy.ensure_tenant_store_dir(&root, &tenant.id)?;
            let db_url = format!("sqlite://{}", db_path.display());

            let data_store =
                crate::config::DataStoreConfig::Sqlite(crate::config::SqliteDataStoreConfig {
                    db_url,
                    run_repairs: false,
                    skip_broken: false,
                });
            // `migrate: true`, and this is not a shortcut. A tenant's store is
            // created by whatever inserts the row — the CLI in item 11, or a
            // test seeding the control plane — and **nothing** guarantees that
            // actor ran the migrations. With `false`, the first request for a
            // brand-new tenant fails with `no such table: davpush_vapid_key` and
            // every subsequent one fails identically: a tenant that exists, is
            // dispatched to, and can never serve.
            //
            // It is cheap in the steady state: SQLx records applied migrations in
            // `_sqlx_migrations`, so this is one indexed lookup per *build*, and
            // a build happens once per tenant per cache residency — not per
            // request. The expensive parts of `get_store_bundle` (the repair
            // sweep and per-principal validation) are already switched off by
            // `run_repairs: false` above, and are a no-op on a fresh tenant with
            // no principals.
            let bundle = crate::get_store_bundle(true, &data_store)
                .await
                .map_err(|e| format!("tenant {} stores: {e}", tenant.slug))?;

            // §3.6's merge: the tenant's `config_json` over the global config.
            //
            // This is what mounts the three public routers at all. Before it,
            // `scheduler` and `subscriptions` were `None`, so `/export/{token}.ics`
            // and `/rsvp/{token}` returned 404 for *every* tenant including its
            // own — rows 26 and 27 were not reachable, because there was nothing
            // to scope. See `tenant_overrides` for why the merge cannot be
            // deferred to item 10.
            // §3.6's merge: the tenant's `config_json` over the global config.
            //
            // This is what mounts the three public routers at all. Before it,
            // `scheduler` and `subscriptions` were `None`, so `/export/{token}.ics`
            // and `/rsvp/{token}` returned 404 for *every* tenant including its
            // own — rows 26 and 27 were unreachable, because there was nothing to
            // scope. `tenant_overrides` explains why the merge cannot be deferred
            // to item 10.
            let overrides = crate::tenant_overrides::Overrides::parse(&tenant.config_json);
            let scheduling = overrides.scheduling(&config.scheduling);
            let subscriptions_config = overrides.subscriptions(&config.subscriptions);
            let registration_config = overrides.registration(&config.registration);

            // §3.6: every tenant's subscribe links point at its own host. Falls
            // back to the base domain, so a hosted deployment with no explicit
            // public URL still generates tenant-correct links rather than links
            // to the bare apex.
            let public_base = subscriptions_config.public_url.clone().unwrap_or_else(|| {
                if config.tenancy.base_domain.is_empty() {
                    format!("http://{}", config.http.bind.clone().unwrap_or_default())
                } else {
                    format!("https://{}", config.tenancy.base_domain)
                }
            });

            // The extensions, built over **this tenant's** stores. The scheduler
            // is what holds the RSVP secret, so a per-tenant secret here is the
            // whole of row 27.
            let (scheduler, subscriptions, registration) = crate::build_extensions(
                &scheduling,
                &subscriptions_config,
                &registration_config,
                Arc::new(rustical_store_sqlite::SqliteSchedulingStore::new(
                    (*bundle.cal_store).clone(),
                )),
                bundle.subscription_store.clone(),
                bundle.invite_store.clone(),
            );

            let mut app_config = app_config_for(&config);
            app_config.scheduler = scheduler;
            app_config.subscriptions = subscriptions;
            app_config.registration = registration;
            app_config.subscriptions_public_url = public_base;
            app_config.smtp_accounts.clone_from(&scheduling.smtp);

            let mut bundle = bundle;
            let router = crate::app::make_app_for(Some(tenant), app_config, bundle.app_stores());
            // DAV-Push is wired per tenant in a later part; until then the
            // channel is left unconsumed rather than silently drained, so a
            // notification cannot be lost to a receiver nobody is reading.
            let _ = bundle.take_update_recv();
            Ok((bundle, router))
        })
    })
}

/// The router decisions for one tenant, from the global config.
///
/// A copy of `cmd_serve`'s own call, which is the duplication §3.6 warns about.
/// It is a *copy* rather than a shared helper because sharing it would mean
/// editing `cmd_serve`'s `make_app` arguments — the thing §18.11 promised this
/// commit would not touch. The cost is that the two lists must be kept in step,
/// and the mitigation is that both call `make_app_for` with the same
/// [`AppConfig`] type, so a field added to one is a compile error in the other.
fn app_config_for(config: &Config) -> AppConfig {
    let public_base = config
        .subscriptions
        .public_url
        .clone()
        .unwrap_or_else(|| "http://localhost".to_owned());
    AppConfig {
        frontend: config.frontend.clone(),
        oidc: config.oidc.clone(),
        caldav: config.caldav.clone(),
        scheduler: None,
        subscriptions: None,
        registration: None,
        nextcloud_login: config.nextcloud_login.clone(),
        dav_push_enabled: config.dav_push.enabled,
        session_cookie_samesite_strict: config.http.session_cookie_samesite_strict,
        payload_limit_mb: config.http.payload_limit_mb,
        subscriptions_public_url: public_base,
        smtp_accounts: config.scheduling.smtp.clone(),
    }
}
