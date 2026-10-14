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
//! 1. the **control plane** — a second `SQLite` file, opened and migrated;
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

use crate::store_bundle::StoreBundle;
use rustical_dav_push::{DavPushService, VapidStore};
use rustical_frontend::{AdminPanel, AppliancePanel};
use rustical_scheduling::Scheduler;
use rustical_store::CalendarStorePruneDeleted;
use rustical_store::TenantId;
use rustical_store::admin_store::AdminCredentialStore;
use rustical_store::auth::AuthenticationProvider;
use rustical_store::tenant_store::TenantStore;
use rustical_store_sqlite::{SqliteTenantStore, create_control_plane_pool};
use std::collections::HashSet;
use std::sync::Arc;
use std::sync::Mutex;
use tracing::info;

use crate::app::AppConfig;
use crate::config::{Config, DataStoreConfig, SqliteDataStoreConfig};
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
    serve_dispatch_with_config_file(config, None).await
}

/// [`serve_dispatch`], told where the config file is.
///
/// The extra argument exists for exactly one thing: the appliance panel's
/// redaction pass reads the config's **text**, so its key-shape pass can cover
/// fields this build does not know about. `Config` deliberately does not carry
/// its own path — a `Config` assembled by a test has no file, and one loaded
/// from `RUSTICAL_*` environment variables has none either — so the path has to
/// be handed in rather than derived.
///
/// `None` is the honest default and it means the key-shape pass is unavailable.
/// The typed-config pass still runs, so the SMTP passwords and the RSVP secret
/// are still redacted; only fields this build has never heard of are not
/// covered. `cmd_serve` passes the real path.
///
/// # Errors
/// Anything [`TenancyConfig::validate`](crate::config::TenancyConfig::validate)
/// rejects, a failure to open or migrate the control plane, a reserved admin
/// host a tenant has claimed, or an enabled-but-unusable `[appliance]` config.
/// All startup failures: a server that boots and then 404s everybody is worse
/// than one that says why it will not start.
pub async fn serve_dispatch_with_config_file(
    config: &Config,
    config_file: Option<&std::path::Path>,
) -> anyhow::Result<TenancyAwareApp> {
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
        admin_hosts = ?config.tenancy.normalised_admin_hosts(),
        "tenancy enabled: requests will be dispatched by Host"
    );

    let builder = tenant_builder(config, &control_plane, &cache);
    let dispatch = Arc::new(HostDispatch::new(
        control_plane.clone(),
        Arc::clone(&cache),
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
    let admin_hosts = config.tenancy.normalised_admin_hosts();
    let panel = if admin_hosts.is_empty() {
        info!("no admin_host configured, so there is no admin panel");
        None
    } else {
        // A **clone of the same store**, not a second `open_control_plane`. The
        // pool inside is refcounted, so a clone is the same two connections
        // under a different `Arc` — a second call would open a second pool
        // against the same file, which is the exact thing
        // `store_sqlite`'s module doc argues against for the tenant stores and
        // which the control plane's own two-connection cap depends on.
        let panel_store: Arc<dyn TenantStore> = Arc::new(control_plane.clone());
        let admins: Arc<dyn AdminCredentialStore> = Arc::new(control_plane.clone());
        let admin_panel = Arc::new(AdminPanel::new(
            panel_store,
            admins,
            config.tenancy.platform_admins.clone(),
            &admin_hosts,
            // Already validated by `TenancyConfig::validate`, called at the
            // top of this function, so this cannot fail. Propagated rather
            // than `expect`ed because a `.expect` here would be a panic on a
            // path that a malformed config should have refused earlier —
            // and quietly substituting an empty list would turn that config
            // bug into a security control that silently does nothing.
            config
                .tenancy
                .parsed_trusted_proxies()
                .map_err(anyhow::Error::msg)?,
        ));

        // The appliance section (item 14). Merged into the admin panel's router
        // so it shares one session, one cookie and one CSRF token — a second
        // `SessionManagerLayer` would mean a second login for one operator.
        //
        // A **separate struct with its own state**, and `AdminPanel` gains no
        // field for it. That is what keeps the panel's never-open-a-tenant-DB
        // invariant (§6.6.6) a property of its types: the appliance service
        // holds one *configured path*, never a `TenantStore` that could resolve
        // an arbitrary tenant.
        let appliance = build_appliance_panel(config, &control_plane, config_file)?;

        Some(admin_panel.router_with(appliance))
    };

    // §7.4 (item 18): the readiness probe, over the same two things a request
    // needs — the control plane and the tenant pool. Built here because this is
    // the only place that has all three (the control plane Arc, the cache, and
    // the resolved data root).
    let readiness = Arc::new(crate::readiness::ReadinessProbe::new(
        Arc::new(control_plane.clone()),
        Arc::clone(&cache),
        config
            .tenancy
            .data_root(&config.data_store)
            .map_err(anyhow::Error::msg)?,
    ));

    Ok(TenancyAwareApp::Hosted(Arc::new(Tenancy::with_readiness(
        dispatch,
        panel,
        &admin_hosts,
        readiness,
    ))))
}

/// Build the appliance section, or `None` when it is not configured.
///
/// **`None` is the default and it means absent** — no routes, on no host. An
/// install that upgrades does not acquire a panel that can replace its database
/// because a new config section was added, which is §6.6.2's rule applied a
/// second time.
///
/// # Errors
/// [`Config::appliance_paths`]'s refusals. A **startup refusal**, not a
/// warning: a panel whose restore has no target is a control surface that looks
/// armed and is not, and an operator discovers that at the worst possible moment.
fn build_appliance_panel(
    config: &Config,
    control_plane: &SqliteTenantStore,
    config_file: Option<&std::path::Path>,
) -> anyhow::Result<Option<Arc<AppliancePanel>>> {
    if !config.appliance.enabled {
        return Ok(None);
    }
    let paths = config.appliance_paths().map_err(anyhow::Error::msg)?;

    // The config file's **text**, for the redaction pass's key-shape half. Read
    // once here rather than per-request: a config that became unreadable after
    // boot is then a fact about this build, not a surprise that appears and
    // disappears between page views.
    //
    // **Read for structure, never echoed.** §5.2 records that a `sed` on this
    // file during a previous session put two SMTP passwords and the RSVP secret
    // into a transcript. This read exists so the panel's *own* output is
    // redacted; the value never leaves this function except as a `&str` handed
    // straight to `secrets_in`.
    //
    // An unreadable or absent path yields an empty string, and the redaction
    // falls back to the typed config's known secrets. That is a **weaker** pass
    // and it is stated rather than glossed: the key-shape pass, which covers a
    // field a later version added, needs the file. The support bundle remains
    // the surface that shows an operator the full redacted config.
    let raw_config = config_file
        .and_then(|path| std::fs::read_to_string(path).ok())
        .unwrap_or_default();

    let binary = crate::appliance::current_executable()
        .unwrap_or_else(|| std::path::PathBuf::from("/usr/sbin/rustical"));

    let facts = crate::appliance::ApplianceFacts {
        database: paths.database.clone(),
        backup_dir: paths.backup_dir.clone(),
        binary,
        overlay_mount: paths.overlay_mount.clone(),
        config: config.clone(),
        raw_config,
    };

    let firmware_dir = paths.firmware_dir.clone();
    let service = crate::appliance_service::service_for(
        facts,
        crate::appliance_service::sysupgrade_writer(),
        // A **clone of the same control plane**, for the audit trail only.
        Arc::new(control_plane.clone()),
        Arc::new(crate::setup_mode::ProcdRestart),
        firmware_dir.clone(),
    )?;

    info!(
        database = %paths.database.display(),
        backup_dir = %paths.backup_dir.display(),
        firmware_dir = %firmware_dir.display(),
        "appliance panel enabled"
    );
    Ok(Some(Arc::new(AppliancePanel::new(service))))
}

/// Open and migrate the control plane — a **different file** from any tenant
/// store (§3.4).
///
/// # Errors
/// If the control plane cannot be opened or migrated. The message names the URL,
/// because a control plane that will not open is a path problem and the path is
/// the only thing an operator can act on.
pub async fn open_control_plane(url: &str) -> anyhow::Result<SqliteTenantStore> {
    let pool = create_control_plane_pool(url, true)
        .await
        .map_err(|e| anyhow::anyhow!("could not open the control plane at {url}: {e}"))?;
    Ok(SqliteTenantStore::new(pool))
}

/// The environment variable that names the tenant a CLI command acts as.
///
/// Deliberately **not** a config key: `Config` is `deny_unknown_fields`, so
/// adding it there makes every command fail with `unknown field`. The first
/// version used `RUSTICAL_TENANT` and failed exactly that way, on every
/// command. A separate prefix is also the honest shape — this is a selection,
/// not a configuration value, and should not sit in `config.toml` next to
/// `[tenancy]`.
pub const TENANT_ENV: &str = "OMNICAL_TENANT";

/// The explicitly selected tenant, if the operator named one.
///
/// Deliberately **explicit only**, with no fallback to `default_tenant`: this is
/// what the layering of a tenant's `config_json` is keyed on, and layering the
/// default tenant's overrides into every command that did not ask for a tenant
/// is a separate decision. [`cli_tenant_slug`] is the one that falls back.
#[must_use]
pub fn tenant_selection() -> Option<String> {
    std::env::var(TENANT_ENV)
        .ok()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
}

/// The tenant a CLI command should resolve its database for: the explicit
/// selection, else `default_tenant`.
///
/// `None` only when tenancy is on and neither is set, which
/// [`TenancyConfig::validate`](crate::config::TenancyConfig::validate) already
/// refuses to boot a server for.
#[must_use]
pub fn cli_tenant_slug(config: &Config) -> Option<String> {
    tenant_selection().or_else(|| {
        let fallback = config.tenancy.default_tenant.trim();
        (!fallback.is_empty()).then(|| fallback.to_owned())
    })
}

/// The data store a **CLI command** must use — which, with tenancy enabled, is
/// not `config.data_store`.
///
/// ## Why this exists
///
/// With `[tenancy] enabled = true` the server never reads
/// `[data_store.sqlite] db_url`. [`tenant_builder`] builds a per-tenant
/// `DataStoreConfig` pointing at `{data_root}/tenants/{id}/db.sqlite3` and
/// calls [`get_store_bundle`](crate::get_store_bundle) with that, once per
/// tenant. The platform database named by `db_url` holds the control plane's
/// own tables and, on a tenancy install, **no tenant data at all**.
///
/// A CLI command that passed `config.data_store` was therefore mutating a file
/// the server does not read, while reporting success. Measured on a live
/// router: `app-token create` printed a secret, the token appeared in
/// `app-token list`, and no row existed in the tenant database — so the secret
/// 401'd. `regenerate` rotated a hash the server never consulted, so **the
/// previous secret kept working**; `remove` dropped the token from `list` while
/// the row survived in the database the server reads. A credential rotation
/// runbook whose gate is "the old token 401s" cannot catch that, because a
/// rotation that fails to revoke never trips its own gate.
///
/// And the obvious existing mechanism does not cover it: `OMNICAL_TENANT` layers
/// a tenant's `config_json` over the global config, but
/// [`Config::with_tenant_overrides`] overrides `scheduling`, `subscriptions` and
/// `registration` — **not `data_store`**. So naming a tenant got the SMTP
/// identity and the register link right and still pointed the command at the
/// platform database.
///
/// This is the same family as the `backup-all` bug documented on
/// [`TenancyConfig::tenant_db_path`]: a second, wrong answer to "where does this
/// tenant's data live", in a file the server never reads.
///
/// ## Which tenant
///
/// [`OMNICAL_TENANT`](TENANT_ENV) wins — an operator who named a tenant meant
/// that one. Otherwise `default_tenant`: a CLI command has no `Host` header, so
/// the server's step-2 chain has nothing to work with, and `default_tenant` is
/// its documented last resort and N=1 escape hatch for exactly this shape of
/// install. That fallback is the case that broke on the appliance, where
/// nothing selects a tenant and every command fell through to the platform
/// database.
///
/// `get_tenant_by_slug` returns `None` for a suspended tenant, so this refuses
/// a suspended one for free — a CLI must not become a way to edit the data of a
/// tenant the server has taken away.
///
/// ## What is preserved
///
/// Only `db_url` is redirected. `run_repairs` and `skip_broken` stay whatever
/// the global config says, because those are operator-chosen and a CLI command
/// asking for repairs should get them.
///
/// # Errors
/// If tenancy is enabled and the selected tenant cannot be resolved — none
/// selected, unknown, or suspended. Each names the slug, because that is what the
/// operator can edit. Also if the control plane or the tenant store directory
/// cannot be opened.
pub async fn cli_data_store(config: &Config) -> anyhow::Result<DataStoreConfig> {
    if !config.tenancy.enabled {
        return Ok(config.data_store.clone());
    }
    let DataStoreConfig::Sqlite(global) = &config.data_store;

    // Already tenant-scoped? Leave it alone.
    //
    // `OMNICAL_TENANT` and `default_tenant` are how a *global* config finds a
    // tenant, but a config may already name a tenant's own database — the
    // integration harness writes one per tenant, and an operator can too.
    // Redirecting in that case would resolve the tenant a second time and could
    // point the command at a *different* tenant's database than the config asked
    // for, which is worse than the bug this function exists to fix.
    if let (Ok(configured), Ok(root)) = (
        global.database_file(),
        config.tenancy.data_root(&config.data_store),
    ) && configured.starts_with(root.join("tenants"))
    {
        return Ok(config.data_store.clone());
    }

    let Some(slug) = cli_tenant_slug(config) else {
        anyhow::bail!(
            "[tenancy] is enabled but neither {TENANT_ENV} nor [tenancy] default_tenant names a \
             tenant, so there is nothing for a CLI command to act on. Set one, or pass the store \
             path explicitly."
        );
    };

    let control_plane = open_control_plane(&config.tenancy.control_db_url).await?;
    let tenant = control_plane
        .get_tenant_by_slug(&slug)
        .await?
        .ok_or_else(|| {
            anyhow::anyhow!(
                "no active tenant with slug {slug:?} in {}. A suspended tenant is \
             indistinguishable from an unknown one here by design; check \
             `rustical tenants list`.",
                config.tenancy.control_db_url
            )
        })?;

    // The same two calls, in the same order, as `tenant_builder` above. If one
    // of them ever changes there it has to change here too, which is why this
    // is written out rather than shared: the closure is the server's hot path
    // and this is not, and the alternative — a helper both call — is a
    // refactor of working dispatch code for the sake of four CLI sites.
    let root = config
        .tenancy
        .data_root(&config.data_store)
        .map_err(anyhow::Error::msg)?;
    let db_path = config
        .tenancy
        .ensure_tenant_store_dir(&root, &tenant.id)
        .map_err(anyhow::Error::msg)?;

    Ok(DataStoreConfig::Sqlite(SqliteDataStoreConfig {
        db_url: format!("sqlite://{}", db_path.display()),
        run_repairs: global.run_repairs,
        skip_broken: global.skip_broken,
    }))
}

/// The closure that turns one tenant into `(stores, router)`.
///
/// Everything a tenant needs is inside the closure, so the dispatch loop stays a
/// pure "resolve then serve".
/// Starts this tenant's background tasks, at most once per tenant.
///
/// iMIP ingestion, the DAV-push notifier and trash retention are per-tenant
/// facts: the IMAP accounts that receive RSVP replies, the collections whose
/// deletions expire, and the subscriptions that need notifying all belong to one
/// tenant's database. Spawning them once from `cmd_serve` meant every tenant but
/// one got none, and the one that did got them against the platform database —
/// which `cmd_serve` no longer does under tenancy, see the guards there.
///
/// `spawned` guards the **once**: the tenant closure runs on every cache miss,
/// and a tenant evicted from `StoreBundleCache` and requested again would
/// otherwise get a second set of tasks over the same rows — double deletes,
/// duplicate notifications, two pollers on one IMAP folder. A task set that has
/// been spawned is never restarted, so a long-lived process also never
/// accumulates tasks for tenants that have fallen out of the cache.
///
/// Takes `update_recv` out of the bundle: consuming the receiver half of that
/// channel is what makes this tenant's DAV-push notifications drain rather than
/// queue unread.
fn spawn_tenant_tasks(
    tenant_id: &TenantId,
    spawned: &Mutex<HashSet<String>>,
    config: &Config,
    ingest_scheduler: Option<&Arc<Scheduler>>,
    bundle: &mut StoreBundle<impl AuthenticationProvider>,
) {
    let Ok(mut guard) = spawned.lock() else {
        // A poisoned lock means some other tenant's task set panicked on the way
        // in. Refusing to spawn this one is safer than a second set.
        tracing::error!("not starting background tasks: the per-tenant guard is poisoned");
        return;
    };
    if !guard.insert(tenant_id.to_string()) {
        return;
    }
    drop(guard);

    if let Some(scheduler) = ingest_scheduler {
        rustical_scheduling::ingest::spawn_ingestion(scheduler, &crate::shutdown_signal);
    }

    let update_recv = bundle.update_recv.take();
    if config.dav_push.enabled {
        let dav_push_store = bundle.dav_push_store.clone();
        let allowed = config.dav_push.allowed_push_servers.clone();
        tokio::spawn(async move {
            // The VAPID keypair is per tenant, so this service can only be built
            // once the tenant's bundle exists.
            let vapid_key = match dav_push_store.get_vapid_keypair().await {
                Ok(vapid_key) => (*vapid_key).clone(),
                Err(e) => {
                    tracing::error!(
                        "DAV-push notifier not started for this tenant: reading its VAPID \
                         keypair failed: {e}"
                    );
                    return;
                }
            };
            match DavPushService::new(allowed, dav_push_store, vapid_key) {
                Ok(service) => {
                    if let Some(recv) = update_recv {
                        service.notifier_loop(recv).await;
                    }
                }
                Err(e) => {
                    tracing::error!("this tenant's DAV-push notifier is invalid: {e}");
                }
            }
        });
    }

    if let Some(days) = config.maintenance.trash_retention_days {
        let cal_store: Arc<dyn CalendarStorePruneDeleted> = Arc::new((*bundle.cal_store).clone());
        tokio::spawn(crate::tasks::cleanup_trashed_calendar_entities(
            cal_store,
            days,
            crate::shutdown_signal(),
        ));
    }
}

fn tenant_builder(
    config: &Config,
    _control_plane: &SqliteTenantStore,
    _cache: &Arc<StoreBundleCache>,
) -> TenantBuilder {
    let config = config.clone();
    // One background task set per tenant, ever — see the note at the spawn.
    let spawned: Arc<std::sync::Mutex<std::collections::HashSet<String>>> =
        Arc::new(std::sync::Mutex::new(std::collections::HashSet::new()));
    Arc::new(move |tenant| {
        let config = config.clone();
        // Cloned, not moved: the outer closure is `Fn` and runs once per
        // request that misses the cache.
        let spawned = spawned.clone();
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

            let mut app_config =
                app_config_for(&config).map_err(|e| format!("the tenant router config: {e}"))?;
            // Cloned before the move on the next line: the per-tenant iMIP
            // ingestion task below needs its own handle to this scheduler.
            let ingest_scheduler = scheduler.clone();
            app_config.scheduler = scheduler;
            app_config.subscriptions = subscriptions;
            app_config.registration = registration;
            app_config.subscriptions_public_url = public_base;
            app_config.smtp_accounts.clone_from(&scheduling.smtp);

            let mut bundle = bundle;

            spawn_tenant_tasks(
                &tenant.id,
                &spawned,
                &config,
                ingest_scheduler.as_ref(),
                &mut bundle,
            );

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
fn app_config_for(config: &Config) -> Result<AppConfig, String> {
    let public_base = config
        .subscriptions
        .public_url
        .clone()
        .unwrap_or_else(|| "http://localhost".to_owned());

    // C5, §7.3.4: the parsed proxy trust list is put on the `FrontendConfig`
    // copy here, so **every** tenant's router is built from the same one and
    // neither the registration limiter nor the two password-reset limiters can
    // end up with a different view of who is allowed to set
    // `X-Forwarded-For`.
    //
    // Parsed per tenant rather than once at startup because this is the only
    // place a tenant's `AppConfig` is built, and the cost is a handful of
    // address comparisons per *tenant build* — not per request. A first draft
    // forgot this entirely, which left the whole feature inert on the tenancy
    // path; the fail-closed default hid it, and only the *second* direction of
    // the row-34 test ("a configured proxy gets real per-client buckets") caught
    // it. A missing capability that fails safe is still a missing capability.
    let mut frontend = config.frontend.clone();
    frontend.trusted_proxies = config
        .tenancy
        .parsed_trusted_proxies()
        .map_err(|e| format!("trusted_proxies: {e}"))?;

    Ok(AppConfig {
        frontend,
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
        // §18.42: the mirror config rides the same per-tenant path as the
        // extensions above — this is the production (router) route, so
        // these two are the ones that matter. Targets verbatim from
        // `[mirror.targets]`; the deployment timezone is the cascade's
        // second rung (the owner's own setting, looked up per run, is the
        // first), UTC last.
        mirror_targets: config.mirror.targets.clone(),
        mirror_timezone: config
            .caldav
            .dailyview_timezone()
            .map_or_else(|| "UTC".to_owned(), str::to_owned),
    })
}
