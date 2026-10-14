#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
use crate::config::{Config, HttpBindConfig};
use anyhow::{Result, anyhow};
use app::make_app;
use axum::ServiceExt;
use axum::extract::Request;
use clap::{Parser, Subcommand};
use config::{DataStoreConfig, SqliteDataStoreConfig};
use host_dispatch::TenancyAwareApp;
use provided_listeners::ProvidedListeners;
use register::RegistrationContext;
use rustical_dav_push::{DavPushService, DavPushStore, VapidStore};
use rustical_scheduling::Scheduler;
use rustical_store::auth::AuthenticationProvider;
use rustical_store::{AddressbookStore, CalendarStore, CollectionOperation, PrefixedCalendarStore};
use rustical_store::{
    CalendarSourceStore, CollectionShareStore, InviteStore, MirrorStore, PasswordResetStore,
    PrintStore, SchedulingStore, SubscriptionStore,
};
use rustical_store_sqlite::SqliteAddressbookStore;
use rustical_store_sqlite::SqliteCalendarStore;
use rustical_store_sqlite::SqlitePrincipalStore;
use rustical_store_sqlite::SqliteSchedulingStore;
use rustical_store_sqlite::SqliteSubscriptionStore;
use rustical_store_sqlite::{
    SqliteCalendarSourceStore, SqliteCollectionShareStore, SqliteDavPushStore, SqliteInviteStore,
    SqliteMirrorStore, SqlitePasswordResetStore, SqlitePrintStore, create_db_pool,
};
use setup_tracing::setup_tracing;
use std::fs;
use std::net::SocketAddr;
use std::os::unix::fs::FileTypeExt;
use std::sync::Arc;
use store_bundle::StoreBundle;
use tokio::sync::Notify;
use tokio::sync::mpsc::Receiver;
use tower::Layer;
use tower_http::normalize_path::NormalizePathLayer;
use tracing::{info, warn};

pub mod admin;
pub mod app;
pub mod appliance;
pub mod appliance_service;
pub mod build_provenance;
pub mod commands;
mod tasks;
pub use commands::*;
pub mod config;
// §18.42: the push-mirror engine moved to `rustical_caldav::mirror`; the
// re-export keeps `crate::mirror::sync_target` (the CLI, the background
// loop) resolving as before.
pub use rustical_caldav::mirror;
pub mod export;
pub mod host_dispatch;
pub mod quota;
pub mod readiness;
pub mod register;
pub mod rsvp;
pub mod setup_mode;
mod setup_tracing;
pub mod source_offer;
pub mod store_bundle;
pub mod tenancy;
pub mod tenant_overrides;
pub mod tenant_telemetry;
pub mod tenant_usage;
// Shared with the frontend crate so the portal prints byte-identical
// export URLs to the CLI (PLAN.md §17.8.4).
pub use rustical_frontend::url_builder;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    #[arg(short, long, env, default_value = "/etc/rustical/config.toml")]
    pub config_file: String,
    #[arg(long, env, help = "Do no run database migrations (only for sql store)")]
    pub no_migrations: bool,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    #[command(about = "Run the RustiCal server")]
    Serve,
    GenConfig(commands::GenConfigArgs),
    #[command(
        about = "Healthcheck for running instance (Used for HEALTHCHECK in Docker container)"
    )]
    Health(HealthArgs),
    Principals(PrincipalsArgs),
    Subscriptions(SubscriptionsArgs),
    /// §18.41: one-way push of a local calendar into a remote `CalDAV`
    /// collection (aphy in the reference deployment).
    Mirror(MirrorArgs),
    Invites(InvitesArgs),
    #[command(about = "Manage per-calendar guest shares (Omnical §17.10)")]
    GuestShare(GuestSharesArgs),
    #[command(about = "Write a verified backup archive of the database (PLAN_DEPLOYMENTS.md §8.4)")]
    Backup(commands::BackupArgs),
    /// §7.4: one archive per tenant, the payoff of C7.
    BackupAll(commands::backup::BackupAllArgs),
    /// §7.5 item 20a: measure one tenant, or all of them, into the control plane.
    #[command(about = "Measure tenant usage into the control plane (PLAN_DEPLOYMENTS.md §7.5)")]
    TenantUsage(commands::tenant_usage::TenantUsageArgs),
    #[command(about = "Restore a backup archive, verifying it first (§8.4)")]
    Restore(commands::RestoreArgs),
    #[command(about = "Interactive first-run setup wizard (PLAN_DEPLOYMENTS.md §8.2)")]
    Setup(commands::SetupArgs),
    /// §9.4's diagnostics bundle. The redaction inside it is the gate (row 50).
    SupportBundle(commands::support_bundle::SupportBundleArgs),
    #[command(about = "Create, inspect, suspend and delete tenants (PLAN_DEPLOYMENTS.md §6.5)")]
    Tenant(commands::tenants::TenantArgs),
    /// item 21 / §12 row 42: roll the schema back, or report what that would do.
    #[command(about = "Roll the database schema back (PLAN_DEPLOYMENTS.md item 21, row 42)")]
    Upgrade(commands::upgrade::UpgradeArgs),
}

/// The thirteen stores, as a named [`StoreBundle`].
///
/// §3.2 needs one of these per tenant, and the tuple this replaces had two
/// adjacent `Arc<dyn …>` fields over the same pool (`subscription_store` and
/// `invite_store`) that a reorder would not have caught. The construction body
/// below is unchanged from the tuple version; only the return shape differs.
#[allow(clippy::missing_errors_doc)]
pub async fn get_store_bundle(
    migrate: bool,
    config: &DataStoreConfig,
) -> Result<StoreBundle<SqlitePrincipalStore>> {
    Ok(match &config {
        DataStoreConfig::Sqlite(SqliteDataStoreConfig {
            db_url,
            run_repairs,
            skip_broken,
        }) => {
            let db = create_db_pool(db_url, migrate).await?;

            // Channel to watch for changes (for DAV Push)
            let (send, recv) = tokio::sync::mpsc::channel(1000);

            let addressbook_store = Arc::new(SqliteAddressbookStore::new(
                db.clone(),
                send.clone(),
                *skip_broken,
            ));
            let cal_store = SqliteCalendarStore::new(db.clone(), send, *skip_broken);
            // The scheduling store shares the calendar store's pool and push channel
            let scheduling_store: Arc<dyn SchedulingStore> =
                Arc::new(SqliteSchedulingStore::new(cal_store.clone()));
            // The share-links subscription store shares it as well
            let subscription_store: Arc<dyn SubscriptionStore> =
                Arc::new(SqliteSubscriptionStore::new(cal_store.clone()));
            // Registration (`rustical invites`) + linked platforms
            let invite_store: Arc<dyn InviteStore> =
                Arc::new(SqliteInviteStore::new(cal_store.clone()));
            let calendar_source_store: Arc<dyn CalendarSourceStore> =
                Arc::new(SqliteCalendarSourceStore::new(cal_store.clone()));
            // Guest calendar shares (Omnical §17.10) share the pool and push
            // channel too.
            let share_store: Arc<dyn CollectionShareStore> =
                Arc::new(SqliteCollectionShareStore::new(cal_store.clone()));
            // Public forgot-/reset-password tokens share them as well.
            let password_reset_store: Arc<dyn PasswordResetStore> =
                Arc::new(SqlitePasswordResetStore::new(cal_store.clone()));
            // Print-state tracking for the portal print pages shares the pool
            // too (PLAN_NEXT_AGENT_PRINTING.md §3.4).
            let print_store: Arc<dyn PrintStore> =
                Arc::new(SqlitePrintStore::new(cal_store.clone()));
            // Push-mirror state (§18.41) shares the pool as well: one table,
            // read and written only by the mirror sync.
            let mirror_store: Arc<dyn MirrorStore> =
                Arc::new(SqliteMirrorStore::new(cal_store.clone()));
            let cal_store = Arc::new(cal_store);
            if *run_repairs {
                info!("Running repair tasks");
                addressbook_store.repair_orphans().await?;
                cal_store.repair_invalid_version_4_0().await?;
                cal_store.repair_orphans().await?;
            }
            let dav_push_store = Arc::new(SqliteDavPushStore::new(db.clone()));
            // Run key generation in advance to populate local cache
            dav_push_store.initialise().await?;
            let principal_store = Arc::new(SqlitePrincipalStore::new(db));

            // Validate all calendar objects
            for principal in principal_store.get_principals().await? {
                cal_store.validate_objects(&principal.id).await?;
                addressbook_store.validate_objects(&principal.id).await?;
            }

            StoreBundle {
                addr_store: addressbook_store,
                cal_store,
                dav_push_store,
                auth_provider: principal_store,
                update_recv: Some(recv),
                scheduling_store,
                subscription_store,
                invite_store,
                calendar_source_store,
                share_store,
                password_reset_store,
                print_store,
                mirror_store,
            }
        }
    })
}

/// [`get_data_stores`] as a 14-tuple — **a shim**.
///
/// Kept so the five CLI call sites did not have to move in this commit, the
/// same way `make_app` outlived `make_app_for` (§18.11). New code should call
/// [`get_store_bundle`]: the tuple's element order is checked by nothing, and
/// two of its fields are `Arc<dyn …>` over the same pool.
#[allow(clippy::missing_errors_doc, clippy::type_complexity)]
/// The pool a single-tenant process's readiness probe runs its one query on.
///
/// **This is a second pool against the same file**, which deserves an
/// explanation rather than a justification. `store_sqlite`'s module doc argues
/// against that, and it is right about the case it means: tenant stores, where a
/// pool per cache miss multiplied across 50 residents. Here it is one extra
/// connection for one probe, on the single install that has no control plane to
/// borrow one from.
///
/// The alternative was to thread the pool out of `get_data_stores`, and that is
/// worse: it widens a public tuple return and forces four unrelated CLI call
/// sites to change, for a dependency that only exists under a feature flag. The
/// concrete `SqliteCalendarStore` is erased to `Arc<impl CalendarStore>` in that
/// return type, which is *why* the pool cannot simply be handed over.
///
/// `create_if_missing` is **not** used, and that is load-bearing: a readiness
/// probe must never be the thing that creates a database, or a typo'd `db_url`
/// becomes a fresh empty file that answers "ready" for a server holding nothing.
#[cfg(feature = "single-tenant-probes")]
async fn single_tenant_pool_for_probe(config: &DataStoreConfig) -> Result<sqlx::SqlitePool> {
    let DataStoreConfig::Sqlite(SqliteDataStoreConfig { db_url, .. }) = config;
    let options: sqlx::sqlite::SqliteConnectOptions = db_url
        .parse()
        .map_err(|error| anyhow::anyhow!("data_store.sqlite.db_url is unusable: {error}"))?;
    Ok(sqlx::SqlitePool::connect_with(
        options
            .create_if_missing(false)
            .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal),
    )
    .await?)
}

/// # Errors
/// If the store cannot be opened, or — when `migrate` is set — if a pending
/// migration fails. Both are startup failures: a server that boots with a
/// half-migrated store serves requests it will corrupt.
pub async fn get_data_stores(
    migrate: bool,
    config: &DataStoreConfig,
) -> Result<(
    Arc<impl AddressbookStore + PrefixedCalendarStore>,
    Arc<impl CalendarStore>,
    Arc<impl DavPushStore>,
    Arc<impl AuthenticationProvider>,
    Receiver<CollectionOperation>,
    Arc<dyn SchedulingStore>,
    Arc<dyn SubscriptionStore>,
    Arc<dyn InviteStore>,
    Arc<dyn CalendarSourceStore>,
    Arc<dyn CollectionShareStore>,
    Arc<dyn PasswordResetStore>,
    Arc<dyn PrintStore>,
    Arc<dyn MirrorStore>,
)> {
    let b = get_store_bundle(migrate, config).await?;
    Ok((
        b.addr_store,
        b.cal_store,
        b.dav_push_store,
        b.auth_provider,
        b.update_recv.ok_or_else(|| {
            anyhow::anyhow!("the DAV-Push channel was taken before the stores were unpacked")
        })?,
        b.scheduling_store,
        b.subscription_store,
        b.invite_store,
        b.calendar_source_store,
        b.share_store,
        b.password_reset_store,
        b.print_store,
        b.mirror_store,
    ))
}

#[allow(clippy::missing_errors_doc, clippy::missing_panics_doc)]
/// Long by design: it wires data stores, optional extensions, and the HTTP
/// server in one sequential startup path.
#[allow(clippy::too_many_lines)]
pub async fn cmd_serve(
    args: Args,
    config: Config,
    start_notifier: Option<Arc<Notify>>,
    tracing: bool,
) -> Result<()> {
    if tracing {
        setup_tracing(&config.tracing);
    }

    // Captured at the very top, because `cmd_serve` moves fields out of `config`
    // as it goes (`dav_push.allowed_push_servers` among them) and a clone taken
    // further down would be a clone of a half-moved value. The tenancy branch
    // needs a whole `Config`; the single-tenant branch ignores both.
    let tenancy_enabled = config.tenancy.enabled;
    let config_for_tenancy = config.clone();

    // Which database this process's *own* long-lived tasks run against: the
    // DAV-push notifier, iMIP ingestion, and trash retention, all of which are
    // spawned below from these stores.
    //
    // Under tenancy the server answers requests from the tenant store, so a
    // bundle built over `config.data_store` is building the wrong one — and
    // worse, silently: on an install that *copied* its store into
    // `tenants/<id>/` rather than moving it, the platform database still holds
    // a full set of tables, so nothing fails. Those tasks then run against a
    // duplicate nobody is served from. Measured on the deployed appliance:
    // inbound iMIP replies were being parsed out of IMAP and written to the
    // platform copy while every tenant was served from its own.
    //
    // Resolving the same way the CLI now does makes them act on the data that
    // actually exists. A hosted install with no `default_tenant` has no tenant
    // to resolve, and per-tenant task spawning is a larger change than this;
    // that case warns and keeps today's behaviour rather than refusing to boot.
    let serve_store = match crate::tenancy::cli_data_store(&config).await {
        Ok(store) => store,
        Err(e) => {
            warn!(
                "{e}\n    continuing on the configured data_store, which no tenant is served \
                 from: iMIP ingestion, DAV push and trash retention will not see tenant data"
            );
            config.data_store.clone()
        }
    };

    let (
        addr_store,
        cal_store,
        dav_push_store,
        principal_store,
        update_recv,
        scheduling_store,
        subscription_store,
        invite_store,
        // Unpacked and passed straight through to `make_app`, so the pool is
        // created and kept alive even though nothing reads it yet. Named so the
        // destructure says which field it is.
        calendar_source_store,
        share_store,
        password_reset_store,
        // Print-state tracking (the portal print pages' new-vs-all scope) —
        // same straight-through treatment as the share/password-reset stores.
        print_store,
        // Push-mirror state (§18.41) — consumed by the background mirror loop
        // spawned below, same straight-through treatment.
        mirror_store,
    ) = get_data_stores(!args.no_migrations, &serve_store).await?;

    // Tenancy spawns these per tenant, from the tenant closure in `tenancy.rs`,
    // over that tenant's stores. Spawning them here as well would run a second
    // set against the default tenant's database — which is the bug: on a
    // tenancy install the server never reads `config.data_store`, so iMIP
    // replies, DAV-push notifications and trash sweeps would all go to a
    // database no tenant is served from.
    if config.dav_push.enabled && !tenancy_enabled {
        let vapid_key = dav_push_store.get_vapid_keypair().await?;
        let dav_push_service = DavPushService::new(
            config.dav_push.allowed_push_servers,
            dav_push_store.clone(),
            vapid_key.clone(),
        )?;
        // Atm we never join this task
        tokio::spawn(async move {
            dav_push_service.notifier_loop(update_recv).await;
        });
    }

    // Build the Omnical extension inputs (scheduling, share feeds,
    // registration). Each is constructed only when enabled, so a disabled
    // config has zero footprint (no inbox/outbox, /export, or /register
    // routes — byte-for-byte like the current build).
    let (scheduler, subscriptions, registration) = build_extensions(
        &config.scheduling,
        &config.subscriptions,
        &config.registration,
        scheduling_store,
        subscription_store.clone(),
        invite_store.clone(),
    );

    // Inbound iMIP ingestion: poll the configured IMAP mailboxes for
    // attendee REPLY emails. No-op unless [scheduling.imap] is configured.
    if let Some(scheduler) = scheduler.clone().filter(|_| !tenancy_enabled) {
        // The spawned task is detached on purpose: it runs for the life of the
        // process and there is nothing to do with a handle to it. `spawn_ingestion`
        // returns `()`, so there is no handle to hold on to.
        rustical_scheduling::ingest::spawn_ingestion(&scheduler, &shutdown_signal);
    }

    // The base URL the portal Share page prints — computed with the same
    // `public_base_url` as the `subscriptions add` CLI, so portal and CLI
    // print byte-identical export URLs (PLAN.md §17.8.4).
    let subscriptions_public_url = url_builder::public_base_url(
        config.subscriptions.public_url.as_deref(),
        config
            .http
            .bind_config()
            .ok()
            .as_ref()
            .and_then(|c| match c {
                config::HttpBindConfig::Tcp(addr) => Some(addr.as_str()),
                // A unix socket has no address to advertise. Named rather than
                // `_` so that adding a `HttpBindConfig` variant makes this a
                // compile error instead of a silently-absent public URL.
                config::HttpBindConfig::Unix(_) => None,
            }),
    );

    // Strict SMTP receivers (Postfix `reject_unknown_helo_hostname`, e.g.
    // smtp.novo-ordo.com) require a DNS-resolvable EHLO name — identify
    // ourselves with the public hostname, never an internal placeholder.
    // Only set it when a real public URL is configured (not the bind
    // fallback, whose host would be an IP literal).
    if let Some(public_url) = config.subscriptions.public_url.as_deref() {
        rustical_scheduling::smtp::set_ehlo_name_from_url(public_url);
    }

    // §3.6's "enabled = false behaves exactly as today", enforced here rather
    let parsed_trusted_proxies = config
        .tenancy
        .parsed_trusted_proxies()
        .map_err(anyhow::Error::msg)?;
    // Carried on `FrontendConfig` as a `serde(skip)` runtime field, so the
    // operator-facing key stays `[tenancy] trusted_proxies` and there is no
    // second spelling in the config file.
    let mut frontend_config = config.frontend.clone();
    frontend_config.trusted_proxies = parsed_trusted_proxies.clone();

    // than by convention: the `false` arm below builds the *same* `make_app`
    // call with the *same* arguments and puts no dispatch layer in front of it.
    // There is no third path in which tenancy is on but not routing.
    // Read before `make_app` below consumes `config.caldav`: the §18.41
    // mirror loop stamps instances in the deployment's own zone (§18.36).
    let mirror_timezone = config
        .caldav
        .dailyview_timezone()
        .map_or_else(|| "UTC".to_owned(), str::to_owned);

    let app = make_app(
        addr_store.clone(),
        cal_store.clone(),
        dav_push_store.clone(),
        principal_store.clone(),
        frontend_config,
        config.oidc.clone(),
        config.caldav,
        scheduler,
        subscriptions,
        registration,
        &config.nextcloud_login,
        config.dav_push.enabled,
        config.http.session_cookie_samesite_strict,
        config.http.payload_limit_mb,
        // A positional argument, so the name is fixed by the callee. The store
        // is unpacked above so its pool exists; the router decides what to do
        // with it.
        calendar_source_store,
        subscriptions_public_url,
        invite_store.clone(),
        share_store,
        password_reset_store,
        print_store,
        // §18.42: the mirror state + run history store, and the config
        // axis (targets + deployment timezone) — the same three the
        // tenancy path fills from `app_config_for`.
        mirror_store.clone(),
        config.scheduling.smtp.clone(),
        config.mirror.targets.clone(),
        mirror_timezone.clone(),
    );
    let app = if tenancy_enabled {
        // The config file's path, for the appliance panel's redaction pass — see
        // `tenancy::serve_dispatch_with_config_file`. Taken from `args` rather
        // than threaded in as a new parameter because every existing caller
        // already passes `Args` and none of them has the path in scope.
        let config_file = std::path::PathBuf::from(&args.config_file);
        crate::tenancy::serve_dispatch_with_config_file(&config_for_tenancy, Some(&config_file))
            .await
            .map_err(anyhow::Error::msg)?
    } else {
        // Byte-for-byte the pre-tenancy path. No `HostDispatch`, no control
        // plane, no cache: this arm does not touch any of them.
        //
        // The one exception is opt-in and additive: with
        // `single-tenant-probes`, `/healthz` and `/readyz` are answered ahead of
        // the router, reusing the pool `cal_store` already holds rather than
        // opening a second one against the same file.
        #[cfg(feature = "single-tenant-probes")]
        {
            TenancyAwareApp::SingleProbed {
                router: app,
                readiness: std::sync::Arc::new(crate::readiness::SingleTenantReadiness::new(
                    single_tenant_pool_for_probe(&config.data_store).await?,
                )),
            }
        }
        #[cfg(not(feature = "single-tenant-probes"))]
        {
            TenancyAwareApp::Single(app)
        }
    };

    // C5, §7.3.4: the *router* is built once and the make-service is built per
    // arm, because only the TCP arm can carry connect info.
    //
    // With it, a handler can see the **immediate peer** and decide whether that
    // peer's `X-Forwarded-For` is worth believing. Without it there is no way to
    // implement a proxy trust list at all, and the three rate limiters in this
    // tree (registration, password reset, admin login) are limited by an
    // attacker-chosen address behind a load balancer.
    //
    // A Unix socket has no peer *address*, so the Unix arm keeps the plain
    // make-service and its handlers see `ConnectInfo` as absent — for which
    // `client_ip` returns `<local>`, the honest answer, since no proxy can be in
    // the path of a Unix socket.
    //
    // `SocketAddr` and not something more permissive, because `axum` requires a
    // concrete `FromConnectInfo` and anything looser would be another place a
    // peer address could be forged.
    let app = NormalizePathLayer::trim_trailing_slash().layer(app);

    let mut provided_listeners = ProvidedListeners::from_env()?;
    if let Some(trash_retention_days) = config
        .maintenance
        .trash_retention_days
        .filter(|_| !tenancy_enabled)
    {
        {
            tokio::spawn(tasks::cleanup_trashed_calendar_entities(
                cal_store.clone(),
                trash_retention_days,
                shutdown_signal(),
            ));
        }
    }

    // §18.41 push mirrors: one loop per target, over the default tenant's
    // stores. Tenancy deployments do not get a background mirror yet — a
    // target names its source principal explicitly, and per-tenant mirror
    // wiring is §7 work, not §18.41's.
    //
    // The loop takes the auth provider and the **deployment** timezone
    // (§18.42): the owner's own zone is looked up fresh on every tick, so a
    // user changing their zone mid-uptime is picked up without a restart —
    // `run_mirror_target` resolves the cascade per run.
    if config.mirror.enabled && !tenancy_enabled {
        for target in config.mirror.targets.clone() {
            tokio::spawn(tasks::run_mirror_target(
                target,
                cal_store.clone(),
                mirror_store.clone(),
                principal_store.clone(),
                mirror_timezone.clone(),
                shutdown_signal(),
            ));
        }
    }

    let bind_config = config.http.bind_config()?;
    let serve_task = match bind_config {
        HttpBindConfig::Tcp(address) => {
            let listener = provided_listeners
                .tcp_tokio_resolved_or_bind(&address)
                .await?;

            tokio::spawn(async move {
                info!("RustiCal serving on http://{address}");
                if let Some(start_notifier) = start_notifier {
                    // `notify_one`, deliberately: it stores a permit, so a
                    // waiter that registers after the signal still wakes.
                    // `notify_waiters` woke only listeners polled at the
                    // exact signal instant — under the CI runner's crowded
                    // scheduling the spawned server could out-run the test
                    // thread to this line, the wakeup was lost, and the
                    // http_integration startup wait died on its timeout.
                    start_notifier.notify_one();
                }
                let make =
                    ServiceExt::<Request>::into_make_service_with_connect_info::<SocketAddr>(app);
                axum::serve(listener, make)
                    .with_graceful_shutdown(shutdown_signal())
                    .await
                    .unwrap();
            })
        }

        HttpBindConfig::Unix(path) => {
            let listener = if let Some(listener) = provided_listeners.unix_tokio(path.as_path()) {
                listener?
            } else {
                if path.exists() {
                    let metadata = fs::metadata(&path)?;
                    if metadata.file_type().is_socket() {
                        // Only remove existing file if it's a socket
                        fs::remove_file(&path)?;
                    } else {
                        return Err(anyhow!(
                            "Path {path} exists and is not a socket",
                            path = path.display()
                        ));
                    }
                }

                tokio::net::UnixListener::bind(&path)?
            };

            tokio::spawn(async move {
                info!("RustiCal serving on unix://{path}", path = path.display());
                if let Some(start_notifier) = start_notifier {
                    // See the TCP arm: `notify_one` keeps the permit, so the
                    // waiter cannot miss the wakeup.
                    start_notifier.notify_one();
                }
                // **No** connect info: a Unix socket has no peer address, and
                // `SocketAddr: Connected<UnixStream>` does not exist. The
                // handlers here see no peer, and `client_ip` answers `<local>`.
                let make = ServiceExt::<Request>::into_make_service(app);
                axum::serve(listener, make)
                    .with_graceful_shutdown(shutdown_signal())
                    .await
                    .unwrap();
            })
        }
    };

    serve_task.await?;

    Ok(())
}

/// Construct the Omnical extension inputs (scheduling, share feeds,
/// registration), each only when enabled.
#[allow(clippy::type_complexity)]
fn build_extensions(
    scheduling_config: &rustical_scheduling::SchedulingConfig,
    subscriptions_config: &config::SubscriptionsConfig,
    registration_config: &config::RegistrationConfig,
    scheduling_store: Arc<dyn SchedulingStore>,
    subscription_store: Arc<dyn SubscriptionStore>,
    invite_store: Arc<dyn InviteStore>,
) -> (
    Option<Arc<Scheduler>>,
    Option<Arc<dyn SubscriptionStore>>,
    Option<Arc<RegistrationContext>>,
) {
    let scheduler = scheduling_config.enabled.then(|| {
        let mut config = scheduling_config.clone();
        // The one-click RSVP link base URL defaults to the share-links
        // public URL — the same public dav-tls front end.
        if config.rsvp_base_url.is_none() {
            config
                .rsvp_base_url
                .clone_from(&subscriptions_config.public_url);
        }
        if config.rsvp_secret.is_some() && config.rsvp_base_url.is_none() {
            warn!(
                "scheduling: rsvp_secret is set but no public URL is configured \
                 ([scheduling] rsvp_base_url or [subscriptions] public_url) — \
                 invitation RSVP links stay disabled"
            );
        }
        Arc::new(Scheduler::new(config, scheduling_store))
    });
    if let Some(scheduler) = &scheduler {
        let rsvp = if scheduler.rsvp_links_enabled() {
            "enabled"
        } else {
            "disabled (no rsvp_secret / public URL)"
        };
        info!(
            "Scheduling extension enabled ({} SMTP identities, RSVP links {rsvp})",
            scheduling_config.smtp.len()
        );
    }

    let subscriptions = subscriptions_config.enabled.then_some(subscription_store);
    if subscriptions.is_some() {
        info!("Subscriptions extension enabled (public export feeds)");
    }

    let registration = registration_config.enabled.then(|| {
        Arc::new(RegistrationContext {
            config: registration_config.clone(),
            invite_store,
            subscription_store: subscriptions.clone(),
            subscriptions_public_url: subscriptions_config.public_url.clone(),
        })
    });
    if registration.is_some() {
        info!("Registration extension enabled (public /register)");
    }

    (scheduler, subscriptions, registration)
}

/// `pub(crate)` because the tenancy layer spawns **per-tenant** copies of the
/// background tasks, and those need the same shutdown signal the single-tenant
/// path uses. Not `pub`: it is not part of the crate's API.
pub(crate) async fn shutdown_signal() -> () {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => tracing::debug!("Received SIGINT signal"),
        () = terminate => tracing::debug!("Received SIGTERM signal"),
    }
}
