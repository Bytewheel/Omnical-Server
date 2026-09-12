#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
use crate::config::{Config, HttpBindConfig};
use anyhow::{Result, anyhow};
use app::make_app;
use axum::ServiceExt;
use axum::extract::Request;
use clap::{Parser, Subcommand};
use config::{DataStoreConfig, SqliteDataStoreConfig};
use provided_listeners::ProvidedListeners;
use register::RegistrationContext;
use rustical_dav_push::{DavPushService, DavPushStore, VapidStore};
use rustical_scheduling::Scheduler;
use rustical_store::auth::AuthenticationProvider;
use rustical_store::{AddressbookStore, CalendarStore, CollectionOperation, PrefixedCalendarStore};
use rustical_store::{CalendarSourceStore, InviteStore, SchedulingStore, SubscriptionStore};
use rustical_store_sqlite::SqliteAddressbookStore;
use rustical_store_sqlite::SqliteCalendarStore;
use rustical_store_sqlite::SqlitePrincipalStore;
use rustical_store_sqlite::SqliteSchedulingStore;
use rustical_store_sqlite::SqliteSubscriptionStore;
use rustical_store_sqlite::{
    SqliteCalendarSourceStore, SqliteDavPushStore, SqliteInviteStore, create_db_pool,
};
use setup_tracing::setup_tracing;
use std::fs;
use std::os::unix::fs::FileTypeExt;
use std::sync::Arc;
use tokio::sync::Notify;
use tokio::sync::mpsc::Receiver;
use tower::Layer;
use tower_http::normalize_path::NormalizePathLayer;
use tracing::{info, warn};

pub mod app;
mod commands;
mod tasks;
pub use commands::*;
pub mod config;
pub mod export;
pub mod register;
pub mod rsvp;
mod setup_tracing;
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
    Invites(InvitesArgs),
}

#[allow(clippy::missing_errors_doc)]
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
)> {
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

            (
                addressbook_store,
                cal_store,
                dav_push_store,
                principal_store,
                recv,
                scheduling_store,
                subscription_store,
                invite_store,
                calendar_source_store,
            )
        }
    })
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

    let (
        addr_store,
        cal_store,
        dav_push_store,
        principal_store,
        update_recv,
        scheduling_store,
        subscription_store,
        invite_store,
        _calendar_source_store,
    ) = get_data_stores(!args.no_migrations, &config.data_store).await?;

    if config.dav_push.enabled {
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
        invite_store,
    );

    // Inbound iMIP ingestion: poll the configured IMAP mailboxes for
    // attendee REPLY emails. No-op unless [scheduling.imap] is configured.
    if let Some(scheduler) = scheduler.clone() {
        rustical_scheduling::ingest::spawn_ingestion(scheduler, shutdown_signal);
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
                _ => None,
            }),
    );

    let app = make_app(
        addr_store.clone(),
        cal_store.clone(),
        dav_push_store.clone(),
        principal_store.clone(),
        config.frontend.clone(),
        config.oidc.clone(),
        config.caldav,
        scheduler,
        subscriptions,
        registration,
        &config.nextcloud_login,
        config.dav_push.enabled,
        config.http.session_cookie_samesite_strict,
        config.http.payload_limit_mb,
        _calendar_source_store,
        subscriptions_public_url,
    );
    let app = ServiceExt::<Request>::into_make_service(
        NormalizePathLayer::trim_trailing_slash().layer(app),
    );

    let mut provided_listeners = ProvidedListeners::from_env()?;
    if let Some(trash_retention_days) = config.maintenance.trash_retention_days {
        tokio::spawn(tasks::cleanup_trashed_calendar_entities(
            cal_store.clone(),
            trash_retention_days,
            shutdown_signal(),
        ));
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
                    start_notifier.notify_waiters();
                }
                axum::serve(listener, app)
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
                    start_notifier.notify_waiters();
                }
                axum::serve(listener, app)
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

async fn shutdown_signal() -> () {
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
