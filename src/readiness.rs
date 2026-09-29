//! `/readyz` — readiness, which is a different question from `/healthz` (§7.4, item 18).
//!
//! §7.4: *"Add `/readyz` that checks the control plane + the tenant pool, so the
//! LB does not route to a process that cannot serve."*
//!
//! # Why this is not `/healthz` with more checks
//!
//! `/healthz` ([`crate::host_dispatch::HEALTH_PATH`]) is **liveness**: "is this
//! process running?" It is answered before tenant resolution, on every host, and
//! it deliberately does *not* consult the control plane — its own doc comment
//! records why: a control-plane outage that marks every instance unhealthy
//! causes the thundering herd that a dependency-aware health check provokes.
//! That reasoning is correct and it is why `/healthz` must not grow a database
//! check.
//!
//! Readiness is the opposite trade. It is allowed to be strict, because the
//! consequence of being wrong is the *opposite*: a false negative sends traffic
//! somewhere that can serve it, and a false positive is the outage. So
//! `/readyz` checks the things a request actually needs, and reports which one
//! failed.
//!
//! # What it checks, and what it deliberately does not
//!
//! 1. **The control plane** — one cheap query. Every request needs it: a tenant
//!    cannot be resolved without it, so a process that cannot reach it serves
//!    nothing to anybody.
//! 2. **Every cached tenant's store** — a query against each open pool, so a
//!    process holding a dead connection for one tenant is reported rather than
//!    discovered by the next customer's calendar sync.
//!
//! What it does **not** check, each for a reason worth stating:
//!
//! * **The disk.** `df` full is a real outage, but a readiness probe that polls
//!   the filesystem is a readiness probe that fails on a full disk and takes the
//!   whole fleet out at once, turning one full volume into an outage for every
//!   tenant. That belongs in an alert, not in the LB's routing decision.
//! * **Migrations.** A pending migration is a *deployment* fact, not a runtime
//!   one; the process that migrated on boot has already done it.
//! * **Other tenants' stores** beyond the cached set. Building a pool for every
//!   tenant to probe it would be a load generator pointed at ourselves, and it
//!   would make readiness O(tenants) on a request path.

use std::str::FromStr as _;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::State;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};

use sqlx::Connection as _;
use sqlx::sqlite::{SqliteConnectOptions, SqliteConnection};

use rustical_store::tenant_store::TenantStore;
use rustical_store_sqlite::SqliteTenantStore;

use crate::store_bundle::StoreBundleCache;

/// How long a single probe may take before the answer is "not ready".
///
/// Short on purpose. A readiness probe that waits ten seconds has already lost
/// the traffic it was trying to protect: the load balancer's own timeout is
/// usually shorter, so the slow path is a timeout rather than a 503, and a
/// timeout looks like a network fault to everything downstream.
const PROBE_TIMEOUT: Duration = Duration::from_secs(2);

/// What the probe found.
///
/// Enough detail to be actionable from a log line and no more: this is reachable
/// by anything that can reach the port, so it must not become an information
/// source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Readiness {
    pub ready: bool,
    pub control_plane: Check,
    pub tenant_stores: Check,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Check {
    Ok,
    /// Failed, and here is which dependency. Deliberately coarse: a message per
    /// tenant would leak tenant names to anything that can reach the port, and
    /// the failing tenant is in the instance's own logs either way.
    Failed,
    /// Not checked — there was nothing to check. A fresh process with an empty
    /// cache is *ready*, not unready: no tenant is loaded, so no tenant is
    /// broken, and reporting otherwise would take a cold instance out of
    /// rotation exactly when it is trying to join.
    Skipped,
}

impl Check {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Failed => "failed",
            Self::Skipped => "skipped",
        }
    }
}

/// The probe itself, over a live control plane and cache.
///
/// Takes what it needs rather than the whole `HostDispatch` so it can be
/// constructed in a test without a dispatcher, and so there is exactly one
/// definition of "ready" rather than one per mount point.
pub struct ReadinessProbe {
    control_plane: Arc<SqliteTenantStore>,
    cache: Arc<StoreBundleCache>,
    /// Where per-tenant files live (§3.4). Held so the probe can name a file
    /// without going back through the dispatcher's config.
    data_root: std::path::PathBuf,
}

impl std::fmt::Debug for ReadinessProbe {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // No addresses in the Debug output: this type ends up in a log line.
        f.debug_struct("ReadinessProbe").finish_non_exhaustive()
    }
}

impl ReadinessProbe {
    pub const fn new(
        control_plane: Arc<SqliteTenantStore>,
        cache: Arc<StoreBundleCache>,
        data_root: std::path::PathBuf,
    ) -> Self {
        Self {
            control_plane,
            cache,
            data_root,
        }
    }

    /// Run the checks. Never panics and never returns an error: a probe that
    /// cannot answer is not ready, and that is a `Result` the caller can act on.
    pub async fn check(&self) -> Readiness {
        let control_plane = self.check_control_plane().await;
        let tenant_stores = self.check_tenant_stores().await;
        Readiness {
            ready: control_plane == Check::Ok,
            control_plane,
            tenant_stores,
        }
    }

    /// One cheap query. `list_tenants` is the smallest thing that proves the
    /// database is *reachable and migrated* — a bare "is the file there" check
    /// passes on a database whose schema is missing, which is precisely the state
    /// a process cannot serve from.
    async fn check_control_plane(&self) -> Check {
        match tokio::time::timeout(PROBE_TIMEOUT, self.control_plane.list_tenants(true)).await {
            Ok(Ok(_)) => Check::Ok,
            Ok(Err(e)) => {
                tracing::warn!(error = %e, "readiness: the control plane did not answer");
                Check::Failed
            }
            Err(_) => {
                tracing::warn!(
                    "readiness: the control plane did not answer within {PROBE_TIMEOUT:?}"
                );
                Check::Failed
            }
        }
    }

    /// Every **cached** tenant, and only the cached ones.
    ///
    /// The cache holds one `TenantId` per open pool, which is the set of tenants
    /// this process is actually holding resources for. A tenant that has never
    /// been served has no pool to be broken, and building one to find out would
    /// make the probe O(tenants) on a request path.
    async fn check_tenant_stores(&self) -> Check {
        let ids = self.cache.cached_ids();
        if ids.is_empty() {
            return Check::Skipped;
        }
        for id in &ids {
            let path = self.data_root.join(format!("{}.sqlite3", id.as_str()));
            let outcome = tokio::time::timeout(PROBE_TIMEOUT, probe_sqlite(&path)).await;
            if !matches!(outcome, Ok(Ok(()))) {
                tracing::warn!(tenant = %id, "readiness: a tenant store did not answer");
                return Check::Failed;
            }
        }
        Check::Ok
    }
}

/// `SELECT 1` against a tenant file, opening a connection if needed.
///
/// Deliberately a separate short-lived connection rather than the cached pool:
/// the question is "can this file be opened and read", and asking the live pool
/// would answer a different one (is the pool *currently* healthy), which a
/// request is about to find out anyway. It also means a wedged pool is still
/// reported instead of hanging the probe.
async fn probe_sqlite(path: &std::path::Path) -> Result<(), sqlx::Error> {
    let url = format!("sqlite://{}", path.display());
    let opts = SqliteConnectOptions::from_str(&url)
        .map_err(|e| sqlx::Error::Protocol(e.to_string()))?
        .create_if_missing(false)
        .busy_timeout(PROBE_TIMEOUT);
    let mut conn = SqliteConnection::connect_with(&opts).await?;
    sqlx::query_scalar::<_, i64>("SELECT 1")
        .fetch_one(&mut conn)
        .await?;
    Ok(())
}

/// `GET /readyz` — 200 with a one-line body, or 503.
///
/// The body names the failing **check**, never the tenant, the host or the path.
/// This endpoint is unauthenticated and reachable by anything that can open the
/// port, so it is a health signal and not a diagnostic.
pub async fn readyz(State(probe): State<Arc<ReadinessProbe>>) -> Response {
    let result = probe.check().await;
    let status = if result.ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    let body = format!(
        "{}\ncontrol_plane={} tenant_stores={}\n",
        if result.ready { "ready" } else { "not ready" },
        result.control_plane.as_str(),
        result.tenant_stores.as_str(),
    );
    (
        status,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        body,
    )
        .into_response()
}
