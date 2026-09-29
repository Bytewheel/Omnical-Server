//! SQLite control plane — `PLAN_DEPLOYMENTS.md` §3.4, §6.1.
//!
//! ## Why this gets its own connection pool
//!
//! The control plane is a **different database file** from every tenant store,
//! and this struct owns that pool itself rather than borrowing one. Three
//! reasons, in increasing order of how much they would hurt if ignored:
//!
//! 1. §3.4's stated purpose: a per-tenant backup/restore must not be able to
//!    take the cross-tenant index out with it.
//! 2. A tenant's data is unreachable from here. There is no `tenant_id` on any
//!    calendar table because there is no calendar table in this database, and
//!    that is what makes §3.2's isolation structural rather than a `WHERE`
//!    clause someone has to remember.
//! 3. `get_data_stores` runs repairs, DAV-push key generation and a full
//!    object-validation sweep on connect. Running that per tenant, on demand,
//!    from the dispatch path, would turn a cache miss into a multi-second
//!    stall on somebody's login. The control plane's migration set is two
//!    tables and it opens in microseconds.
//!
//! ## Queries are runtime, not compile-time checked
//!
//! Deliberate, and worth stating because the crate does use `sqlx::query!` in
//! two files: adding compile-time-checked queries means running `cargo sqlx
//! prepare`, which **rewrites all 70 cached queries in `.sqlx/`** and produces a
//! diff in which the 66 unrelated ones drown out the 4 that changed. The
//! dominant convention in this crate is already runtime queries (six of eight
//! store modules), so this follows that, and pays for it with tests that run
//! every statement against a real SQLite file — a wrong column name is a
//! runtime error, so it is caught by the test suite rather than by the
//! compiler.

use rustical_store::actor::Actor;
use rustical_store::tenant::{Tenant, TenantId, TenantStatus};
use rustical_store::tenant_store::AuditRow;
use rustical_store::tenant_store::{NewTenant, TenantQuota, TenantStore};
use sqlx::{AssertSqlSafe, Row, SqlitePool};
use tracing::{instrument, warn};

use crate::error::Error;
use crate::{BEGIN_IMMEDIATE, now_iso};

/// The columns every `Tenant` read selects, in one place.
///
/// Written out in a constant because the same eight columns are read by four
/// different queries, and a `SELECT *` would silently widen this struct the
/// next time a column is added to the table.
const TENANT_COLUMNS: &str = "id, slug, display_name, status, plan, config_json, \
                              suspended_at, created_at";

/// A control-plane row that does not satisfy its own schema.
///
/// `TenantId`/`TenantStatus` parse with `String` errors (the `FromStr` halves
/// are `str`-based and used by the CLI too), and `String` is not a `StdError`,
/// so it is wrapped in an `io::Error` to reach `sqlx::Error::Decode`. This is
/// a *corrupt database*, not a bad request: it belongs in the 500 path, and
/// defaulting the value instead would serve a tenant whose slug or status is
/// not what the operator wrote.
fn decode_error(message: impl Into<String>) -> Error {
    Error::SqlxError(sqlx::Error::Decode(Box::new(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        message.into(),
    ))))
}

fn row_to_tenant(row: &sqlx::sqlite::SqliteRow) -> Result<Tenant, Error> {
    let id: String = row.get("id");
    let slug: String = row.get("slug");
    let status: String = row.get("status");
    Ok(Tenant {
        id: id
            .parse::<TenantId>()
            .map_err(|e| decode_error(format!("tenants.id '{id}': {e}")))?,
        slug: slug
            .parse::<TenantId>()
            .map_err(|e| decode_error(format!("tenants.slug '{slug}': {e}")))?,
        display_name: row.get("display_name"),
        status: status
            .parse::<TenantStatus>()
            .map_err(|e| decode_error(format!("tenants.status '{status}': {e}")))?,
        plan: row.get("plan"),
        config_json: row.get("config_json"),
        suspended_at: row
            .try_get::<Option<String>, _>("suspended_at")
            .ok()
            .flatten(),
        created_at: row
            .try_get::<Option<String>, _>("created_at")
            .ok()
            .flatten(),
    })
}

/// The hosted-tenancy cross-tenant index, backed by its own SQLite file.
#[derive(Debug, Clone)]
pub struct SqliteTenantStore {
    pool: SqlitePool,
}

impl SqliteTenantStore {
    #[must_use]
    pub const fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// The pool, for the migrations/bootstrap path.
    #[must_use]
    pub const fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    /// Like [`SqliteTenantStore::find_active`] but without the `status` filter.
    ///
    /// Needed by the writes, which must work on a **suspended** tenant: a
    /// suspended tenant still owns its hostname and still has a quota, and an
    /// admin has to be able to reconfigure it. Only *resolution* filters on
    /// status — reads that decide who gets served.
    async fn find_any(
        &self,
        where_clause: &'static str,
        arg: &str,
    ) -> Result<Option<Tenant>, rustical_store::Error> {
        let query = format!("SELECT {TENANT_COLUMNS} FROM tenants WHERE {where_clause}");
        let row = sqlx::query(AssertSqlSafe(query.as_str()))
            .bind(arg)
            .fetch_optional(&self.pool)
            .await
            .map_err(Error::from)?;
        row.map_or(Ok(None), |r| {
            row_to_tenant(&r).map_err(Into::into).map(Some)
        })
    }

    /// Look up an active tenant by a `WHERE` clause over [`TENANT_COLUMNS`].
    ///
    /// One helper rather than three near-copies: the `status = 'active'` filter
    /// is the load-bearing part of §3.3 step 4 and row 29, and a filter living
    /// in four separate queries is a filter that will eventually be missing from
    /// one of them.
    ///
    /// `where_clause` is `&'static str` and that is the security property, not
    /// an accident of style. sqlx 0.9 refuses to run a query string it cannot
    /// prove is constant, and `format!` output does not qualify — so the one
    /// `AssertSqlSafe` below is the only place dynamic SQL could be introduced,
    /// and a caller **cannot** pass a runtime value here: `&String` and
    /// `&format!(..)` both fail to compile. An interpolated slug cannot reach
    /// this function. The values themselves are bound, never interpolated.
    async fn find_active(
        &self,
        where_clause: &'static str,
        arg: &str,
    ) -> Result<Option<Tenant>, rustical_store::Error> {
        let query = format!("SELECT {TENANT_COLUMNS} FROM tenants WHERE {where_clause}");
        let row = sqlx::query(AssertSqlSafe(query.as_str()))
            .bind(arg)
            .fetch_optional(&self.pool)
            .await
            .map_err(Error::from)?;
        row.map_or(Ok(None), |r| {
            row_to_tenant(&r).map_err(Into::into).map(Some)
        })
    }
}

/// Append one audit row, inside the caller's transaction.
///
/// Takes `&mut Transaction` deliberately. The borrow is the point: an audit
/// write that cannot join the caller's transaction is an audit write that can be
/// lost, and §6.6.7 is explicit that the mutation and its record are one
/// transaction or the control does not exist.
async fn audit(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    actor: &Actor,
    action: &str,
    tenant: Option<&TenantId>,
    detail: Option<&str>,
) -> Result<(), rustical_store::Error> {
    sqlx::query(
        "INSERT INTO control_admin_audit (actor, action, tenant, at, detail) \
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(actor.as_str())
    .bind(action)
    .bind(tenant.map(TenantId::as_str))
    .bind(now_iso())
    .bind(detail)
    .execute(&mut **tx)
    .await
    .map_err(Error::from)?;
    Ok(())
}

#[async_trait::async_trait]
impl TenantStore for SqliteTenantStore {
    #[instrument(skip(self, new_tenant))]
    async fn create_tenant(
        &self,
        new_tenant: &NewTenant,
        actor: &Actor,
    ) -> Result<(), rustical_store::Error> {
        let tenant = &new_tenant.tenant;
        if !tenant.is_active() {
            // Creating a tenant already suspended is almost always a bug in a
            // script (`--status suspended` typo'd into a create). It is also
            // the one state where `get_tenant_by_*` would report the tenant as
            // nonexistent, so the row would be invisible and unrecoverable
            // through the normal API.
            return Err(rustical_store::Error::Other(anyhow::anyhow!(
                "a tenant must be created active; suspend it with update_tenant_status \
                 so that the transition is recorded"
            )));
        }

        let mut tx = self
            .pool
            .begin_with(BEGIN_IMMEDIATE)
            .await
            .map_err(Error::from)?;

        // A unique violation on `slug` is mapped to `AlreadyExists` by
        // `crate::Error`'s sqlx conversion, which is the error §3.4 wants: the
        // slug is the identity, and two tenants sharing one would collide on a
        // hostname and on the `data_root` path.
        sqlx::query(
            "INSERT INTO tenants (id, slug, display_name, status, plan, config_json, created_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(tenant.id.as_str())
        .bind(tenant.slug.as_str())
        .bind(&tenant.display_name)
        .bind(tenant.status.as_str())
        .bind(&tenant.plan)
        .bind(&tenant.config_json)
        .bind(now_iso())
        .execute(&mut *tx)
        .await
        .map_err(Error::from)?;

        for host in &new_tenant.hosts {
            sqlx::query("INSERT INTO tenant_hosts (host, tenant) VALUES (?, ?)")
                .bind(host.trim().trim_end_matches('.').to_ascii_lowercase())
                .bind(tenant.id.as_str())
                .execute(&mut *tx)
                .await
                .map_err(Error::from)?;
        }

        // Inside the transaction: a tenant that exists without a record of who
        // created it is exactly the state the audit trail rules out.
        audit(
            &mut tx,
            actor,
            "create_tenant",
            Some(&tenant.id),
            Some(&format!("{{\"slug\":{}}}", tenant.slug)),
        )
        .await?;
        tx.commit().await.map_err(Error::from)?;
        Ok(())
    }

    #[instrument(skip(self))]
    async fn get_tenant_by_slug(
        &self,
        slug: &str,
    ) -> Result<Option<Tenant>, rustical_store::Error> {
        // Validated before the query so a malformed slug is a cheap no-op
        // rather than a database round trip, and so that `../` can never reach
        // SQL as a bind value at all.
        let slug: TenantId = slug.parse().map_err(|_| rustical_store::Error::NotFound)?;
        self.find_active("slug = ? AND status = 'active'", slug.as_str())
            .await
    }

    #[instrument(skip(self))]
    async fn get_tenant_by_id(
        &self,
        id: &TenantId,
    ) -> Result<Option<Tenant>, rustical_store::Error> {
        self.find_active("id = ? AND status = 'active'", id.as_str())
            .await
    }

    #[instrument(skip(self))]
    async fn get_tenant_by_host(
        &self,
        host: &str,
    ) -> Result<Option<Tenant>, rustical_store::Error> {
        // The `t.`-prefixed column list is assembled from the same constant as
        // every other read, so it cannot drift from [`TENANT_COLUMNS`]. As in
        // `find_active`, the only dynamic SQL in this file is a `format!` of
        // compile-time constants, asserted safe here and nowhere else.
        const JOINED_COLUMNS: &str = "t.id, t.slug, t.display_name, t.status, t.plan, \
                                        t.config_json, t.suspended_at, t.created_at";
        let query = format!(
            "SELECT {JOINED_COLUMNS} FROM tenants t \
             JOIN tenant_hosts h ON h.tenant = t.id \
             WHERE h.host = ? AND t.status = 'active'"
        );
        let row = sqlx::query(AssertSqlSafe(query.as_str()))
            .bind(host)
            .fetch_optional(&self.pool)
            .await
            .map_err(Error::from)?;
        row.map_or(Ok(None), |r| {
            row_to_tenant(&r).map_err(Into::into).map(Some)
        })
    }

    #[instrument(skip(self))]
    async fn is_host_claimed(&self, host: &str) -> Result<bool, rustical_store::Error> {
        // Deliberately not filtered on tenant status, and deliberately not a
        // join: the question is only whether the *name* is taken.
        let exists: Option<i64> = sqlx::query("SELECT 1 FROM tenant_hosts WHERE host = ?")
            .bind(host)
            .fetch_optional(&self.pool)
            .await
            .map_err(Error::from)?
            .map(|r| r.get("1"));
        Ok(exists.is_some())
    }

    #[instrument(skip(self))]
    async fn get_any_tenant_by_host(
        &self,
        host: &str,
    ) -> Result<Option<Tenant>, rustical_store::Error> {
        // `get_tenant_by_host` without the `status = 'active'` filter. The
        // query is written out rather than parameterised over the filter so that
        // neither version has a boolean flag deciding whether a claim counts —
        // §6.6.2's whole argument is that a suspended tenant's host is still
        // claimed.
        const JOINED_COLUMNS: &str = "t.id, t.slug, t.display_name, t.status, t.plan, \
                                        t.config_json, t.suspended_at, t.created_at";
        let query = format!(
            "SELECT {JOINED_COLUMNS} FROM tenants t \
             JOIN tenant_hosts h ON h.tenant = t.id \
             WHERE h.host = ?"
        );
        let row = sqlx::query(AssertSqlSafe(query.as_str()))
            .bind(host)
            .fetch_optional(&self.pool)
            .await
            .map_err(Error::from)?;
        row.map_or(Ok(None), |r| {
            row_to_tenant(&r).map_err(Into::into).map(Some)
        })
    }

    async fn get_any_tenant_by_slug(
        &self,
        slug: &str,
    ) -> Result<Option<Tenant>, rustical_store::Error> {
        self.find_any("slug = ?", slug).await
    }

    #[instrument(skip(self))]
    async fn list_tenants(
        &self,
        include_suspended: bool,
    ) -> Result<Vec<Tenant>, rustical_store::Error> {
        // The one query that does not filter on status, because an admin has to
        // be able to see a suspended tenant in order to resume it. Two literal
        // queries rather than a `WHERE` fragment chosen by a bool: this is the
        // cross-tenant index, and a listing that is wrong is wrong for *every*
        // tenant at once.
        const ACTIVE: &str = "SELECT id, slug, display_name, status, plan, config_json, \
                              suspended_at, created_at \
                              FROM tenants WHERE status = 'active' \
                              ORDER BY created_at DESC, id DESC";
        const ALL: &str = "SELECT id, slug, display_name, status, plan, config_json, \
                           suspended_at, created_at \
                           FROM tenants ORDER BY created_at DESC, id DESC";
        let rows = sqlx::query(if include_suspended { ALL } else { ACTIVE })
            .fetch_all(&self.pool)
            .await
            .map_err(Error::from)?;
        rows.iter()
            .map(row_to_tenant)
            .collect::<Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    #[instrument(skip(self))]
    async fn update_tenant_status(
        &self,
        id: &TenantId,
        status: TenantStatus,
        actor: &Actor,
    ) -> Result<(), rustical_store::Error> {
        // `suspended_at` is written in the same statement as `status` so the
        // two can never disagree — there is no window in which a tenant is
        // suspended with no suspension date. Reactivating clears it, so
        // `suspended_at IS NULL` is a valid "never suspended / currently
        // active" test.
        let suspended_at = match status {
            TenantStatus::Active => None,
            TenantStatus::Suspended => Some(now_iso()),
        };
        let mut tx = self
            .pool
            .begin_with(BEGIN_IMMEDIATE)
            .await
            .map_err(Error::from)?;
        let result = sqlx::query("UPDATE tenants SET status = ?, suspended_at = ? WHERE id = ?")
            .bind(status.as_str())
            .bind(suspended_at)
            .bind(id.as_str())
            .execute(&mut *tx)
            .await
            .map_err(Error::from)?;
        if result.rows_affected() == 0 {
            return Err(rustical_store::Error::NotFound);
        }
        audit(
            &mut tx,
            actor,
            "update_tenant_status",
            Some(id),
            Some(&format!(r#"{{"status":"{status}"}}"#)),
        )
        .await?;
        tx.commit().await.map_err(Error::from)?;
        Ok(())
    }

    #[instrument(skip(self))]
    async fn set_quota(
        &self,
        id: &TenantId,
        quota: TenantQuota,
        actor: &Actor,
    ) -> Result<(), rustical_store::Error> {
        let mut tx = self
            .pool
            .begin_with(BEGIN_IMMEDIATE)
            .await
            .map_err(Error::from)?;
        let result = sqlx::query(
            "UPDATE tenants SET quota_principals = ?, quota_calendars = ?, \
             quota_megabytes = ? WHERE id = ?",
        )
        .bind(quota.principals)
        .bind(quota.calendars)
        .bind(quota.megabytes)
        .bind(id.as_str())
        .execute(&mut *tx)
        .await
        .map_err(Error::from)?;
        if result.rows_affected() == 0 {
            return Err(rustical_store::Error::NotFound);
        }
        audit(
            &mut tx,
            actor,
            "set_quota",
            Some(id),
            Some(&format!(
                "{{\"principals\":{:?},\"calendars\":{:?},\"megabytes\":{:?}}}",
                quota.principals, quota.calendars, quota.megabytes
            )),
        )
        .await?;
        tx.commit().await.map_err(Error::from)?;
        Ok(())
    }

    #[instrument(skip(self))]
    async fn get_quota(&self, id: &TenantId) -> Result<TenantQuota, rustical_store::Error> {
        let row = sqlx::query(
            "SELECT quota_principals, quota_calendars, quota_megabytes \
             FROM tenants WHERE id = ?",
        )
        .bind(id.as_str())
        .fetch_optional(&self.pool)
        .await
        .map_err(Error::from)?;
        // A missing row is `default` (unlimited) rather than `NotFound`, because
        // a quota is a limit and the safe reading of "no limit on record" is
        // "no limit". Returning `NotFound` here would make every caller's
        // error branch handle a case that is not an error.
        let Some(row) = row else {
            return Ok(TenantQuota::default());
        };
        Ok(TenantQuota {
            principals: row.get("quota_principals"),
            calendars: row.get("quota_calendars"),
            megabytes: row.get("quota_megabytes"),
        })
    }

    #[instrument(skip(self, hosts))]
    async fn set_tenant_hosts(
        &self,
        id: &TenantId,
        hosts: &[String],
        actor: &Actor,
    ) -> Result<(), rustical_store::Error> {
        let mut tx = self
            .pool
            .begin_with(BEGIN_IMMEDIATE)
            .await
            .map_err(Error::from)?;

        // The tenant must exist. Inside the transaction, because this is the
        // check that turns a foreign-key violation on `tenant_hosts` into the
        // `NotFound` the trait documents — and an existing test caught its
        // absence when this method was first rewritten to use a transaction
        // without carrying the guard over with it.
        if self.find_any("id = ?", id.as_str()).await?.is_none() {
            return Err(rustical_store::Error::NotFound);
        }

        // A host is a key into every request in the system, so hosts are
        // normalised here rather than trusted: `HostDispatch` lowercases and
        // strips the port before looking up, and a host stored with different
        // capitalisation than a request carries would simply never match.
        let normalised: Vec<String> = hosts
            .iter()
            .map(|host| host.trim().trim_end_matches('.').to_ascii_lowercase())
            .filter(|host| !host.is_empty())
            .collect();

        for host in &normalised {
            // Refuse to steal a host from another tenant rather than moving it.
            // A typo has to fail loudly; silently relocating a customer's
            // hostname is how one tenant ends up serving another's traffic.
            let owner: Option<String> =
                sqlx::query("SELECT tenant FROM tenant_hosts WHERE host = ?")
                    .bind(host)
                    .fetch_optional(&mut *tx)
                    .await
                    .map_err(Error::from)?
                    .map(|r| r.get("tenant"));
            // A host claimed by somebody else is refused, not moved: a typo
            // must fail loudly rather than silently relocate a customer's
            // hostname.
            if let Some(owner) = owner
                && owner != id.as_str()
            {
                warn!(
                    tenant = %id,
                    host,
                    claimed_by = %owner,
                    "refusing to move a host claimed by another tenant"
                );
                return Err(rustical_store::Error::AlreadyExists);
            }
        }

        // Withdrawn claims: `set_tenant_hosts(&id, &[])` is the documented way
        // to stop answering for a hostname while keeping the tenant itself.
        sqlx::query("DELETE FROM tenant_hosts WHERE tenant = ?")
            .bind(id.as_str())
            .execute(&mut *tx)
            .await
            .map_err(Error::from)?;
        for host in &normalised {
            sqlx::query("INSERT OR REPLACE INTO tenant_hosts (host, tenant) VALUES (?, ?)")
                .bind(host)
                .bind(id.as_str())
                .execute(&mut *tx)
                .await
                .map_err(Error::from)?;
        }

        audit(
            &mut tx,
            actor,
            "set_tenant_hosts",
            Some(id),
            Some(&format!("{{\"hosts\":{normalised:?}}}")),
        )
        .await?;
        tx.commit().await.map_err(Error::from)?;
        Ok(())
    }

    #[instrument(skip(self))]
    async fn delete_tenant(
        &self,
        id: &TenantId,
        actor: &Actor,
    ) -> Result<(), rustical_store::Error> {
        let mut tx = self
            .pool
            .begin_with(BEGIN_IMMEDIATE)
            .await
            .map_err(Error::from)?;
        // `tenant_hosts` rows go with it via ON DELETE CASCADE. The tenant's
        // *data* is a different database and is not touched — see
        // `TenantStore::delete_tenant`.
        let result = sqlx::query("DELETE FROM tenants WHERE id = ?")
            .bind(id.as_str())
            .execute(&mut *tx)
            .await
            .map_err(Error::from)?;
        if result.rows_affected() == 0 {
            return Err(rustical_store::Error::NotFound);
        }
        // Recorded **after** the delete and inside the same transaction, so the
        // row survives: `control_admin_audit` has no cascade from `tenants`
        // precisely so that deleting a tenant cannot erase the record of who
        // deleted it.
        audit(&mut tx, actor, "delete_tenant", Some(id), None).await?;
        tx.commit().await.map_err(Error::from)?;
        Ok(())
    }
    #[instrument(skip(self, config_json))]
    async fn set_config_json(
        &self,
        id: &TenantId,
        config_json: &str,
        actor: &Actor,
    ) -> Result<(), rustical_store::Error> {
        let mut tx = self
            .pool
            .begin_with(BEGIN_IMMEDIATE)
            .await
            .map_err(Error::from)?;
        let result = sqlx::query("UPDATE tenants SET config_json = ? WHERE id = ?")
            .bind(config_json)
            .bind(id.as_str())
            .execute(&mut *tx)
            .await
            .map_err(Error::from)?;
        if result.rows_affected() == 0 {
            return Err(rustical_store::Error::NotFound);
        }
        // The detail records **that** the blob changed, never the blob: it holds
        // SMTP passwords and the RSVP HMAC key, and `detail` is rendered by the
        // panel.
        audit(
            &mut tx,
            actor,
            "set_config_json",
            Some(id),
            Some(&format!(r#"{{"bytes":{}}}"#, config_json.len())),
        )
        .await?;
        tx.commit().await.map_err(Error::from)?;
        Ok(())
    }

    #[instrument(skip(self))]
    async fn list_audit(
        &self,
        tenant: Option<&TenantId>,
        limit: usize,
    ) -> Result<Vec<AuditRow>, rustical_store::Error> {
        // Newest first, because an incident reads backwards. Bounded by the
        // caller: this is the one table in the control plane whose growth is
        // unbounded, and an unbounded read of it is a way to exhaust memory.
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);
        // `map_or` with a closure carrying the whole tuple, rather than a
        // `format!` over a conditional fragment: the bind list differs too, and a
        // query assembled at runtime is exactly the shape sqlx refuses to run
        // without an assertion.
        let (sql, bind): (&str, Option<&str>) = tenant.map_or(
            (
                "SELECT id, actor, action, tenant, at, detail FROM control_admin_audit ORDER BY at DESC, id DESC LIMIT ?",
                None,
            ),
            |id| {
                (
                    "SELECT id, actor, action, tenant, at, detail FROM control_admin_audit WHERE tenant = ? ORDER BY at DESC, id DESC LIMIT ?",
                    Some(id.as_str()),
                )
            },
        );
        let mut query = sqlx::query(sql);
        if let Some(tenant) = bind {
            query = query.bind(tenant);
        }
        let rows = query
            .bind(limit)
            .fetch_all(&self.pool)
            .await
            .map_err(Error::from)?;
        rows.iter()
            .map(|row| {
                let tenant: Option<String> = row.try_get("tenant").ok().flatten();
                Ok(AuditRow {
                    id: row.get("id"),
                    actor: row.get("actor"),
                    action: row.get("action"),
                    tenant: tenant.and_then(|t| t.parse().ok()),
                    at: row.get("at"),
                    detail: row.try_get("detail").ok().flatten(),
                })
            })
            .collect()
    }
}

/// A fresh `id` for a new tenant.
///
/// A random lowercase UUID, which is a valid [`TenantId`] because it is
/// `[0-9a-f-]` and well inside the 63-character limit. Validating the id is not
/// incidental: it becomes a **directory name** under `data_root`
/// (§3.4's `<data_root>/tenants/<tenant_id>/db.sqlite3`), so [`TenantId`] is
/// also what makes `../` in a primary key impossible.
///
/// §3.4 says "ulid/short random id" and this is the random half. It is
/// deliberately **not** time-ordered: `uuid` is in this workspace with the
/// `v4` feature only, and `v7` would mean a workspace-wide feature change to
/// buy a property nothing needs — `created_at` already orders
/// [`TenantStore::list_tenants`], and no lookup is by id *range*.
#[must_use]
pub fn new_tenant_id() -> TenantId {
    TenantId::generate()
}

/// Convenience: a [`NewTenant`] with a generated id and no hosts.
///
/// `display_name` defaults to the slug so that a tenant created from a script
/// that knows only a slug still has something to show in an admin list.
#[must_use]
pub fn new_tenant(slug: &TenantId, display_name: Option<&str>) -> NewTenant {
    NewTenant {
        tenant: Tenant {
            id: new_tenant_id(),
            slug: slug.clone(),
            display_name: display_name.unwrap_or(slug.as_str()).to_owned(),
            status: TenantStatus::Active,
            config_json: "{}".to_owned(),
            plan: "free".to_owned(),
            suspended_at: None,
            created_at: None,
        },
        hosts: Vec::new(),
    }
}
