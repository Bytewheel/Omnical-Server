//! The tenancy control plane's read/write surface — `PLAN_DEPLOYMENTS.md`
//! §3.4, §6.1.
//!
//! ## What this trait is for, and what it is emphatically not
//!
//! §3.2 made a tenant a **resolved `Router`**, not a column, and that decision
//! has one important consequence for this trait: **none of these methods can
//! express a data-access boundary, and none is asked to.** A tenant's calendars,
//! addresses and credentials live in a *different database file*, reached
//! through a store bundle that this trait never sees. There is no
//! `tenant_id` parameter on any calendar method, because there is nothing to
//! filter on — the connection is already the boundary.
//!
//! So the shape here is unusual for a "store" trait, and deliberately so. It is
//! an **index**, not a data layer:
//!
//! - it holds **no** calendar, contact or credential data (§3.4), which is what
//!   makes a per-tenant backup unable to take the control plane out with it;
//! - it is the one place a cross-tenant query is *wanted* — "list every tenant",
//!   "suspend this one" — because per-tenant stores cannot answer those;
//! - it resolves `Host` → tenant, which is [`TenantStore::get_tenant_by_host`].
//!
//! ## Why lookups filter on `status = 'active'`
//!
//! Every getter here returns `None` for a suspended tenant rather than the
//! tenant itself. That is the whole of §3.3 step 4 and row 29's "suspension is
//! immediate", and it is why it is done in SQL rather than in `HostDispatch`:
//!
//! ```text
//! Host -> control plane (always) -> TenantId -> cache -> Arc<Router>
//! ```
//!
//! The control plane is consulted on *every* request, and the cache is only
//! ever reached *after* a tenant has resolved. A suspended tenant therefore
//! never reaches the cache, so there is no cached router to invalidate, no
//! eviction path to get wrong, and no window in which a suspended tenant is
//! still served. Caching the *lookup* instead of the *router* would reintroduce
//! exactly that window, which is why §3.3 forbids it.
//!
//! [`TenantStore::list_tenants`] is the one deliberate exception: an admin
//! listing must be able to see suspended tenants, so it takes an explicit flag.

use crate::actor::Actor;
use crate::error::Error;
use crate::tenant::{Tenant, TenantId, TenantStatus};
use async_trait::async_trait;

/// Per-tenant resource limits. `None` means **unlimited**, not "zero" and not
/// "unset" — §3.4 stores these as nullable columns for that reason.
///
/// Split out of [`Tenant`] because the limits are a distinct concern with a
/// distinct "absent means no limit" semantic, and because [`TenantStore::
/// set_quota`] needs a parameter type anyway. Merging them would have made
/// `Tenant` a faithful image of one table row, which is the shape §3.2 argues
/// against.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TenantQuota {
    pub principals: Option<i64>,
    pub calendars: Option<i64>,
    pub megabytes: Option<i64>,
}

impl TenantQuota {
    /// `true` when no limit is set on any dimension.
    #[must_use]
    pub const fn is_unlimited(&self) -> bool {
        self.principals.is_none() && self.calendars.is_none() && self.megabytes.is_none()
    }
}

/// The arguments for [`TenantStore::create_tenant`].
///
/// A struct rather than a long parameter list because `create_tenant` needs
/// seven things and a call site that gets the order wrong is a tenant whose
/// display name is its quota.
#[derive(Debug, Clone)]
pub struct NewTenant {
    pub tenant: Tenant,
    /// Hostnames this tenant claims outright (§3.3 match 1). A tenant may hold
    /// several. Slug- and `base_domain`-derived hosts do not belong here —
    /// they are derived, and storing them would create two sources of truth for
    /// one host.
    pub hosts: Vec<String>,
}

/// Read/write access to the cross-tenant index.
///
/// The default implementations return [`Error::ReadOnly`] so that test and
/// in-memory stores keep compiling without implementing tenancy, matching
/// [`crate::invite_store::InviteStore`]'s convention.
/// One row of the control-plane audit trail (row 33).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditRow {
    pub id: i64,
    /// The [`Actor`] that performed the change. Never empty: an [`Actor`] cannot
    /// be constructed empty, so neither can this.
    pub actor: String,
    /// The trait method that performed it, e.g. `update_tenant_status`.
    pub action: String,
    /// The tenant it concerned, `None` for a creation.
    pub tenant: Option<TenantId>,
    /// ISO-8601 UTC, e.g. `2026-09-29T14:22:07Z`.
    pub at: String,
    /// Optional JSON. Never a credential — the panel renders this.
    pub detail: Option<String>,
}

#[async_trait]
pub trait TenantStore: Send + Sync + 'static {
    /// Insert a new tenant, plus any hosts it claims.
    ///
    /// # Errors
    /// - [`Error::AlreadyExists`] if the slug is taken — the slug is the
    ///   identity, and two tenants sharing one would collide on a hostname and
    ///   on the `data_root` path.
    /// - [`Error::ReadOnly`] if the store does not implement tenancy.
    async fn create_tenant(&self, _new_tenant: &NewTenant, _actor: &Actor) -> Result<(), Error> {
        Err(Error::ReadOnly)
    }

    /// Look up an active tenant by slug (§3.3 matches 2-4 all reduce here).
    ///
    /// Returns `None` for a suspended or unknown slug.
    ///
    /// # Errors
    /// - [`Error::Other`] on a store failure.
    async fn get_tenant_by_slug(&self, _slug: &str) -> Result<Option<Tenant>, Error> {
        Ok(None)
    }

    /// Look up an active tenant by slug, typed. Convenience over
    /// [`TenantStore::get_tenant_by_slug`] that keeps the parse from becoming
    /// the caller's problem at every site.
    ///
    /// # Errors
    /// As [`TenantStore::get_tenant_by_slug`].
    async fn get_tenant_by_id(&self, _id: &TenantId) -> Result<Option<Tenant>, Error> {
        Ok(None)
    }

    /// Resolve a `Host` header to an active tenant via an explicit
    /// `tenant_hosts` claim (§3.3 match 1).
    ///
    /// `host` is expected pre-normalised (lowercased, port stripped) by
    /// `HostDispatch`; the store does not re-normalise, because a host is
    /// matched as a stored key and silently accepting `ACME.com` here would
    /// mean two spellings of one host in the table.
    ///
    /// Returns `None` for a suspended tenant, an unclaimed host, and an unknown
    /// host alike — the three cases are deliberately indistinguishable to the
    /// caller, so a probe cannot learn which hosts exist.
    ///
    /// # Errors
    /// - [`Error::Other`] on a store failure.
    async fn get_tenant_by_host(&self, _host: &str) -> Result<Option<Tenant>, Error> {
        Ok(None)
    }

    /// Whether *any* tenant claims this host, active or not.
    ///
    /// **This exists because of a bug the dispatch tests found**, and the reason
    /// is worth stating precisely, because the fix is not obvious from the
    /// symptom.
    ///
    /// [`TenantStore::get_tenant_by_host`] filters on `status = 'active'`, which
    /// is right for *resolution* and wrong for *ownership*. With both an explicit
    /// host claim and a `default_tenant` configured, a request for a
    /// **suspended** tenant's hostname would fail the active-only lookup and
    /// then fall through the remaining match rules to `default_tenant` — and be
    /// served the default tenant's data, under the suspended tenant's URL.
    ///
    /// That is worse than a 404: it is one customer being shown another
    /// customer's calendar. The fix is to distinguish "nobody owns this host"
    /// (keep matching) from "a suspended tenant owns it" (stop, 404).
    ///
    /// # Errors
    /// - [`Error::Other`] on a store failure.
    async fn is_host_claimed(&self, _host: &str) -> Result<bool, Error> {
        Ok(false)
    }

    /// Look up a tenant by slug **including suspended ones**, so that dispatch
    /// can tell a suspended tenant apart from a nonexistent one.
    ///
    /// Same reasoning as [`TenantStore::is_host_claimed`]: a request for
    /// `{slug}.{base_domain}` where that slug exists but is suspended must 404,
    /// not fall through to `default_tenant`.
    ///
    /// # Errors
    /// - [`Error::Other`] on a store failure.
    async fn get_any_tenant_by_slug(&self, _slug: &str) -> Result<Option<Tenant>, Error> {
        Ok(None)
    }

    /// List tenants, newest first, optionally including suspended ones.
    ///
    /// The one getter that does not filter on `status`, because an admin view
    /// has to be able to see suspended tenants in order to resume them. The
    /// flag is explicit and defaults to *excluding* them, so a forgotten
    /// argument cannot leak suspended tenants into a normal listing.
    ///
    /// # Errors
    /// - [`Error::Other`] on a store failure.
    async fn list_tenants(&self, _include_suspended: bool) -> Result<Vec<Tenant>, Error> {
        Ok(Vec::new())
    }

    /// Set a tenant's status, stamping or clearing `suspended_at`.
    ///
    /// This is the only write that changes what dispatch resolves, and it takes
    /// effect on the next request without any cache eviction — see this
    /// module's docs for why.
    ///
    /// # Errors
    /// - [`Error::NotFound`] if the id is unknown.
    /// - [`Error::ReadOnly`] if the store does not implement tenancy.
    async fn update_tenant_status(
        &self,
        _id: &TenantId,
        _status: TenantStatus,
        _actor: &Actor,
    ) -> Result<(), Error> {
        Err(Error::ReadOnly)
    }

    /// Overwrite a tenant's quota. Passing [`TenantQuota::default`] clears
    /// every limit back to unlimited.
    ///
    /// # Errors
    /// - [`Error::NotFound`] if the id is unknown.
    /// - [`Error::ReadOnly`] if the store does not implement tenancy.
    async fn set_quota(
        &self,
        _id: &TenantId,
        _quota: TenantQuota,
        _actor: &Actor,
    ) -> Result<(), Error> {
        Err(Error::ReadOnly)
    }

    /// Replace a tenant's `config_json`.
    ///
    /// On the trait rather than a direct statement in the CLI for one reason:
    /// the CLI writes this column today, and a column written outside the trait
    /// is a column that escapes the audit trail. `tenant config set` is exactly
    /// the kind of change — an RSVP HMAC key, an SMTP identity — where an
    /// unrecorded edit is worth knowing about.
    ///
    /// # Errors
    /// - [`Error::NotFound`] if the id is unknown.
    /// - [`Error::ReadOnly`] if the store does not implement tenancy.
    async fn set_config_json(
        &self,
        _id: &TenantId,
        _config_json: &str,
        _actor: &Actor,
    ) -> Result<(), Error> {
        Err(Error::ReadOnly)
    }

    /// Read the audit trail, newest first, optionally for one tenant.
    ///
    /// Read-only by design: there is no `ON DELETE CASCADE` from `tenants` and no
    /// update or delete path for this table anywhere in the fork, so an audit row
    /// outlives the tenant it describes. Deleting a tenant must not erase the
    /// record of who deleted it.
    ///
    /// # Errors
    /// - [`Error::Other`] on a store failure.
    async fn list_audit(
        &self,
        _tenant: Option<&TenantId>,
        _limit: usize,
    ) -> Result<Vec<AuditRow>, Error> {
        Ok(Vec::new())
    }

    /// Read a tenant's quota.
    ///
    /// # Errors
    /// - [`Error::Other`] on a store failure.
    async fn get_quota(&self, _id: &TenantId) -> Result<TenantQuota, Error> {
        Ok(TenantQuota::default())
    }

    /// Replace a tenant's explicit host claims.
    ///
    /// A host already claimed by a *different* tenant is refused rather than
    /// moved, so a typo cannot silently take a customer offline. Note the
    /// ordering hazard: the caller must set this *after* `create_tenant`, and
    /// suspension is unaffected either way.
    ///
    /// # Errors
    /// - [`Error::AlreadyExists`] if a host is claimed by another tenant.
    /// - [`Error::NotFound`] if the id is unknown.
    /// - [`Error::ReadOnly`] if the store does not implement tenancy.
    async fn set_tenant_hosts(
        &self,
        _id: &TenantId,
        _hosts: &[String],
        _actor: &Actor,
    ) -> Result<(), Error> {
        Err(Error::ReadOnly)
    }

    /// Delete a tenant row and its host claims (`ON DELETE CASCADE`).
    ///
    /// **This does not delete the tenant's store file.** A tenant's data is its
    /// own database, and destroying it is an explicit, separate operation —
    /// `rustical tenant delete` will require `--purge-data` for that, precisely
    /// so that "remove the tenant" and "destroy the customer's calendars" can
    /// never be the same command by accident.
    ///
    /// # Errors
    /// - [`Error::NotFound`] if the id is unknown.
    /// - [`Error::ReadOnly`] if the store does not implement tenancy.
    async fn delete_tenant(&self, _id: &TenantId, _actor: &Actor) -> Result<(), Error> {
        Err(Error::ReadOnly)
    }
}
