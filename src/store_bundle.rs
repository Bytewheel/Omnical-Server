//! Per-tenant store bundles and the cache that bounds them — `PLAN_DEPLOYMENTS`
//! §3.5, §6.2.
//!
//! ## Why this is a struct and not a tuple
//!
//! `get_data_stores` returned a **12-element tuple**. §3.2's design needs to
//! hold that bundle per tenant, and a 12-tuple that crosses a module boundary
//! is a tuple whose element order is checked by nothing. The two fields most
//! likely to be confused — `subscription_store` and `invite_store`, both
//! `Arc<dyn …>` over the same pool — are adjacent in the tuple and both are
//! `dyn` traits, so a swap compiles.
//!
//! So the bundle is named. This is the "small change" §3.8 predicted for
//! `get_data_stores`; the tuple survives as a shim so the five CLI call sites
//! did not have to move in the same commit, exactly the way item 7 left
//! `make_app` as a shim around `make_app_for`.
//!
//! ## The cache memoises *construction*, never *resolution*
//!
//! This is the single most important property of the file, and §3.3 spells it
//! out:
//!
//! ```text
//! Host -> control plane (ALWAYS) -> TenantId -> cache -> Arc<Router>
//! ```
//!
//! [`StoreBundleCache`] is consulted **only after** the control plane has
//! returned an active [`TenantId`]. It answers "have I already built this
//! tenant's router", and nothing else. Three consequences follow:
//!
//! 1. **Suspension is immediate for free.** A suspended tenant never resolves,
//!    so it never reaches the cache. There is no eviction to forget and no
//!    window in which it is still served. (Row 29.)
//! 2. **A `Host` header can never select a cached router directly.** The cache
//!    has no `get_by_host`; the only key is a `TenantId` the control plane
//!    vouched for. A host-keyed cache would be a second, less-filtered
//!    resolution path — exactly what would make suspension lag.
//! 3. **The control plane is hit on every request.** §3.3 budgets ~50 µs
//!    against a small SQLite file. That is the deliberate price of never
//!    caching a decision that can be revoked.

use lru::LruCache;
use rustical_store::auth::AuthenticationProvider;
use rustical_store::{
    CalendarSourceStore, CollectionOperation, CollectionShareStore, InviteStore,
    PasswordResetStore, SchedulingStore, SubscriptionStore, TenantId,
};
use rustical_store_sqlite::{
    SqliteAddressbookStore, SqliteCalendarStore, SqliteDavPushStore, SqlitePrincipalStore,
};
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};

/// The `default_max_cached_tenants` of §3.6.
///
/// 64 is the plan's number and it is deliberately small: §3.2's stated cost is
/// "N routers + N pools in one process's memory", and on the 256 MiB appliance
/// a pool is the expensive part, not a router. 64 idle tenants is generous for
/// a self-hosted install (which has exactly one) and a starting point for
/// hosted, not a target.
pub const DEFAULT_MAX_CACHED_TENANTS: usize = 64;

/// One tenant's twelve stores, named.
///
/// `AP` stays a generic parameter for the reason §18.11 recorded: the DAV and
/// frontend routers are generic over a **concrete** authentication provider, so
/// erasing it here would not compile. The stores that are already trait objects
/// upstream stay erased, because that is how the callers already hold them.
///
/// Not `Clone`, because [`StoreBundle::update_recv`] is a one-shot channel
/// endpoint. That is not an inconvenience to work around; it is a fact about
/// WebDAV-Push, and a `Clone` here would imply a tenant can have two notifier
/// loops reading the same channel.
pub struct StoreBundle<AP: AuthenticationProvider> {
    pub addr_store: Arc<SqliteAddressbookStore>,
    pub cal_store: Arc<SqliteCalendarStore>,
    pub dav_push_store: Arc<SqliteDavPushStore>,
    pub auth_provider: Arc<AP>,
    /// DAV-Push change notifications, **taken out once** by
    /// [`StoreBundle::take_update_recv`].
    ///
    /// An `Option` because a `mpsc::Receiver` cannot be cloned and a second
    /// notifier loop on one channel is impossible. Modelling that as an
    /// `Option` puts the fact in the type instead of in a comment nobody reads.
    pub update_recv: Option<tokio::sync::mpsc::Receiver<CollectionOperation>>,
    pub scheduling_store: Arc<dyn SchedulingStore>,
    pub subscription_store: Arc<dyn SubscriptionStore>,
    pub invite_store: Arc<dyn InviteStore>,
    pub calendar_source_store: Arc<dyn CalendarSourceStore>,
    pub share_store: Arc<dyn CollectionShareStore>,
    pub password_reset_store: Arc<dyn PasswordResetStore>,
}

/// The concrete provider type this build uses, so callers need not name it.
pub type SqliteStoreBundle = StoreBundle<SqlitePrincipalStore>;

/// The concrete type behind an `Arc<T>`, for [`StoreBundle`]'s `Debug`.
fn type_name<T>(_: &Arc<T>) -> &'static str {
    std::any::type_name::<T>()
}

impl<AP: AuthenticationProvider> std::fmt::Debug for StoreBundle<AP> {
    /// Hand-written because six of the twelve fields are `dyn` traits that do
    /// not implement `Debug` — and printing them would say nothing anyway. What
    /// is actually useful when a tenant misbehaves is *which concrete stores* it
    /// is built over, because that is the database to go and look at.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoreBundle")
            .field("addr_store", &type_name(&self.addr_store))
            .field("cal_store", &type_name(&self.cal_store))
            .field("dav_push_store", &type_name(&self.dav_push_store))
            .field("auth_provider", &type_name(&self.auth_provider))
            .field("scheduling_store", &"dyn SchedulingStore")
            .field("subscription_store", &"dyn SubscriptionStore")
            .field("invite_store", &"dyn InviteStore")
            .field("calendar_source_store", &"dyn CalendarSourceStore")
            .field("share_store", &"dyn CollectionShareStore")
            .field("password_reset_store", &"dyn PasswordResetStore")
            .field(
                "update_recv",
                &self.update_recv.as_ref().map_or("taken", |_| "held"),
            )
            .finish()
    }
}

impl<AP: AuthenticationProvider> StoreBundle<AP> {
    /// Take the DAV-Push notification receiver, leaving `None` behind.
    ///
    /// An `Err` on the second call, and that is deliberate: "the channel was
    /// already consumed" is a real state the serve path has to survive, not a
    /// programming error worth panicking a running server over. The honest
    /// response is to serve without WebDAV-Push for that tenant and say so.
    ///
    /// # Errors
    /// If the receiver was already taken. A `String`, not a typed error: this is
    /// a lifecycle report for a log line, and a one-off type in `app.rs` would
    /// be a worse trade than a message.
    pub fn take_update_recv(
        &mut self,
    ) -> Result<tokio::sync::mpsc::Receiver<CollectionOperation>, String> {
        self.update_recv.take().ok_or_else(|| {
            "this tenant's DAV-Push channel was already consumed by a notifier loop".to_owned()
        })
    }

    /// This bundle's stores, for `make_app_for`.
    ///
    /// One place that maps a bundle onto [`crate::app::AppStores`], so the eight
    /// fields can never be supplied in two different orders.
    ///
    /// Note what is **not** a parameter: the tenant. A `StoreBundle` is stores;
    /// the tenant is an argument to the router builder. Bundling them here would
    /// let a `make_app_for` call site forget to pass the tenant it had just
    /// looked up, producing an unlabelled router — precisely the §18.12 failure
    /// that a compile error is much better at catching than a test.
    #[must_use]
    pub fn app_stores(
        &self,
    ) -> crate::app::AppStores<SqliteAddressbookStore, SqliteCalendarStore, SqliteDavPushStore, AP>
    {
        crate::app::AppStores {
            addr_store: self.addr_store.clone(),
            cal_store: self.cal_store.clone(),
            dav_push_store: self.dav_push_store.clone(),
            auth_provider: self.auth_provider.clone(),
            source_store: self.calendar_source_store.clone(),
            invite_store: self.invite_store.clone(),
            share_store: self.share_store.clone(),
            password_reset_store: self.password_reset_store.clone(),
        }
    }
}

/// What the cache holds for one tenant.
///
/// The `Weak` is §3.5's shape and it is load-bearing: the `Arc<Router>` holds
/// `Arc`s to every store, so **the router is what keeps the pool open**. Holding
/// a `Weak<StoreBundle>` lets the cache observe that the bundle is gone — the
/// honest signal that the pool closed — without the cache itself extending the
/// pool's life. A strong reference here would mean evicting a tenant from the
/// LRU failed to release its pools, and the memory bound §7.2 states would be a
/// fiction.
#[derive(Debug, Clone)]
pub struct CachedTenant {
    pub bundle: std::sync::Weak<SqliteStoreBundle>,
    pub router: Arc<axum::Router>,
}

impl CachedTenant {
    /// `true` when the router is the only thing left holding the stores.
    #[must_use]
    pub fn bundle_is_gone(&self) -> bool {
        self.bundle.strong_count() == 0
    }
}

/// A bounded cache of built tenant routers, keyed by `TenantId`.
///
/// Bounded because §3.2's memory cost is N pools, and an unbounded cache in a
/// process that resolves tenants from a `Host` header is a denial-of-service
/// surface. The bound is enforced by [`Self::insert`] as well as by the LRU
/// itself, so even a caller that inserts in a loop cannot grow it.
pub struct StoreBundleCache {
    entries: Mutex<LruCache<TenantId, CachedTenant>>,
}

impl StoreBundleCache {
    /// A cache holding at most `capacity` tenants.
    ///
    /// A capacity of 0 becomes 1 rather than 0. A zero-capacity LRU retains
    /// nothing, so every request would rebuild its tenant at full construction
    /// cost while the configuration *looked* like it cached. `unwrap_or` rather
    /// than `expect` because the input is user-supplied config, and a config
    /// value must never be able to panic the server.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        let capacity = NonZeroUsize::new(capacity).unwrap_or(NonZeroUsize::MIN);
        Self {
            entries: Mutex::new(LruCache::new(capacity)),
        }
    }

    /// The cached router for an **already resolved** tenant, marking it used.
    pub fn get(&self, id: &TenantId) -> Option<Arc<axum::Router>> {
        self.entries
            .lock()
            .ok()
            .and_then(|mut e| e.get(id).map(|cached| cached.router.clone()))
    }

    /// Store a tenant's router, returning whatever was **evicted** to make room.
    ///
    /// The returned [`CachedTenant`] has already left the LRU, so dropping it is
    /// what actually closes the evicted tenant's pool once its last in-flight
    /// request finishes.
    ///
    /// `LruCache::push`, **not** `LruCache::put`. This is not a stylistic
    /// choice: `put` calls `capturing_put(_, _, false)`, which drops the evicted
    /// entry on the floor and returns `None` for a capacity eviction. A cache
    /// built on `put` therefore honours the memory *count* bound while leaking a
    /// pool per eviction — and because the count is what the tests and §7.2's
    /// gate measure, the leak is invisible to both.
    /// `eviction_reports_what_it_dropped` is the test that caught it.
    #[must_use]
    pub fn insert(&self, id: TenantId, cached: CachedTenant) -> Option<CachedTenant> {
        self.entries
            .lock()
            .ok()
            .and_then(|mut e| e.push(id, cached))
            .map(|(_evicted_id, evicted)| evicted)
    }

    /// Drop a tenant's router without rebuilding it.
    ///
    /// §3.3 describes suspension as "removed from the map and its pool closed",
    /// and suspension does not need this — it never reaches the cache. A
    /// *deleted* tenant, a config change, and an explicit `rustical tenant cache
    /// drop` do, and having the eviction path exist and be tested means the
    /// first real use of it is not also its first execution.
    pub fn evict(&self, id: &TenantId) -> Option<CachedTenant> {
        self.entries.lock().ok().and_then(|mut e| e.pop(id))
    }

    /// How many tenants are currently cached — for the admin view and for
    /// asserting the bound.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.lock().map_or(0, |e| e.len())
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The ids currently cached, least-recently-used first.
    ///
    /// Ids only, never a router or a store: a diagnostic that could hand out a
    /// live `Arc<Router>` is a diagnostic that can be asked to serve traffic.
    #[must_use]
    pub fn cached_ids(&self) -> Vec<TenantId> {
        self.entries
            .lock()
            .map(|e| e.iter().map(|(id, _)| id.clone()).collect())
            .unwrap_or_default()
    }

    /// Drop every entry. For a config change or an orderly shutdown.
    pub fn clear(&self) {
        if let Ok(mut e) = self.entries.lock() {
            e.clear();
        }
    }
}

impl std::fmt::Debug for StoreBundleCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoreBundleCache")
            .field("len", &self.len())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::{CachedTenant, DEFAULT_MAX_CACHED_TENANTS, StoreBundleCache};
    use axum::Router;
    use rustical_store::TenantId;
    use std::sync::{Arc, Weak};

    fn id(s: &str) -> TenantId {
        s.parse().expect("a valid slug")
    }

    /// A cache entry with no bundle behind it.
    ///
    /// The tests here are about the cache's bookkeeping — capacity, recency,
    /// eviction — and none of that depends on a tenant's data. Building a real
    /// bundle would mean a database per test to exercise a `HashMap`.
    fn entry(name: &str) -> (TenantId, CachedTenant) {
        (
            id(name),
            CachedTenant {
                bundle: Weak::new(),
                router: Arc::new(Router::new()),
            },
        )
    }

    #[test]
    fn insert_then_get_returns_the_same_router() {
        let cache = StoreBundleCache::new(4);
        let (tid, cached) = entry("acme");
        let expected = cached.router.clone();
        assert!(cache.insert(tid.clone(), cached).is_none());
        assert_eq!(
            cache.get(&tid).as_ref().map(Arc::as_ptr),
            Some(Arc::as_ptr(&expected))
        );
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn a_miss_is_a_miss_and_not_a_build() {
        // The caller is responsible for building on a miss; the cache must not
        // pretend it can serve an unresolved tenant.
        let cache = StoreBundleCache::new(4);
        assert!(cache.get(&id("never-built")).is_none());
        assert!(cache.is_empty());
    }

    #[test]
    fn the_capacity_is_never_exceeded() {
        let cache = StoreBundleCache::new(3);
        for name in ["a", "b", "c", "d", "e", "f"] {
            let (tid, cached) = entry(name);
            let _ = cache.insert(tid, cached);
            assert!(cache.len() <= 3, "capacity breached: {}", cache.len());
        }
        assert_eq!(cache.len(), 3);
    }

    #[test]
    fn eviction_reports_what_it_dropped() {
        // The caller needs the evicted entry so it can let go of the router,
        // which is what closes the pool. An LRU that evicted silently would
        // leak precisely the resource the cap exists to bound.
        let cache = StoreBundleCache::new(2);
        let (a, ca) = entry("a");
        let (b, cb) = entry("b");
        let (c, cc) = entry("c");
        let _ = cache.insert(a, ca);
        let _ = cache.insert(b, cb);
        let evicted = cache.insert(c.clone(), cc);
        assert!(evicted.is_some(), "inserting a third tenant must evict one");
        assert!(cache.get(&c).is_some(), "the newest tenant is present");
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn a_read_marks_a_tenant_as_used_so_it_survives() {
        // The difference between an LRU and random eviction. If `get` did not
        // refresh recency, a *busy* tenant would be the one evicted, which is
        // backwards: a hosted install's popular tenant is the one whose pool
        // most needs to stay warm.
        let cache = StoreBundleCache::new(2);
        let (a, ca) = entry("a");
        let (b, cb) = entry("b");
        let _ = cache.insert(a.clone(), ca);
        let _ = cache.insert(b.clone(), cb);

        assert!(
            cache.get(&a).is_some(),
            "touch a, so b is now the stale one"
        );
        let (c, cc) = entry("c");
        let _ = cache.insert(c, cc);

        assert!(cache.get(&a).is_some(), "the recently read tenant survived");
        assert!(cache.get(&b).is_none(), "the stale tenant was evicted");
    }

    #[test]
    fn eviction_can_be_explicit_and_is_idempotent() {
        let cache = StoreBundleCache::new(4);
        let (a, ca) = entry("a");
        let _ = cache.insert(a.clone(), ca);
        assert!(cache.evict(&a).is_some());
        assert!(cache.evict(&a).is_none(), "evicting twice is not an error");
        assert!(cache.get(&a).is_none());
        assert!(cache.is_empty());
    }

    #[test]
    fn clear_drops_everything() {
        let cache = StoreBundleCache::new(4);
        for name in ["a", "b"] {
            let (tid, cached) = entry(name);
            let _ = cache.insert(tid, cached);
        }
        assert_eq!(cache.len(), 2);
        cache.clear();
        assert!(cache.is_empty());
    }

    #[test]
    fn a_zero_capacity_is_coerced_rather_than_silently_uncached() {
        // `max_cached_tenants = 0` is a plausible operator typo. It must not
        // degrade into "rebuild the tenant on every request" while the config
        // implies a cache.
        let cache = StoreBundleCache::new(0);
        let (a, ca) = entry("a");
        assert!(cache.insert(a.clone(), ca).is_none());
        assert_eq!(cache.len(), 1, "must retain at least one tenant");
        assert!(cache.get(&a).is_some());
    }

    #[test]
    fn the_default_capacity_is_the_plans_number() {
        assert_eq!(DEFAULT_MAX_CACHED_TENANTS, 64);
    }

    #[test]
    fn cached_ids_lists_what_is_held() {
        let cache = StoreBundleCache::new(4);
        for name in ["a", "b"] {
            let (tid, cached) = entry(name);
            let _ = cache.insert(tid, cached);
        }
        let mut ids = cache.cached_ids();
        ids.sort();
        let mut expected = vec![id("a"), id("b")];
        expected.sort();
        assert_eq!(ids, expected);
    }

    #[test]
    fn a_dead_bundle_is_reported_as_gone() {
        // The cache must not be what keeps a tenant's pool alive; evicting an
        // entry has to be allowed to actually release the stores.
        let cached = CachedTenant {
            bundle: Weak::new(),
            router: Arc::new(Router::new()),
        };
        assert!(cached.bundle_is_gone());
    }
}
