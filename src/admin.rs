//! The admin surface's **startup invariants** — `PLAN_DEPLOYMENTS.md` §6.6.2.
//!
//! Phase 2 of item 17: the configuration checks that decide whether an admin
//! panel is allowed to exist, and the credential store it will authenticate
//! against. Phase 3 adds the router itself. The two live together because
//! `serve_dispatch` is where the refusals have to fire, and the panel cannot be
//! mounted without them.
//!
//! ## What is refused, and why refusing beats serving
//!
//! Three refusals, all at startup, none of them recoverable at request time:
//!
//! 1. **`admin_host` set without the single-instance acknowledgement**
//!    ([`TenancyConfig::validate_admin`]). With k>1 each instance has its own
//!    `control.sqlite3` and its own in-memory sessions, so a tenant created on
//!    one does not resolve on another and an admin's session evaporates
//!    whenever the load balancer routes them elsewhere. Nothing in the program
//!    can count its own instances, so this is an operator assertion — see §6.6.4
//!    for why that is the honest implementation and a heuristic would be worse.
//!
//! 2. **A tenant claims `admin_host`** ([`assert_admin_host_unclaimed`]).
//!    The panel is selected *before* `HostDispatch`, so a collision does not
//!    produce an error at the point of collision — it makes that tenant
//!    **silently unreachable**. A customer's hostname answering for a control
//!    surface is the worst available failure mode, and it is silent, which is
//!    the part that makes it the worst.
//!
//! 3. **`admin_host` set with no `platform_admins`** — also in `validate_admin`.
//!    `tenant admin add` refuses any name the allowlist does not contain, so an
//!    empty list means there is no supported way to create the first credential:
//!    a reserved, healthy, permanently unauthenticatable panel with no error
//!    after boot.
//!
//! ## Why the collision check asks two questions
//!
//! A tenant can reach a hostname two ways, and `admin_host` has to be reserved
//! against both:
//!
//! - an **explicit** `tenant_hosts` row — [`TenantStore::is_host_claimed`];
//! - **derivably**, as `{slug}.{base_domain}` for a tenant that happens to exist.
//!
//! Checking only the first is the obvious implementation and it is wrong: a
//! hosted deployment gets a derivable host for free from every tenant, so the
//! derivable case is the *likely* one and the explicit row is the rare one. The
//! derivation is inverted here — the candidate host is split against
//! `base_domain` and the prefix is looked up as a slug — because `admin_host` is
//! a concrete hostname and the slug is the unknown.

use rustical_store::admin_store::AdminCredentialStore;
use rustical_store::tenant_store::TenantStore;
use rustical_store_sqlite::SqliteTenantStore;
use tracing::warn;

use crate::config::TenancyConfig;
use crate::host_dispatch::normalise_host;

/// Refuse to serve if any tenant claims `admin_host` (§6.6.2).
///
/// Both reachability routes are checked, and **both include suspended tenants**:
/// a suspended tenant that still owns a hostname is exactly the case
/// [`TenantStore::is_host_claimed`] exists for (see its doc comment), and a
/// hostname that a suspended tenant owns is not free for the panel to take.
///
/// # Errors
/// A store failure, or a named refusal explaining which tenant holds the host.
/// The message is the whole point: "refusing to start" without saying *which*
/// tenant and *how* it claims the host is an operator's worst morning.
pub async fn assert_admin_host_unclaimed(
    store: &SqliteTenantStore,
    tenancy: &TenancyConfig,
) -> anyhow::Result<()> {
    let admin = tenancy.normalised_admin_host();
    if admin.is_empty() {
        return Ok(());
    }

    if store.is_host_claimed(&admin).await? {
        // `get_any_tenant_by_host`, not `get_tenant_by_host`: the latter filters
        // on `status = 'active'`, and a *suspended* tenant's hostname is still
        // a claim. A refusal that cannot name the tenant is half a refusal.
        let holder = store.get_any_tenant_by_host(&admin).await?;
        return Err(anyhow::anyhow!(
            "[tenancy] admin_host = {admin:?} is already claimed by an explicit tenant_hosts \
             row (tenant {}). The admin panel is selected before tenant dispatch, so this \
             tenant would become silently unreachable on that hostname. Remove the tenant_hosts \
             row, or choose a different admin_host.",
            holder.map_or_else(|| "<unknown>".to_owned(), |t| t.slug.as_str().to_owned())
        ));
    }

    // The derivable case. `admin_host` is a concrete hostname and the slug is
    // the unknown, so this is `{slug}.{base_domain}` read backwards: strip the
    // suffix and ask whether that slug is a tenant.
    if !tenancy.base_domain.is_empty() {
        let suffix = format!(".{}", normalise_host(&tenancy.base_domain));
        if let Some(slug) = admin.strip_suffix(&suffix)
            && !slug.is_empty()
            && !slug.contains(['.', '/', ':'])
            && let Ok(candidate) = slug.parse::<rustical_store::TenantId>()
            && let Some(tenant) = store.get_any_tenant_by_slug(candidate.as_ref()).await?
        {
            return Err(anyhow::anyhow!(
                "[tenancy] admin_host = {admin:?} is tenant {:?}'s derived hostname \
                 ({{slug}}.{{base_domain}}, base_domain = {:?}). The admin panel is selected \
                 before tenant dispatch, so that tenant would become silently unreachable. Pick \
                 a host outside base_domain, or rename the tenant.",
                tenant.slug,
                tenancy.base_domain
            ));
        }
    }

    Ok(())
}

/// Warn about an allowlist that names an admin with no credential row.
///
/// A **warning, not a refusal**: the config is the authority, so the allowlist
/// is allowed to lead — that is how an operator bootstraps, by adding the name
/// to config first and running `tenant admin add` next. What they must not do
/// is leave it there for a month believing the admin can log in.
///
/// The mirror case (a credential row that is not allowlisted) is a *security*
/// finding rather than a misconfiguration, and it is reported by
/// `tenant admin list` on demand rather than here, where it would print on every
/// boot of a deployment that has never been attacked.
pub async fn warn_about_allowlist_gaps(store: &SqliteTenantStore, tenancy: &TenancyConfig) {
    if tenancy.normalised_admin_host().is_empty() {
        return;
    }
    match store.allowlist_gaps(&tenancy.platform_admins).await {
        Ok(entries) => {
            for (name, standing) in entries {
                if matches!(standing, rustical_store::AdminStanding::NoCredential) {
                    warn!(
                        admin = %name,
                        "[tenancy] platform_admins names this admin but the control plane has \
                         no credential row for it, so they cannot log in yet. Run: rustical \
                         tenant admin add {name}"
                    );
                }
            }
        }
        Err(e) => warn!("could not read platform-admin credentials: {e}"),
    }
}

/// The CLI's half of refusal 2, for `tenant create --host` (§6.6.2).
///
/// Refuses at **create** time rather than leaving the collision to be found at
/// the next boot, so it cannot be introduced in the first place. It checks the
/// *config's* view only — no store — because a `create` that is about to write a
/// host row should not depend on a read of a table it is concurrently changing,
/// and the authoritative check still runs at startup.
///
/// # Errors
/// A refusal naming the reserved host, if `host` is the `admin_host`.
pub fn refuse_reserved_admin_host(tenancy: &TenancyConfig, host: &str) -> anyhow::Result<()> {
    if tenancy.is_admin_host(host) {
        let admin = tenancy.normalised_admin_host();
        return Err(anyhow::anyhow!(
            "[tenancy] {host:?} is admin_host ({admin:?}) and is reserved. The admin panel is \
             selected before tenant dispatch, so a tenant claiming it would be silently \
             unreachable. Pick a different --host."
        ));
    }
    Ok(())
}
