//! Platform-admin credentials — Omnical §6.6.3.
//!
//! ## Why this is a separate store, and not another row in `principals`
//!
//! The split is the security property, not a tidy-up. **Names live in config**
//! (`[tenancy] platform_admins`), **hashes live in the control plane** (the
//! `platform_admins` table), and *config is authoritative*: an admin
//! authenticates only if their name is in the list **and** has a valid hash
//! row. Either half alone grants nothing.
//!
//! That is what stops anyone who can write `control.sqlite3` — the file that
//! already holds every tenant's SMTP password (§3.6) — from promoting
//! themselves. If the hashes were the whole of the answer, that file would be
//! a full-privilege credential store, and it is the one file in the install
//! with the widest blast radius. With a config allowlist in front of it, the
//! same write access buys a row that is never consulted.
//!
//! ## What is deliberately absent
//!
//! **No delete.** Revoking an admin is a config edit (remove the name) and a
//! `tenant admin remove` (`DELETE` the row), and §6.6.3 accepts that the two
//! can disagree. What this trait does provide is
//! [`AdminCredentialStore::allowlist_gaps`], so an operator can *see* the
//! disagreement — allowlisted names with no credential row cannot log in, and
//! credential rows with no allowlist entry never will. A panel that listed only
//! the table would show the second group as active admins.
//!
//! ## The lockout is here, not in the caller
//!
//! `failed_attempts`/`locked_until` are columns rather than in-memory counters
//! because a lockout that resets on restart is not a lockout, and an admin
//! brute-force must not be able to wait one out. [`Self::record_login_failure`]
//! increments and locks in a single statement so that N concurrent wrong
//! passwords still produce exactly one increment each.

use crate::error::Error;
use async_trait::async_trait;

/// Failures before an admin is locked out.
///
/// **Fixed, not configurable.** A threshold an operator can raise is a
/// threshold they can raise to 0 and lock themselves out, and a threshold they
/// can lower is a weak one. §6.6.5 copies this from `password_reset.rs`, which
/// uses the same number; the two surfaces are the same class of credential.
pub const ADMIN_MAX_FAILED_ATTEMPTS: i64 = 5;

/// How long a lockout lasts once `ADMIN_MAX_FAILED_ATTEMPTS` is reached.
pub const ADMIN_LOCKOUT_SECS: i64 = 900;

/// One row of `platform_admins`.
///
/// `password_hash` is an argon2 PHC string, the same primitive and parameters
/// `principals` uses, so the two are interchangeable and an operator has one
/// hashing story rather than two.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminCredential {
    pub name: String,
    pub password_hash: String,
    pub created_at: String,
    /// ISO 8601 UTC; `None` until the first successful login.
    pub last_login_at: Option<String>,
    pub failed_attempts: i64,
    /// ISO 8601 UTC; set while the name is locked out.
    pub locked_until: Option<String>,
}

impl AdminCredential {
    /// Is this name locked out at `now` (ISO 8601 UTC)?
    ///
    /// String comparison, because that is the format the column is written in
    /// and the same comparison `PasswordReset::expires_at` already uses. Both
    /// sides are normalised to `YYYY-MM-DDTHH:MM:SSZ` before they are stored.
    #[must_use]
    pub fn is_locked(&self, now: &str) -> bool {
        self.locked_until
            .as_ref()
            .is_some_and(|until| until.as_str() > now)
    }
}

/// One name's standing, reconciled across config and the control plane.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdminStanding {
    /// Allowlisted, with a credential row. Can authenticate.
    Ready { credential: AdminCredential },
    /// Allowlisted, **no credential row**: cannot authenticate, and
    /// `tenant admin add` is how that is fixed.
    NoCredential,
    /// Has a credential row but is **not** allowlisted. The hash is never
    /// consulted. This is what someone with write access to `control.sqlite3`
    /// can create for themselves, and it must be visible here so an operator
    /// can spot it.
    NotAllowlisted { credential: AdminCredential },
    /// Neither.
    Absent,
}

/// Platform-admin credentials in the control plane (§6.6.3).
///
/// Deliberately **not** a method on [`TenantStore`](crate::tenant_store::TenantStore):
/// tenant rows and admin credentials have different lifecycles, different
/// audit requirements, and — the point — a tenant's database must never be
/// involved in authenticating somebody who crosses tenant boundaries.
#[async_trait]
pub trait AdminCredentialStore: Send + Sync + 'static {
    /// Create or replace one admin's credential.
    ///
    /// Upsert rather than insert, so a re-`add` rotates a password without the
    /// operator having to remember whether a `remove` came first. Note that it
    /// resets `failed_attempts`/`locked_until`: re-adding a name is a
    /// credential reset, and a locked-out admin must be un-lockable somehow.
    ///
    /// # Errors
    /// Any store error.
    async fn set_admin_credential(
        &self,
        _name: &str,
        _password_hash: &str,
        _now: &str,
    ) -> Result<(), Error> {
        Err(Error::ReadOnly)
    }

    /// One admin's credential row, by exact name.
    ///
    /// # Errors
    /// Any store error. An unknown name is `Ok(None)`, not an error.
    async fn get_admin_credential(&self, _name: &str) -> Result<Option<AdminCredential>, Error> {
        Ok(None)
    }

    /// Every credential row, name-ascending.
    ///
    /// Read by `tenant admin list` so that a row with no allowlist entry is
    /// visible rather than invisible-but-effective.
    ///
    /// # Errors
    /// Any store error.
    async fn list_admin_credentials(&self) -> Result<Vec<AdminCredential>, Error> {
        Ok(Vec::new())
    }

    /// Delete one admin's credential row.
    ///
    /// Returns `Ok(false)` for a name that had no row, so a caller can report
    /// "nothing to remove" without treating it as a failure.
    ///
    /// # Errors
    /// Any store error.
    async fn remove_admin_credential(&self, _name: &str) -> Result<bool, Error> {
        Ok(false)
    }

    /// Record a failed login attempt: increment the counter and set
    /// `locked_until` if this attempt reached
    /// [`ADMIN_MAX_FAILED_ATTEMPTS`].
    ///
    /// One statement, so N simultaneous wrong passwords increment N times and
    /// never fewer — a read-modify-write in Rust would lose the race and make
    /// the lockout *weaker* under exactly the load an attacker would apply.
    ///
    /// A locked-out name stays locked: the increment still happens, and
    /// `locked_until` is not shortened, so a flood of failures extends nothing
    /// and clears nothing.
    ///
    /// # Errors
    /// Any store error.
    async fn record_login_failure(
        &self,
        _name: &str,
        _now: &str,
        _lockout_until: &str,
    ) -> Result<(), Error> {
        Err(Error::ReadOnly)
    }

    /// Record a successful login: clear the counter and any lockout, and set
    /// `last_login_at`.
    ///
    /// # Errors
    /// Any store error.
    async fn record_login_success(&self, _name: &str, _now: &str) -> Result<(), Error> {
        Err(Error::ReadOnly)
    }

    /// Reconcile `allowlist` (from config) against the credential table.
    ///
    /// The default is the credential-table side only, which is what a store
    /// with no notion of config can honestly do; the caller pairs it with
    /// config. Returns one entry per name in the union of both sides, so a
    /// name present in either is never silently omitted — an omission here
    /// would be an admin who is invisible in exactly the listing an operator
    /// runs to find them.
    ///
    /// # Errors
    /// Any store error.
    async fn allowlist_gaps(
        &self,
        allowlist: &[String],
    ) -> Result<Vec<(String, AdminStanding)>, Error> {
        let credentials = self.list_admin_credentials().await?;
        let mut out: Vec<(String, AdminStanding)> = credentials
            .iter()
            .map(|c| {
                (
                    c.name.clone(),
                    if allowlist.iter().any(|n| n == &c.name) {
                        AdminStanding::Ready {
                            credential: c.clone(),
                        }
                    } else {
                        AdminStanding::NotAllowlisted {
                            credential: c.clone(),
                        }
                    },
                )
            })
            .collect();
        for name in allowlist {
            if !out.iter().any(|(n, _)| n == name) {
                out.push((name.clone(), AdminStanding::NoCredential));
            }
        }
        out.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(out)
    }
}
