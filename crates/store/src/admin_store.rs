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

/// The outcome of an admin login attempt.
///
/// Deliberately **coarse**: `Unknown` and `WrongPassword` are different variants
/// so the *store* can decide whether to record a failure, and are rendered
/// identically by every caller, because telling an attacker which of the two
/// they hit is the difference between a rate limit and a username oracle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminAuthOutcome {
    /// Authenticated, and the login was recorded.
    Ok,
    /// No such credential row, **or** the password did not match. One variant on
    /// purpose — see above.
    Refused,
    /// The name exists and is locked out. The caller may say so: the attacker
    /// already knows the name is real, because they are being rate limited
    /// against it.
    Locked,
}

/// The current time, in the format the credential columns are written in.
///
/// `chrono` is already a dependency of this crate. The format is a property of
/// the **trait's** contract — [`AdminCredential::is_locked`] compares these as
/// strings — so the two functions that produce them belong beside it rather
/// than in whichever store crate happens to be the SQLite one this month.
#[must_use]
pub fn admin_now() -> String {
    chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

/// The lockout deadline for a failure recorded at `now`.
///
/// Computed in Rust, **not** in SQL, because SQLite's date functions return
/// `YYYY-MM-DD HH:MM:SS` — a space and no `Z` — and [`AdminCredential::is_locked`]
/// compares these as strings. A deadline written by SQLite and compared against
/// a `now` from Rust would sort wrong for every timestamp, which is to say it
/// would expire immediately.
///
/// Never fails: an unparseable `now` falls back to the real clock, because a
/// malformed timestamp should not panic on a login path.
#[must_use]
pub fn admin_lockout_until(now: &str) -> String {
    let deadline = chrono::DateTime::parse_from_rfc3339(now)
        .unwrap_or_else(|_| chrono::Utc::now().fixed_offset())
        + chrono::Duration::seconds(ADMIN_LOCKOUT_SECS);
    deadline.format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

/// Verify a password against an admin's stored argon2 hash.
///
/// In this crate, and not in the caller, for two reasons: the hash format is the
/// store's business, and the panel should not be able to skip the verification
/// and read `password_hash` directly. `password-auth` is already a dependency
/// here (it is what `principals` uses), so nothing new is pulled in.
#[must_use]
pub fn verify_admin_password(password: &str, hash: &str) -> bool {
    password_auth::verify_password(password, hash).is_ok()
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

    /// Authenticate one admin, and record the attempt.
    ///
    /// The whole sequence — lookup, lockout check, verify, record — lives in one
    /// trait method for two reasons that both came from bugs this design avoids:
    ///
    /// 1. **The order is load-bearing.** A caller that checked the lockout
    ///    *after* verifying the password would still burn argon2 on every
    ///    attempt against a locked name, which is a free denial-of-service.
    /// 2. **The record is not optional.** A caller that verifies and forgets to
    ///    call [`Self::record_login_failure`] gets a lockout that silently does
    ///    not lock, and nothing in the type system would say so.
    ///
    /// The allowlist is **not** consulted here, because this layer cannot see
    /// config. Every caller must check `name` against the allowlist *first*
    /// (§6.6.3) — `Ok(Refused)` for an unlisted name is the right answer, but
    /// the caller is what enforces it, and the panel is where that check has to
    /// be visible.
    ///
    /// `now` and `lockout_until` are supplied rather than read from the clock
    /// here so a caller can compute the deadline in the same format it is
    /// compared in, and so a test can drive time without sleeping.
    ///
    /// # Errors
    /// Any store error.
    async fn authenticate_admin(
        &self,
        _name: &str,
        _password: &str,
        _now: &str,
        _lockout_until: &str,
    ) -> Result<AdminAuthOutcome, Error> {
        Ok(AdminAuthOutcome::Refused)
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
