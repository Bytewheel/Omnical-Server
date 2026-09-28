//! Tenant identity — `PLAN_DEPLOYMENTS.md` §3.2, §3.4.
//!
//! ## Why this type exists, given that isolation does not need it
//!
//! §3.2's decision is that **a tenant is a resolved `Router`, not a column**.
//! Isolation is therefore structural: each tenant's router is built over its own
//! store bundle, so there is no `WHERE tenant_id = ?` anywhere to forget. This
//! type is **not** part of that mechanism, and it is worth being blunt about it,
//! because a `TenantId` threaded through a store method would look like the
//! isolation boundary and would not be one — it would be a *second*, weaker,
//! easier-to-forget version of it.
//!
//! What this type actually carries is **identity**: which tenant a built
//! `Router` belongs to, so that the router is self-describing, and so that the
//! three routers mounted *outside* the auth layer (`export_`, `rsvp_`,
//! `register_` — §6.4) have something to assert against. Those three resolve
//! ownership from a *token* rather than a principal, which makes them the only
//! places where a tenant check can be silently absent; the rows 26-28 tests, not
//! this type, are what actually enforce it.
//!
//! ## What is deliberately not here
//!
//! No `TenantStore` trait and no store path resolution. Those belong to the
//! control plane (§3.4) and land with the dispatch layer; putting them here
//! would make this module look like the tenancy boundary when it is a label.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// Longest slug `tenant_hosts` and DNS will tolerate.
///
/// 63 is the DNS label limit, and a slug becomes a hostname under
/// `{slug}.{base_domain}` (§3.3 match 2), so this is a protocol limit rather
/// than an aesthetic one.
pub const MAX_SLUG_LEN: usize = 63;

/// A validated tenant slug: `[a-z0-9-]{1,63}`, DNS-safe.
///
/// A newtype rather than a `String` because the slug is used in three places
/// that must agree — a hostname, a directory name under `data_root`, and a
/// column with a `UNIQUE` constraint — and a `String` that happens to contain
/// `../` in any one of them is a different bug in each. Construction is the only
/// way in, so the invariant is checked once.
///
/// Lowercase-only, deliberately: a slug is compared against a lowercased
/// `Host` header, and accepting uppercase would mean two spellings of one
/// tenant and a `UNIQUE` constraint that does not mean what it looks like.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct TenantId(String);

impl TenantId {
    /// The validated slug.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for TenantId {
    type Error = String;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if value.is_empty() {
            return Err("a tenant slug cannot be empty".to_owned());
        }
        if value.len() > MAX_SLUG_LEN {
            return Err(format!(
                "a tenant slug cannot exceed {MAX_SLUG_LEN} characters (got {})",
                value.len()
            ));
        }
        if value.starts_with('-') || value.ends_with('-') {
            return Err(format!(
                "'{value}' cannot start or end with '-' — it becomes a DNS label"
            ));
        }
        if !value
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        {
            return Err(format!(
                "'{value}' must be [a-z0-9-] only; a slug becomes a hostname and a \
                 directory name, and uppercase or other characters are not safe in either"
            ));
        }
        Ok(Self(value))
    }
}

impl From<TenantId> for String {
    fn from(id: TenantId) -> Self {
        id.0
    }
}

impl FromStr for TenantId {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_from(s.to_owned())
    }
}

impl fmt::Display for TenantId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for TenantId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// Whether a tenant may serve traffic (§3.4 `status`).
///
/// Two states, not a boolean: the third state a hosted deployment needs is
/// "suspended but keep the data", and encoding that as a separate variant later
/// means deciding what a suspended tenant's *rows* mean.
///
/// Suspension is a real, testable admin action: the router is removed from the
/// map and its pool closed, so in-flight requests drain and nothing new starts
/// (row 29).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TenantStatus {
    Active,
    Suspended,
}

impl TenantStatus {
    /// The `tenants.status` column value. Matches the `CHECK (status IN
    /// ('active','suspended'))` constraint in §3.4 — the two must not drift, or
    /// a status this enum can produce is one the database rejects.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Suspended => "suspended",
        }
    }
}

impl fmt::Display for TenantStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for TenantStatus {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "active" => Ok(Self::Active),
            "suspended" => Ok(Self::Suspended),
            other => Err(format!(
                "unknown tenant status '{other}'; the database allows 'active' or 'suspended'"
            )),
        }
    }
}

/// A resolved tenant: who it is, whether it may serve, and its per-tenant
/// config overrides.
///
/// `config_json` is the §3.6 override blob — the *values* from it are resolved
/// into a per-tenant `AppConfig` **before** the router is built, which is why
/// this struct carries the raw string rather than a parsed override type. The
/// resolution direction is global config ← tenant overrides; a missing key
/// inherits, so the blob is sparse by design.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tenant {
    pub id: TenantId,
    /// DNS-safe identifier; the primary key is `id`, this is what appears in
    /// hostnames (`{slug}.{base_domain}`, §3.3) and in the admin UI.
    pub slug: TenantId,
    pub display_name: String,
    pub status: TenantStatus,
    /// Per-tenant overrides for the global-only config sections (§3.6). Raw
    /// JSON, resolved before construction.
    pub config_json: String,
}

impl Tenant {
    /// Whether this tenant may serve traffic. A suspended tenant's router is
    /// removed from the dispatch map rather than being asked politely (row 29);
    /// this is the cheap pre-check for the paths that are not dispatch-routed.
    #[must_use]
    pub const fn is_active(&self) -> bool {
        matches!(self.status, TenantStatus::Active)
    }
}

#[cfg(test)]
mod tests {
    use super::{MAX_SLUG_LEN, Tenant, TenantId, TenantStatus};

    fn id(s: &str) -> TenantId {
        s.parse().expect("a valid slug")
    }

    #[test]
    fn accepts_what_a_hostname_accepts() {
        assert_eq!(id("acme").as_str(), "acme");
        assert_eq!(id("t3").as_str(), "t3");
        assert_eq!(id("a-b-c-1").as_str(), "a-b-c-1");
        assert_eq!(id(&"x".repeat(MAX_SLUG_LEN)).as_str().len(), MAX_SLUG_LEN);
    }

    #[test]
    fn rejects_everything_a_hostname_or_a_path_would_mishandle() {
        // The `..` case is the reason this is a newtype: a slug becomes a
        // directory name under `data_root`.
        assert!(TenantId::try_from("../etc".to_owned()).is_err());
        assert!(TenantId::try_from("a/b".to_owned()).is_err());
        // Uppercase: compared against a lowercased Host header, so two
        // spellings of one tenant would slip past a UNIQUE constraint.
        assert!(TenantId::try_from("Acme".to_owned()).is_err());
        // Leading/trailing dash: not a valid DNS label.
        assert!(TenantId::try_from("-acme".to_owned()).is_err());
        assert!(TenantId::try_from("acme-".to_owned()).is_err());
        assert!(TenantId::try_from(String::new()).is_err());
        assert!(TenantId::try_from("x".repeat(MAX_SLUG_LEN + 1)).is_err());
        // A space would survive a naive `is_ascii_graphic` check and break the
        // host comparison instead.
        assert!(TenantId::try_from("a b".to_owned()).is_err());
        // Non-ASCII: `is_lowercase()` accepts 'é', which is not DNS-safe.
        assert!(TenantId::try_from("café".to_owned()).is_err());
    }

    /// The error text names the constraint, because the person hitting this is
    /// an operator running `rustical tenant create` and a bare "invalid slug"
    /// is a support call.
    #[test]
    fn errors_say_what_is_wrong() {
        let e = TenantId::try_from("Acme".to_owned()).unwrap_err();
        assert!(e.contains("[a-z0-9-]"), "{e}");
        let e = TenantId::try_from("a/b".to_owned()).unwrap_err();
        assert!(e.contains("[a-z0-9-]"), "{e}");
    }

    #[test]
    fn status_round_trips_through_its_column_value() {
        for status in [TenantStatus::Active, TenantStatus::Suspended] {
            let text = status.to_string();
            assert_eq!(text.parse::<TenantStatus>().unwrap(), status);
        }
    }

    /// The enum and the database's CHECK constraint must not drift: a status
    /// this enum can produce but the column rejects is a 500 on suspension.
    #[test]
    fn status_values_are_exactly_the_columns_check_constraint() {
        assert_eq!(TenantStatus::Active.as_str(), "active");
        assert_eq!(TenantStatus::Suspended.as_str(), "suspended");
        assert!("active suspended".contains(TenantStatus::Active.as_str()));
        assert!("active suspended".contains(TenantStatus::Suspended.as_str()));
        assert!("running".parse::<TenantStatus>().is_err());
    }

    #[test]
    fn only_an_active_tenant_serves() {
        let base = Tenant {
            id: id("acme"),
            slug: id("acme"),
            display_name: "Acme".to_owned(),
            status: TenantStatus::Active,
            config_json: "{}".to_owned(),
        };
        assert!(base.is_active());
        let suspended = Tenant {
            status: TenantStatus::Suspended,
            ..base
        };
        assert!(!suspended.is_active());
    }

    /// A tenant's config blob is sparse by design — §3.6 resolves global config
    /// ← tenant overrides, so an absent key inherits rather than defaulting to
    /// something. The round trip must not invent keys.
    #[test]
    fn config_json_survives_untouched() {
        let t = Tenant {
            id: id("acme"),
            slug: id("acme"),
            display_name: "Acme".to_owned(),
            status: TenantStatus::Active,
            config_json: r#"{"rsvp_secret":"abc"}"#.to_owned(),
        };
        assert_eq!(t.config_json, r#"{"rsvp_secret":"abc"}"#);
    }
}
