//! The usage-snapshot type (§7.5 item 20a).
//!
//! It lives here rather than in the `rustical` crate because
//! [`TenantStore`](crate::tenant_store::TenantStore) carries it, and
//! `rustical_store` cannot depend on the crate that depends on it.
//!
//! # `NULL` is not zero
//!
//! Every count is `Option`, and `None` means **not measured** — a different fact
//! from zero. This is the single most important property of the type: a usage
//! figure rendered as `0` tells a customer they are at their limit when nothing
//! is known about them. A missing snapshot must read as "not measured" in the
//! panel, and it does.

use serde::{Deserialize, Serialize};

/// One tenant's usage, as stored in `control_tenant_usage`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TenantUsage {
    pub tenant_id: String,
    /// When the snapshot was taken, written by the job rather than defaulted by
    /// the database, so a clock skew shows up as a wrong timestamp instead of a
    /// plausible one.
    pub measured_at: String,
    /// Who ran the job. §6.6.7's rule: a number with no provenance is a number
    /// nobody can act on.
    pub actor: String,
    pub principals: Option<i64>,
    pub calendars: Option<i64>,
    pub addressbooks: Option<i64>,
    pub bytes_on_disk: Option<i64>,
    pub object_count: Option<i64>,
}

impl TenantUsage {
    /// A snapshot that has not been taken.
    #[must_use]
    pub fn unmeasured(
        tenant_id: impl Into<String>,
        at: impl Into<String>,
        actor: impl Into<String>,
    ) -> Self {
        Self {
            tenant_id: tenant_id.into(),
            measured_at: at.into(),
            actor: actor.into(),
            principals: None,
            calendars: None,
            addressbooks: None,
            bytes_on_disk: None,
            object_count: None,
        }
    }

    /// Has anything actually been counted?
    #[must_use]
    pub const fn is_measured(&self) -> bool {
        self.principals.is_some() || self.calendars.is_some() || self.addressbooks.is_some()
    }

    /// The one-line form a human reads, with unknowns spelled out.
    #[must_use]
    pub fn summary(&self) -> String {
        fn n(v: Option<i64>) -> String {
            v.map_or_else(|| "not measured".to_owned(), |v| v.to_string())
        }
        format!(
            "{} — {} principals, {} calendars, {} addressbooks, {} objects, {} on disk (measured {}){}",
            self.tenant_id,
            n(self.principals),
            n(self.calendars),
            n(self.addressbooks),
            n(self.object_count),
            n(self.bytes_on_disk),
            self.measured_at,
            if self.is_measured() {
                ""
            } else {
                "  NOTHING MEASURED"
            }
        )
    }
}
