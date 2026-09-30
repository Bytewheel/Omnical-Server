//! Quota enforcement in the write path (§7.5 item 20b).
//!
//! §7.5 calls this **wave 3** and the only part of quotas with real blast
//! radius: *"it is the first change that makes a write **fail** because of a
//! customer's plan."* Item 20a made usage visible; this makes it binding.
//!
//! # The one rule that matters
//!
//! **A quota refusal must be the customer's own limit, not a 500.**
//!
//! That is the whole design constraint, and it is easy to get wrong in three
//! ways that all look like "quota enforcement" in a log:
//!
//! * the check **panics** on a missing quota row — which is a 500 for a customer
//!   who did nothing wrong;
//! * it **counts on every write** — so a tenant at the limit makes every
//!   calendar sync slower, and the slowness looks like a performance problem
//!   rather than a policy;
//! * it returns a **500** for "your plan does not include this" — which tells a
//!   client to retry, so a `CalDAV` client retries forever against a limit that
//!   will never lift.
//!
//! [`QuotaDecision`] is the type that makes each of those a different, testable
//! answer, and [`quota_refusal_status`] is the one place the status code is
//! chosen.
//!
//! # Counting is not free, so it is explicit
//!
//! The usage numbers come from item 20a's **snapshot**, not from a live count. A
//! snapshot is a minute old, so a tenant one principal over the limit may get
//! one more through — and that is the correct trade, stated plainly: a quota
//! system that runs `count(*)` on the write path is a system whose write path
//! gets slower the more successful the product is. The snapshot's age is on the
//! row, so a panel can show it and an operator can reason about it.

use rustical_store::tenant_store::TenantQuota;
use rustical_store::tenant_usage::TenantUsage;

/// What a quota check concluded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuotaDecision {
    /// No limit is set on this dimension, or no usage has been measured.
    ///
    /// **"No usage measured" is treated as allowed**, and that is a decision
    /// rather than an oversight. Failing closed on an unmeasured tenant means a
    /// fresh install refuses every write until the job has run, which looks
    /// exactly like a broken server. Failing open on a *measured* tenant that is
    /// over its limit is a different thing entirely, and does not happen.
    Allowed,
    /// The tenant is at or over the limit on this dimension.
    Refused {
        dimension: &'static str,
        limit: i64,
        used: i64,
    },
}

impl QuotaDecision {
    /// Was the write allowed?
    #[must_use]
    pub const fn is_allowed(&self) -> bool {
        matches!(self, Self::Allowed)
    }
}

/// Check one dimension.
///
/// # The arithmetic
///
/// `used >= limit` refuses, so a limit of `10` admits principals 1 through 10
/// and refuses the eleventh. `used > limit` would admit eleven. This is the
/// whole off-by-one and it is worth a test either way.
#[must_use]
pub const fn check_dimension(
    dimension: &'static str,
    limit: Option<i64>,
    used: Option<i64>,
) -> QuotaDecision {
    let (Some(limit), Some(used)) = (limit, used) else {
        return QuotaDecision::Allowed;
    };
    // A limit of 0 or below is a configuration mistake, not a policy. Refusing
    // every write on a tenant whose quota was set to -1 by a bad script would be
    // a self-inflicted outage, and "no limit" is the safe reading of a nonsense
    // one.
    if limit <= 0 {
        return QuotaDecision::Allowed;
    }
    if used >= limit {
        QuotaDecision::Refused {
            dimension,
            limit,
            used,
        }
    } else {
        QuotaDecision::Allowed
    }
}

/// Can this tenant create another principal?
#[must_use]
pub fn check_principals(quota: &TenantQuota, usage: Option<&TenantUsage>) -> QuotaDecision {
    check_dimension(
        "principals",
        quota.principals,
        usage.and_then(|u| u.principals),
    )
}

/// …another calendar?
#[must_use]
pub fn check_calendars(quota: &TenantQuota, usage: Option<&TenantUsage>) -> QuotaDecision {
    check_dimension(
        "calendars",
        quota.calendars,
        usage.and_then(|u| u.calendars),
    )
}

/// …another calendar object?
///
/// The quota column is `quota_megabytes`, so this compares **bytes on disk** and
/// not an object count. The snapshot's `bytes_on_disk` is the file's size, which
/// includes SQLite's free pages after a delete — so a tenant who deletes a large
/// event may stay over the limit until a `VACUUM`. That is a real inaccuracy and
/// it is the conservative direction: the tenant is told they are at the limit when
/// the disk says they are.
#[must_use]
pub fn check_storage(quota: &TenantQuota, usage: Option<&TenantUsage>) -> QuotaDecision {
    const MIB: i64 = 1024 * 1024;
    let Some(limit_mib) = quota.megabytes else {
        return QuotaDecision::Allowed;
    };
    if limit_mib <= 0 {
        return QuotaDecision::Allowed;
    }
    let Some(bytes) = usage.and_then(|u| u.bytes_on_disk) else {
        return QuotaDecision::Allowed;
    };
    let used_mib = bytes / MIB;
    if used_mib >= limit_mib {
        QuotaDecision::Refused {
            dimension: "storage",
            limit: limit_mib,
            used: used_mib,
        }
    } else {
        QuotaDecision::Allowed
    }
}

/// The HTTP status a refusal gets.
///
/// **507 Insufficient Storage**, with one exception: 507 is defined for a server
/// that is out of space, and a customer's *plan* being full is not that — a
/// strict reading makes this the wrong code, and 403 Forbidden is the one people
/// see on quota systems everywhere.
///
/// 403 is used, and 403 plus `Retry-After: never` semantics is the important
/// part: the response carries a machine-readable reason, and a client that
/// retries against a limit will never succeed. The alternative — 503, which
/// every `CalDAV` client treats as "try again later" — produces a retry storm
/// against a condition that will not change.
///
/// §7.5's requirement is the one this encodes: the error must be the customer's
/// own limit and not a 500, and it must not invite a retry.
#[must_use]
pub const fn quota_refusal_status() -> u16 {
    // 403
    403
}

/// The body a refusal returns, naming the dimension and both numbers.
///
/// A client sees this and a person debugging sees this, so it says what was
/// refused, what the limit is and what the usage is — and nothing about any other
/// tenant.
#[must_use]
pub fn refusal_body(decision: &QuotaDecision, unit: &str) -> String {
    match decision {
        QuotaDecision::Allowed => String::new(),
        QuotaDecision::Refused {
            dimension,
            limit,
            used,
        } => format!(
            "Your plan's {dimension} limit has been reached ({used}{unit} of {limit}{unit}). \
             This is a limit on your account, not a temporary error, so retrying will not help. \
             Contact your administrator to have it raised."
        ),
    }
}

/// The `ErrorKind` a `CalDAV` client sees.
///
/// `InsufficientStorage` is what DAV defines for "the server cannot store this",
/// and it is the semantically correct condition even though the HTTP status is
/// 403 — a client that understands DAV shows the right message, and one that only
/// reads the status still does not retry.
#[must_use]
pub const fn refusal_error_kind_name() -> &'static str {
    "InsufficientStorage"
}
