//! Item 20b: quota enforcement, and the three ways it goes wrong invisibly.
//!
//! The rules under test are all about a **failure that looks like something
//! else**. A quota refusal that returns 500 tells a CalDAV client to retry, so it
//! retries forever against a limit that will never lift. A check that counts on
//! the write path makes every sync slower the more successful the product is. A
//! `>=`/`>` off-by-one either lets a tenant one over the limit or refuses a
//! tenant who is exactly on it.

use rustical::quota::{
    QuotaDecision, check_calendars, check_dimension, check_principals, check_storage,
    quota_refusal_status, refusal_body,
};
use rustical_store::tenant_store::TenantQuota;
use rustical_store::tenant_usage::TenantUsage;

fn quota(principals: Option<i64>, calendars: Option<i64>, megabytes: Option<i64>) -> TenantQuota {
    TenantQuota {
        principals,
        calendars,
        megabytes,
    }
}

fn usage(principals: Option<i64>, calendars: Option<i64>, bytes: Option<i64>) -> TenantUsage {
    TenantUsage {
        tenant_id: "T-1".to_owned(),
        measured_at: "2026-09-29T00:00:00Z".to_owned(),
        actor: "nightly-cron".to_owned(),
        principals,
        calendars,
        addressbooks: None,
        bytes_on_disk: bytes,
        object_count: None,
    }
}

// ── the status code, which is the whole point ──────────────────────────────

#[test]
fn a_quota_refusal_is_not_a_500_and_does_not_invite_a_retry() {
    // §7.5: "the error has to be the customer's own limit and not a 500". A 500
    // tells every CalDAV client to retry, so it retries forever against a
    // condition that cannot change.
    let status = quota_refusal_status();
    assert_ne!(status, 500, "a 500 invites a retry storm");
    assert_ne!(
        status, 503,
        "503 is 'try again later'; this will never be later"
    );
    assert_eq!(
        status, 403,
        "the limit is the client's own account, not the server's"
    );

    let body = refusal_body(
        &QuotaDecision::Refused {
            dimension: "calendars",
            limit: 10,
            used: 10,
        },
        "",
    );
    assert!(body.contains("limit"), "{body}");
    assert!(
        body.to_lowercase().contains("retrying will not help"),
        "the body must tell the client not to retry: {body}"
    );
    assert!(
        body.to_lowercase().contains("contact your administrator"),
        "and where to go instead: {body}"
    );
}

#[test]
fn a_refusal_body_names_only_this_tenants_own_numbers() {
    // The body reaches a client, so it must not carry anything about another
    // tenant — and there is nothing in `QuotaDecision` to leak, which is worth
    // asserting at the type level.
    let decision = QuotaDecision::Refused {
        dimension: "storage",
        limit: 100,
        used: 120,
    };
    let body = refusal_body(&decision, " MiB");
    assert!(body.contains("120 MiB"), "{body}");
    assert!(body.contains("100 MiB"), "{body}");
    assert!(!body.to_lowercase().contains("tenant"), "{body}");
    // And an *allowed* decision has no body at all, so an accidental call cannot
    // emit a nonsense message.
    assert!(refusal_body(&QuotaDecision::Allowed, "").is_empty());
}

// ── the arithmetic ─────────────────────────────────────────────────────────

#[test]
fn the_limit_is_inclusive() {
    // `used >= limit` refuses. A limit of 10 admits principals 1..=10 and refuses
    // the eleventh; `used > limit` would admit eleven.
    assert!(
        check_principals(
            &quota(Some(10), None, None),
            Some(&usage(Some(9), None, None))
        )
        .is_allowed()
    );
    assert!(
        !check_principals(
            &quota(Some(10), None, None),
            Some(&usage(Some(10), None, None))
        )
        .is_allowed()
    );
    assert!(
        !check_principals(
            &quota(Some(10), None, None),
            Some(&usage(Some(11), None, None))
        )
        .is_allowed()
    );
}

#[test]
fn no_limit_means_no_refusal() {
    for q in [quota(None, None, None), quota(None, Some(5), None)] {
        assert!(check_principals(&q, Some(&usage(Some(999), Some(999), Some(999)))).is_allowed());
    }
    assert!(quota(None, None, None).is_unlimited());
}

#[test]
fn a_nonsense_limit_does_not_refuse_everything() {
    // A limit of 0 or below is a configuration mistake, not a policy. Refusing
    // every write on a tenant whose quota was set to -1 by a bad script is a
    // self-inflicted outage, and "no limit" is the safe reading of a nonsense
    // one.
    assert!(
        check_principals(
            &quota(Some(0), None, None),
            Some(&usage(Some(5), None, None))
        )
        .is_allowed()
    );
    assert!(
        check_principals(
            &quota(Some(-1), None, None),
            Some(&usage(Some(5), None, None))
        )
        .is_allowed()
    );
    assert!(
        check_storage(
            &quota(None, None, Some(-5)),
            Some(&usage(None, None, Some(999 * 1024 * 1024)))
        )
        .is_allowed()
    );
}

#[test]
fn an_unmeasured_tenant_is_allowed_and_says_why() {
    // Failing closed on an unmeasured tenant means a fresh install refuses every
    // write until the job has run — which looks exactly like a broken server. The
    // decision is deliberate and this is the test that states it.
    assert!(check_principals(&quota(Some(1), None, None), None).is_allowed());
    assert!(check_calendars(&quota(None, Some(1), None), None).is_allowed());
    assert!(check_storage(&quota(None, None, Some(1)), None).is_allowed());

    // …and an unmeasured *dimension* on a measured tenant behaves the same way,
    // rather than being treated as zero-of-a-real-measurement.
    let partial = usage(Some(1), None, None);
    assert!(check_calendars(&quota(None, Some(1), None), Some(&partial)).is_allowed());
    // while a measured dimension is enforced on the same row.
    assert!(!check_principals(&quota(Some(1), None, None), Some(&partial)).is_allowed());
}

// ── each dimension, and the units ──────────────────────────────────────────

#[test]
fn calendars_are_checked_on_calendars() {
    assert!(
        check_calendars(
            &quota(None, Some(3), None),
            Some(&usage(None, Some(2), None))
        )
        .is_allowed()
    );
    assert!(
        !check_calendars(
            &quota(None, Some(3), None),
            Some(&usage(None, Some(3), None))
        )
        .is_allowed()
    );
}

#[test]
fn storage_is_compared_in_mib_because_the_quota_is() {
    const MIB: i64 = 1024 * 1024;
    // 99 MiB used against a 100 MiB limit: allowed.
    assert!(
        check_storage(
            &quota(None, None, Some(100)),
            Some(&usage(None, None, Some(99 * MIB)))
        )
        .is_allowed()
    );
    // 100 MiB: refused. `>=`, like the count dimensions.
    assert!(
        !check_storage(
            &quota(None, None, Some(100)),
            Some(&usage(None, None, Some(100 * MIB)))
        )
        .is_allowed()
    );
    // A few MiB *under* the limit measured in bytes is still under, which the
    // integer division must not get wrong: 100 MiB - 1 byte divides to 99 MiB,
    // and that is correct (it is under).
    assert!(
        check_storage(
            &quota(None, None, Some(100)),
            Some(&usage(None, None, Some(100 * MIB - 1)))
        )
        .is_allowed()
    );
}

#[test]
fn storage_uses_bytes_on_disk_and_says_so() {
    // The snapshot's `bytes_on_disk` is the *file's* size, which includes
    // SQLite's free pages after a delete. So a tenant who deletes a large event
    // may stay over the limit until a VACUUM. That is a real inaccuracy and it is
    // in the conservative direction: the tenant is told they are at the limit when
    // the disk says they are. The alternative — summing object lengths — is a
    // full scan of a customer's data on every quota check.
    const MIB: i64 = 1024 * 1024;
    let snapshot = usage(None, None, Some(150 * MIB));
    let decision = check_storage(&quota(None, None, Some(100)), Some(&snapshot));
    assert!(matches!(
        decision,
        QuotaDecision::Refused {
            dimension: "storage",
            ..
        }
    ));
    let body = refusal_body(&decision, " MiB");
    assert!(body.contains("150 MiB"), "{body}");
}

// ── the design constraints, asserted against the source ────────────────────

#[test]
fn the_write_path_does_not_count_on_every_write() {
    // A live `count(*)` per write makes the write path slower the more
    // successful the product is. The check must read the *snapshot*.
    // Comments excluded: the module's own doc comment *names* `count(*)` to
    // explain why it does not run one, and a naive substring check fails on the
    // explanation. The same lesson as §18.22's recipe check matching a comment.
    let src = include_str!("../src/quota.rs");
    let code: String = src
        .lines()
        .filter(|l| !l.trim_start().starts_with("//!") && !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        !code.contains("count("),
        "quota.rs must not count rows; it reads item 20a's snapshot"
    );
    assert!(
        src.contains("snapshot"),
        "and the module should say that is the reason"
    );
}

#[test]
fn the_check_cannot_panic_on_a_missing_row() {
    // A panic here is a 500 for a customer who did nothing wrong, and it is the
    // most likely way this code gets written.
    let src = include_str!("../src/quota.rs");
    assert!(
        !src.contains(".expect(") && !src.contains(".unwrap()"),
        "quota.rs must not unwrap: a missing quota is a normal state"
    );
    // …and the type makes it unrepresentable rather than merely unlikely.
    let d = check_dimension("principals", None, None);
    assert_eq!(d, QuotaDecision::Allowed);
    let _ = check_dimension("principals", Some(5), None);
    assert!(check_dimension("principals", Some(5), None).is_allowed());
}

#[test]
fn a_refusal_is_reachable_and_an_allowance_is_not_an_error() {
    // Every dimension must be able to refuse, or one of them is decorative.
    assert!(
        check_principals(
            &quota(Some(1), None, None),
            Some(&usage(Some(1), None, None))
        ) == QuotaDecision::Refused {
            dimension: "principals",
            limit: 1,
            used: 1,
        }
    );
    assert!(
        check_calendars(
            &quota(None, Some(2), None),
            Some(&usage(None, Some(2), None))
        ) == QuotaDecision::Refused {
            dimension: "calendars",
            limit: 2,
            used: 2,
        }
    );
    assert!(
        !check_storage(
            &quota(None, None, Some(1)),
            Some(&usage(None, None, Some(1024 * 1024)))
        )
        .is_allowed(),
        "exactly at the limit must refuse"
    );
}
