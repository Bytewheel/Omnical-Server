#![cfg(test)]
//! Control-plane tests — `PLAN_DEPLOYMENTS.md` §3.4, rows 24-25, 29.
//!
//! ## Why these use a real file and not `:memory:`
//!
//! `create_db_pool(":memory:", true)` is what the other store tests do, and it
//! would be wrong here for a reason worth stating. With SQLite, `:memory:`
//! gives **each connection its own private database**. The tenant pools are
//! built on `SqlitePool` and work anyway because the tests happen to use one
//! connection at a time; the control-plane pool is deliberately capped at two
//! (it exists so a CLI listing can read while the server resolves hosts), and
//! against `:memory:` the second connection would find **no `tenants` table at
//! all**. A test suite that passed against `:memory:` would be testing a
//! configuration that cannot occur in production.
//!
//! So: a real `tempfile`, which is also what `control_db_url` points at.

use rstest::rstest;
use rustical_store::Error as StoreError;
use rustical_store::tenant::{Tenant, TenantId, TenantStatus};
use rustical_store::tenant_store::{NewTenant, TenantQuota, TenantStore};
use sqlx::Row;

use crate::{SqliteTenantStore, create_control_plane_pool, new_tenant, new_tenant_id};

/// A control-plane database in a real, throwaway file, deleted on drop.
///
/// ## Why not `tempfile`, and why not `:memory:`
///
/// `create_db_pool(":memory:", true)` is what the other store tests do, and it
/// would be wrong here twice over. Under SQLite, `:memory:` gives **each
/// connection its own private database**; the tenant pools get away with it
/// because they happen to use one connection at a time, while the control-plane
/// pool is deliberately capped at two so a CLI listing can read while the server
/// resolves hosts — against `:memory:` the second connection finds **no `tenants`
/// table**. A suite that passed against `:memory:` would be testing a
/// configuration that cannot occur in production.
///
/// `tempfile` is the obvious crate for the file, and it is genuinely not usable
/// here: this module is gated `#[cfg(any(test, feature = "test"))]`, so with
/// `--all-features` it also compiles in the **plain library build**, where
/// dev-dependencies do not exist. So the path is built by hand from `uuid`,
/// which `store_sqlite` already depends on, and removed by `Drop`.
struct TempDb(std::path::PathBuf);

impl Drop for TempDb {
    fn drop(&mut self) {
        // SQLite in WAL mode leaves `-wal` and `-shm` siblings; leaving them
        // behind in /tmp on every test run is litter, and the next run would
        // use a different random name anyway.
        for suffix in ["", "-wal", "-shm"] {
            let mut name = self.0.clone().into_os_string();
            name.push(suffix);
            let _ = std::fs::remove_file(name);
        }
    }
}

async fn control_plane() -> (SqliteTenantStore, TempDb) {
    let path = std::env::temp_dir().join(format!("omnical-cp-{}.sqlite3", uuid::Uuid::new_v4()));
    let url = format!("sqlite://{}", path.display());
    let pool = create_control_plane_pool(&url, true)
        .await
        .expect("the control plane migrates");
    (SqliteTenantStore::new(pool), TempDb(path))
}

fn id(s: &str) -> TenantId {
    s.parse().expect("a valid slug")
}

fn acme() -> NewTenant {
    let mut t = new_tenant(&id("acme"), Some("Acme Corp"));
    t.hosts = vec!["cal.acme.test".to_owned()];
    t
}

fn globex() -> NewTenant {
    let mut t = new_tenant(&id("globex"), Some("Globex"));
    t.hosts = vec!["cal.globex.test".to_owned()];
    t
}

#[rstest]
#[tokio::test]
async fn a_new_tenant_round_trips() {
    let (cp, _dir) = control_plane().await;
    let new = acme();
    let new_id = new.tenant.id.clone();
    cp.create_tenant(&new).await.expect("created");

    let got = cp.get_tenant_by_slug("acme").await.expect("a lookup");
    let got = got.expect("acme exists");
    assert_eq!(got.id, new_id);
    assert_eq!(got.slug, id("acme"));
    assert_eq!(got.display_name, "Acme Corp");
    assert_eq!(got.status, TenantStatus::Active);
    assert_eq!(got.plan, "free", "the schema's default is the plan");
    assert!(got.created_at.is_some(), "creation is stamped");
    assert!(got.suspended_at.is_none());
}

#[rstest]
#[tokio::test]
async fn the_config_blob_survives_verbatim() {
    // The §3.6 resolution is global config <- this blob, and it happens during
    // router construction. If the store ever parsed, normalised or re-serialised
    // it, a tenant's override would silently change meaning. It is stored and
    // returned as bytes.
    let (cp, _dir) = control_plane().await;
    let mut new = acme();
    new.tenant.config_json =
        r#"{"rsvp_secret":"s3cret","registration":{"enabled":true}}"#.to_owned();
    cp.create_tenant(&new).await.expect("created");

    let got = cp
        .get_tenant_by_slug("acme")
        .await
        .expect("ok")
        .expect("exists");
    assert_eq!(got.config_json, new.tenant.config_json);
}

#[rstest]
#[tokio::test]
async fn a_duplicate_slug_is_refused() {
    // The slug is the identity: it becomes a hostname and a directory under
    // `data_root`. Two tenants sharing one is a collision in both.
    let (cp, _dir) = control_plane().await;
    cp.create_tenant(&acme()).await.expect("created");

    let mut clash = globex();
    clash.tenant.slug = id("acme");
    clash.hosts.clear();
    let err = cp
        .create_tenant(&clash)
        .await
        .expect_err("a duplicate slug must be refused");
    assert!(
        matches!(err, StoreError::AlreadyExists),
        "expected AlreadyExists, got {err:?}"
    );
}

#[rstest]
#[tokio::test]
async fn a_tenant_cannot_be_created_suspended() {
    // Invisible-by-construction otherwise: every getter filters on
    // `status = 'active'`, so a row created suspended could not be listed,
    // resolved, or suspended again. It would exist and be unreachable.
    let (cp, _dir) = control_plane().await;
    let mut new = acme();
    new.tenant.status = TenantStatus::Suspended;
    let err = cp.create_tenant(&new).await.expect_err("must be refused");
    assert!(matches!(err, StoreError::Other(_)), "got {err:?}");
}

#[rstest]
#[tokio::test]
async fn a_host_resolves_to_its_tenant() {
    let (cp, _dir) = control_plane().await;
    cp.create_tenant(&acme()).await.expect("acme");
    cp.create_tenant(&globex()).await.expect("globex");

    let a = cp
        .get_tenant_by_host("cal.acme.test")
        .await
        .expect("ok")
        .expect("claimed");
    assert_eq!(a.slug, id("acme"));
    let g = cp
        .get_tenant_by_host("cal.globex.test")
        .await
        .expect("ok")
        .expect("claimed");
    assert_eq!(g.slug, id("globex"));
}

/// **Row 29's mechanism.** Suspension is immediate because the `status = 'active'`
/// filter lives in the SQL, not in the caller: there is no cache to invalidate
/// and no window in which a suspended tenant still resolves.
///
/// This is the assertion that would catch the cache-the-lookup design §3.3
/// forbids — under that design this test would need an eviction step, and
/// forgetting it would leave a suspended tenant serving traffic.
#[rstest]
#[tokio::test]
async fn suspension_takes_effect_on_the_next_lookup() {
    let (cp, _dir) = control_plane().await;
    let acme_new = acme();
    let acme_id = acme_new.tenant.id.clone();
    cp.create_tenant(&acme_new).await.expect("created");

    // Serving first, so the "after" is a real transition rather than a tenant
    // that never worked.
    assert!(
        cp.get_tenant_by_host("cal.acme.test")
            .await
            .expect("ok")
            .is_some()
    );
    assert!(cp.get_tenant_by_slug("acme").await.expect("ok").is_some());
    assert!(cp.get_tenant_by_id(&acme_id).await.expect("ok").is_some());

    cp.update_tenant_status(&acme_id, TenantStatus::Suspended)
        .await
        .expect("suspended");

    assert!(
        cp.get_tenant_by_host("cal.acme.test")
            .await
            .expect("ok")
            .is_none(),
        "a suspended tenant must stop resolving by host"
    );
    assert!(cp.get_tenant_by_slug("acme").await.expect("ok").is_none());
    assert!(cp.get_tenant_by_id(&acme_id).await.expect("ok").is_none());

    // And the row is still there, still addressable for an admin — suspension is
    // not deletion.
    let all = cp.list_tenants(true).await.expect("ok");
    assert_eq!(all.len(), 1, "the tenant still exists");
    assert_eq!(all[0].status, TenantStatus::Suspended);
}

#[rstest]
#[tokio::test]
async fn suspension_is_dated_and_resuming_clears_the_date() {
    let (cp, _dir) = control_plane().await;
    let new = acme();
    let tid = new.tenant.id.clone();
    cp.create_tenant(&new).await.expect("created");

    cp.update_tenant_status(&tid, TenantStatus::Suspended)
        .await
        .expect("ok");
    let listed = cp.list_tenants(true).await.expect("ok");
    let suspended = &listed[0];
    assert_eq!(suspended.status, TenantStatus::Suspended);
    assert!(
        suspended
            .suspended_at
            .as_deref()
            .is_some_and(|t| t.len() == 20),
        "expected an ISO-8601 UTC stamp like 2026-09-28T12:00:00Z, got {:?}",
        suspended.suspended_at
    );

    cp.update_tenant_status(&tid, TenantStatus::Active)
        .await
        .expect("ok");
    let listed = cp.list_tenants(true).await.expect("ok");
    assert!(listed[0].suspended_at.is_none(), "active must not be dated");
    assert!(cp.get_tenant_by_slug("acme").await.expect("ok").is_some());
}

#[rstest]
#[tokio::test]
async fn timestamptz_order_correctly_against_other_tables() {
    // `created_at` is written by this crate as `YYYY-MM-DDTHH:MM:SSZ`, NOT
    // SQLite's `CURRENT_TIMESTAMP` (`YYYY-MM-DD HH:MM:SS`). The two sort
    // differently as strings — a space sorts before a `T` — so mixing them
    // silently misorders anything that sorts across both. This pins the shape.
    let (cp, _dir) = control_plane().await;
    let new = acme();
    cp.create_tenant(&new).await.expect("created");
    let t = cp
        .get_tenant_by_slug("acme")
        .await
        .expect("ok")
        .expect("exists");
    let created = t.created_at.expect("stamped");
    assert_eq!(created.len(), 20, "YYYY-MM-DDTHH:MM:SSZ");
    assert!(created.ends_with('Z'), "must be UTC-marked: {created}");
    assert!(created.as_bytes()[10] == b'T', "not a space: {created}");
}

#[rstest]
#[tokio::test]
async fn listing_hides_suspended_tenants_unless_asked() {
    let (cp, _dir) = control_plane().await;
    let a = acme();
    let g = globex();
    let a_id = a.tenant.id.clone();
    cp.create_tenant(&a).await.expect("acme");
    cp.create_tenant(&g).await.expect("globex");
    cp.update_tenant_status(&a_id, TenantStatus::Suspended)
        .await
        .expect("suspend");

    let visible = cp.list_tenants(false).await.expect("ok");
    assert_eq!(visible.len(), 1);
    assert_eq!(visible[0].slug, id("globex"));

    let all = cp.list_tenants(true).await.expect("ok");
    assert_eq!(all.len(), 2);
}

#[rstest]
#[tokio::test]
async fn a_host_cannot_be_stolen_from_another_tenant() {
    // The failure this prevents: a typo in an admin's host list silently moving
    // a customer's hostname, so one tenant starts serving another's requests.
    let (cp, _dir) = control_plane().await;
    let g = globex();
    let g_id = g.tenant.id.clone();
    cp.create_tenant(&acme()).await.expect("acme");
    cp.create_tenant(&g).await.expect("globex");

    let err = cp
        .set_tenant_hosts(&g_id, &["cal.acme.test".to_owned()])
        .await
        .expect_err("must refuse");
    assert!(
        matches!(err, StoreError::AlreadyExists),
        "expected AlreadyExists, got {err:?}"
    );

    // Acme still owns it, and globex's own claim is untouched: the refusal
    // happened before anything was written.
    assert_eq!(
        cp.get_tenant_by_host("cal.acme.test")
            .await
            .expect("ok")
            .expect("still acme")
            .slug,
        id("acme")
    );
    assert_eq!(
        cp.get_tenant_by_host("cal.globex.test")
            .await
            .expect("ok")
            .expect("still globex")
            .slug,
        id("globex")
    );
}

#[rstest]
#[tokio::test]
async fn replacing_a_hosts_list_withdraws_the_old_claims() {
    // This is the documented way to stop answering for a hostname while keeping
    // the tenant — the "customer moved domains" operation.
    let (cp, _dir) = control_plane().await;
    let new = acme();
    let a_id = new.tenant.id.clone();
    cp.create_tenant(&new).await.expect("created");
    assert!(
        cp.get_tenant_by_host("cal.acme.test")
            .await
            .expect("ok")
            .is_some()
    );

    cp.set_tenant_hosts(&a_id, &["calendar.acme.test".to_owned()])
        .await
        .expect("ok");
    assert!(
        cp.get_tenant_by_host("cal.acme.test")
            .await
            .expect("ok")
            .is_none(),
        "the old claim must be gone"
    );
    assert!(
        cp.get_tenant_by_host("calendar.acme.test")
            .await
            .expect("ok")
            .is_some()
    );
    assert!(
        cp.get_tenant_by_slug("acme").await.expect("ok").is_some(),
        "the tenant itself is untouched"
    );
}

#[rstest]
#[tokio::test]
async fn hosts_are_normalised_before_they_are_stored() {
    // `HostDispatch` lowercases and strips the port before looking up, so a host
    // stored with capitals or a trailing dot would simply never match. Storing
    // it as given is the kind of bug that only appears under a real Host header.
    let (cp, _dir) = control_plane().await;
    let new = acme();
    let a_id = new.tenant.id.clone();
    cp.create_tenant(&new).await.expect("created");

    cp.set_tenant_hosts(
        &a_id,
        &[
            "CAL.Acme.TEST".to_owned(),
            "  spaced.acme.test  ".to_owned(),
            "dotted.acme.test.".to_owned(),
        ],
    )
    .await
    .expect("ok");

    for host in ["cal.acme.test", "spaced.acme.test", "dotted.acme.test"] {
        assert!(
            cp.get_tenant_by_host(host).await.expect("ok").is_some(),
            "{host} should have been normalised into a match"
        );
    }
}

#[rstest]
#[tokio::test]
async fn a_blank_host_is_dropped_rather_than_stored() {
    // A `host = ''` row would shadow nothing useful but would be returned by
    // `get_tenant_by_host("")` — and a `Host` header that normalises to empty is
    // a request we should not be routing to a tenant at all.
    let (cp, _dir) = control_plane().await;
    let new = acme();
    let a_id = new.tenant.id.clone();
    cp.create_tenant(&new).await.expect("created");

    cp.set_tenant_hosts(&a_id, &[String::new(), "  ".to_owned()])
        .await
        .expect("ok");
    assert!(cp.get_tenant_by_host("").await.expect("ok").is_none());
    assert!(
        cp.get_tenant_by_host("cal.acme.test")
            .await
            .expect("ok")
            .is_none(),
        "setting an empty list withdraws every claim"
    );
}

#[rstest]
#[tokio::test]
async fn quotas_round_trip_and_none_means_unlimited() {
    let (cp, _dir) = control_plane().await;
    let new = acme();
    let a_id = new.tenant.id.clone();
    cp.create_tenant(&new).await.expect("created");

    assert!(
        cp.get_quota(&a_id).await.expect("ok").is_unlimited(),
        "a new tenant is unlimited, not zero"
    );

    let quota = TenantQuota {
        principals: Some(10),
        calendars: Some(50),
        megabytes: None,
    };
    cp.set_quota(&a_id, quota).await.expect("ok");
    assert_eq!(cp.get_quota(&a_id).await.expect("ok"), quota);

    // Clearing one dimension must not clear the others — three separate
    // columns, not one JSON blob.
    let partial = TenantQuota {
        principals: None,
        calendars: Some(50),
        megabytes: None,
    };
    cp.set_quota(&a_id, partial).await.expect("ok");
    assert_eq!(cp.get_quota(&a_id).await.expect("ok"), partial);
    assert!(!cp.get_quota(&a_id).await.expect("ok").is_unlimited());

    cp.set_quota(&a_id, TenantQuota::default())
        .await
        .expect("ok");
    assert!(cp.get_quota(&a_id).await.expect("ok").is_unlimited());
}

#[rstest]
#[tokio::test]
async fn writes_to_an_unknown_tenant_are_not_found() {
    let (cp, _dir) = control_plane().await;
    let ghost = new_tenant_id();
    for err in [
        cp.update_tenant_status(&ghost, TenantStatus::Suspended)
            .await
            .expect_err("no such tenant"),
        cp.set_quota(&ghost, TenantQuota::default())
            .await
            .expect_err("no such tenant"),
        cp.delete_tenant(&ghost).await.expect_err("no such tenant"),
        cp.set_tenant_hosts(&ghost, &["x.test".to_owned()])
            .await
            .expect_err("no such tenant"),
    ] {
        assert!(matches!(err, StoreError::NotFound), "got {err:?}");
    }
}

#[rstest]
#[tokio::test]
async fn deleting_a_tenant_withdraws_its_host_claims() {
    // ON DELETE CASCADE, so a deleted tenant cannot keep owning a hostname and
    // block the next tenant from claiming it.
    let (cp, _dir) = control_plane().await;
    let new = acme();
    let a_id = new.tenant.id.clone();
    cp.create_tenant(&new).await.expect("created");
    cp.delete_tenant(&a_id).await.expect("deleted");

    assert!(
        cp.get_tenant_by_host("cal.acme.test")
            .await
            .expect("ok")
            .is_none()
    );
    assert!(cp.get_tenant_by_slug("acme").await.expect("ok").is_none());

    // The host is now free for someone else.
    let mut other = globex();
    other.hosts = vec!["cal.acme.test".to_owned()];
    cp.create_tenant(&other).await.expect("reclaimed");
    assert_eq!(
        cp.get_tenant_by_host("cal.acme.test")
            .await
            .expect("ok")
            .expect("reclaimed")
            .slug,
        id("globex")
    );
}

/// The structural claim of §3.4, and the reason `control_migrations/` is a
/// separate directory: the control plane is specified to hold no calendar,
/// contact or credential data.
///
/// If the control plane were pointed at `./migrations` instead, this test is
/// what would notice — a control plane with a `calendar_objects` table is a
/// per-tenant backup that can take out every other tenant.
#[rstest]
#[tokio::test]
async fn the_control_plane_holds_no_calendar_data() {
    let (cp, _dir) = control_plane().await;
    let tables: Vec<String> =
        sqlx::query("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")
            .fetch_all(cp.pool())
            .await
            .expect("introspect")
            .iter()
            .map(|r| r.get::<String, _>("name"))
            .collect();

    for expected in ["tenants", "tenant_hosts", "_sqlx_migrations"] {
        assert!(
            tables.iter().any(|t| t == expected),
            "missing {expected} in {tables:?}"
        );
    }
    for forbidden in [
        "principals",
        "calendar_objects",
        "calendar_components",
        "addressbook_objects",
        "invites",
        "password_resets",
    ] {
        assert!(
            !tables.iter().any(|t| t == forbidden),
            "the control plane must not contain {forbidden}; found {tables:?}"
        );
    }
    assert_eq!(
        tables.len(),
        3,
        "the control plane is exactly two tables plus sqlx's migration ledger: {tables:?}"
    );
}

#[rstest]
#[tokio::test]
async fn a_malformed_slug_never_reaches_sql() {
    // Validated in Rust before the query, so a traversal-shaped slug is a cheap
    // `NotFound` rather than a bind value. Cheap matters: this is on the
    // dispatch path for any request whose Host looks like a slug (§3.3 match 3).
    let (cp, _dir) = control_plane().await;
    for bad in ["../../etc/passwd", "ACME", "", "a b", &"x".repeat(64)] {
        let r = cp.get_tenant_by_slug(bad).await;
        assert!(
            matches!(r, Ok(None) | Err(StoreError::NotFound)),
            "{bad:?} gave {r:?}"
        );
    }
}

#[rstest]
#[tokio::test]
async fn two_tenants_stay_independent() {
    // The property the whole design rests on, at the only level the control
    // plane can show it: neither tenant's row, host, status or quota is
    // reachable through the other's id.
    let (cp, _dir) = control_plane().await;
    let a = acme();
    let g = globex();
    let (a_id, g_id) = (a.tenant.id.clone(), g.tenant.id.clone());
    cp.create_tenant(&a).await.expect("acme");
    cp.create_tenant(&g).await.expect("globex");

    cp.set_quota(
        &a_id,
        TenantQuota {
            principals: Some(1),
            ..TenantQuota::default()
        },
    )
    .await
    .expect("ok");
    cp.update_tenant_status(&g_id, TenantStatus::Suspended)
        .await
        .expect("ok");

    assert_eq!(
        cp.get_quota(&a_id).await.expect("ok").principals,
        Some(1),
        "acme's quota is acme's"
    );
    assert!(
        cp.get_quota(&g_id).await.expect("ok").is_unlimited(),
        "globex's quota is untouched by acme's write"
    );
    assert!(
        cp.get_tenant_by_slug("acme").await.expect("ok").is_some(),
        "suspending globex did not suspend acme"
    );
    assert!(cp.get_tenant_by_slug("globex").await.expect("ok").is_none());
    assert_eq!(
        cp.get_tenant_by_host("cal.acme.test")
            .await
            .expect("ok")
            .expect("acme")
            .id,
        a_id
    );
    assert!(
        cp.get_tenant_by_host("cal.globex.test")
            .await
            .expect("ok")
            .is_none()
    );
}

#[rstest]
#[tokio::test]
async fn a_suspended_tenant_still_owns_its_host_claim() {
    // Suspension must not free the hostname. If it did, `HostDispatch` would
    // fall through to a slug match or `default_tenant` and serve *somebody*
    // under a suspended tenant's URL — which is the opposite of the intent.
    let (cp, _dir) = control_plane().await;
    let new = acme();
    let a_id = new.tenant.id.clone();
    cp.create_tenant(&new).await.expect("created");
    cp.update_tenant_status(&a_id, TenantStatus::Suspended)
        .await
        .expect("suspend");

    // Still claimed in the table...
    let owner: Option<String> = sqlx::query("SELECT tenant FROM tenant_hosts WHERE host = ?")
        .bind("cal.acme.test")
        .fetch_optional(cp.pool())
        .await
        .expect("ok")
        .map(|r| r.get("tenant"));
    assert_eq!(owner.as_deref(), Some(a_id.as_str()));

    // ...but never resolves to a tenant. The suspension filter is in the JOIN.
    assert!(
        cp.get_tenant_by_host("cal.acme.test")
            .await
            .expect("ok")
            .is_none()
    );
}

#[rstest]
#[tokio::test]
async fn the_round_trip_preserves_every_field() {
    // A struct-field-by-struct-field check, because a column that is written
    // but never read back is a silent data-loss bug that no other test here
    // would catch.
    let (cp, _dir) = control_plane().await;
    let mut new = acme();
    new.tenant.display_name = "Acme Corp (EMEA)".to_owned();
    new.tenant.plan = "enterprise".to_owned();
    new.tenant.config_json = r#"{"scheduling":{"smtp":[]}}"#.to_owned();
    new.tenant.slug = id("acme-emea");
    let created = new.tenant.clone();
    cp.create_tenant(&new).await.expect("created");

    let got: Tenant = cp
        .get_tenant_by_id(&created.id)
        .await
        .expect("ok")
        .expect("exists");
    assert_eq!(got.id, created.id);
    assert_eq!(got.slug, created.slug);
    assert_eq!(got.display_name, created.display_name);
    assert_eq!(got.status, created.status);
    assert_eq!(got.plan, created.plan);
    assert_eq!(got.config_json, created.config_json);
    assert_eq!(got.suspended_at, created.suspended_at);
    assert!(got.created_at.is_some());
}
