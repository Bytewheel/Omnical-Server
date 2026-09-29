//! **Row 33** — the control-plane audit trail. `PLAN_DEPLOYMENTS.md` §6.6.7.
//!
//! ## The hole this closes
//!
//! `rustical tenant` could already create, suspend, resume, quota, reconfigure
//! and delete tenants **with no audit at all** (§18.19). An audit in the panel
//! alone would have been a hole wearing a control's name, because the same acts
//! were reachable by a different tool. So the audit write lives in
//! [`TenantStore`], and these tests are about both paths and about the
//! transaction.
//!
//! ## The three properties, and why each has its own test
//!
//! - **Row 33**: a mutation produces exactly one row, with actor, tenant and
//!   timestamp.
//! - **Row 33a**: a CLI mutation with no discoverable actor is **refused** — an
//!   action that cannot be attributed does not happen.
//! - **Row 33b**: if the audit write cannot happen, the **mutation does not
//!   happen either**. That is the property that distinguishes "same transaction"
//!   from "write the audit row first and hope", and it is the one a test of the
//!   happy path cannot see.
//!
//! Each of these is a *negative* claim about a failure, so each has a positive
//! control beside it — the pattern §18.18 recorded after it went wrong three
//! times.

mod tenant_support;
use rustical_store::tenant::{TenantId, TenantStatus};
use rustical_store::tenant_store::TenantStore;
use tenant_support::Fixture;

const TENANT: &str = "acme";
const OTHER: &str = "globex";

fn actor() -> rustical_store::Actor {
    rustical_store::Actor::new("ops").expect("a valid actor")
}

fn fixture() -> Fixture {
    Fixture::new(Some(("t3.gg", "")))
}

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Runtime::new().expect("a runtime")
}

// ------------------------------------------------------------------- row 33

/// **Row 33.** Every mutating call leaves exactly one row, naming the actor and
/// the tenant.
#[test]
fn every_mutation_is_audited_with_its_actor_and_tenant() {
    let fixture = fixture();
    let store = fixture.control_plane();
    let who = actor();

    rt().block_on(async {
        let id = rustical_store_sqlite::new_tenant(&TENANT.parse().expect("a slug"), None).tenant;
        store
            .create_tenant(
                &rustical_store::tenant_store::NewTenant {
                    tenant: id.clone(),
                    hosts: Vec::new(),
                },
                &who,
            )
            .await
            .expect("created");
        store
            .update_tenant_status(&id.id, TenantStatus::Suspended, &who)
            .await
            .expect("suspended");
        store
            .set_quota(
                &id.id,
                rustical_store::tenant_store::TenantQuota::default(),
                &who,
            )
            .await
            .expect("quota");
        store
            .set_config_json(&id.id, r#"{"rsvp_secret":"s"}"#, &who)
            .await
            .expect("config");
        store
            .set_tenant_hosts(&id.id, &["a.test".to_owned()], &who)
            .await
            .expect("hosts");
        store.delete_tenant(&id.id, &who).await.expect("deleted");

        let rows = store.list_audit(None, 100).await.expect("the audit trail");
        assert_eq!(
            rows.len(),
            6,
            "one row per mutation, got {:?}",
            rows.iter().map(|r| &r.action).collect::<Vec<_>>()
        );

        // Newest first, so an incident reads backwards.
        let actions: Vec<&str> = rows.iter().map(|r| r.action.as_str()).collect();
        assert_eq!(
            actions,
            vec![
                "delete_tenant",
                "set_tenant_hosts",
                "set_config_json",
                "set_quota",
                "update_tenant_status",
                "create_tenant",
            ]
        );
        for row in &rows {
            assert_eq!(row.actor, "ops", "every row names the actor");
            assert!(!row.at.is_empty(), "every row is timestamped");
            assert!(row.at.ends_with('Z'), "ISO-8601 UTC, got {}", row.at);
        }
    });
}

/// A row outlives the tenant it describes.
///
/// `control_admin_audit` has no `ON DELETE CASCADE` from `tenants` precisely so
/// that deleting a tenant cannot erase the record of who deleted it. A cascade
/// here would be invisible until the one time somebody needed the trail.
#[test]
fn an_audit_row_outlives_the_tenant_it_describes() {
    let fixture = fixture();
    let store = fixture.control_plane();
    let who = actor();
    let id: TenantId = rt().block_on(async {
        let tenant =
            rustical_store_sqlite::new_tenant(&TENANT.parse().expect("a slug"), None).tenant;
        store
            .create_tenant(
                &rustical_store::tenant_store::NewTenant {
                    tenant: tenant.clone(),
                    hosts: Vec::new(),
                },
                &who,
            )
            .await
            .expect("created");
        tenant.id
    });

    rt().block_on(async {
        store.delete_tenant(&id, &who).await.expect("deleted");
        assert!(
            store
                .get_any_tenant_by_slug(TENANT)
                .await
                .expect("q")
                .is_none(),
            "the tenant is gone"
        );
        let rows = store.list_audit(None, 100).await.expect("the audit trail");
        assert!(
            rows.iter().any(|r| r.action == "delete_tenant"),
            "the record of the deletion must survive the deletion"
        );
    });
}

/// The audit detail never carries the thing it changed.
///
/// `set_config_json` writes the blob, and the blob holds SMTP passwords and the
/// RSVP HMAC key. `detail` is rendered by the panel, so recording the blob would
/// put every tenant's credentials into an HTML view.
#[test]
fn the_audit_detail_records_that_a_blob_changed_but_not_its_contents() {
    let fixture = fixture();
    let store = fixture.control_plane();
    let who = actor();
    let secret = "an-rsvp-hmac-key-that-must-not-be-logged";

    rt().block_on(async {
        let tenant =
            rustical_store_sqlite::new_tenant(&TENANT.parse().expect("a slug"), None).tenant;
        store
            .create_tenant(
                &rustical_store::tenant_store::NewTenant {
                    tenant: tenant.clone(),
                    hosts: Vec::new(),
                },
                &who,
            )
            .await
            .expect("created");
        store
            .set_config_json(
                &tenant.id,
                &format!(r#"{{"rsvp_secret":"{secret}"}}"#),
                &who,
            )
            .await
            .expect("config");

        let rows = store.list_audit(None, 10).await.expect("the audit trail");
        let row = rows
            .iter()
            .find(|r| r.action == "set_config_json")
            .expect("a set_config_json row");
        let detail = row.detail.as_deref().unwrap_or_default();
        assert!(
            !detail.contains(secret),
            "the audit detail must not contain the blob it recorded: {detail}"
        );
        assert!(
            detail.contains("bytes"),
            "it records the size instead, so a change is visible: {detail}"
        );
    });
}

/// Reads are not audited.
///
/// Row 33 is about *actions*. An audit row per read would make the table grow
/// with traffic rather than with changes, and would turn the trail into a
/// request log — which is a different product with different retention
/// obligations.
#[test]
fn reads_leave_no_audit_rows() {
    let fixture = fixture();
    let store = fixture.control_plane();
    let who = actor();
    rt().block_on(async {
        let tenant =
            rustical_store_sqlite::new_tenant(&TENANT.parse().expect("a slug"), None).tenant;
        store
            .create_tenant(
                &rustical_store::tenant_store::NewTenant {
                    tenant: tenant.clone(),
                    hosts: vec!["a.test".to_owned()],
                },
                &who,
            )
            .await
            .expect("created");
        let before = store.list_audit(None, 100).await.expect("audit").len();

        for _ in 0..10 {
            assert!(store.get_tenant_by_slug(TENANT).await.expect("q").is_some());
            assert!(
                store
                    .get_tenant_by_host("a.test")
                    .await
                    .expect("q")
                    .is_some()
            );
            assert!(!store.list_tenants(true).await.expect("q").is_empty());
            assert!(
                store
                    .get_tenant_by_id(&tenant.id)
                    .await
                    .expect("q")
                    .is_some()
            );
        }
        let after = store.list_audit(None, 100).await.expect("audit").len();
        assert_eq!(after, before, "reads must not grow the audit trail");
    });
}

// ------------------------------------------------------------------ row 33a

/// **Row 33a.** A CLI mutation with no discoverable actor is refused, and
/// nothing is written.
#[test]
fn a_mutation_with_no_actor_is_refused() {
    let fixture = fixture();
    let config = fixture.control_config();
    fixture.cli_raw(
        &config,
        &["tenant", "create", "--slug", TENANT, "--actor", "ops"],
    );

    // A deliberately bare environment: no `OMNICAL_ACTOR`, no `SUDO_USER`, no
    // `USER`. `env -i` is not available portably, so the variables are cleared
    // explicitly — and the test asserts they are gone, so a future harness
    // cannot quietly reintroduce one and make this pass for the wrong reason.
    let out = fixture.cli_fail_bare_env(
        &config,
        &["tenant", "suspend", TENANT],
        &["OMNICAL_ACTOR", "SUDO_USER", "USER"],
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        combined.contains("--actor"),
        "the refusal must name the way out; got:\n{combined}"
    );
    assert!(
        combined.contains("unaudited") || combined.contains("attributed"),
        "the refusal must say why; got:\n{combined}"
    );

    // Nothing happened: the tenant is still active.
    let store = fixture.control_plane();
    let still = rt()
        .block_on(async { store.get_tenant_by_slug(TENANT).await })
        .expect("a lookup");
    assert!(
        still.is_some(),
        "a refused suspend must leave the tenant serving"
    );
}

/// The positive control for 33a: the same command *does* work when an actor is
/// discoverable, so the refusal above is attributable to the actor and not to
/// something else about the command.
#[test]
fn a_mutation_with_an_actor_succeeds_and_is_recorded() {
    let fixture = fixture();
    let config = fixture.control_config();
    fixture.cli_raw(
        &config,
        &["tenant", "create", "--slug", TENANT, "--actor", "ops"],
    );
    fixture.cli_raw(&config, &["tenant", "suspend", TENANT, "--actor", "ops"]);

    let store = fixture.control_plane();
    let rows = rt()
        .block_on(async { store.list_audit(None, 50).await })
        .expect("audit");
    let row = rows
        .iter()
        .find(|r| r.action == "update_tenant_status")
        .expect("a status row");
    assert_eq!(row.actor, "ops", "the --actor value is what is recorded");
}

/// The env fallback is a fallback, not a loophole: `OMNICAL_ACTOR` is what gets
/// recorded, so an operator can attribute an action from a script.
#[test]
fn the_environment_supplies_an_actor_when_the_flag_is_absent() {
    let fixture = fixture();
    let config = fixture.control_config();
    fixture.cli_raw_with_env(
        &config,
        &["tenant", "create", "--slug", TENANT],
        &[("OMNICAL_ACTOR", "deploy-bot")],
    );
    let store = fixture.control_plane();
    let rows = rt()
        .block_on(async { store.list_audit(None, 50).await })
        .expect("audit");
    assert_eq!(rows[0].actor, "deploy-bot", "the env value is recorded");
}

// ------------------------------------------------------------------ row 33b

/// **Row 33b.** If the audit row cannot be written, the mutation does not
/// happen.
///
/// This is the test that distinguishes "same transaction" from "audit first,
/// then mutate", and it is the reason the audit write lives inside the
/// transaction rather than beside it. The way to break the audit write without
/// breaking anything else is to make the table un-writable — which a `BEFORE
/// INSERT` trigger is exactly for.
#[test]
fn a_failed_audit_write_blocks_the_mutation() {
    let fixture = fixture();
    let store = fixture.control_plane();
    let who = actor();
    let id: TenantId = rt().block_on(async {
        let tenant =
            rustical_store_sqlite::new_tenant(&TENANT.parse().expect("a slug"), None).tenant;
        store
            .create_tenant(
                &rustical_store::tenant_store::NewTenant {
                    tenant: tenant.clone(),
                    hosts: Vec::new(),
                },
                &who,
            )
            .await
            .expect("created");
        tenant.id
    });

    // Make every future audit insert fail, without touching `tenants`.
    rt().block_on(async {
        sqlx::query(
            // One line, and no `\`-continuation: a stray backslash inside a
            // string literal is a parse error in the *test*, which is a
            // confusing way to learn that a trigger was meant.
            "CREATE TRIGGER block_audit BEFORE INSERT ON control_admin_audit BEGIN SELECT RAISE(ABORT, 'audit unavailable'); END",
        )
        .execute(store.pool())
        .await
        .expect("the trigger installs");
    });

    let before = rt()
        .block_on(async { store.list_audit(None, 100).await })
        .expect("audit")
        .len();

    // Every mutating method must now refuse.
    for name in ["suspend", "quota", "config", "hosts", "delete"] {
        let outcome = rt().block_on(async {
            match name {
                "suspend" => {
                    store
                        .update_tenant_status(&id, TenantStatus::Suspended, &who)
                        .await
                }
                "quota" => {
                    store
                        .set_quota(
                            &id,
                            rustical_store::tenant_store::TenantQuota::default(),
                            &who,
                        )
                        .await
                }
                "config" => store.set_config_json(&id, "{}", &who).await,
                "hosts" => {
                    store
                        .set_tenant_hosts(&id, &["x.test".to_owned()], &who)
                        .await
                }
                _ => store.delete_tenant(&id, &who).await,
            }
        });
        assert!(
            outcome.is_err(),
            "{name} succeeded while the audit table was unwritable — the mutation and its \\
             record are not one transaction"
        );
    }

    // And the tenant is untouched: still active, still there.
    let still = rt()
        .block_on(async { store.get_tenant_by_slug(TENANT).await })
        .expect("a lookup");
    assert!(
        still.is_some(),
        "the tenant must survive a failed audit write"
    );
    assert_eq!(
        still.expect("still active").status,
        TenantStatus::Active,
        "a failed suspend must not have suspended it"
    );
    let after = rt()
        .block_on(async { store.list_audit(None, 100).await })
        .expect("audit")
        .len();
    assert_eq!(after, before, "no audit rows were written either");
}

/// The positive control for 33b, and the reason the trigger above is the right
/// tool: with the trigger gone, the very same call succeeds.
#[test]
fn removing_the_obstruction_makes_the_mutation_work_again() {
    let fixture = fixture();
    let store = fixture.control_plane();
    let who = actor();
    let id: TenantId = rt().block_on(async {
        let tenant =
            rustical_store_sqlite::new_tenant(&TENANT.parse().expect("a slug"), None).tenant;
        store
            .create_tenant(
                &rustical_store::tenant_store::NewTenant {
                    tenant: tenant.clone(),
                    hosts: Vec::new(),
                },
                &who,
            )
            .await
            .expect("created");
        tenant.id
    });

    rt().block_on(async {
        sqlx::query(
            // One line, and no `\`-continuation: a stray backslash inside a
            // string literal is a parse error in the *test*, which is a
            // confusing way to learn that a trigger was meant.
            "CREATE TRIGGER block_audit BEFORE INSERT ON control_admin_audit BEGIN SELECT RAISE(ABORT, 'audit unavailable'); END",
        )
        .execute(store.pool())
        .await
        .expect("the trigger installs");
    });
    assert!(
        rt().block_on(async {
            store
                .update_tenant_status(&id, TenantStatus::Suspended, &who)
                .await
        })
        .is_err()
    );

    rt().block_on(async {
        sqlx::query("DROP TRIGGER block_audit")
            .execute(store.pool())
            .await
            .expect("the trigger is removed");
    });
    rt().block_on(async {
        store
            .update_tenant_status(&id, TenantStatus::Suspended, &who)
            .await
    })
    .expect("with the audit table writable, the same call succeeds");
    let rows = rt()
        .block_on(async { store.list_audit(None, 50).await })
        .expect("audit");
    assert!(
        rows.iter().any(|r| r.action == "update_tenant_status"),
        "and it is recorded"
    );
}

/// A second tenant's mutations do not appear in the first's trail.
///
/// The `WHERE tenant = ?` filter on [`TenantStore::list_audit`] is the only thing
/// separating them, and a missing filter would be an unauditable surface: an
/// operator investigating one customer would see the others' changes.
#[test]
fn the_audit_trail_can_be_read_per_tenant() {
    let fixture = fixture();
    let store = fixture.control_plane();
    let who = actor();
    rt().block_on(async {
        for slug in [TENANT, OTHER] {
            let tenant =
                rustical_store_sqlite::new_tenant(&slug.parse().expect("a slug"), None).tenant;
            store
                .create_tenant(
                    &rustical_store::tenant_store::NewTenant {
                        tenant,
                        hosts: Vec::new(),
                    },
                    &who,
                )
                .await
                .expect("created");
        }
        let acme = store
            .get_tenant_by_slug(TENANT)
            .await
            .expect("q")
            .expect("acme");
        let globex = store
            .get_tenant_by_slug(OTHER)
            .await
            .expect("q")
            .expect("globex");
        store
            .update_tenant_status(&acme.id, TenantStatus::Suspended, &who)
            .await
            .expect("suspended");

        let acme_rows = store.list_audit(Some(&acme.id), 50).await.expect("audit");
        assert!(
            acme_rows
                .iter()
                .all(|r| r.tenant.as_ref() == Some(&acme.id)),
            "acme's trail must contain only acme's changes"
        );
        assert!(acme_rows.iter().any(|r| r.action == "update_tenant_status"));
        assert!(
            !acme_rows
                .iter()
                .any(|r| r.action == "create_tenant" && r.tenant.as_ref() == Some(&globex.id)),
            "globex's creation must not appear in acme's trail"
        );
    });
}

/// The list is bounded, because this is the one table in the control plane whose
/// growth is unbounded and an unbounded read of it is a way to exhaust memory.
#[test]
fn the_audit_trail_is_bounded_by_the_caller() {
    let fixture = fixture();
    let store = fixture.control_plane();
    let who = actor();
    rt().block_on(async {
        // Distinct slugs: `slug` is UNIQUE (§3.4), so five tenants cannot all
        // be "acme" — a first draft asserted the bound by creating the same one
        // five times and got `AlreadyExists` on the second.
        for n in 0..5 {
            let slug = format!("t{n}");
            let tenant =
                rustical_store_sqlite::new_tenant(&slug.parse().expect("a slug"), None).tenant;
            store
                .create_tenant(
                    &rustical_store::tenant_store::NewTenant {
                        tenant,
                        hosts: Vec::new(),
                    },
                    &who,
                )
                .await
                .expect("created");
        }
        assert_eq!(store.list_audit(None, 3).await.expect("audit").len(), 3);
        assert_eq!(store.list_audit(None, 0).await.expect("audit").len(), 0);
        assert_eq!(store.list_audit(None, 100).await.expect("audit").len(), 5);
    });
}
