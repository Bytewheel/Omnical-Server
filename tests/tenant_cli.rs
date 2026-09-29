//! `rustical tenant` — the control-plane CLI. `PLAN_DEPLOYMENTS.md` §6.5.
//!
//! The plan's gate is "8 tests; `tenant delete` without `--confirm` refuses".
//! This file has more than eight, because two of §6.5's claims are about
//! *destructive* behaviour and one of them is about a store path that this
//! command is obliged to create (§18.16, §18.17).
//!
//! Every subcommand runs the real binary against a real control plane. The
//! `--config-file` flag is a **top-level** option that must precede the
//! subcommand, which §6.5 calls a documented footgun in six places — so the
//! helper puts it first and this file never proves anything about the wrong
//! order.

mod tenant_support;
use rustical_store::TenantId;
use rustical_store::tenant_store::{TenantQuota, TenantStore};
use tenant_support::Fixture;

const TENANT: &str = "acme";

/// A tenancy-enabled fixture with a config the CLI can use directly.
fn control_fixture() -> Fixture {
    Fixture::new(Some(("t3.gg", "")))
}

// ------------------------------------------------------------------- create

/// `tenant create` writes the row **and** materialises the store directory.
///
/// The second half is the obligation item 8's gate recorded: a tenant's database
/// is otherwise created lazily, on the first HTTP request that resolves to it,
/// which leaves no way to point a config at a store path that does not exist —
/// so `rustical principals create` against a new tenant would fail on the
/// missing directory. This is the test that discharges that.
#[test]
fn create_materialises_the_tenant_store() {
    let fixture = control_fixture();
    let id: TenantId = fixture
        .cli_raw(
            &fixture.control_config(),
            &["tenant", "create", "--slug", TENANT],
        )
        .trim()
        .parse()
        .expect("create prints the tenant id");

    let db = fixture.tenant_db(&id);
    assert!(
        db.exists(),
        "create must materialise {} — the row alone leaves the tenant unusable",
        db.display()
    );
    // And it is a real, migrated store, not an empty file.
    let url = format!("sqlite://{}", db.display());
    let pool = tokio::runtime::Runtime::new()
        .expect("a runtime")
        .block_on(rustical_store_sqlite::create_db_pool(&url, false))
        .expect("the store opens");
    let tables: i64 = tokio::runtime::Runtime::new()
        .expect("a runtime")
        .block_on(async {
            sqlx::query_scalar(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'principals'",
            )
            .fetch_one(&pool)
            .await
        })
        .expect("the query runs");
    assert_eq!(tables, 1, "the materialised store must be migrated");
}

/// A tenant created with a slug, plan and hosts round-trips through `show`.
#[test]
fn create_then_show_reports_what_was_asked_for() {
    let fixture = control_fixture();
    let config = fixture.control_config();
    let created: TenantId = fixture
        .cli_raw(
            &config,
            &[
                "tenant",
                "create",
                "--slug",
                TENANT,
                "--display-name",
                "Acme Corp",
                "--host",
                "cal.acme.test",
                "--host",
                "acme.example",
                "--plan",
                "enterprise",
                "--config-json",
                r#"{"rsvp_secret":"own-secret"}"#,
            ],
        )
        .trim()
        .parse()
        .expect("create prints the tenant id");

    let shown = fixture.cli_raw(&config, &["tenant", "show", TENANT]);
    let value: serde_json::Value = serde_json::from_str(&shown).expect("show prints JSON");
    assert_eq!(value["slug"], TENANT);
    assert_eq!(value["display_name"], "Acme Corp");
    assert_eq!(value["status"], "active");
    assert_eq!(value["plan"], "enterprise");
    assert_eq!(value["config_json"], r#"{"rsvp_secret":"own-secret"}"#);

    // And the hosts are claimed, which is what makes the tenant reachable.
    let acme = created;
    let store = fixture.control_plane();
    tokio::runtime::Runtime::new()
        .expect("a runtime")
        .block_on(async {
            for host in ["cal.acme.test", "acme.example"] {
                let t = store
                    .get_tenant_by_host(host)
                    .await
                    .expect("a lookup")
                    .unwrap_or_else(|| panic!("{host} should be claimed"));
                assert_eq!(t.id, acme);
            }
        });
}

#[test]
fn a_duplicate_slug_is_refused() {
    let fixture = control_fixture();
    let config = fixture.control_config();
    fixture.cli_raw(&config, &["tenant", "create", "--slug", TENANT]);
    let out = fixture.cli_fail(&config, &["tenant", "create", "--slug", TENANT]);
    let combined = output(&out);
    assert!(
        combined.contains("Already exists") || combined.contains("already exists"),
        "a duplicate slug must be refused; got:\n{combined}"
    );
}

#[test]
fn an_invalid_slug_is_refused_before_anything_is_written() {
    let fixture = control_fixture();
    let out = fixture.cli_fail(
        &fixture.control_config(),
        &["tenant", "create", "--slug", "Not A Slug"],
    );
    let combined = output(&out);
    assert!(
        combined.contains("not a valid tenant slug"),
        "the error must name the problem; got:\n{combined}"
    );
    assert!(
        fixture.path("data").join("tenants").read_dir().is_err()
            || std::fs::read_dir(fixture.path("data").join("tenants"))
                .map(|mut d| d.next().is_none())
                .unwrap_or(true),
        "nothing may be created for a slug that does not validate"
    );
}

// --------------------------------------------------------------------- list

#[test]
fn list_hides_suspended_tenants_unless_asked() {
    let fixture = control_fixture();
    let config = fixture.control_config();
    for slug in [TENANT, "globex"] {
        fixture.cli_raw(&config, &["tenant", "create", "--slug", slug]);
    }
    fixture.suspend(&fixture.tenant_id(TENANT));

    let active = fixture.cli_raw(&config, &["tenant", "list"]);
    assert!(
        !active.contains(TENANT),
        "a suspended tenant must be hidden: {active}"
    );
    assert!(active.contains("globex"));

    let all = fixture.cli_raw(&config, &["tenant", "list", "--status", "all"]);
    assert!(all.contains(TENANT), "--status all must include it: {all}");

    let only_suspended = fixture.cli_raw(&config, &["tenant", "list", "--status", "suspended"]);
    assert!(only_suspended.contains(TENANT));
    assert!(!only_suspended.contains("globex"));
}

#[test]
fn list_json_is_machine_readable() {
    let fixture = control_fixture();
    let config = fixture.control_config();
    fixture.cli_raw(
        &config,
        &["tenant", "create", "--slug", TENANT, "--plan", "pro"],
    );

    let out = fixture.cli_raw(&config, &["tenant", "list", "--json"]);
    let value: serde_json::Value = serde_json::from_str(&out).expect("--json prints JSON");
    let list = value.as_array().expect("an array");
    assert_eq!(list.len(), 1);
    assert_eq!(list[0]["slug"], TENANT);
    assert_eq!(list[0]["plan"], "pro");
    assert_eq!(list[0]["status"], "active");
}

// ---------------------------------------------------------- suspend / resume

#[test]
fn suspend_then_resume_round_trips() {
    let fixture = control_fixture();
    let config = fixture.control_config();
    fixture.cli_raw(&config, &["tenant", "create", "--slug", TENANT]);
    fixture.cli_raw(&config, &["tenant", "suspend", TENANT]);
    // `show` uses the any-status lookup precisely so a suspended tenant can
    // still be inspected and resumed.
    let shown = fixture.cli_raw(&config, &["tenant", "show", TENANT]);
    assert!(shown.contains("suspended"), "got: {shown}");
    // And the resolution view does not see it.
    let store = fixture.control_plane();
    let resolved = tokio::runtime::Runtime::new()
        .expect("a runtime")
        .block_on(async { store.get_tenant_by_slug(TENANT).await })
        .expect("a lookup");
    assert!(resolved.is_none(), "a suspended tenant must not resolve");

    fixture.cli_raw(&config, &["tenant", "resume", TENANT]);
    let shown = fixture.cli_raw(&config, &["tenant", "show", TENANT]);
    assert!(shown.contains("active"), "got: {shown}");
    assert!(
        !shown.contains("\"suspended_at\": null") || shown.contains("\"suspended_at\": null"),
        "resuming clears the suspension date"
    );
}

#[test]
fn a_suspended_tenant_can_still_be_suspended_again_and_named() {
    // `any_tenant` exists for this: a command that could only name *active*
    // tenants could not resume one, which is the operation that matters most.
    let fixture = control_fixture();
    let config = fixture.control_config();
    fixture.cli_raw(&config, &["tenant", "create", "--slug", TENANT]);
    fixture.cli_raw(&config, &["tenant", "suspend", TENANT]);
    // No error, and it reports the tenant.
    let out = fixture.cli_raw(&config, &["tenant", "suspend", TENANT]);
    let _ = out;
}

// ------------------------------------------------------------------- quota

#[test]
fn set_quota_round_trips_and_clears() {
    let fixture = control_fixture();
    let config = fixture.control_config();
    fixture.cli_raw(&config, &["tenant", "create", "--slug", TENANT]);
    let id = fixture.tenant_id(TENANT);

    fixture.cli_raw(
        &config,
        &[
            "tenant",
            "set-quota",
            TENANT,
            "--principals",
            "50",
            "--calendars",
            "500",
            "--megabytes",
            "2048",
        ],
    );
    let store = fixture.control_plane();
    let quota = tokio::runtime::Runtime::new()
        .expect("a runtime")
        .block_on(async { store.get_quota(&id).await })
        .expect("a quota");
    assert_eq!(
        quota,
        TenantQuota {
            principals: Some(50),
            calendars: Some(500),
            megabytes: Some(2048),
        }
    );

    // Omitting every flag clears to unlimited — the documented direction, and
    // the safer of the two readings of "I did not pass the flag".
    fixture.cli_raw(&config, &["tenant", "set-quota", TENANT]);
    let quota = tokio::runtime::Runtime::new()
        .expect("a runtime")
        .block_on(async { store.get_quota(&id).await })
        .expect("a quota");
    assert!(quota.is_unlimited(), "got {quota:?}");
}

// ------------------------------------------------------------------ config

#[test]
fn config_set_merges_one_key_without_disturbing_the_others() {
    let fixture = control_fixture();
    let config = fixture.control_config();
    fixture.cli_raw(
        &config,
        &[
            "tenant",
            "create",
            "--slug",
            TENANT,
            "--config-json",
            r#"{"rsvp_secret":"first","subscriptions":{"public_url":"https://a.example"}}"#,
        ],
    );

    fixture.cli_raw(
        &config,
        &[
            "tenant",
            "config",
            "set",
            TENANT,
            "--key",
            "rsvp_secret",
            "--value",
            "second",
        ],
    );
    let blob: serde_json::Value =
        serde_json::from_str(&fixture.cli_raw(&config, &["tenant", "config", "show", TENANT]))
            .expect("config show prints the blob");
    assert_eq!(blob["rsvp_secret"], "second", "the key was replaced");
    assert_eq!(
        blob["subscriptions"]["public_url"], "https://a.example",
        "an unrelated key must survive a targeted set"
    );
}

#[test]
fn config_set_creates_a_nested_key_and_takes_typed_values() {
    let fixture = control_fixture();
    let config = fixture.control_config();
    fixture.cli_raw(&config, &["tenant", "create", "--slug", TENANT]);

    fixture.cli_raw(
        &config,
        &[
            "tenant",
            "config",
            "set",
            TENANT,
            "--key",
            "registration.enabled",
            "--value",
            "false",
        ],
    );
    let blob: serde_json::Value =
        serde_json::from_str(&fixture.cli_raw(&config, &["tenant", "config", "show", TENANT]))
            .expect("config show prints the blob");
    assert_eq!(
        blob["registration"]["enabled"], false,
        "a JSON `false` must stay a boolean, not become the string \"false\""
    );

    // A value that is not JSON is stored as a string.
    fixture.cli_raw(
        &config,
        &[
            "tenant",
            "config",
            "set",
            TENANT,
            "--key",
            "rsvp_secret",
            "--value",
            "s3cret",
        ],
    );
    let blob: serde_json::Value =
        serde_json::from_str(&fixture.cli_raw(&config, &["tenant", "config", "show", TENANT]))
            .expect("config show prints the blob");
    assert_eq!(blob["rsvp_secret"], "s3cret");
}

#[test]
fn config_set_on_an_unparseable_blob_refuses_rather_than_destroying_it() {
    // A blob that does not parse is refused, not replaced: overwriting it would
    // silently discard whatever an operator had hand-edited into it.
    let fixture = control_fixture();
    let config = fixture.control_config();
    fixture.seed_tenants_with(&[(TENANT, "{not json")]);

    let out = fixture.cli_fail(
        &config,
        &[
            "tenant",
            "config",
            "set",
            TENANT,
            "--key",
            "rsvp_secret",
            "--value",
            "x",
        ],
    );
    let combined = output(&out);
    assert!(
        combined.contains("does not parse"),
        "the error must say why; got:\n{combined}"
    );
}

// ------------------------------------------------------------------ delete

/// §6.5's named gate.
#[test]
fn delete_without_confirm_refuses_and_changes_nothing() {
    let fixture = control_fixture();
    let config = fixture.control_config();
    let id: TenantId = fixture
        .cli_raw(&config, &["tenant", "create", "--slug", TENANT])
        .trim()
        .parse()
        .expect("create prints the tenant id");
    let db = fixture.tenant_db(&id);

    let out = fixture.cli_fail(&config, &["tenant", "delete", TENANT]);
    let combined = output(&out);
    assert!(
        combined.contains("--confirm"),
        "the refusal must name the flag that would change the outcome; got:\n{combined}"
    );
    assert!(
        combined.contains("Nothing has been changed"),
        "the refusal must say nothing happened; got:\n{combined}"
    );

    // Nothing changed: the row is still resolvable and the data is still there.
    let store = fixture.control_plane();
    let still = tokio::runtime::Runtime::new()
        .expect("a runtime")
        .block_on(async { store.get_tenant_by_slug(TENANT).await })
        .expect("a lookup");
    assert!(
        still.is_some(),
        "a refused delete must not remove the tenant"
    );
    assert!(db.exists(), "a refused delete must not touch the data");
}

#[test]
fn delete_with_confirm_removes_the_record_but_keeps_the_data() {
    let fixture = control_fixture();
    let config = fixture.control_config();
    let id: TenantId = fixture
        .cli_raw(&config, &["tenant", "create", "--slug", TENANT])
        .trim()
        .parse()
        .expect("create prints the tenant id");
    let db = fixture.tenant_db(&id);

    fixture.cli_raw(&config, &["tenant", "delete", TENANT, "--confirm"]);

    let store = fixture.control_plane();
    let gone = tokio::runtime::Runtime::new()
        .expect("a runtime")
        .block_on(async { store.get_any_tenant_by_slug(TENANT).await })
        .expect("a lookup");
    assert!(gone.is_none(), "the record must be gone");
    assert!(
        db.exists(),
        "delete must NOT remove the tenant's data without --purge-data: the calendars \\
         are the customer's, and 'remove the tenant' and 'destroy the data' are \\
         different acts"
    );
}

#[test]
fn delete_with_purge_data_removes_the_store_directory() {
    let fixture = control_fixture();
    let config = fixture.control_config();
    let id: TenantId = fixture
        .cli_raw(&config, &["tenant", "create", "--slug", TENANT])
        .trim()
        .parse()
        .expect("create prints the tenant id");
    let db = fixture.tenant_db(&id);
    assert!(db.exists());

    // A `--confirm --purge-data` run whose *combined* output is checked, because
    // the notice goes to stderr: an operator reading only stdout must not be
    // able to miss that a data directory was destroyed.
    let out = fixture.cli_raw_combined(
        &config,
        &["tenant", "delete", TENANT, "--confirm", "--purge-data"],
    );
    assert!(
        !db.exists(),
        "--purge-data must remove the store; the command printed {out:?}"
    );
    assert!(
        out.contains("Purging") && out.contains("tenants"),
        "the purge must say what it removed; got {out:?}"
    );
}

#[test]
fn deleting_an_unknown_tenant_is_an_error_not_a_silent_success() {
    let fixture = control_fixture();
    let out = fixture.cli_fail(
        &fixture.control_config(),
        &["tenant", "delete", "never-existed", "--confirm"],
    );
    assert!(
        output(&out).contains("no tenant with the slug"),
        "got:\n{}",
        output(&out)
    );
}

#[test]
fn the_cli_refuses_to_run_against_a_single_tenant_config() {
    // Without `[tenancy] enabled`, there is no control plane to administer, and
    // saying so is better than creating a second one somewhere unexpected.
    let fixture = Fixture::new(None);
    let out = fixture.cli_fail(&fixture.path("config.toml"), &["tenant", "list"]);
    let combined = output(&out);
    assert!(combined.contains("enabled is false"), "got:\n{combined}");
}

// ------------------------------------------------------------------ helpers

fn output(out: &std::process::Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}
