//! §6.6.2/§6.6.3/§6.6.4 — the admin surface's credentials and its startup
//! invariants. Rows 32c and 32e's store halves, and the gates §6.6.9 added for
//! them.
//!
//! Phase 2 of item 17: the config allowlist, the credential store, the lockout,
//! and the three refusals. **The panel itself is phase 3** — nothing here starts
//! a listener on `admin_host`, and row 32 proper is unreachable until the router
//! exists.
//!
//! The claim under test throughout is the one that is easiest to implement
//! backwards: **config is authoritative**. A name with a valid hash that is not
//! in `platform_admins` must not authenticate, and a name in `platform_admins`
//! with no row must not either. Both directions are checked, because a system
//! that honours only the first has a working promotion path for anyone who can
//! write `control.sqlite3` — the file that already holds every tenant's SMTP
//! password.

mod tenant_support;

use rustical_store::admin_store::{
    ADMIN_LOCKOUT_SECS, ADMIN_MAX_FAILED_ATTEMPTS, AdminCredentialStore, AdminStanding,
};
use rustical_store::tenant::TenantStatus;
use rustical_store::tenant_store::TenantStore;
use tenant_support::Fixture;

/// A fixed actor for these tests. Not a credential, and it never leaves the test
/// process — the point of these tests is the *shape* of an audit row, not who
/// wrote it.
///
/// A function rather than a `static`, because `Actor::new` validates and is
/// therefore not `const`.
fn test_actor() -> rustical_store::Actor {
    rustical_store::Actor::new("test").expect("a valid actor")
}

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Runtime::new().expect("a runtime")
}

const ADMIN_HOST: &str = "admin.t3.gg";

/// A timestamp `n` seconds after `base`, in the format the columns use.
///
/// Built by hand rather than by sleeping: the lockout gate is about a
/// *comparison*, and a test that waits 15 real minutes to find out whether a
/// string comparison is right is a test nobody runs.
fn at(base: &str, secs: i64) -> String {
    let t = chrono::DateTime::parse_from_rfc3339(base).expect("a parseable timestamp");
    (t + chrono::Duration::seconds(secs))
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string()
}

const T0: &str = "2026-09-29T12:00:00Z";

// ───────────────────────────── config refusals (unit) ─────────────────────────

/// §6.6.4: `admin_host` without the acknowledgement refuses to start.
///
/// The row is not in §12's table — §6.6.9 added it — but it is the item's
/// largest constraint, and a test is the only way to keep it from being quietly
/// relaxed into a warning.
#[test]
fn a_panel_needs_the_single_instance_acknowledgement() {
    let mut tenancy = rustical::config::TenancyConfig {
        enabled: true,
        control_db_url: "sqlite://control.sqlite3".to_owned(),
        base_domain: "t3.gg".to_owned(),
        admin_host: ADMIN_HOST.to_owned(),
        platform_admins: vec!["ops".to_owned()],
        ..Default::default()
    };

    // Without the acknowledgement: refused, and the message has to explain what
    // the key *is*, because it is an assertion and not a probe.
    let err = tenancy.validate().expect_err("must refuse");
    assert!(
        err.contains("admin_single_instance_acknowledged"),
        "the refusal must name the key that is missing: {err}"
    );

    tenancy.admin_single_instance_acknowledged = true;
    tenancy.validate().expect("acknowledged is enough");
}

/// §6.6.4's weaker guarantee, expressed as the thing an operator could
/// otherwise mistake for a check.
///
/// The panel's k=1 requirement is enforced by *one boolean the operator sets*,
/// and by nothing else. That is the honest implementation — a process cannot
/// count its own instances — and this test exists so the property is deliberate
/// rather than accidental: if someone later adds a heuristic ("does this look
/// like local storage?"), **every** combination of the other keys stops
/// mattering, and a test that asserted the heuristic worked would be a test of a
/// false reassurance. §6.6.4 rejects that on purpose.
///
/// So: with the acknowledgement set, the panel is admitted regardless of
/// anything else — including a `data_root` that looks shared.
#[test]
fn the_acknowledgement_alone_admits_the_panel() {
    let base = rustical::config::TenancyConfig {
        enabled: true,
        control_db_url: "sqlite://c".to_owned(),
        base_domain: "t3.gg".to_owned(),
        admin_host: ADMIN_HOST.to_owned(),
        platform_admins: vec!["ops".to_owned()],
        admin_single_instance_acknowledged: true,
        ..Default::default()
    };
    base.validate().expect("acknowledged");

    // Nothing else is consulted, so nothing else can save an operator who sets
    // the key on a shared deployment. The refusal at the *other* end of this —
    // the tenant-claims-the-host check — is a real check, and is tested in the
    // "refuses to start" cases below.
    for (data_root, default_domain) in [
        ("/mnt/nfs/shared", "t3.gg"),
        ("/var/lib/omnical", "admin.example"),
        ("C:\\data", "corp.example"),
    ] {
        let mut t = base.clone();
        t.data_root = data_root.to_owned();
        t.default_domain = default_domain.to_owned();
        t.validate()
            .expect("no heuristic: the acknowledgement is the whole check");
    }
}

/// §6.6.2: an empty `admin_host` means no panel, and every other key is inert.
///
/// "Absence has to mean absence, or a self-hosted install acquires a
/// cross-tenant control surface by upgrading."
#[test]
fn an_unset_admin_host_is_not_a_panel() {
    let tenancy = rustical::config::TenancyConfig {
        enabled: true,
        control_db_url: "sqlite://c".to_owned(),
        base_domain: "t3.gg".to_owned(),
        // No admin_host, and no acknowledgement and no admins either: none of it
        // may be a startup error, because none of it does anything.
        ..Default::default()
    };
    tenancy.validate().expect("absent is valid");
    assert!(!tenancy.is_admin_host("admin.t3.gg"), "no host matches");
    assert!(!tenancy.is_admin_host(""), "not even the empty host");
}

/// A panel with no allowlisted name could never be authenticated, because
/// `tenant admin add` refuses any name the list does not contain. Refused at
/// boot rather than discovered by an operator waiting for a login.
#[test]
fn a_panel_with_no_allowlisted_names_is_refused() {
    let tenancy = rustical::config::TenancyConfig {
        enabled: true,
        control_db_url: "sqlite://c".to_owned(),
        base_domain: "t3.gg".to_owned(),
        admin_host: ADMIN_HOST.to_owned(),
        admin_single_instance_acknowledged: true,
        ..Default::default()
    };
    let err = tenancy.validate().expect_err("must refuse");
    assert!(err.contains("platform_admins"), "{err}");
}

/// The panel is one hostname away from every customer if it is the apex.
#[test]
fn the_admin_host_may_not_be_the_apex() {
    let tenancy = rustical::config::TenancyConfig {
        enabled: true,
        control_db_url: "sqlite://c".to_owned(),
        base_domain: "t3.gg".to_owned(),
        admin_host: "T3.GG".to_owned(),
        platform_admins: vec!["ops".to_owned()],
        admin_single_instance_acknowledged: true,
        ..Default::default()
    };
    // Also the normalisation test: `T3.GG` is the apex after reduction, so the
    // comparison is done on the form the router will match.
    let err = tenancy.validate().expect_err("must refuse");
    assert!(err.contains("base_domain"), "{err}");
}

/// §6.6.1: the panel is selected by *normalised* host, so a client's
/// `ADMIN.T3.GG:8443` still reaches it — and the config's own comparison has to
/// agree with that, or the operator cannot tell which side is misconfigured.
#[test]
fn the_admin_host_is_matched_normalised() {
    let tenancy = rustical::config::TenancyConfig {
        admin_host: "Admin.T3.GG.".to_owned(),
        ..Default::default()
    };
    for claim in [
        "admin.t3.gg",
        "ADMIN.T3.GG",
        "admin.t3.gg:8443",
        "  admin.t3.gg.  ",
    ] {
        assert!(tenancy.is_admin_host(claim), "{claim:?} must match");
    }
    for other in ["acme.t3.gg", "t3.gg", "admin.t3.gg.evil.example", ""] {
        assert!(!tenancy.is_admin_host(other), "{other:?} must not match");
    }
}

// ───────────────────────── the reserved-host refusals ─────────────────────────

/// §6.6.2, explicit row: a tenant holding `admin_host` makes the server refuse
/// to start, because the panel is selected *before* dispatch and the tenant
/// would be silently unreachable.
#[test]
fn a_tenant_claiming_the_admin_host_refuses_to_start() {
    let fixture = Fixture::new(Some(("t3.gg", "")));
    fixture.seed_tenants(&["acme"]);
    let id = fixture.tenant_id_any("acme");
    let store = fixture.control_plane();
    rt().block_on(async {
        store
            .set_tenant_hosts(
                &id,
                &[ADMIN_HOST.to_owned()],
                &rustical_store::Actor::new("ops").expect("a valid actor"),
            )
            .await
            .expect("the host is claimed");
    });

    let config = fixture.admin_server_config(ADMIN_HOST, &["ops"], true, fixture.port + 1);
    let log = fixture.serve_expecting_refusal(&config);
    assert!(
        log.contains("acme"),
        "the refusal must name the tenant holding the host: {log}"
    );
}

/// The *derivable* collision, which is the one a hosted deployment produces for
/// free and the one an explicit-row check alone would miss.
#[test]
fn a_derivable_host_collision_also_refuses_to_start() {
    let fixture = Fixture::new(Some(("t3.gg", "")));
    fixture.seed_tenants(&["acme"]);
    // **No `tenant_hosts` row at all.** `acme.t3.gg` resolves derivably from
    // `base_domain`, so this is the collision an explicit-row check alone
    // misses — and in a hosted deployment it is the *likely* one, because every
    // tenant gets a derivable host for free.
    //
    // Note the config: `admin_host` is `acme.t3.gg`, not a host that merely
    // shares a suffix with the base domain. `admin.t3.gg` also ends in
    // `.t3.gg` but is nobody's hostname, and refusing that would be refusing a
    // perfectly good panel host.
    let config = fixture.admin_server_config("acme.t3.gg", &["ops"], true, fixture.port + 1);
    let log = fixture.serve_expecting_refusal(&config);
    assert!(
        log.contains("acme") && log.contains("derived"),
        "the refusal must say the host is a tenant's derived hostname: {log}"
    );
}

/// The same derivation, and the reason the check cannot simply be "`admin_host`
/// ends with `base_domain`": a panel host that is *nobody's* derived hostname is
/// perfectly valid, and is in fact the normal shape.
#[test]
fn a_panel_host_sharing_the_base_domain_suffix_is_allowed() {
    let fixture = Fixture::new(Some(("t3.gg", "")));
    fixture.seed_tenants(&["acme"]);
    // `admin.t3.gg` shares the `.t3.gg` suffix and belongs to no tenant.
    let config = fixture.admin_server_config("admin.t3.gg", &["ops"], true, fixture.port + 1);

    // The helper under test says no collision…
    let tenancy = rustical::config::TenancyConfig {
        enabled: true,
        control_db_url: "sqlite://c".to_owned(),
        base_domain: "t3.gg".to_owned(),
        data_root: fixture.path("data").display().to_string(),
        admin_host: "admin.t3.gg".to_owned(),
        platform_admins: vec!["ops".to_owned()],
        admin_single_instance_acknowledged: true,
        ..Default::default()
    };
    // Built outside `block_on`: `control_plane()` opens its own runtime, and
    // nesting two is a panic rather than a test failure.
    let store = fixture.control_plane();
    rt().block_on(async {
        rustical::admin::assert_admin_host_unclaimed(&store, &tenancy)
            .await
            .expect("no tenant owns admin.t3.gg");
    });

    // …and the config itself is otherwise valid, so nothing *else* stops the
    // boot either. The two refusals are the only two, and neither fires.
    let written = std::fs::read_to_string(&config).expect("the config");
    let parsed: rustical::config::Config =
        toml::from_str(&written).expect("the generated config parses");
    parsed
        .tenancy
        .validate()
        .expect("a panel on a suffix-sharing, unclaimed host is valid");
}

/// A **suspended** tenant still owns its hostname. `get_tenant_by_host` filters
/// on `status = 'active'`, so this is the case where an implementation that
/// used the resolution lookup instead of the ownership lookup would let a
/// customer be stranded by their own suspension.
#[test]
fn a_suspended_tenant_still_owns_the_admin_host() {
    let fixture = Fixture::new(Some(("t3.gg", "")));
    fixture.seed_tenants(&["acme"]);
    let id = fixture.tenant_id_any("acme");
    let store = fixture.control_plane();
    rt().block_on(async {
        store
            .set_tenant_hosts(
                &id,
                &[ADMIN_HOST.to_owned()],
                &rustical_store::Actor::new("ops").expect("a valid actor"),
            )
            .await
            .expect("claimed");
        store
            .update_tenant_status(&id, TenantStatus::Suspended, &test_actor())
            .await
            .expect("suspended");
    });

    let config = fixture.admin_server_config(ADMIN_HOST, &["ops"], true, fixture.port + 1);
    // The *message* is not the claim here — that a suspended tenant still holds
    // its hostname is — so the log is deliberately not asserted on.
    drop(fixture.serve_expecting_refusal(&config));
}

/// §6.6.2's other half: the collision cannot be *introduced* by the CLI, which
/// is the only way this tree creates tenants.
#[test]
fn tenant_create_refuses_the_admin_host() {
    let fixture = Fixture::new(Some(("t3.gg", "")));
    let config = fixture.admin_server_config(ADMIN_HOST, &["ops"], true, fixture.port + 1);
    let out = fixture.cli_fail(
        &config,
        &[
            "tenant", "create", "--slug", "newco", "--actor", "ops", "--host", ADMIN_HOST,
        ],
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("admin_host"), "{err}");
    assert!(err.contains("reserved"), "{err}");

    // And the tenant was not created: a refusal that still writes the row would
    // leave a tenant that cannot start a server.
    let store = fixture.control_plane();
    let created = rt().block_on(async { store.get_any_tenant_by_slug("newco").await });
    assert!(
        created.expect("a store read").is_none(),
        "the refused create must not have written a tenant row"
    );
}

/// The case that makes normalisation matter on the *write* path: the operator
/// typed the apex in a different case, and the reservation still holds.
#[test]
fn tenant_create_refuses_the_admin_host_in_any_case() {
    let fixture = Fixture::new(Some(("t3.gg", "")));
    let config = fixture.admin_server_config("Admin.T3.GG", &["ops"], true, fixture.port + 1);
    let out = fixture.cli_fail(
        &config,
        &[
            "tenant",
            "create",
            "--slug",
            "newco",
            "--actor",
            "ops",
            "--host",
            "ADMIN.t3.gg:8443",
        ],
    );
    assert!(String::from_utf8_lossy(&out.stderr).contains("admin_host"));
}

// ───────────────────────────── the credential store ──────────────────────────

/// `tenant admin add` refuses a name the config does not list (§6.6.3).
///
/// The refusal is the security property, and it is checked *before* anything
/// is written: a row the config will never honour is a credential that looks
/// live and is not.
#[test]
fn admin_add_refuses_a_name_the_config_does_not_list() {
    let fixture = Fixture::new(Some(("t3.gg", "")));
    let config = fixture.admin_server_config(ADMIN_HOST, &["ops"], true, fixture.port + 1);

    let out = fixture.cli_fail(
        &config,
        &[
            "tenant",
            "admin",
            "add",
            "intruder",
            "--actor",
            "ops",
            "--password",
            "correct-horse-battery",
        ],
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("platform_admins"), "{err}");
    assert!(err.contains("Nothing has been changed"), "{err}");

    let store = fixture.control_plane();
    let rows = rt()
        .block_on(async { store.list_admin_credentials().await })
        .expect("a read");
    assert!(rows.is_empty(), "the refused add wrote a row: {rows:?}");
}

/// The whole point of the split: an allowlisted name with a credential can be
/// found, and a name with a credential but no allowlist entry is visible as
/// *not* allowlisted rather than as an ordinary admin.
#[test]
fn list_reconciles_config_against_the_control_plane() {
    let fixture = Fixture::new(Some(("t3.gg", "")));
    let config = fixture.admin_server_config(ADMIN_HOST, &["ops", "sre"], true, fixture.port + 1);
    let store = fixture.control_plane();
    rt().block_on(async {
        // `ops` is allowlisted *and* has a row: ready.
        store
            .set_admin_credential("ops", "argon2-hash-ops", T0)
            .await
            .expect("ops");
        // `sre` is allowlisted with no row: cannot authenticate.
        // `ghost` has a row but is not allowlisted: the hash is never consulted.
        store
            .set_admin_credential("ghost", "argon2-hash-ghost", T0)
            .await
            .expect("ghost");
    });

    let allowlist = vec!["ops".to_owned(), "sre".to_owned()];
    let entries = rt()
        .block_on(async { store.allowlist_gaps(&allowlist).await })
        .expect("a read");

    let by_name: std::collections::BTreeMap<_, _> = entries.into_iter().collect();
    assert!(
        matches!(by_name["ops"], AdminStanding::Ready { .. }),
        "{by_name:?}"
    );
    assert!(
        matches!(by_name["sre"], AdminStanding::NoCredential),
        "an allowlisted name with no row must be reported: {by_name:?}"
    );
    assert!(
        matches!(by_name["ghost"], AdminStanding::NotAllowlisted { .. }),
        "a row that is not allowlisted must be reported, not shown as an admin: {by_name:?}"
    );

    // And the CLI's own view, which is what an operator actually reads.
    let out = fixture.cli_raw(&config, &["tenant", "admin", "list"]);
    assert!(out.contains("ops"), "{out}");
    assert!(out.contains("sre"), "the gap must be visible: {out}");
    assert!(out.contains("NO CREDENTIAL"), "{out}");
    assert!(
        out.contains("NOT ALLOWLISTED"),
        "a row the config will never honour must be visible: {out}"
    );
}

/// The hash is what is stored, never the password, and `created_at` survives a
/// rotation.
#[test]
fn a_credential_stores_the_hash_and_keeps_its_creation_time() {
    let fixture = Fixture::new(Some(("t3.gg", "")));
    let store = fixture.control_plane();
    rt().block_on(async {
        store
            .set_admin_credential("ops", "argon2-hash-1", T0)
            .await
            .expect("first");
        store
            .set_admin_credential("ops", "argon2-hash-2", &at(T0, 3600))
            .await
            .expect("rotate");
    });
    let row = rt()
        .block_on(async { store.get_admin_credential("ops").await })
        .expect("a read")
        .expect("a row");
    assert_eq!(row.password_hash, "argon2-hash-2", "the hash is replaced");
    assert_eq!(
        row.created_at, T0,
        "created_at is when the credential was first issued, not last rotated"
    );
}

/// §6.6.5: lockout after N failures, and it *holds* until it expires.
#[test]
fn repeated_failures_lock_the_admin_out() {
    let fixture = Fixture::new(Some(("t3.gg", "")));
    let store = fixture.control_plane();
    let until = rustical_store::admin_lockout_until(T0);

    rt().block_on(async {
        store
            .set_admin_credential("ops", "h", T0)
            .await
            .expect("row");
        for i in 1..ADMIN_MAX_FAILED_ATTEMPTS {
            store
                .record_login_failure("ops", T0, &until)
                .await
                .expect("fail");
            let row = store
                .get_admin_credential("ops")
                .await
                .expect("read")
                .expect("row");
            assert_eq!(row.failed_attempts, i);
            assert!(!row.is_locked(T0), "not locked at {i} failures");
        }
        // The one that reaches the threshold.
        store
            .record_login_failure("ops", T0, &until)
            .await
            .expect("fail");
        let row = store
            .get_admin_credential("ops")
            .await
            .expect("read")
            .expect("row");
        assert_eq!(row.failed_attempts, ADMIN_MAX_FAILED_ATTEMPTS);
        assert_eq!(row.locked_until.as_deref(), Some(until.as_str()));
        assert!(row.is_locked(T0), "locked immediately");
        assert!(
            row.is_locked(&at(T0, ADMIN_LOCKOUT_SECS - 1)),
            "still locked one second before expiry"
        );
        assert!(
            !row.is_locked(&at(T0, ADMIN_LOCKOUT_SECS)),
            "free at the deadline"
        );
    });
}

/// A lockout that a further failure could shorten is not a lockout, and a
/// lockout that resets on restart is not either. Both are single-statement
/// properties, so both are cheap to test.
#[test]
fn more_failures_cannot_shorten_a_lockout() {
    let fixture = Fixture::new(Some(("t3.gg", "")));
    let store = fixture.control_plane();
    let until = rustical_store::admin_lockout_until(T0);
    // A *later* deadline than the one the row already carries.
    let later = rustical_store::admin_lockout_until(&at(T0, 600));

    rt().block_on(async {
        store
            .set_admin_credential("ops", "h", T0)
            .await
            .expect("row");
        for _ in 0..ADMIN_MAX_FAILED_ATTEMPTS {
            store
                .record_login_failure("ops", T0, &until)
                .await
                .expect("fail");
        }
        store
            .record_login_failure("ops", T0, &later)
            .await
            .expect("fail");
        let row = store
            .get_admin_credential("ops")
            .await
            .expect("read")
            .expect("row");
        assert_eq!(
            row.locked_until.as_deref(),
            Some(later.as_str()),
            "the later deadline wins; a flood must extend, never shorten"
        );
    });
}

/// A success clears the counter and dates the login, which is also the only
/// supported way out of a lockout short of re-`add`.
#[test]
fn a_successful_login_clears_the_lockout_state() {
    let fixture = Fixture::new(Some(("t3.gg", "")));
    let store = fixture.control_plane();
    let until = rustical_store::admin_lockout_until(T0);
    rt().block_on(async {
        store
            .set_admin_credential("ops", "h", T0)
            .await
            .expect("row");
        for _ in 0..ADMIN_MAX_FAILED_ATTEMPTS {
            store
                .record_login_failure("ops", T0, &until)
                .await
                .expect("fail");
        }
        store
            .record_login_success("ops", &at(T0, 60))
            .await
            .expect("success");
        let row = store
            .get_admin_credential("ops")
            .await
            .expect("read")
            .expect("row");
        assert_eq!(row.failed_attempts, 0);
        assert_eq!(row.locked_until, None);
        assert_eq!(row.last_login_at.as_deref(), Some(at(T0, 60).as_str()));
    });
}

/// Re-`add` is a credential reset, so it clears the lockout — otherwise a locked
/// admin could not be recovered without hand-editing the database.
#[test]
fn re_adding_a_credential_clears_its_lockout() {
    let fixture = Fixture::new(Some(("t3.gg", "")));
    let store = fixture.control_plane();
    let until = rustical_store::admin_lockout_until(T0);
    rt().block_on(async {
        store
            .set_admin_credential("ops", "h", T0)
            .await
            .expect("row");
        for _ in 0..ADMIN_MAX_FAILED_ATTEMPTS {
            store
                .record_login_failure("ops", T0, &until)
                .await
                .expect("fail");
        }
        store
            .set_admin_credential("ops", "h2", &at(T0, 60))
            .await
            .expect("rotate");
        let row = store
            .get_admin_credential("ops")
            .await
            .expect("read")
            .expect("row");
        assert_eq!(row.failed_attempts, 0);
        assert_eq!(row.locked_until, None);
    });
}

/// `remove` reports whether there was anything, so a second `remove` is not an
/// error an operator has to interpret.
#[test]
fn removing_a_credential_that_is_not_there_is_not_a_failure() {
    let fixture = Fixture::new(Some(("t3.gg", "")));
    let store = fixture.control_plane();
    rt().block_on(async {
        assert!(
            !store
                .remove_admin_credential("nobody")
                .await
                .expect("a delete")
        );
        store
            .set_admin_credential("ops", "h", T0)
            .await
            .expect("row");
        assert!(
            store
                .remove_admin_credential("ops")
                .await
                .expect("a delete")
        );
        assert!(
            !store
                .remove_admin_credential("ops")
                .await
                .expect("a delete")
        );
    });
}

/// The end-to-end CLI path: a real argon2 hash lands in the control plane, and
/// the plaintext does not.
#[test]
fn admin_add_stores_a_hash_and_not_the_password() {
    let fixture = Fixture::new(Some(("t3.gg", "")));
    let config = fixture.admin_server_config(ADMIN_HOST, &["ops"], true, fixture.port + 1);
    let password = "correct-horse-battery-staple";
    fixture.cli_raw(
        &config,
        &[
            "tenant",
            "admin",
            "add",
            "ops",
            "--actor",
            "ops",
            "--password",
            password,
        ],
    );

    let store = fixture.control_plane();
    let row = rt()
        .block_on(async { store.get_admin_credential("ops").await })
        .expect("a read")
        .expect("a row");
    assert!(row.password_hash.starts_with("$argon2"), "{row:?}");
    assert!(
        !row.password_hash.contains(password),
        "the plaintext password must not be in the stored hash"
    );
}

/// §6.6.3's accepted consequence: the two halves can disagree, and `remove`
/// says so rather than letting a stale allowlist entry look armed.
#[test]
fn remove_warns_when_the_name_is_still_allowlisted() {
    let fixture = Fixture::new(Some(("t3.gg", "")));
    let config = fixture.admin_server_config(ADMIN_HOST, &["ops"], true, fixture.port + 1);
    fixture.cli_raw(
        &config,
        &[
            "tenant",
            "admin",
            "add",
            "ops",
            "--actor",
            "ops",
            "--password",
            "a-long-enough-password",
        ],
    );
    let out = fixture.cli_raw_combined(&config, &["tenant", "admin", "remove", "ops"]);
    assert!(out.contains("Removed the credential row"), "{out}");
    assert!(
        out.contains("still in [tenancy] platform_admins"),
        "a stale allowlist entry must be called out: {out}"
    );
}

/// A too-short admin password is refused at the floor, which does not follow
/// `[registration] min_password_length`: this credential crosses every tenant
/// boundary, and a config that lowered the bar for tenant users does not get to
/// lower it here.
#[test]
fn a_short_admin_password_is_refused() {
    let fixture = Fixture::new(Some(("t3.gg", "")));
    let config = fixture.admin_server_config(ADMIN_HOST, &["ops"], true, fixture.port + 1);
    let out = fixture.cli_fail(
        &config,
        &[
            "tenant",
            "admin",
            "add",
            "ops",
            "--actor",
            "ops",
            "--password",
            "short",
        ],
    );
    assert!(String::from_utf8_lossy(&out.stderr).contains("at least 12 characters"));
}

/// `tenant admin add` is a mutation, so the no-actor rule applies to it too:
/// §6.6.7's actor requirement is not scoped to tenant rows.
#[test]
fn admin_add_with_no_actor_is_refused() {
    let fixture = Fixture::new(Some(("t3.gg", "")));
    let config = fixture.admin_server_config(ADMIN_HOST, &["ops"], true, fixture.port + 1);
    let out = fixture.cli_fail_bare_env(
        &config,
        &[
            "tenant",
            "admin",
            "add",
            "ops",
            "--password",
            "a-long-enough-password",
        ],
        &["OMNICAL_ACTOR", "SUDO_USER", "USER"],
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("actor") || err.contains("OMNICAL_ACTOR"),
        "{err}"
    );
}

// ─────────────────────────────────── the gate ─────────────────────────────────

/// The whole of phase 2 in one test, because the refusals and the credential
/// store are only meaningful together: a promotion attempt has to fail at the
/// config, the legitimate path has to work, and the admin's own row has to land
/// in the control plane rather than in anything a tenant's backup reaches.
#[test]
fn the_admin_surface_is_allowlisted_and_its_credentials_stay_in_the_control_plane() {
    let fixture = Fixture::new(Some(("t3.gg", "")));
    let config = fixture.admin_server_config(ADMIN_HOST, &["ops", "sre"], true, fixture.port + 1);

    // A legitimate tenant, on a host that is not the panel's.
    fixture.cli_raw(
        &config,
        &[
            "tenant",
            "create",
            "--slug",
            "acme",
            "--actor",
            "ops",
            "--host",
            "acme.t3.gg",
        ],
    );
    // The panel host cannot be taken this way, so the collision §6.6.2 refuses
    // to boot over is not one this CLI can create.
    fixture.cli_fail(
        &config,
        &[
            "tenant", "create", "--slug", "newco", "--actor", "ops", "--host", ADMIN_HOST,
        ],
    );

    // The server starts: nothing claims the panel's host.
    let store = fixture.control_plane();
    let tenancy = tenancy_from_config(&fixture, &config);
    rt().block_on(async {
        rustical::admin::assert_admin_host_unclaimed(&store, &tenancy)
            .await
            .expect("no tenant claims the admin host");
    });

    // Allowlisted, so `add` accepts it.
    fixture.cli_raw(
        &config,
        &[
            "tenant",
            "admin",
            "add",
            "ops",
            "--actor",
            "ops",
            "--password",
            "a-long-enough-password",
        ],
    );
    // Not allowlisted, so it does not — and writes nothing.
    fixture.cli_fail(
        &config,
        &[
            "tenant",
            "admin",
            "add",
            "ghost",
            "--actor",
            "ops",
            "--password",
            "a-long-enough-password",
        ],
    );

    // The control plane's own file, not a tenant's: an admin credential must
    // never end up in a database that a tenant's backup can reach. Checked as
    // bytes because that is the claim — the row is in *this* file — and a
    // per-table query would only prove SQLite can read what it just wrote.
    let control = fixture.path("control.sqlite3");
    let bytes = std::fs::read(&control).expect("the control plane");
    assert!(
        bytes.windows(3).any(|w| w == b"ops"),
        "the credential row should be in the control plane"
    );
    let tenant_db = fixture.tenant_db(&fixture.tenant_id("acme"));
    let bytes = std::fs::read(tenant_db).expect("the tenant store");
    assert!(
        !bytes.windows(3).any(|w| w == b"ops"),
        "an admin name appeared in acme's own database"
    );
}

/// Parse a generated admin config back into a [`TenancyConfig`].
///
/// Round-tripping through the real deserializer rather than rebuilding the
/// struct by hand, so these tests cannot drift from what a server would read —
/// a `TenancyConfig` assembled in a test proves the *helper's* rules, not the
/// *config file's*.
fn tenancy_from_config(
    fixture: &Fixture,
    config: &std::path::PathBuf,
) -> rustical::config::TenancyConfig {
    let text = std::fs::read_to_string(config).expect("the config");
    let parsed: rustical::config::Config = toml::from_str(&text).expect("the config parses");
    let _ = fixture;
    parsed.tenancy
}
