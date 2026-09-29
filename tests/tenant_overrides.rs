//! **Rows 30 and 31** — per-tenant config overrides reaching a *command*.
//! `PLAN_DEPLOYMENTS.md` §6.3, and item 10's gate.
//!
//! ## Why this is a separate target from `public_routes.rs`
//!
//! §6.4's rows are about what the **server** does with a `Host` header. These
//! two are about what a **command** does, which is a different surface reached a
//! different way: `rustical invites create --send` and `rustical subscriptions
//! add` read their SMTP identity and their public URL out of the config, and the
//! per-tenant overrides live in the *control plane*, not in the config file. So
//! without `RUSTICAL_TENANT` an admin operating on tenant A's data would send
//! A's invitation from the **global** `From:` with a link to the **global** host
//! — and nothing in §6.4's tests would notice, because those all go through the
//! server.
//!
//! | Row | Claim | Observable |
//! |---|---|---|
//! | 30 | Per-tenant SMTP identity | the resolved account's `identity`/`From:` |
//! | 31 | Per-tenant `public_url` | the subscribe/export link printed on stdout |
//!
//! ## What is *not* covered, stated plainly
//!
//! Row 30's gate is "`From:`/`Return-Path` are tenant A's identity", and the
//! bytes that leave the process are produced by
//! `send_mail(account, &account.identity, …)`. This target asserts the two halves
//! of that — the account the command *resolves*, and the `From:` that account
//! produces — but **not** an actual SMTP transaction.
//!
//! It cannot, cheaply: `send_mail_inner` requires the server to advertise
//! `STARTTLS`, so a fake SMTP peer would need a certificate, and no cert-issuing
//! crate (`rcgen`) is vendored in this workspace. Adding one as a dev-dependency
//! for a test is a worse trade than naming the gap, because the untested half is
//! `MAIL FROM:` framing in a shared function that the global-tenant path already
//! exercises, while the half that could regress — *which account a command picks
//! for a tenant* — is exactly what is tested here.

mod tenant_support;
use rustical::config::Config;
use rustical_store::Tenant;
use tenant_support::Fixture;

/// The per-tenant SMTP identity and public URL, and the global ones they must
/// not be.
const ACME_SMTP: &str = "cal@acme.example";
const GLOBEX_SMTP: &str = "cal@globex.example";
const ACME_HOST: &str = "https://cal.acme.example";
const GLOBEX_HOST: &str = "https://cal.globex.example";

fn url_blob(public_url: &str) -> String {
    format!(r#"{{"subscriptions":{{"public_url":"{public_url}"}}}}"#)
}

fn smtp_blob(identity: &str) -> String {
    format!(
        r#"{{"scheduling":{{"smtp":[{{"identity":"{identity}","host":"mail.example","port":587,"username":"{identity}","password":"hunter2"}}]}},"subscriptions":{{"public_url":"{ACME_HOST}"}}}}"#
    )
}

fn tenant(slug: &str, config_json: &str) -> Tenant {
    let mut new = rustical_store_sqlite::new_tenant(&slug.parse().expect("a slug"), None);
    new.tenant.config_json = config_json.to_owned();
    new.tenant
}

/// **Row 30.** Tenant A's invitation goes out from tenant A's identity.
///
/// Asserted in the two pieces it is actually made of: the account the config
/// resolves to, and the `From:` that account produces. The `From:` half uses the
/// product's own `build_registration_invite`, so a change to how the header is
/// written is caught here rather than only in production mail.
#[test]
fn an_invite_is_sent_from_the_tenants_own_smtp_identity() {
    let base = Config::default_config();
    let acme = tenant("acme", &smtp_blob(ACME_SMTP));
    let globex = tenant("globex", &smtp_blob(GLOBEX_SMTP));

    let acme_config = base.with_tenant_overrides(&acme);
    let globex_config = base.with_tenant_overrides(&globex);

    let acme_account = acme_config
        .scheduling
        .smtp
        .first()
        .expect("acme has an smtp account");
    let globex_account = globex_config
        .scheduling
        .smtp
        .first()
        .expect("globex has an smtp account");

    assert_eq!(acme_account.identity, ACME_SMTP);
    assert_eq!(globex_account.identity, GLOBEX_SMTP);
    assert_ne!(
        acme_account.identity, globex_account.identity,
        "the two tenants must resolve to different identities, or row 30 has \\
         nothing to distinguish"
    );

    // The `From:` the product actually writes. `cmd_invites` passes
    // `&account.identity` as the envelope sender and the same account to the
    // builder, so this is the header that goes out.
    let message = rustical_scheduling::mime::build_registration_invite(
        acme_account,
        "newcomer@example.net",
        &format!("{ACME_HOST}/register?code=CODE"),
        "admin",
        None,
    );
    assert!(
        message.contains(&format!("From: {ACME_SMTP}")),
        "the From: must be tenant acme's identity; message was:\n{message}"
    );
    assert!(
        !message.contains(GLOBEX_SMTP),
        "acme's invitation must not carry globex's identity"
    );
    // And the register link inside the body is the tenant's own host.
    assert!(
        message.contains(&format!("{ACME_HOST}/register?code=CODE")),
        "the link in the body must be on acme's host"
    );
}

/// **Row 31.** Tenant A's subscribe link points at tenant A's host.
#[test]
fn a_subscribe_link_uses_the_tenants_public_url() {
    let base = Config::default_config();
    let acme = base.with_tenant_overrides(&tenant("acme", &url_blob(ACME_HOST)));
    let globex = base.with_tenant_overrides(&tenant("globex", &url_blob(GLOBEX_HOST)));
    let inherits = base.with_tenant_overrides(&tenant("plain", "{}"));

    assert_eq!(acme.subscriptions.public_url.as_deref(), Some(ACME_HOST));
    assert_eq!(
        globex.subscriptions.public_url.as_deref(),
        Some(GLOBEX_HOST)
    );
    assert_ne!(
        acme.subscriptions.public_url, globex.subscriptions.public_url,
        "two tenants with different hosts must survive the merge distinctly"
    );
    // A tenant that overrides nothing keeps the *global* value, which is the
    // direction §3.6 specifies and the reason a blob can stay sparse.
    assert_eq!(
        inherits.subscriptions.public_url, base.subscriptions.public_url,
        "an empty blob must inherit the global public_url unchanged"
    );
}

/// **Row 31, end to end.** The link the CLI *prints* names tenant A's host.
///
/// This is the part §6.4's server-side tests cannot reach, and it is the part an
/// operator actually hands to somebody. `RUSTICAL_TENANT=acme` on the command
/// line must change the printed URL.
#[test]
fn the_subscriptions_command_prints_a_tenant_scoped_link() {
    let mut fixture = Fixture::new(Some(("t3.gg", "")));
    // The tenant overrides the public URL; the config an admin uses names a
    // different one, so the printed link says which applied.
    fixture.seed_tenants_with(&[("acme", &url_blob(ACME_HOST))]);
    fixture.materialise_tenant("acme");
    fixture.cli(
        "acme",
        &[
            "principals",
            "create",
            "users",
            "--for-testing-password-from-arg",
            "pw",
        ],
    );
    fixture.start();
    fixture.wait_ready(fixture.health_path());
    let app = fixture.cli(
        "acme",
        &["principals", "app-token", "create", "users", "--name", "g"],
    );
    // `subscriptions add` resolves the collection, so it has to exist.
    let (status, body) = fixture.mkcalendar("acme.t3.gg", "cal", "users", &app);
    assert_eq!(status, 201, "creating the collection failed: {body:?}");

    // Without the selection, the config's own (wrong) public URL applies.
    let unscoped = fixture.cli(
        "acme",
        &["subscriptions", "add", "--kind", "calendar", "users", "cal"],
    );
    assert!(
        unscoped.contains("global.example"),
        "without OMNICAL_TENANT the config's public_url applies; got {unscoped:?}"
    );

    // With it, the tenant's host is printed. Same command, same database — only
    // the selection differs.
    let scoped = fixture.cli_as(
        "acme",
        "acme",
        &["subscriptions", "add", "--kind", "calendar", "users", "cal"],
    );
    assert!(
        scoped.contains(ACME_HOST),
        "row 31: the printed link must be on the tenant's host; got {scoped:?}"
    );
    assert!(
        !scoped.contains("global.example"),
        "the config's own host must not appear; got {scoped:?}"
    );
}

/// A named tenant that does not resolve must **fail**, not fall back.
///
/// The failure this prevents is quiet and expensive: an admin who believes they
/// are inviting somebody on behalf of tenant A, and whose invitation goes out
/// with the platform's own `From:` and the platform's own link. Nothing about the
/// resulting mail is obviously wrong.
#[test]
fn a_named_tenant_that_does_not_exist_refuses_rather_than_falling_back() {
    let fixture = Fixture::new(Some(("t3.gg", "")));
    fixture.seed_tenants(&["acme"]);
    fixture.materialise_tenant("acme");
    // With no selection the same command succeeds, which is what makes the
    // refusal below attributable to the refusal.
    let _ = fixture.cli("acme", &["principals", "list"]);

    // `principals list` succeeds on its own, so the only reason this can fail is
    // the refusal. The first draft used `subscriptions add` with a
    // non-existent collection, which failed anyway — so the test passed against a
    // build that *did* fall back to the global config, which is the opposite of
    // what it claims.
    let out = fixture.cli_expect_failure("acme", "does-not-exist", &["principals", "list"]);
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        combined.contains("does-not-exist"),
        "the error must name the tenant; got:\n{combined}"
    );
    assert!(
        combined.contains("Refusing") || combined.contains("refusing"),
        "the error must say it refused rather than falling back; got:\n{combined}"
    );
}

/// A **suspended** tenant is not a resolvable tenant, and must be refused for the
/// same reason an unknown one is.
#[test]
fn a_suspended_tenant_cannot_be_selected() {
    let fixture = Fixture::new(Some(("t3.gg", "")));
    fixture.seed_tenants(&["acme"]);
    fixture.materialise_tenant("acme");
    let id = fixture.tenant_id("acme");
    fixture.suspend(&id);

    let out = fixture.cli_expect_failure("acme", "acme", &["principals", "list"]);
    let combined = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        combined.contains("Refusing") || combined.contains("refusing"),
        "a suspended tenant must be refused like an unknown one; got:\n{combined}"
    );
}

/// The control plane holds SMTP passwords, so its file must not be readable by
/// other accounts. §6.3 calls this out as **critical**, and a SQLite file is
/// created 0644 by default.
#[test]
fn the_control_plane_file_is_not_world_readable() {
    use std::os::unix::fs::PermissionsExt;

    let fixture = Fixture::new(Some(("t3.gg", "")));
    fixture.seed_tenants(&["acme"]);
    let path = fixture.path("control.sqlite3");
    // Reading a tenant id opens the control plane, which is the code path under
    // test.
    let _ = fixture.tenant_id("acme");

    assert!(path.exists(), "{} should exist", path.display());
    let mode = std::fs::metadata(&path)
        .expect("metadata")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(
        mode & 0o077,
        0,
        "the control plane holds tenant SMTP passwords and must not be group- or \\
         world-accessible; it is {:o} at {}",
        mode,
        path.display()
    );
}
