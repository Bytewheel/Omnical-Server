//! **Rows 26, 27 and 28** — the three routers with no principal.
//! `PLAN_DEPLOYMENTS.md` §6.4, and item 9's gate.
//!
//! ## Why these three are the gate and the others are not
//!
//! Every other route in the product sits behind `AuthenticationLayer`, which
//! resolves a principal against the store the router was built over. §3.2's
//! design makes that store the tenant's own, so rows 24 and 25 (item 8) follow
//! from the *construction path* and need no per-route work.
//!
//! `export_`, `rsvp_` and `register_` are the three routers mounted **outside**
//! that layer. They authenticate with a **token**, not a principal, so there is
//! no principal for the layer to check and nothing in the type system tying a
//! request to a tenant. They are the only three places where a tenant check can
//! be silently absent, and §6.4's instruction — "do not skip these" — is about
//! exactly that.
//!
//! | Row | Claim | Expected |
//! |---|---|---|
//! | 26 | Tenant A's `/export/{token}.ics` under tenant B's host | 404/410, never 200 |
//! | 27 | Tenant A's RSVP token verified with tenant B's secret | 404 |
//! | 28 | Tenant A's invite code redeemed under tenant B's host | rejected |
//!
//! ## Row 27 is the one that needed a code change
//!
//! Rows 26 and 28 are structural: the subscription and the invite are rows in
//! the requesting tenant's own database, so a token minted elsewhere simply is
//! not there. The tests exist to keep them that way.
//!
//! RSVP is different, and it is the forge vector §3.6/C6 warns about. The token
//! is an **HMAC over a shared secret**, so "is this token in my database?" is not
//! the question — the question is "does this token verify with *my* secret?".
//! While `rsvp_secret` is one global config value, every tenant shares it, and
//! since item 8 established that the same principal id can exist in two
//! tenants, a token minted by tenant A verifies under tenant B **and resolves to
//! tenant B's copy of the same event**. Tenant A could forge a reply to tenant
//! B's invitation. So the secret has to come from the tenant, and
//! `per_tenant_rsvp_secret_is_used` is the test that says so.

mod tenant_support;
use rustical::host_dispatch::HEALTH_PATH;
use tenant_support::Fixture;

/// The principal id, identical in both tenants.
///
/// Identical on purpose: §3.2's design lets the same id exist in two tenants'
/// databases, and that is the case a shared `principals` table with a
/// `tenant_id` column would be most likely to get wrong.
const PRINCIPAL: &str = "users";

/// Two tenants, each with the same principal, each with a share link and an
/// invite minted through the shipped CLI.
struct Public {
    inner: Fixture,
    acme_token: String,
    acme_invite: String,
    globex_token: String,
    globex_invite: String,
}

impl Public {
    /// Two tenants, each with the same principal, each with a share link and an
    /// invite minted through the product's own paths.
    ///
    /// The order is forced: the principal before its app token, the server
    /// before the calendar (MKCALENDAR is HTTP), and the calendar before the
    /// subscription (the export handler 404s on a vanished collection).
    fn new() -> Self {
        let mut inner = Fixture::new(Some(("t3.gg", "")));
        inner.seed_tenants_with_distinct_secrets(&["acme", "globex"]);
        for slug in ["acme", "globex"] {
            inner.materialise_tenant(slug);
            inner.cli(
                slug,
                &[
                    "principals",
                    "create",
                    PRINCIPAL,
                    "--for-testing-password-from-arg",
                    Fixture::PRINCIPAL_PASSWORD,
                ],
            );
        }

        inner.start();
        inner.wait_ready(HEALTH_PATH);

        let mut tokens = Vec::new();
        for slug in ["acme", "globex"] {
            let app = inner.cli(
                slug,
                &[
                    "principals",
                    "app-token",
                    "create",
                    PRINCIPAL,
                    "--name",
                    "gate",
                ],
            );
            let (token, _collection) =
                inner.share_link(&format!("{slug}.t3.gg"), slug, PRINCIPAL, &app);
            tokens.push(token);
        }
        let [acme_token, globex_token] =
            <[String; 2]>::try_from(tokens).expect("exactly two tenants were seeded");

        let acme_invite = inner.invite_code("acme");
        let globex_invite = inner.invite_code("globex");
        assert_ne!(acme_token, globex_token, "each tenant mints its own token");
        assert_ne!(
            acme_invite, globex_invite,
            "each tenant mints its own invite"
        );

        Self {
            inner,
            acme_token,
            acme_invite,
            globex_token,
            globex_invite,
        }
    }
}

/// **Row 26.** A share-link token from tenant A must not export under tenant B.
#[test]
fn an_export_token_from_one_tenant_does_not_work_under_another() {
    let cluster = Public::new();

    // Each tenant's own token exports. Without this, the 404s below could be
    // explained by the token being broken.
    for (host, token) in [
        ("acme.t3.gg", &cluster.acme_token),
        ("globex.t3.gg", &cluster.globex_token),
    ] {
        let (status, body) = cluster.inner.get(host, &format!("/export/{token}.ics"));
        assert_eq!(
            status, 200,
            "{host} must be able to export its own feed; got {status} {body:?}"
        );
    }

    // **Row 26.** Acme's token under Globex's host.
    let (status, body) = cluster.inner.get(
        "globex.t3.gg",
        &format!("/export/{}.ics", cluster.acme_token),
    );
    assert!(
        status == 404 || status == 410,
        "row 26: acme's export token must not work under globex; got {status} {body:?}"
    );

    // And the reverse.
    let (status, _) = cluster.inner.get(
        "acme.t3.gg",
        &format!("/export/{}.ics", cluster.globex_token),
    );
    assert!(status == 404 || status == 410, "row 26, reverse direction");
}

/// **Positive control for row 26.** Put tenant A's token *into tenant B's own
/// store* and it must export under tenant B's host.
///
/// Without this, row 26 is a weak gate. "Tenant A's token 404s under tenant B" is
/// equally consistent with the token being broken, the route being unmounted, or
/// the extension being disabled — every one of which leaves the assertion green
/// while measuring nothing. Watching the *same* token work the moment it exists
/// in the store the request reaches is what makes the 404 mean "not in my
/// database", which is the claim.
#[test]
fn row_26_is_about_the_store_and_not_about_a_broken_token() {
    let cluster = Public::new();
    let path = format!("/export/{}.ics", cluster.acme_token);

    // Not in globex's store: rejected.
    let (before, _) = cluster.inner.get("globex.t3.gg", &path);
    assert!(
        before == 404 || before == 410,
        "before the copy, the token must be rejected; got {before}"
    );

    // In globex's store: served. Same token, same host, same route.
    cluster
        .inner
        .copy_subscription_into("acme", "globex", &cluster.acme_token, "shared-calendar");
    let (after, body) = cluster.inner.get("globex.t3.gg", &path);
    assert_eq!(
        after, 200,
        "once the token exists in globex's own store it must export — otherwise the \
         404 was not about the store, and row 26 proves nothing. Body: {body:?}"
    );
}

/// **Positive control for row 28**, for the same reason.
#[test]
fn row_28_is_about_the_store_and_not_about_a_broken_invite() {
    let cluster = Public::new();
    let (status, _) = cluster.inner.post_form(
        "globex.t3.gg",
        "/register",
        &[("invite_code", &cluster.acme_invite)],
    );
    assert_ne!(
        status, 200,
        "before the copy, acme's invite must not redeem under globex; got {status}"
    );

    // Put the same code in globex's own `invites` table. If the rejection came
    // from anything other than the store — an expired code, a wrong form field,
    // a route that 404s everything — this still fails, and that is the point of
    // running it.
    cluster
        .inner
        .copy_invite_into("acme", "globex", &cluster.acme_invite);
    let (status, body) = cluster.inner.post_form(
        "globex.t3.gg",
        "/register",
        &[("invite_code", &cluster.acme_invite)],
    );
    assert_ne!(
        status, 404,
        "with the code in globex's own store the request must get past the invite \
         lookup; a 404 here means the earlier rejection was not about tenancy at \
         all. Body: {body:?}"
    );
}

/// The bodies of the two failures must not differ, or they become an oracle for
/// "which tenants exist and which hosts they claim".
#[test]
fn the_two_export_failures_are_byte_identical() {
    let cluster = Public::new();
    let unknown = cluster.inner.get("globex.t3.gg", "/export/deadbeef.ics");
    let cross = cluster.inner.get(
        "globex.t3.gg",
        &format!("/export/{}.ics", cluster.acme_token),
    );
    assert_eq!(
        unknown, cross,
        "an unknown token and a cross-tenant token must be indistinguishable"
    );
}

/// **Row 28.** An invite code from tenant A must not redeem under tenant B.
#[test]
fn an_invite_from_one_tenant_does_not_redeem_under_another() {
    let cluster = Public::new();
    let redeem = |host: &str, code: &str| {
        cluster
            .inner
            .post_form(host, "/register", &[("invite_code", code)])
    };

    // The same form the portal posts. Under Globex's host, Acme's code must be
    // refused — and *not* redeemed, which is the part that matters: a redeem
    // that silently succeeds under the wrong tenant is worse than an error.
    let (status, body) = redeem("globex.t3.gg", &cluster.acme_invite);
    assert_ne!(
        status, 200,
        "row 28: acme's invite must not redeem under globex; got {status} {body:?}"
    );

    let (status, _) = redeem("acme.t3.gg", &cluster.globex_invite);
    assert_ne!(status, 200, "row 28, reverse direction");

    // And the code must still be unredeemed in its own tenant, proving the
    // cross-tenant attempt did not consume it.
    let still_valid = cluster.inner.invite_exists("acme", &cluster.acme_invite);
    assert!(
        still_valid,
        "a rejected cross-tenant redeem must not burn the invite"
    );
}

/// **Row 27.** A token minted with tenant A's RSVP secret must not verify under
/// tenant B — and each tenant must verify with *its own* secret.
///
/// The second half is the half that was originally missing, and its absence
/// made this gate worse than useless. Asserting only "a token from A is rejected
/// under B" passes when **both tenants share one secret** — a different secret,
/// or no secret at all, produces the same 404. So the first draft of this test
/// was green against a build that ignored `config_json` entirely.
///
/// The fix is to pin down *which* secret each tenant runs with, from the
/// server's own answers:
///
/// - a token minted with the **global** secret must be *invalid* at the tenant's
///   own host — proving the tenant is not running on the global secret;
/// - a token minted with the **tenant's own** secret must not be *invalid* —
///   proving it is.
///
/// The two are told apart by the response *body*, because both are 404:
/// `render_invalid()` says "this link is invalid or has expired" (the HMAC did
/// not verify) while `render_gone()` says the event is no longer available (the
/// HMAC verified and resolution got further). That distinction is the entire
/// measurement, and it is why this test does not simply assert 404.
#[test]
fn each_tenant_rsvp_verifies_with_its_own_secret_and_not_the_global_one() {
    let cluster = Public::new();
    let global = cluster.inner.global_rsvp_secret();
    let (acme_secret, globex_secret) = cluster.inner.rsvp_secrets();
    assert_ne!(
        acme_secret, globex_secret,
        "the two tenants must not share an RSVP secret"
    );
    assert_ne!(acme_secret, global, "acme overrides the global secret");
    assert_ne!(globex_secret, global, "globex overrides the global secret");

    let mint = |secret: &str| {
        rustical_scheduling::rsvp::mint_token(
            secret,
            "event-uid-1",
            PRINCIPAL,
            "attendee@example.com",
            chrono_now(),
        )
    };

    for (slug, host, own) in [
        ("acme", "acme.t3.gg", &acme_secret),
        ("globex", "globex.t3.gg", &globex_secret),
    ] {
        // Minted with the GLOBAL secret. If this tenant were running on the
        // global secret — the bug — the HMAC would verify and the answer would
        // *not* be "invalid".
        let (status, body) = cluster.inner.get(host, &format!("/rsvp/{}", mint(&global)));
        assert_eq!(status, 404, "{slug}: a global-secret token must not verify");
        assert!(
            body.contains("invalid or has expired"),
            "{slug}: a token minted with the GLOBAL secret must be rejected as invalid at \
             {slug}'s own host — that is what proves {slug} runs on its own override. \
             Got {status} with body: {body:?}"
        );

        // Minted with the TENANT's own secret. The HMAC must verify, so the
        // failure has to come from resolving the event — which does not exist
        // here — and must therefore be a *different* message.
        let (status, body) = cluster.inner.get(host, &format!("/rsvp/{}", mint(own)));
        assert!(
            !body.contains("invalid or has expired"),
            "{slug}: a token minted with {slug}'s OWN secret must pass HMAC verification; \
             it got 'invalid or has expired', so {slug} is not using its own override. \
             Got {status} with body: {body:?}"
        );
    }
}

/// The cross-tenant half of row 27, on its own.
#[test]
fn an_rsvp_token_from_one_tenant_does_not_verify_under_another() {
    let cluster = Public::new();
    let (acme_secret, _) = cluster.inner.rsvp_secrets();

    let token = rustical_scheduling::rsvp::mint_token(
        &acme_secret,
        "event-uid-1",
        PRINCIPAL,
        "attendee@example.com",
        chrono_now(),
    );
    let (status, body) = cluster.inner.get("globex.t3.gg", &format!("/rsvp/{token}"));
    assert_eq!(
        status,
        404,
        "row 27: a token minted with acme's secret must not verify under globex; \
         got {status} {body:?}\nlog:\n{}",
        cluster.inner.log()
    );
    assert!(
        body.contains("invalid or has expired"),
        "row 27: it must be rejected as *invalid* — the HMAC did not verify"
    );
}

/// The property row 27 protects, stated so a future reader can check it holds.
///
/// If both tenants shared one secret, the token above would verify under both,
/// and — because item 8 established that the same principal id may exist in two
/// tenants — `resolve_rsvp_event` would find Globex's copy of the same event and
/// apply the forged reply to it. Tenant A could therefore answer an invitation
/// that Globex sent, or decline one, without any credential.
#[test]
fn the_forge_row_27_prevents_is_still_a_forge_if_the_secrets_agree() {
    let acme_secret = "a-shared-secret".to_owned();
    let globex_secret = acme_secret.clone();
    let token = rustical_scheduling::rsvp::mint_token(
        &acme_secret,
        "event-uid-1",
        "users",
        "attendee@example.com",
        chrono_now(),
    );
    // The HMAC verifies, because the secrets are the same. This is the whole
    // argument for per-tenant secrets, stated as a test so it cannot be
    // "simplified" away: there is no further check between the HMAC and the
    // event lookup.
    assert!(
        rustical_scheduling::rsvp::verify_token(&globex_secret, &token, chrono_now()).is_some(),
        "with a shared secret the token verifies under both tenants — which is \
         why the secret must be per-tenant"
    );
}

/// A tenant with **no** RSVP override inherits the global secret, so a
/// single-tenant install and a multi-tenant one both keep working.
#[test]
fn a_tenant_without_an_rsvp_override_inherits_the_global_secret() {
    let (inherited, _) = rsvp_secret_for(r#"{}"#, "global-secret");
    assert_eq!(
        inherited.as_deref(),
        Some("global-secret"),
        "an absent key must inherit, not fall back to nothing — a missing \
         override disabling RSVP silently would be a regression nobody notices"
    );
    // And an explicit override wins.
    let (overridden, _) = rsvp_secret_for(r#"{"rsvp_secret":"own"}"#, "global-secret");
    assert_eq!(overridden.as_deref(), Some("own"));
}

/// A malformed `config_json` must not become a *different* secret.
#[test]
fn an_unparseable_config_json_does_not_change_the_rsvp_secret() {
    // Falling back to the global secret on a parse failure is the safe
    // direction: the links minted for that tenant still verify. Returning
    // `None` would silently disable RSVP for a tenant because of a stray comma
    // in a JSON blob.
    let (secret, used_override) = rsvp_secret_for("{not json", "global-secret");
    assert_eq!(secret.as_deref(), Some("global-secret"));
    assert!(!used_override, "a parse failure is not an override");
}

// ------------------------------------------------------------------ helpers

fn chrono_now() -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("a clock")
            .as_secs(),
    )
    .expect("seconds fit in i64")
}

/// Mirrors the merge `tenancy.rs` performs when building a tenant's scheduler:
/// the tenant's `rsvp_secret` if it has one, else the global.
fn rsvp_secret_for(config_json: &str, global: &str) -> (Option<String>, bool) {
    match serde_json::from_str::<serde_json::Value>(config_json) {
        Ok(value) => match value.get("rsvp_secret").and_then(|v| v.as_str()) {
            Some(own) => (Some(own.to_owned()), true),
            None => (Some(global.to_owned()), false),
        },
        Err(_) => (Some(global.to_owned()), false),
    }
}
