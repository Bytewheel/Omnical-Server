//! §6.6.1, §6.6.5, §6.6.6 — the admin panel itself. Rows 32, 32a-32d, and the
//! panel's half of row 33.
//!
//! Phase 3 of item 17. Phases 1 and 2 built the audit trail and the credential
//! store; this mounts the **router** in front of `HostDispatch` and puts a login
//! form on exactly one host.
//!
//! ## Why these are in-process
//!
//! Almost every claim here is about **which router answers**, so the tests drive
//! [`serve_dispatch`]'s returned [`TenancyAwareApp`] with a `Host` header rather
//! than booting a server and making HTTP calls. That makes the host selection
//! the *only* variable — a booted server has a port, a scheduler and a
//! `reqwest` client in the picture, and a test that fails for one of those
//! reasons teaches nothing about row 32.
//!
//! What "in-process" does **not** mean is "mocked": the control plane is a real
//! SQLite file, the credentials are real argon2 hashes, the session is a real
//! `MemoryStore` with a real cookie, and the CSRF token is scraped out of the
//! rendered HTML exactly as a browser would find it.
//!
//! ## The claims, and where each is checked
//!
//! | Claim | Test |
//! |---|---|
//! | 32: a non-admin sees **404**, not 403, and no login form | `an_unauthenticated_request_is_404_not_a_login_form` |
//! | 32a: the same path on a **tenant** host | `the_panel_does_not_exist_on_a_tenant_host` |
//! | 32b: allowlisted **and** authenticated → 200 | `an_allowlisted_admin_can_log_in` |
//! | 32c: valid hash, **not** allowlisted → 404 | `a_name_with_a_hash_but_not_allowlisted_cannot_log_in` |
//! | 32d: `admin_host` unset → no panel anywhere | `an_unset_admin_host_means_no_panel_anywhere` |
//! | 33: a panel mutation is audited with the admin's name | `a_panel_mutation_is_audited_with_the_admin_name` |

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use rustical::config::Config;
use rustical_store::admin_store::AdminCredentialStore;
use rustical_store::tenant_store::TenantStore;
use tower::Service;

mod tenant_support;
use tenant_support::Fixture;

const ADMIN_HOST: &str = "admin.t3.gg";
const PASSWORD: &str = "correct-horse-battery-staple";

/// A config for a tenancy-enabled install, with the panel on or off.
///
/// Built by writing TOML and parsing it back, **not** by assembling a
/// [`Config`] struct: `deny_unknown_fields` means a struct literal can drift from
/// the keys a real operator writes, and these tests are about what a config
/// *file* does.
fn config_for(fixture: &Fixture, admin_host: &str, admins: &[&str]) -> Config {
    let path = fixture.path(&format!(
        "panel-{}-{admins:?}.toml",
        if admin_host.is_empty() { "none" } else { "on" }
    ));
    let body = format!(
        "[data_store.sqlite]\ndb_url = \"sqlite://{db}\"\nrun_repairs = false\n\
         skip_broken = false\n\n\
         [tenancy]\nenabled = true\n\
         control_db_url = \"sqlite://{control}\"\nbase_domain = \"t3.gg\"\n\
         data_root = \"{root}\"\nmax_cached_tenants = 8\n\
         admin_host = \"{admin_host}\"\nplatform_admins = [{admins}]\n\
         admin_single_instance_acknowledged = {ack}\n",
        db = fixture.path("data").join("db.sqlite3").display(),
        control = fixture.path("control.sqlite3").display(),
        root = fixture.path("data").display(),
        admins = admins
            .iter()
            .map(|a| format!("\"{a}\""))
            .collect::<Vec<_>>()
            .join(", "),
        // The acknowledgement is required whenever a host is set — that is
        // phase 2's rule, and these tests must not be the thing that changes it.
        ack = !admin_host.is_empty(),
    );
    std::fs::write(&path, &body).expect("the config");
    toml::from_str(&body).expect("the config parses")
}

/// The app under test.
async fn app(config: &Config) -> rustical::host_dispatch::TenancyAwareApp {
    rustical::tenancy::serve_dispatch(config)
        .await
        .expect("a tenancy-enabled app")
}

/// A request with a `Host` header, which is the only thing that selects a router.
fn get(host: &str, path: &str) -> Request<Body> {
    Request::builder()
        .uri(format!("http://{host}{path}"))
        .header(header::HOST, host)
        .body(Body::empty())
        .expect("a request")
}

/// A form POST, with the `Host` header and an optional session cookie.
fn post(host: &str, path: &str, form: &[(&str, &str)], cookie: Option<&str>) -> Request<Body> {
    let encoded = form
        .iter()
        .map(|(k, v)| format!("{k}={}", urlencode(v)))
        .collect::<Vec<_>>()
        .join("&");
    let mut builder = Request::builder()
        .method("POST")
        .uri(format!("http://{host}{path}"))
        .header(header::HOST, host)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    if let Some(cookie) = cookie {
        builder = builder.header(header::COOKIE, cookie);
    }
    builder.body(Body::from(encoded)).expect("a request")
}

fn urlencode(value: &str) -> String {
    value
        .bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

async fn send(
    app: &mut rustical::host_dispatch::TenancyAwareApp,
    request: Request<Body>,
) -> (StatusCode, String, Vec<String>) {
    let response = app.call(request).await.expect("infallible");
    let status = response.status();
    let cookies = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .map(ToOwned::to_owned)
        .collect();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("a body");
    (status, String::from_utf8_lossy(&body).into_owned(), cookies)
}

/// The `name=value` pair of the first `Set-Cookie`, ready to send back.
fn session_cookie(set_cookies: &[String]) -> Option<String> {
    set_cookies
        .iter()
        .find_map(|c| c.split(';').next())
        .map(ToOwned::to_owned)
}

/// Scrape the CSRF token out of rendered HTML.
///
/// The way a browser finds it, and the reason the tests cannot pass by having
/// the server hand one out on a side channel: if the token is not in the form,
/// the form cannot be submitted.
fn csrf_in(html: &str) -> String {
    let needle = "name=\"csrf\" value=\"";
    let start = html
        .find(needle)
        .unwrap_or_else(|| panic!("no CSRF token in the rendered page:\n{html}"))
        + needle.len();
    let end = start + html[start..].find('"').expect("a closing quote");
    html[start..end].to_owned()
}

/// The cookie name in force on a response.
fn cookie_name(set_cookies: &[String]) -> Option<String> {
    session_cookie(set_cookies).map(|c| c.split('=').next().unwrap_or_default().to_owned())
}

/// A real argon2 hash of [`PASSWORD`].
///
/// The same primitive `tenant admin add` uses, because a test that hashed with
/// something else would be testing a different verifier than production reads.
fn admin_hash() -> String {
    use argon2::password_hash::{PasswordHasher, SaltString, rand_core::OsRng};
    argon2::Argon2::default()
        .hash_password(PASSWORD.as_bytes(), &SaltString::generate(OsRng))
        .expect("argon2 hashing cannot fail for valid parameters")
        .to_string()
}

/// Give `name` a real credential row, bypassing the CLI so a test can set up the
/// *unallowlisted* case that §6.6.3 exists to describe.
async fn give_credential(fixture: &Fixture, name: &str) {
    let store = fixture.control_plane_async().await;
    let hash = admin_hash();
    let now = rustical_store::admin_now();
    store
        .set_admin_credential(name, &hash, &now)
        .await
        .expect("a credential row");
}

/// Log in over HTTP and return the session cookie, exactly as a browser would.
async fn log_in(
    app: &mut rustical::host_dispatch::TenancyAwareApp,
    host: &str,
    name: &str,
    password: &str,
) -> Result<String, (StatusCode, String)> {
    let (status, html, cookies) = send(app, get(host, "/frontend/admin/login")).await;
    assert_eq!(status, StatusCode::OK, "the login page should render");
    // The CSRF token and the session live in the *same* cookie at this point; the
    // admin session is a second, differently-named one minted on success.
    let cookie = session_cookie(&cookies).expect("a session cookie for the CSRF token");
    let csrf = csrf_in(&html);
    let (status, body, cookies) = send(
        app,
        post(
            host,
            "/frontend/admin/login",
            &[("name", name), ("password", password), ("csrf", &csrf)],
            Some(&cookie),
        ),
    )
    .await;
    if status == StatusCode::SEE_OTHER {
        // The session cookie is *rotated* into the admin one; the CSRF cookie
        // from the login page is not the admin session.
        for set in &cookies {
            if set.starts_with("omnical_admin_session=") {
                return Ok(
                    session_cookie(std::slice::from_ref(set)).expect("an admin session cookie")
                );
            }
        }
    }
    // The status and the re-rendered page, so a caller asserting a refusal can
    // read *why* the form says it does.
    Err((status, body))
}

// ───────────────────────────────── row 32 ──────────────────────────────────

/// Row 32: a request with no session is a **404**, not a 403, and does not
/// render a login form.
///
/// Both halves matter. A 403 says "this exists and you may not have it"; a 404
/// says nothing, which is the point of putting the panel on its own host. And a
/// login form on an unauthenticated request would turn every probe into a 200
/// with a form in it.
#[tokio::test]
async fn an_unauthenticated_request_is_404_not_a_login_form() {
    let fixture = Fixture::new(Some(("t3.gg", "")));
    fixture.seed_tenants_async(&["acme"]).await;
    let config = config_for(&fixture, ADMIN_HOST, &["ops"]);
    let mut app = app(&config).await;

    for path in [
        "/frontend/admin/tenants",
        "/frontend/admin/tenants/anything",
        "/frontend/admin",
        "/frontend/admin/",
    ] {
        let (status, body, _) = send(&mut app, get(ADMIN_HOST, path)).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{path} should be 404");
        assert!(
            !body.contains("type=\"password\"") && !body.contains("Sign in"),
            "{path} must not serve a login form: {body}"
        );
    }
}

/// Row 32a: the same paths on a **tenant** host are 404, and no login form is
/// served there either.
///
/// §6.6.1's caveat applies: a tenant has a `/{user}` route, so `/frontend/admin`
/// can match a tenant principal *named* `admin`. That leaks nothing — it is the
/// tenant's own page — and the test asserts the *panel* is absent by checking no
/// panel-specific content appears.
#[tokio::test]
async fn the_panel_does_not_exist_on_a_tenant_host() {
    let fixture = Fixture::new(Some(("t3.gg", "")));
    fixture.seed_tenants_async(&["acme"]).await;
    let config = config_for(&fixture, ADMIN_HOST, &["ops"]);
    let mut app = app(&config).await;

    for host in ["acme.t3.gg", "admin.t3.gg.example.com", "unrelated.invalid"] {
        for path in ["/frontend/admin/tenants", "/frontend/admin/login"] {
            let (status, body, _) = send(&mut app, get(host, path)).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{host}{path} should be 404");
            assert!(
                !body.contains("Omnical administration"),
                "{host}{path} must not render the panel: {body}"
            );
        }
    }
}

/// Row 32b: an allowlisted, authenticated admin gets 200 and the listing.
#[tokio::test]
async fn an_allowlisted_admin_sees_the_tenant_list() {
    let fixture = Fixture::new(Some(("t3.gg", "")));
    fixture.seed_tenants_async(&["acme"]).await;
    give_credential(&fixture, "ops").await;
    let config = config_for(&fixture, ADMIN_HOST, &["ops"]);
    let mut app = app(&config).await;
    let cookie = log_in(&mut app, ADMIN_HOST, "ops", PASSWORD)
        .await
        .expect("the login should succeed");

    let request = Request::builder()
        .uri(format!("http://{ADMIN_HOST}/frontend/admin/tenants"))
        .header(header::HOST, ADMIN_HOST)
        .header(header::COOKIE, &cookie)
        .body(Body::empty())
        .expect("a request");
    let (status, body, _) = send(&mut app, request).await;
    assert_eq!(status, StatusCode::OK, "body was: {body}");
    assert!(body.contains("acme"), "the tenant must be listed: {body}");
    // The panel is metadata only: no link into a tenant's own surfaces.
    for forbidden in ["/frontend/user", "/dav", "/caldav", "export"] {
        assert!(
            !body.contains(forbidden),
            "the panel must not link into tenant content ({forbidden}): {body}"
        );
    }
}

/// Row 32c: a real credential whose name is **not** in `platform_admins` cannot
/// log in — the config is authoritative.
///
/// This is the promotion path the split exists to close: the attacker needs
/// write access to `control.sqlite3`, and the row they would write is useless.
#[tokio::test]
async fn a_name_with_a_hash_but_not_allowlisted_cannot_log_in() {
    let fixture = Fixture::new(Some(("t3.gg", "")));
    fixture.seed_tenants_async(&["acme"]).await;
    give_credential(&fixture, "intruder").await;
    // `intruder` has a perfectly valid argon2 hash and is **not** allowlisted.
    let config = config_for(&fixture, ADMIN_HOST, &["ops"]);
    let mut app = app(&config).await;

    let (status, body) = log_in(&mut app, ADMIN_HOST, "intruder", PASSWORD)
        .await
        .expect_err("the login must be refused");
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    // And the refusal does not say *why* — not "unknown name", not "not
    // allowlisted" — because that would be a username oracle.
    assert!(
        !body.to_lowercase().contains("allowlist") && !body.contains("intruder"),
        "the refusal must not reveal why: {body}"
    );
}

/// Row 32d: with `admin_host` unset there is no panel on **any** host.
///
/// Absence has to mean absence: a panel on a default path, or on every host,
/// would give a self-hosted install a cross-tenant control surface by upgrading
/// and nothing would announce it.
#[tokio::test]
async fn an_unset_admin_host_means_no_panel_anywhere() {
    let fixture = Fixture::new(Some(("t3.gg", "")));
    fixture.seed_tenants_async(&["acme"]).await;
    let config = config_for(&fixture, "", &["ops"]);
    let mut app = app(&config).await;

    for host in [
        ADMIN_HOST,
        "admin.t3.gg",
        "acme.t3.gg",
        "t3.gg",
        "anything.invalid",
    ] {
        let (status, body, _) = send(&mut app, get(host, "/frontend/admin/login")).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{host} should be 404");
        assert!(
            !body.contains("Sign in"),
            "{host} served a login form: {body}"
        );
    }
}

/// Row 32d at the **construction** site, not just the request site.
///
/// A no-panel install is guarded twice: `serve_dispatch` does not build a panel
/// when `admin_host` is empty, *and* `TenancyAwareApp::call` refuses to use one
/// whose host is empty. With both guards in place, removing **either one alone**
/// changes nothing observable — and a mutation run proved it: all three
/// mutations of these guards survived, because the surviving guard covered for
/// the mutated one.
///
/// That redundancy is deliberate, and this test is what makes it safe to have.
/// It asserts the panel is not merely unreachable but **absent**, so a future
/// refactor that drops the construction guard has to remove both.
///
/// **What is still not independently testable:** removing only the *request-path*
/// guard (`!tenancy.admin_host.is_empty()` in `call`) changes no observable
/// behaviour, because the construction guard means there is no panel to be
/// reached. A mutation run confirmed it. That guard is defence in depth against
/// a `Tenancy` built by something other than `serve_dispatch` — a future
/// alternate wiring path — and the honest description of its coverage is "not
/// independently testable", not "covered".
#[tokio::test]
async fn an_unset_admin_host_builds_no_panel_at_all() {
    let fixture = Fixture::new(Some(("t3.gg", "")));
    fixture.seed_tenants_async(&["acme"]).await;
    let config = config_for(&fixture, "", &["ops"]);
    let served = app(&config).await;
    assert!(
        !served.has_admin_panel(),
        "no admin_host must mean no panel is even constructed — the request-path guard is a \
         second line, not the only one"
    );

    // And with a host, there is one.
    let config = config_for(&fixture, ADMIN_HOST, &["ops"]);
    let served = app(&config).await;
    assert!(
        served.has_admin_panel(),
        "a configured admin_host must build the panel"
    );
}

/// A path the panel does not route at all is the panel's own **404**, not a
/// fall-through to anything.
///
/// §6.6.6: there is no request the panel forwards downward, so there is no path
/// from an admin session to tenant content. This is the test that would notice if
/// a catch-all were ever added.
#[tokio::test]
async fn an_unrouted_panel_path_is_404() {
    let fixture = Fixture::new(Some(("t3.gg", "")));
    fixture.seed_tenants_async(&["acme"]).await;
    give_credential(&fixture, "ops").await;
    let config = config_for(&fixture, ADMIN_HOST, &["ops"]);
    let mut app = app(&config).await;
    let cookie = log_in(&mut app, ADMIN_HOST, "ops", PASSWORD)
        .await
        .expect("the login should succeed");

    for path in [
        "/",
        "/frontend",
        "/frontend/admin",
        "/frontend/admin/",
        "/frontend/admin/tenants/acme/delete",
        "/frontend/admin/tenants/acme/anything-at-all",
        "/dav",
        "/caldav",
        "/frontend/user",
    ] {
        let request = Request::builder()
            .uri(format!("http://{ADMIN_HOST}{path}"))
            .header(header::HOST, ADMIN_HOST)
            .header(header::COOKIE, &cookie)
            .body(Body::empty())
            .expect("a request");
        let (status, body, _) = send(&mut app, request).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{path} should be 404");
        assert!(
            !body.contains("acme"),
            "{path} must not render tenant content: {body}"
        );
    }
}

/// §6.6.5: the per-name rate limit actually engages.
///
/// Without this the limiter is untested code on the only login path there is.
/// The response before the limit is a 401 (a refusal, lockout or generic) and
/// after it a 429, so the assertion is "a 429 appears" rather than an exact
/// count — the exact count is a consequence of the per-name and per-source
/// budgets interacting, and pinning it would make a tuning change look like a
/// regression.
#[tokio::test]
async fn repeated_login_attempts_are_rate_limited() {
    let fixture = Fixture::new(Some(("t3.gg", "")));
    fixture.seed_tenants_async(&["acme"]).await;
    give_credential(&fixture, "ops").await;
    let config = config_for(&fixture, ADMIN_HOST, &["ops"]);
    let mut app = app(&config).await;

    let mut saw_429 = false;
    for _ in 0..15 {
        match log_in(&mut app, ADMIN_HOST, "ops", "wrong").await {
            Err((StatusCode::TOO_MANY_REQUESTS, _)) => {
                saw_429 = true;
                break;
            }
            Err((StatusCode::UNAUTHORIZED, _)) => {}
            Err((other, body)) => panic!("unexpected {other}: {body}"),
            Ok(_) => panic!("a wrong password must never succeed"),
        }
    }
    assert!(
        saw_429,
        "15 wrong passwords in a row were never rate limited; the limiter is not engaged"
    );
}

/// §6.6.5: a CSRF token observed once cannot be replayed.
///
/// The token is rotated on a **failed** comparison, so a token that has been
/// seen — over a shared referer, in a proxy log, in a screenshot — is worth
/// nothing afterwards. Found by mutation: dropping the rotation broke no test,
/// because every other test used a fresh form.
#[tokio::test]
async fn a_csrf_token_is_single_use_once_it_has_failed() {
    let fixture = Fixture::new(Some(("t3.gg", "")));
    fixture.seed_tenants_async(&["acme"]).await;
    give_credential(&fixture, "ops").await;
    let config = config_for(&fixture, ADMIN_HOST, &["ops"]);
    let mut app = app(&config).await;
    let cookie = log_in(&mut app, ADMIN_HOST, "ops", PASSWORD)
        .await
        .expect("the login should succeed");
    let csrf = csrf_from_listing(&mut app, &cookie).await;

    // A wrong token first: this is the attempt that burns the token.
    let (status, body, _) = send(
        &mut app,
        post(
            ADMIN_HOST,
            "/frontend/admin/tenants",
            &[("slug", "sneaky"), ("csrf", "not-the-token")],
            Some(&cookie),
        ),
    )
    .await;
    assert!(
        status == StatusCode::FORBIDDEN || status == StatusCode::BAD_REQUEST,
        "{status}: {body}"
    );

    // Now the *real* token, replayed. It must no longer work.
    let (status, body, _) = send(
        &mut app,
        post(
            ADMIN_HOST,
            "/frontend/admin/tenants",
            &[("slug", "sneaky"), ("csrf", csrf.as_str())],
            Some(&cookie),
        ),
    )
    .await;
    assert!(
        status == StatusCode::FORBIDDEN || status == StatusCode::BAD_REQUEST,
        "the burned token was accepted ({status}): {body}"
    );

    let store = fixture.control_plane_async().await;
    assert!(
        store
            .get_any_tenant_by_slug("sneaky")
            .await
            .expect("a read")
            .is_none(),
        "a replayed token must not create a tenant"
    );
}

/// The panel is on **one** host, matched normalised — so `ADMIN.T3.GG:8443`
/// reaches it, and a lookalike does not.
#[tokio::test]
async fn the_panel_is_selected_by_normalised_host() {
    let fixture = Fixture::new(Some(("t3.gg", "")));
    fixture.seed_tenants_async(&["acme"]).await;
    let config = config_for(&fixture, ADMIN_HOST, &["ops"]);
    let mut app = app(&config).await;

    for host in [
        ADMIN_HOST,
        "ADMIN.T3.GG",
        "Admin.T3.GG:8443",
        "admin.t3.gg.",
    ] {
        let (status, body, _) = send(&mut app, get(host, "/frontend/admin/login")).await;
        assert_eq!(status, StatusCode::OK, "{host} should reach the panel");
        assert!(body.contains("Sign in"), "{host}: {body}");
    }
    for host in ["admin.t3.gg.evil.example", "xadmin.t3.gg", "t3.gg"] {
        let (status, _, _) = send(&mut app, get(host, "/frontend/admin/login")).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{host} must not reach it");
    }
}

/// `/healthz` answers on the **admin host too**, because a health check that
/// 404s on one hostname marks a healthy node down.
#[tokio::test]
async fn healthz_answers_on_every_host_including_the_admin_one() {
    let fixture = Fixture::new(Some(("t3.gg", "")));
    fixture.seed_tenants_async(&["acme"]).await;
    let config = config_for(&fixture, ADMIN_HOST, &["ops"]);
    let mut app = app(&config).await;

    for host in [ADMIN_HOST, "acme.t3.gg", "unknown.invalid"] {
        let (status, _, _) = send(&mut app, get(host, "/healthz")).await;
        assert!(status.is_success(), "/healthz on {host} returned {status}");
    }
}

// ───────────────────────────── the login surface ───────────────────────────

/// A wrong password is refused with the *same* message as an unknown name, and
/// the failure is recorded so the lockout can engage.
#[tokio::test]
async fn a_wrong_password_is_refused_and_recorded() {
    let fixture = Fixture::new(Some(("t3.gg", "")));
    fixture.seed_tenants_async(&["acme"]).await;
    give_credential(&fixture, "ops").await;
    let config = config_for(&fixture, ADMIN_HOST, &["ops"]);
    let mut app = app(&config).await;

    let (status, body) = log_in(&mut app, ADMIN_HOST, "ops", "not-the-password")
        .await
        .expect_err("must be refused");
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");

    let store = fixture.control_plane_async().await;
    let row = store
        .get_admin_credential("ops")
        .await
        .expect("a read")
        .expect("a row");
    assert_eq!(
        row.failed_attempts, 1,
        "the attempt must be recorded, or the lockout can never engage"
    );
}

/// A lockout is a lockout: the **correct password** is refused while a name is
/// locked out.
///
/// Found by a mutation. Moving the lockout check below the argon2 verification
/// passed every other test in this file, because every other test either used
/// the right password on an unlocked name or the wrong password on an unlocked
/// one. The case neither covers is the one the control exists for: a lockout
/// that the correct password walks through is not a lockout, it is a suggestion.
#[tokio::test]
async fn a_locked_out_admin_is_refused_even_with_the_right_password() {
    let fixture = Fixture::new(Some(("t3.gg", "")));
    fixture.seed_tenants_async(&["acme"]).await;
    give_credential(&fixture, "ops").await;
    let config = config_for(&fixture, ADMIN_HOST, &["ops"]);
    let mut app = app(&config).await;

    // Lock the name out through the panel itself, by failing N times.
    let failures = rustical_store::admin_store::ADMIN_MAX_FAILED_ATTEMPTS;
    for _ in 0..failures {
        // The early refusals carry the generic message and the last may carry
        // the locked one. Both are refusals, which is all this loop asserts.
        let (status, body) = log_in(&mut app, ADMIN_HOST, "ops", "wrong")
            .await
            .expect_err("a wrong password must be refused");
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    }

    // Now the *right* password, against a locked name.
    let (status, body) = log_in(&mut app, ADMIN_HOST, "ops", PASSWORD)
        .await
        .expect_err("a locked name must not authenticate on the right password");
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert!(
        body.to_lowercase().contains("locked"),
        "the locked state may be reported — the name is already known to exist: {body}"
    );
}

/// The lockout is checked **before** the password is verified, and that ordering
/// is observable rather than a performance detail.
///
/// A locked name given a **wrong** password returns `Locked` and leaves
/// `failed_attempts` alone. Verified first, it would return `Refused` and
/// increment — which tells a client "your password is wrong" for a name that is
/// locked, and lets a flood of guesses against a locked name keep extending the
/// counter that would have released it.
///
/// The other half of the ordering — that argon2 does not run at all for a locked
/// name — is a *performance* property with no observable outcome, so it is not
/// tested by a timing assertion. The bound on that is the rate limiter (10/h per
/// name, 30/h per source), which the panel applies before reaching the store.
#[tokio::test]
async fn a_locked_name_reports_locked_and_does_not_count_the_attempt() {
    let fixture = Fixture::new(Some(("t3.gg", "")));
    fixture.seed_tenants_async(&["acme"]).await;
    give_credential(&fixture, "ops").await;
    let config = config_for(&fixture, ADMIN_HOST, &["ops"]);
    let mut app = app(&config).await;

    for _ in 0..rustical_store::admin_store::ADMIN_MAX_FAILED_ATTEMPTS {
        let _ = log_in(&mut app, ADMIN_HOST, "ops", "wrong")
            .await
            .expect_err("a wrong password must be refused");
    }

    let store = fixture.control_plane_async().await;
    let locked_at = store
        .get_admin_credential("ops")
        .await
        .expect("a read")
        .expect("a row");
    let attempts_when_locked = locked_at.failed_attempts;

    // A locked name, a *wrong* password, straight at the store.
    let now = rustical_store::admin_now();
    let until = rustical_store::admin_lockout_until(&now);
    let outcome = store
        .authenticate_admin("ops", "wrong", &now, &until)
        .await
        .expect("an authentication");
    assert_eq!(
        outcome,
        rustical_store::admin_store::AdminAuthOutcome::Locked,
        "a locked name must report Locked, not Refused — otherwise a client is told its \
         password is wrong when the real answer is that the name is locked"
    );

    let after = store
        .get_admin_credential("ops")
        .await
        .expect("a read")
        .expect("a row");
    assert_eq!(
        after.failed_attempts, attempts_when_locked,
        "a guess against a locked name must not increment the counter that releases it"
    );
}

/// And the lockout is in the **store**, so it survives a process restart, which
/// an in-memory counter would not.
#[tokio::test]
async fn the_lockout_is_in_the_control_plane_not_in_memory() {
    let fixture = Fixture::new(Some(("t3.gg", "")));
    fixture.seed_tenants_async(&["acme"]).await;
    give_credential(&fixture, "ops").await;

    let store = fixture.control_plane_async().await;
    let now = rustical_store::admin_now();
    let until = rustical_store::admin_lockout_until(&now);
    for _ in 0..rustical_store::admin_store::ADMIN_MAX_FAILED_ATTEMPTS {
        store
            .record_login_failure("ops", &now, &until)
            .await
            .expect("a failure");
    }

    // A **fresh store handle** — as a restarted process would have. If the
    // lockout lived in the panel's memory this would be `Ok`.
    let reopened = fixture.control_plane_async().await;
    let outcome = reopened
        .authenticate_admin("ops", PASSWORD, &now, &until)
        .await
        .expect("an authentication");
    assert_eq!(
        outcome,
        rustical_store::admin_store::AdminAuthOutcome::Locked,
        "the right password must not authenticate a locked name"
    );
}

/// An unknown name and a wrong password are indistinguishable in the response.
#[tokio::test]
async fn unknown_name_and_wrong_password_look_identical() {
    let fixture = Fixture::new(Some(("t3.gg", "")));
    fixture.seed_tenants_async(&["acme"]).await;
    give_credential(&fixture, "ops").await;
    let config = config_for(&fixture, ADMIN_HOST, &["ops", "nosuch"]);
    let mut app = app(&config).await;

    let (status_a, body_a) = log_in(&mut app, ADMIN_HOST, "ops", "wrong")
        .await
        .expect_err("refused");
    let (status_b, body_b) = log_in(&mut app, ADMIN_HOST, "nosuch", "wrong")
        .await
        .expect_err("refused");
    assert_eq!(status_a, status_b);
    // The rendered message is the same; the CSRF token differs per attempt and
    // is not part of the comparison.
    let strip = |html: &str| {
        let needle = "name=\"csrf\" value=\"";
        match html.find(needle) {
            Some(i) => {
                let s = i + needle.len();
                let e = s + html[s..].find('"').expect("a closing quote");
                format!("{}{}", &html[..s], &html[e..])
            }
            None => html.to_owned(),
        }
    };
    assert_eq!(strip(&body_a), strip(&body_b), "the two refusals differ");
}

/// A mutating POST with **no session** is a 404, like every other unauthenticated
/// request — and changes nothing.
///
/// This is a separate claim from row 32's GET, and it was found by a mutation:
/// changing `require_admin`'s 404 to a 401 broke no test, because the CSRF test
/// posts *with* a valid session and so never reaches the "no session" branch. A
/// 401 there would tell a prober that the endpoint exists and is worth a token.
#[tokio::test]
async fn an_unauthenticated_post_is_404_and_does_nothing() {
    let fixture = Fixture::new(Some(("t3.gg", "")));
    fixture.seed_tenants_async(&["acme"]).await;
    give_credential(&fixture, "ops").await;
    let config = config_for(&fixture, ADMIN_HOST, &["ops"]);
    let mut app = app(&config).await;
    let id = fixture.tenant_id_async("acme").await;

    // No cookie at all, and a syntactically valid form including a CSRF field —
    // the token is irrelevant without a session to compare it against.
    let routes = [
        format!("/frontend/admin/tenants/{}/suspend", id.as_str()),
        format!("/frontend/admin/tenants/{}/resume", id.as_str()),
        "/frontend/admin/tenants".to_owned(),
    ];
    for path in routes {
        let (status, body, _) = send(
            &mut app,
            post(
                ADMIN_HOST,
                &path,
                &[
                    ("slug", "sneaky"),
                    ("host", "sneaky.t3.gg"),
                    ("csrf", "irrelevant-without-a-session"),
                ],
                None,
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "{path} should be 404 without a session: {body}"
        );
    }

    // Nothing happened: still active, and no new tenant.
    let store = fixture.control_plane_async().await;
    let tenant = store
        .get_any_tenant_by_slug("acme")
        .await
        .expect("a read")
        .expect("a tenant");
    assert_eq!(tenant.status, rustical_store::TenantStatus::Active);
    assert!(
        store
            .get_any_tenant_by_slug("sneaky")
            .await
            .expect("a read")
            .is_none(),
        "an unauthenticated POST must not create a tenant"
    );
}

/// §6.6.5: a session-bound CSRF token on **every** POST.
///
/// A missing token and a wrong token are both refused, and neither is counted
/// against the rate limiter — a CSRF failure is not a credential guess.
#[tokio::test]
async fn a_post_without_a_valid_csrf_token_is_refused() {
    let fixture = Fixture::new(Some(("t3.gg", "")));
    fixture.seed_tenants_async(&["acme"]).await;
    give_credential(&fixture, "ops").await;
    let config = config_for(&fixture, ADMIN_HOST, &["ops"]);
    let mut app = app(&config).await;
    let cookie = log_in(&mut app, ADMIN_HOST, "ops", PASSWORD)
        .await
        .expect("the login should succeed");

    // The slug the create form would have used, so a *successful* CSRF check
    // would produce a visible change.
    let cases: [(&str, Option<&str>); 3] =
        [("", None), ("", Some("not-the-token")), ("", Some(""))];
    for (label, token) in cases {
        let mut form: Vec<(&str, &str)> = vec![("slug", "sneaky"), ("actor", "ops")];
        if let Some(token) = token {
            form.push(("csrf", token));
        }
        let (status, body, _) = send(
            &mut app,
            post(ADMIN_HOST, "/frontend/admin/tenants", &form, Some(&cookie)),
        )
        .await;
        assert!(
            status == StatusCode::FORBIDDEN || status == StatusCode::BAD_REQUEST,
            "a POST with {label:?} token returned {status}: {body}"
        );
    }

    // …and no tenant was created by any of them.
    let store = fixture.control_plane_async().await;
    let created = store.get_any_tenant_by_slug("sneaky").await;
    assert!(
        created.expect("a store read").is_none(),
        "a refused POST must not create a tenant"
    );
}

/// §6.6.4: the panel's session cookie is **not** the portal's.
///
/// One name carrying two different session ids, on a deployment serving
/// `admin.example.com` and `portal.example.com` off one registrable domain, is
/// a session confusion waiting to happen.
#[tokio::test]
async fn the_admin_session_cookie_is_not_the_portal_one() {
    let fixture = Fixture::new(Some(("t3.gg", "")));
    fixture.seed_tenants_async(&["acme"]).await;
    give_credential(&fixture, "ops").await;
    let config = config_for(&fixture, ADMIN_HOST, &["ops"]);
    let mut app = app(&config).await;

    let (_, _, cookies) = send(&mut app, get(ADMIN_HOST, "/frontend/admin/login")).await;
    let name = cookie_name(&cookies).expect("a cookie");
    assert_eq!(
        name,
        rustical_frontend::ADMIN_SESSION_COOKIE,
        "the panel must not use the portal's cookie name"
    );
    assert_ne!(
        name, "rustical_session",
        "§6.6.4 requires a distinct cookie name"
    );
}

/// Logging out ends the session: the cookie stops working immediately.
#[tokio::test]
async fn logging_out_ends_the_session() {
    let fixture = Fixture::new(Some(("t3.gg", "")));
    fixture.seed_tenants_async(&["acme"]).await;
    give_credential(&fixture, "ops").await;
    let config = config_for(&fixture, ADMIN_HOST, &["ops"]);
    let mut app = app(&config).await;
    let cookie = log_in(&mut app, ADMIN_HOST, "ops", PASSWORD)
        .await
        .expect("the login should succeed");

    // Fetched first: computing it inside the `post(...)` argument list would
    // borrow `app` mutably a second time while the `send` borrow is live.
    let csrf = csrf_from_listing(&mut app, &cookie).await;
    let (status, body, _) = send(
        &mut app,
        post(
            ADMIN_HOST,
            "/frontend/admin/logout",
            &[("csrf", csrf.as_str())],
            Some(&cookie),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER, "{body}");

    let request = Request::builder()
        .uri(format!("http://{ADMIN_HOST}/frontend/admin/tenants"))
        .header(header::HOST, ADMIN_HOST)
        .header(header::COOKIE, &cookie)
        .body(Body::empty())
        .expect("a request");
    let (status, _, _) = send(&mut app, request).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "the old cookie must stop working after logout"
    );
}

/// The listing's CSRF token, fetched with a session cookie.
async fn csrf_from_listing(
    app: &mut rustical::host_dispatch::TenancyAwareApp,
    cookie: &str,
) -> String {
    let request = Request::builder()
        .uri(format!("http://{ADMIN_HOST}/frontend/admin/tenants"))
        .header(header::HOST, ADMIN_HOST)
        .header(header::COOKIE, cookie)
        .body(Body::empty())
        .expect("a request");
    let (status, body, _) = send(app, request).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    csrf_in(&body)
}

// ─────────────────────────── what the panel may not do ──────────────────────

/// Row 33's panel half: a mutation made through the panel is audited with the
/// **admin's name**, in the same transaction, exactly like the CLI's.
#[tokio::test]
async fn a_panel_mutation_is_audited_with_the_admin_name() {
    let fixture = Fixture::new(Some(("t3.gg", "")));
    fixture.seed_tenants_async(&["acme"]).await;
    give_credential(&fixture, "ops").await;
    let config = config_for(&fixture, ADMIN_HOST, &["ops"]);
    let mut app = app(&config).await;
    let cookie = log_in(&mut app, ADMIN_HOST, "ops", PASSWORD)
        .await
        .expect("the login should succeed");
    let csrf = csrf_from_listing(&mut app, &cookie).await;

    let id = fixture.tenant_id_async("acme").await;
    let (status, body, _) = send(
        &mut app,
        post(
            ADMIN_HOST,
            &format!("/frontend/admin/tenants/{}/suspend", id.as_str()),
            &[("csrf", &csrf)],
            Some(&cookie),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER, "{body}");

    // The tenant is suspended…
    //
    // Read through `get_any_tenant_by_slug`, **not** `get_tenant_by_id`: the
    // latter filters on `status = 'active'` (it is the *resolution* read), so
    // asking it about a tenant that has just been suspended returns `None` —
    // which reads exactly like "the panel did nothing", and is the wrong thing
    // to assert here. That trap is the same one `get_any_tenant_by_host` was
    // added for in phase 2.
    let store = fixture.control_plane_async().await;
    let tenant = store
        .get_any_tenant_by_slug("acme")
        .await
        .expect("a read")
        .expect("a tenant");
    assert_eq!(tenant.status, rustical_store::TenantStatus::Suspended);

    // …and the audit row names the admin, not a CLI actor.
    let rows = store.list_audit(None, 10).await.expect("a read");
    let row = rows
        .iter()
        .find(|r| r.action == "update_tenant_status")
        .expect("an audit row for the suspension");
    assert_eq!(row.actor, "ops", "the actor must be the admin's name");
    assert_eq!(
        row.tenant.as_ref().map(rustical_store::TenantId::as_str),
        Some(id.as_str()),
        "the audit row must name the tenant"
    );
}

/// §6.6.1: **delete is not in the panel**.
///
/// A browser form is the only irreversible, easily-misclicked path to a
/// customer's data. `DELETE` is not routed, and neither is a GET.
#[tokio::test]
async fn delete_is_not_reachable_in_the_panel() {
    let fixture = Fixture::new(Some(("t3.gg", "")));
    fixture.seed_tenants_async(&["acme"]).await;
    give_credential(&fixture, "ops").await;
    let config = config_for(&fixture, ADMIN_HOST, &["ops"]);
    let mut app = app(&config).await;
    let cookie = log_in(&mut app, ADMIN_HOST, "ops", PASSWORD)
        .await
        .expect("the login should succeed");
    let id = fixture.tenant_id_async("acme").await;

    for method in ["DELETE", "POST", "PUT"] {
        let request = Request::builder()
            .method(method)
            .uri(format!(
                "http://{ADMIN_HOST}/frontend/admin/tenants/{}",
                id.as_str()
            ))
            .header(header::HOST, ADMIN_HOST)
            .header(header::COOKIE, &cookie)
            .body(Body::empty())
            .expect("a request");
        let (status, body, _) = send(&mut app, request).await;
        assert!(
            status == StatusCode::NOT_FOUND || status == StatusCode::METHOD_NOT_ALLOWED,
            "{method} on a tenant returned {status}, which might mean it is routed: {body}"
        );
    }

    // The tenant is still there.
    let store = fixture.control_plane_async().await;
    assert!(
        store.get_tenant_by_id(&id).await.expect("a read").is_some(),
        "the tenant must survive every delete attempt"
    );
}

/// §6.6.6: the panel never opens a tenant's database.
///
/// Proved behaviourally: a tenant whose **store directory does not exist** still
/// lists, still shows a detail page, and can still be suspended. The panel
/// never materialises a store, so it never notices.
#[tokio::test]
async fn the_panel_never_opens_a_tenant_database() {
    let fixture = Fixture::new(Some(("t3.gg", "")));
    fixture.seed_tenants_async(&["acme"]).await;
    give_credential(&fixture, "ops").await;
    let config = config_for(&fixture, ADMIN_HOST, &["ops"]);
    let mut app = app(&config).await;
    let cookie = log_in(&mut app, ADMIN_HOST, "ops", PASSWORD)
        .await
        .expect("the login should succeed");

    // `seed_tenants` writes only the control-plane row. The tenant's store
    // directory is absent, and stays absent.
    let store_dir = fixture.path("data").join("tenants");
    let before = std::fs::read_dir(&store_dir)
        .map(|d| d.count())
        .unwrap_or(0);

    let request = Request::builder()
        .uri(format!("http://{ADMIN_HOST}/frontend/admin/tenants"))
        .header(header::HOST, ADMIN_HOST)
        .header(header::COOKIE, &cookie)
        .body(Body::empty())
        .expect("a request");
    let (status, body, _) = send(&mut app, request).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body.contains("acme"), "{body}");

    // The detail page, which reads the quota — also control-plane data.
    let id = fixture.tenant_id_async("acme").await;
    let request = Request::builder()
        .uri(format!(
            "http://{ADMIN_HOST}/frontend/admin/tenants/{}",
            id.as_str()
        ))
        .header(header::HOST, ADMIN_HOST)
        .header(header::COOKIE, &cookie)
        .body(Body::empty())
        .expect("a request");
    let (status, body, _) = send(&mut app, request).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body.contains("Quota limits"), "{body}");

    let after = std::fs::read_dir(&store_dir)
        .map(|d| d.count())
        .unwrap_or(0);
    assert_eq!(
        before, after,
        "the panel must not materialise a tenant store"
    );
}

/// §6.6.2: the panel's own create form cannot introduce the collision the CLI
/// also refuses. Otherwise the reservation would hold only for the tool an
/// operator is told to use.
#[tokio::test]
async fn the_panel_cannot_create_a_tenant_on_the_admin_host() {
    let fixture = Fixture::new(Some(("t3.gg", "")));
    fixture.seed_tenants_async(&["acme"]).await;
    give_credential(&fixture, "ops").await;
    let config = config_for(&fixture, ADMIN_HOST, &["ops"]);
    let mut app = app(&config).await;
    let cookie = log_in(&mut app, ADMIN_HOST, "ops", PASSWORD)
        .await
        .expect("the login should succeed");
    let csrf = csrf_from_listing(&mut app, &cookie).await;

    let (status, body, _) = send(
        &mut app,
        post(
            ADMIN_HOST,
            "/frontend/admin/tenants",
            &[
                ("slug", "newco"),
                ("host", ADMIN_HOST),
                ("csrf", csrf.as_str()),
            ],
            Some(&cookie),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(body.to_lowercase().contains("reserved"), "{body}");

    let store = fixture.control_plane_async().await;
    let created = store.get_any_tenant_by_slug("newco").await;
    assert!(created.expect("a read").is_none(), "the tenant was created");
}

/// A legitimate create through the panel works, and is audited.
#[tokio::test]
async fn the_panel_can_create_a_tenant() {
    let fixture = Fixture::new(Some(("t3.gg", "")));
    fixture.seed_tenants_async(&["acme"]).await;
    give_credential(&fixture, "ops").await;
    let config = config_for(&fixture, ADMIN_HOST, &["ops"]);
    let mut app = app(&config).await;
    let cookie = log_in(&mut app, ADMIN_HOST, "ops", PASSWORD)
        .await
        .expect("the login should succeed");
    let csrf = csrf_from_listing(&mut app, &cookie).await;

    let (status, body, _) = send(
        &mut app,
        post(
            ADMIN_HOST,
            "/frontend/admin/tenants",
            &[
                ("slug", "newco"),
                ("display_name", "New Company"),
                ("host", "newco.t3.gg"),
                ("csrf", csrf.as_str()),
            ],
            Some(&cookie),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER, "{body}");

    let store = fixture.control_plane_async().await;
    assert!(
        store
            .get_any_tenant_by_slug("newco")
            .await
            .expect("a read")
            .is_some(),
        "the tenant should exist"
    );
    let rows = store.list_audit(None, 10).await.expect("a read");
    assert!(
        rows.iter()
            .any(|r| r.action == "create_tenant" && r.actor == "ops"),
        "the create should be audited as ops: {rows:?}"
    );
}

/// The frontend carries its own copy of the host normaliser, because it cannot
/// import from the binary crate that defines the authority. Duplication is only
/// acceptable while it is **checked**, which is this test.
#[test]
fn the_copied_host_normaliser_agrees_with_the_dispatcher() {
    // A representative table, including the cases that are easy to get wrong:
    // a port, mixed case, a trailing dot, surrounding whitespace, a
    // bracketed IPv6 literal, and a lookalike that must not normalise equal.
    let cases = [
        "admin.t3.gg",
        "ADMIN.T3.GG",
        "Admin.T3.GG:8443",
        "admin.t3.gg.",
        "  admin.t3.gg  ",
        "admin.t3.gg:443",
        "[::1]",
        "[::1]:8443",
        "192.168.1.5:8443",
        "ADMIN.T3.GG.EVIL.EXAMPLE",
        "xadmin.t3.gg",
        "",
    ];
    for raw in cases {
        assert_eq!(
            normalise_host_in_frontend(raw),
            rustical::host_dispatch::normalise_host(raw),
            "the two normalisers disagree on {raw:?}"
        );
    }
}

/// The panel's copy, reached through the crate's public surface.
fn normalise_host_in_frontend(raw: &str) -> String {
    rustical_frontend::admin_normalise_host(raw)
}
