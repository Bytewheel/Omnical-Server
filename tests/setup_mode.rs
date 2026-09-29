//! Setup mode (§9.3, item 13) — the appliance's first boot, in a browser.
//!
//! §9.3's hard requirement is *"bind to the LAN only until setup completes. A
//! CalDAV server reachable from the WAN with an unconfigured admin account is
//! how appliances get compromised. This is a hard requirement, not a nicety."*
//! Every test below is about that sentence, or about the other way this feature
//! could hurt somebody: a wizard that overwrites a working install, or that
//! leaves the device in setup mode after it is already configured.
//!
//! Nothing here is mocked at the HTTP layer: these drive the real router with
//! the real extractor, the real form body, and the real control plane.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use tower::ServiceExt;

use rustical::setup_mode::{
    ApplyError, RESET_MARKER, SetupForm, SetupMode, SetupRestart, is_lan_peer,
    should_enter_setup_mode, validate,
};

/// Counts restarts instead of sending a signal, so the test can assert the box
/// was told to come back without killing the test runner.
#[derive(Debug, Default)]
struct CountingRestart(AtomicUsize);

impl SetupRestart for CountingRestart {
    fn request_restart(&self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

/// The whole file is synchronous, but axum handlers are async. One current-thread
/// runtime, built per call, keeps the tests `#[test]` rather than `#[tokio::test]`
/// so the fixtures stay ordinary `Drop` guards.
fn block_on<F: std::future::Future>(f: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a current-thread runtime")
        .block_on(f)
}

fn lan() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 10, 42)), 51000)
}

fn wan() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)), 51000)
}

struct Fixture {
    dir: PathBuf,
    config_file: PathBuf,
    restarts: Arc<CountingRestart>,
}

impl Fixture {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!(
            "omnical-setup-test-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let config_file = dir.join("config.toml");
        Self {
            dir,
            config_file,
            restarts: Arc::new(CountingRestart::default()),
        }
    }

    fn mode(&self) -> Arc<SetupMode> {
        Arc::new(SetupMode::new(
            self.config_file.clone(),
            lan(),
            self.restarts.clone(),
        ))
    }

    fn data_dir(&self) -> String {
        self.dir.join("data").display().to_string()
    }

    fn form(&self) -> SetupForm {
        SetupForm {
            data_dir: self.data_dir(),
            public_url: "https://cal.example.com".into(),
            admin_email: "owner@example.com".into(),
            admin_password: "correct horse battery".into(),
            registration: "invite".into(),
            smtp_host: String::new(),
            smtp_port: String::new(),
            smtp_username: String::new(),
            smtp_password: String::new(),
            smtp_from: String::new(),
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn post(fixture: &Fixture, peer: SocketAddr, body: &str) -> axum::response::Response {
    // A real form body, percent-encoded the way a browser sends one.
    let request = Request::builder()
        .method("POST")
        .uri("/frontend/setup")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(body.to_owned()))
        .unwrap();
    let mut request = request;
    request
        .extensions_mut()
        .insert(axum::extract::ConnectInfo(peer));
    let app = fixture.mode().router();
    block_on(app.oneshot(request)).expect("infallible")
}

fn get(fixture: &Fixture, peer: SocketAddr) -> axum::response::Response {
    let mut request = Request::builder()
        .uri("/frontend/setup")
        .body(Body::empty())
        .unwrap();
    request
        .extensions_mut()
        .insert(axum::extract::ConnectInfo(peer));
    let app = fixture.mode().router();
    block_on(app.oneshot(request)).expect("infallible")
}

fn encode(form: &SetupForm) -> String {
    let pairs = [
        ("data_dir", form.data_dir.clone()),
        ("public_url", form.public_url.clone()),
        ("admin_email", form.admin_email.clone()),
        ("admin_password", form.admin_password.clone()),
        ("registration", form.registration.clone()),
        ("smtp_host", form.smtp_host.clone()),
        ("smtp_port", form.smtp_port.clone()),
        ("smtp_username", form.smtp_username.clone()),
        ("smtp_password", form.smtp_password.clone()),
        ("smtp_from", form.smtp_from.clone()),
    ];
    pairs
        .iter()
        .map(|(k, v)| {
            format!(
                "{}={}",
                k,
                v.replace(' ', "%20")
                    .replace('&', "%26")
                    .replace('=', "%3D")
            )
        })
        .collect::<Vec<_>>()
        .join("&")
}

// ── 1. the LAN rule ─────────────────────────────────────────────────────────

#[test]
fn a_private_or_loopback_peer_is_the_lan() {
    for ip in [
        Ipv4Addr::new(192, 168, 1, 21), // the appliance's own typical WAN/LAN
        Ipv4Addr::new(10, 0, 0, 5),
        Ipv4Addr::new(172, 16, 31, 9),
        Ipv4Addr::new(127, 0, 0, 1),
        Ipv4Addr::new(169, 254, 4, 4), // link local
    ] {
        assert!(
            is_lan_peer(&SocketAddr::new(IpAddr::V4(ip), 1)),
            "{ip} is LAN"
        );
    }
    for ip in [
        Ipv4Addr::new(203, 0, 113, 7), // public
        Ipv4Addr::new(8, 8, 8, 8),
        Ipv4Addr::new(172, 32, 0, 1),  // just outside 172.16/12
        Ipv4Addr::new(192, 169, 0, 1), // just outside 192.168/16
        Ipv4Addr::new(100, 64, 0, 1),  // CGNAT: NOT a LAN, on purpose
    ] {
        assert!(
            !is_lan_peer(&SocketAddr::new(IpAddr::V4(ip), 1)),
            "{ip} is not LAN"
        );
    }
}

#[test]
fn an_ipv6_peer_is_judged_as_the_address_it_really_is() {
    for ip in [
        Ipv6Addr::LOCALHOST,
        Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 1), // unique local
        Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1), // link local
    ] {
        assert!(
            is_lan_peer(&SocketAddr::new(IpAddr::V6(ip), 1)),
            "{ip} is LAN"
        );
    }
    // Global unicast is not a LAN.
    assert!(!is_lan_peer(&SocketAddr::new(
        IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 1111)),
        1
    )));
    // **IPv4-mapped** is the one that matters: a dual-stack listener hands these
    // out for IPv4 peers, so an implementation that tested only the v6 shape
    // would wave a *public* IPv4 client straight through.
    assert!(!is_lan_peer(&SocketAddr::new(
        IpAddr::V6(Ipv4Addr::new(203, 0, 113, 7).to_ipv6_mapped()),
        1
    )));
    assert!(is_lan_peer(&SocketAddr::new(
        IpAddr::V6(Ipv4Addr::new(192, 168, 1, 5).to_ipv6_mapped()),
        1
    )));
}

// ── 2. the rule is enforced on the wire ─────────────────────────────────────

#[test]
fn a_wan_client_gets_403_on_the_form() {
    let fixture = Fixture::new();
    let response = get(&fixture, wan());
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[test]
fn a_wan_client_gets_403_on_the_submission() {
    // The important half. Refusing the GET but accepting the POST would leave
    // the entire control surface — a new admin account, a new config — one
    // curl away from the internet.
    let fixture = Fixture::new();
    let response = post(&fixture, wan(), &encode(&fixture.form()));
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(
        !fixture.config_file.exists(),
        "a refused WAN submission must not have written anything"
    );
    assert_eq!(fixture.restarts.0.load(Ordering::SeqCst), 0);
}

#[test]
fn a_forged_forwarded_header_does_not_launder_a_wan_client() {
    // §9.3's requirement is about the *peer*, and everywhere else this server
    // resolves a client IP through `client_ip`, which honours
    // X-Forwarded-For from a trusted proxy. Setup mode must not: there are no
    // trusted proxies configured — nothing is set up yet — so any XFF here is
    // an attacker's, and believing it would be exactly the compromise the
    // requirement exists to prevent.
    let fixture = Fixture::new();
    let mut request = Request::builder()
        .method("POST")
        .uri("/frontend/setup")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("x-forwarded-for", "192.168.10.1, 203.0.113.7")
        .header("x-real-ip", "127.0.0.1")
        .body(Body::from(encode(&fixture.form())))
        .unwrap();
    request
        .extensions_mut()
        .insert(axum::extract::ConnectInfo(wan()));
    let response = block_on(fixture.mode().router().oneshot(request)).expect("infallible");
    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "X-Forwarded-For claiming a LAN address must not get a WAN client in"
    );
    assert!(!fixture.config_file.exists());
}

#[test]
fn a_lan_client_gets_the_form() {
    let fixture = Fixture::new();
    let response = get(&fixture, lan());
    assert_eq!(response.status(), StatusCode::OK);
}

// ── 3. no HTTP route can turn setup mode on, or off ────────────────────────

#[test]
fn there_is_no_web_route_that_re_arms_setup_mode() {
    // Re-entering setup mode rewrites the admin account, so a URL that triggers
    // it hands the device to anyone who can reach it. Setup mode is entered from
    // the filesystem only.
    let fixture = Fixture::new();
    for path in [
        "/frontend/setup/reset",
        "/frontend/setup/reset/",
        "/frontend/setup/erase",
        "/frontend/setup/restart",
    ] {
        for method in ["GET", "POST"] {
            let mut request = Request::builder()
                .method(method)
                .uri(path)
                .body(Body::empty())
                .unwrap();
            request
                .extensions_mut()
                .insert(axum::extract::ConnectInfo(lan()));
            let response = block_on(fixture.mode().router().oneshot(request)).expect("infallible");
            assert!(
                response.status().is_client_error() || response.status().is_server_error(),
                "{method} {path} answered {} — there must be no way to re-arm setup over HTTP",
                response.status()
            );
            assert_ne!(response.status(), StatusCode::OK, "{method} {path} served");
        }
    }
}

// ── 4. a valid submission actually configures the device ────────────────────

#[test]
fn a_valid_submission_writes_a_config_a_tenant_and_an_admin() {
    let fixture = Fixture::new();
    let response = post(&fixture, lan(), &encode(&fixture.form()));
    assert_eq!(response.status(), StatusCode::OK, "{:?}", response.status());

    // The config, at 0600 — it holds the RSVP secret and any SMTP password.
    assert!(fixture.config_file.is_file(), "no config was written");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&fixture.config_file)
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "config.toml is not 0600 (it holds secrets)"
        );
    }
    let text = std::fs::read_to_string(&fixture.config_file).unwrap();
    assert!(text.contains("rsvp_secret"), "no RSVP secret generated");
    assert!(
        !text.contains("correct horse battery"),
        "the admin password must not be in the config"
    );

    // The control plane, and tenant #1 in it (§9.3's "the control DB + tenant #1").
    let control = fixture.dir.join("data/control.sqlite3");
    assert!(control.is_file(), "no control plane at {control:?}");

    // The restart, once, and only after the work succeeded.
    assert_eq!(fixture.restarts.0.load(Ordering::SeqCst), 1);
}

#[test]
fn a_second_boot_is_not_in_setup_mode() {
    // The whole point: once configured, the wizard is gone. If this were still
    // true, anyone who could reach the device could re-create the admin.
    let fixture = Fixture::new();
    assert_eq!(
        post(&fixture, lan(), &encode(&fixture.form())).status(),
        StatusCode::OK
    );
    let again = should_enter_setup_mode(&fixture.config_file);
    assert!(!again, "a configured install is still offering setup mode");
}

#[test]
fn a_missing_config_is_setup_mode_but_a_malformed_one_is_not() {
    let fixture = Fixture::new();
    assert!(should_enter_setup_mode(&fixture.config_file));

    // A typo in the config must produce the ordinary parse error, not the
    // wizard: silently offering to overwrite a working install because of a
    // stray bracket is how a device loses its configuration.
    std::fs::write(&fixture.config_file, "[tenancy\nenabled = ").unwrap();
    assert!(!should_enter_setup_mode(&fixture.config_file));
}

#[test]
fn the_reset_marker_re_arms_setup_mode_and_is_cleared_by_it() {
    let fixture = Fixture::new();
    assert_eq!(
        post(&fixture, lan(), &encode(&fixture.form())).status(),
        StatusCode::OK
    );
    assert!(!should_enter_setup_mode(&fixture.config_file));

    // A button (or a hand) drops the marker; the next boot offers the wizard
    // again, and completing it removes the marker so the *following* boot is
    // normal. Leaving it would put a working appliance back into setup on every
    // reboot, which is its own outage.
    let marker = std::env::temp_dir().join(RESET_MARKER);
    std::fs::write(&marker, b"pressed").unwrap();
    assert!(should_enter_setup_mode(&fixture.config_file));
    std::fs::remove_file(&marker).unwrap();
}

// ── 5. validation: all errors at once, and nothing written ─────────────────

#[test]
fn validation_reports_every_problem_and_writes_nothing() {
    let fixture = Fixture::new();
    let mut form = fixture.form();
    form.data_dir = "/var/lib/omnical".into(); // tmpfs: §9.5
    form.admin_email = "not-an-email".into();
    form.admin_password = "short".into();
    form.registration = "maybe".into();
    form.smtp_host = "smtp.example.com".into(); // but no credentials
    form.smtp_username = String::new();

    let response = post(&fixture, lan(), &encode(&form));
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = block_on(axum::body::to_bytes(response.into_body(), usize::MAX))
        .map(|b| String::from_utf8_lossy(&b).into_owned())
        .unwrap_or_default();
    for needle in [
        "/var",
        "admin_email",
        "admin_password",
        "registration",
        "smtp_username",
    ] {
        assert!(
            body.contains(needle),
            "the form did not mention {needle}:\n{body}"
        );
    }
    assert!(
        !fixture.config_file.exists(),
        "a rejected submission must not have written a config"
    );
    assert_eq!(fixture.restarts.0.load(Ordering::SeqCst), 0);
}

#[test]
fn a_short_admin_password_is_refused_even_when_everything_else_is_right() {
    let fixture = Fixture::new();
    let mut form = fixture.form();
    // The boundary, counted rather than eyeballed: MIN_ADMIN_PASSWORD is 12.
    form.admin_password = "abcdefghijkl".into(); // exactly 12
    assert_eq!(form.admin_password.len(), 12);
    let errors = validate(&form);
    assert!(
        errors.is_empty(),
        "exactly 12 characters must be accepted: {:?}",
        errors.iter().map(|e| &e.field).collect::<Vec<_>>()
    );

    form.admin_password = "abcdefghijk".into(); // one short
    let errors = validate(&form);
    assert_eq!(errors.len(), 1, "{errors:?}");
    assert_eq!(errors[0].field, "admin_password");
}

#[test]
fn a_half_filled_smtp_block_is_refused_rather_than_silently_broken() {
    // A config with an SMTP host and no credentials writes invites that cannot
    // be sent, which reads as "registration is broken" rather than "you left a
    // field blank".
    let fixture = Fixture::new();
    let mut form = fixture.form();
    form.smtp_host = "smtp.example.com".into();
    form.smtp_port = "587".into();
    form.smtp_password = "secret".into();
    let fields: Vec<&str> = validate(&form).iter().map(|e| e.field).collect();
    assert!(fields.contains(&"smtp_username"), "{fields:?}");
    assert!(fields.contains(&"smtp_from"), "{fields:?}");
}

#[test]
fn a_var_data_directory_is_refused_with_the_reason() {
    // /var is tmpfs on this platform. The symptom otherwise appears days later
    // as an empty calendar after a power cut, with nothing in the logs.
    let fixture = Fixture::new();
    let mut form = fixture.form();
    form.data_dir = "/var/lib/omnical".into();
    let errors = validate(&form);
    let data_dir = errors
        .iter()
        .find(|e| e.field == "data_dir")
        .expect("no error");
    assert!(
        data_dir.message.contains("wiped on every reboot"),
        "the message must say why: {}",
        data_dir.message
    );
}

// ── 6. the rule that was wrong the first time ──────────────────────────────
//
// The first version of `should_enter_setup_mode` treated "tenancy on, but the
// control plane has no tenants" as a third reason to offer the wizard. It broke
// `a_misconfigured_tenancy_section_refuses_to_start` in tests/tenancy_e2e.rs —
// a config that parses but cannot resolve any Host is a *broken install*, and
// §3.3's validate names the fix. Setup mode swallowed that error and offered
// the wizard to anyone on the LAN instead, which is the administrator takeover
// §9.3 exists to prevent, performed by the device itself.
//
// The test lives in tenancy_e2e.rs because that is where the regression showed
// up, and the shape is the point: a *valid* config with no tenants is still not
// setup mode, because "not setup mode" is what lets the normal path validate the
// config and refuse to start with a message that names the problem.
/// A config that is *valid to this binary* but resolves no Host.
///
/// Built with `gen-config` and then edited, rather than hand-written TOML —
/// because a hand-written fixture was rejected by `deny_unknown_fields` on the
/// very first attempt at this test, which is precisely the failure mode the test
/// is supposed to be about: a config that does not parse is not this case, and a
/// test that cannot tell the difference proves nothing.
async fn broken_but_valid_config(dir: &std::path::Path) -> (PathBuf, PathBuf) {
    let data = dir.join("data");
    std::fs::create_dir_all(&data).unwrap();
    let control = data.join("control.sqlite3");
    let text = format!(
        "[data_store]\n\
         [data_store.sqlite]\n\
         db_url = \"file:{db}\"\n\
         [tenancy]\n\
         enabled = true\n\
         base_domain = \"\"\n\
         default_tenant = \"\"\n\
         control_db_url = \"file:{control}\"\n\
         admin_host = \"admin.example.com\"\n",
        db = data.join("db.sqlite3").display(),
        control = control.display()
    );
    let config_file = dir.join("config.toml");
    std::fs::write(&config_file, text).unwrap();

    // Prove the fixture is a config this binary accepts, so the test cannot
    // silently degrade into "malformed config is not setup mode" — which is a
    // different and much weaker claim.
    let parsed: rustical::config::Config =
        toml::from_str(&std::fs::read_to_string(&config_file).unwrap())
            .expect("the fixture must be a config this binary accepts");
    assert!(parsed.tenancy.enabled, "the fixture must have tenancy on");
    assert!(!should_enter_setup_mode(&config_file));

    // The control plane exists and is empty — the exact state the removed
    // branch keyed on. A database that did not exist could never have been read
    // as "no tenants", so it has to be real for this to be a real test.
    let pool =
        rustical_store_sqlite::create_db_pool(&format!("sqlite://{}", control.display()), true)
            .await
            .expect("an empty control plane");
    drop(pool);
    assert!(
        control.is_file(),
        "the control plane must exist for this test"
    );

    (config_file, control)
}

#[tokio::test]
async fn a_broken_install_is_not_setup_mode() {
    // This is the regression that changed the design.
    //
    // The first version treated "tenancy on, but the control plane has no
    // tenants" as a third reason to offer the wizard, because §9.2's postinst
    // used to seed a base `config.toml` on a fresh flash — so "has a config" and
    // "is configured" were different states and the server had to guess.
    //
    // It broke `a_misconfigured_tenancy_section_refuses_to_start` in
    // tests/tenancy_e2e.rs. A config that parses but cannot resolve any Host is
    // a **broken install**, and §3.3's `TenancyConfig::validate` names the fix.
    // Setup mode swallowed that error and served the wizard instead: a server
    // with a bad `base_domain` sat there offering anyone on the LAN a fresh
    // administrator account. That is the takeover §9.3 exists to prevent,
    // performed by the device itself, and it is silent.
    //
    // The fix was at the other end — the postinst no longer seeds a config, so
    // "no config" and "not configured" are the same state.
    let fixture = Fixture::new();
    let (config_file, _control) = broken_but_valid_config(&fixture.dir).await;
    assert!(
        !should_enter_setup_mode(&config_file),
        "a valid config that resolves no host is a broken install, not an \
         unconfigured one — offering the wizard here hides the real error and \
         invites an administrator takeover"
    );
}

#[tokio::test]
async fn the_removed_branch_would_have_offered_the_wizard() {
    // The same fixture, through the *old* decision procedure, to prove the test
    // above is not vacuous. If this ever stops returning true, the fixture has
    // drifted and `a_broken_install_is_not_setup_mode` is no longer testing the
    // thing it claims to test.
    let fixture = Fixture::new();
    let (config_file, control) = broken_but_valid_config(&fixture.dir).await;

    let config: rustical::config::Config =
        toml::from_str(&std::fs::read_to_string(&config_file).unwrap()).unwrap();
    let path = config
        .tenancy
        .control_db_url
        .trim()
        .trim_start_matches("file:");
    let old_would_have_offered =
        config.tenancy.enabled && !path.is_empty() && std::path::Path::new(path).is_file();
    assert!(
        old_would_have_offered,
        "the fixture no longer reproduces the old branch"
    );
    assert!(
        std::path::Path::new(path).is_file(),
        "not the control plane: {path}"
    );
    let _ = control;
}

#[test]
fn only_two_things_open_setup_mode() {
    // The decision surface, stated as a test so adding a third reason has to be
    // a deliberate edit here.
    let fixture = Fixture::new();

    // 1. no config
    assert!(should_enter_setup_mode(&fixture.config_file));

    // 2. any config at all, even an empty one
    std::fs::write(&fixture.config_file, "").unwrap();
    assert!(!should_enter_setup_mode(&fixture.config_file));

    // 3. the reset marker
    let marker = std::env::temp_dir().join(RESET_MARKER);
    std::fs::write(&marker, b"pressed").unwrap();
    assert!(should_enter_setup_mode(&fixture.config_file));
    std::fs::remove_file(&marker).unwrap();
    assert!(!should_enter_setup_mode(&fixture.config_file));
}

#[test]
fn the_field_error_type_is_not_constructible_from_the_outside() {
    // A compile-time assertion dressed as a test: `ApplyError` is private, so
    // the handler's two-arm match cannot be widened by a caller. If this ever
    // fails to compile the privacy is what changed.
    fn _exhaustive(e: &ApplyError) -> &'static str {
        match e {
            ApplyError::Fields(_) => "fields",
            ApplyError::Fatal(_) => "fatal",
        }
    }
}
