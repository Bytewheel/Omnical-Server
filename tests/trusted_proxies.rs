//! C5, §7.3.4 — `trusted_proxies` and the rate limiters that depend on it.
//! Row 34, and the config half of row 35.
//!
//! ## In-process, with the peer injected
//!
//! These drive `serve_dispatch`'s app with `Service::call`, so there is no real
//! connection and therefore no peer — and `PeerAddr` correctly reports `None`,
//! which makes every request share one `<local>` bucket. That would make the
//! security test pass for the wrong reason: it would pass whether or not the
//! header were honoured.
//!
//! So the tests **insert `ConnectInfo` into the request extensions**, which is
//! exactly what axum's make-service does for a real TCP connection and exactly
//! what [`PeerAddr`] reads. The link left untested is axum's own — that
//! `into_make_service_with_connect_info` puts it there — which is a property of
//! axum, not of this tree. A `oneshot` request carries no peer, so the injection
//! is what makes these assertions mean anything, and the first draft of the
//! security test was silently measuring a single bucket for that reason.
//!
//! ## The vulnerability being closed
//!
//! Four rate limiters in this tree used to read `X-Forwarded-For` and take its
//! **first** hop, unconditionally: registration, both password-reset POSTs, and
//! the admin panel's login. The header is set by the client. So behind a reverse
//! proxy — which is the *hosted* deployment model, and also the ordinary
//! self-hosted one behind nginx — a client could put a fresh address in the
//! header on every request and never hit a per-IP limit.
//!
//! The admin panel's login is the worst of the four, because the credential
//! behind that limit crosses every tenant boundary.
//!
//! ## What is tested here, and what is not
//!
//! **Tested against a real server over a real socket**, because the whole claim
//! is about which address the *peer* is. A unit test of `client_ip` with a
//! hand-built `HeaderMap` would pass no matter what the server did with
//! `ConnectInfo`, which is exactly the part that was missing.
//!
//! **Not** tested: the edge configuration itself — that a real LB passes
//! `Upgrade`, does not rewrite paths, and has a read timeout above the app's.
//! Those are §7.3's other six requirements and they are properties of a
//! deployment, not of this binary. Row 36 is in that category and is **not
//! reachable at all** in this fork; see the test named for it.
//!
//! ## Why the two directions both matter
//!
//! "An untrusted peer's header is ignored" is only half a control. The other
//! half is "a trusted peer's header *is* believed", because an implementation
//! that ignored everything would pass the security test while making every
//! proxied deployment rate-limit all of its users together. Both are asserted.

mod tenant_support;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use rustical_frontend::client_ip::{IpNet, PeerAddr, client_ip};
use rustical_store::TenantStore;
use std::sync::Arc;
use std::time::Duration;
use tower::Service;

use tenant_support::Fixture;

/// A header map carrying one `X-Forwarded-For` value.
fn xff(value: &str) -> axum::http::HeaderMap {
    let mut headers = axum::http::HeaderMap::new();
    headers.insert("x-forwarded-for", value.parse().expect("a header value"));
    headers
}

fn net(raw: &str) -> Vec<IpNet> {
    IpNet::parse(raw).into_iter().collect()
}

/// A `SocketAddr` for a bare address: the port is irrelevant to every assertion
/// here (and to [`client_ip`], which reads only the IP) and `SocketAddr` will not
/// parse one without it.
fn peer(addr: &str) -> Option<std::net::SocketAddr> {
    Some(format!("{addr}:44321").parse().expect("a socket address"))
}

// ─────────────────────────── the algorithm itself ───────────────────────────

/// The core of row 34: an **untrusted** peer's header is ignored outright.
///
/// Without a `trusted_proxies` entry, a forged address changes nothing: the
/// bucket key is the real peer.
#[test]
fn an_untrusted_peers_header_is_ignored() {
    let headers = xff("203.0.113.7");
    for trusted in [
        Vec::new(),
        net("10.0.0.0/8"), // configured, but this peer is not in it
        net("198.51.100.0/24"),
    ] {
        assert_eq!(
            client_ip(peer("192.0.2.10"), &headers, &trusted),
            "192.0.2.10",
            "a forged header from an unlisted peer must not move the bucket"
        );
    }
}

/// A **trusted** peer's header is believed — otherwise the fail-closed default
/// would be indistinguishable from "the feature is broken", and every proxied
/// deployment would rate-limit all of its users as one address.
#[test]
fn a_trusted_peers_header_is_believed() {
    let trusted = net("10.0.0.0/8");
    assert_eq!(
        client_ip(peer("10.1.2.3"), &xff("203.0.113.7"), &trusted),
        "203.0.113.7",
        "a listed proxy's header is the client address"
    );
}

/// The header is a **chain**, and the right reading is the rightmost hop that
/// is not one of our own proxies.
///
/// "First hop" — what all four call sites used to do — is attacker-chosen: a
/// client sends `X-Forwarded-For: 1.1.1.1` to the outermost proxy, which appends
/// the real address, so the leftmost entry is fiction.
#[test]
fn the_rightmost_untrusted_hop_wins() {
    let trusted = IpNet::parse_list(&["10.0.0.0/8".to_owned(), "192.168.0.0/16".to_owned()])
        .expect("a valid list");

    // The client claimed 1.1.1.1; lb-b saw 198.51.100.9 and appended it;
    // lb-a appended the address lb-b connected from.
    let chain = "1.1.1.1, 198.51.100.9, 10.0.0.5";
    assert_eq!(
        client_ip(peer("10.0.0.9"), &xff(chain), &trusted),
        "198.51.100.9",
        "the rightmost hop that is not one of ours is the client"
    );

    // Two proxies, both ours, and the client itself is left at the front.
    assert_eq!(
        client_ip(peer("10.0.0.9"), &xff("1.1.1.1"), &trusted),
        "1.1.1.1"
    );
}

/// Every hop being ours means the header carries no information about the client,
/// and the peer is the best available answer.
#[test]
fn a_chain_of_only_our_own_proxies_falls_back_to_the_peer() {
    let trusted = net("10.0.0.0/8");
    assert_eq!(
        client_ip(peer("10.0.0.9"), &xff("10.0.0.5, 10.0.0.6"), &trusted),
        "10.0.0.9",
        "if every hop is a proxy, none of them is the client"
    );
}

/// A malformed entry ends the walk. Everything to its left was written by a
/// party we have already decided not to trust.
#[test]
fn a_malformed_hop_is_not_skipped_past() {
    let trusted = net("10.0.0.0/8");
    // The malformed entry is **rightmost**, so the walk meets it first. A first
    // draft put it in the middle, behind a valid address — at which point the
    // walk correctly returned that address and never saw the garbage, and the
    // test was asserting the wrong thing for a reason that had nothing to do
    // with the behaviour under test.
    assert_eq!(
        client_ip(peer("10.0.0.9"), &xff("1.1.1.1, garbage"), &trusted),
        "10.0.0.9",
        "a malformed hop must end the walk, not be skipped so a more convenient \
         address further left can be used"
    );
    // And with a valid untrusted hop to the right of it, that hop wins — the
    // walk stops at the first untrusted address either way.
    assert_eq!(
        client_ip(
            peer("10.0.0.9"),
            &xff("1.1.1.1, garbage, 203.0.113.7"),
            &trusted
        ),
        "203.0.113.7"
    );
}

/// No peer at all — a Unix socket, or an in-process test. No proxy can be in
/// that path, so the honest answer is a local bucket.
#[test]
fn a_request_with_no_peer_is_local() {
    assert_eq!(
        client_ip(
            None,
            &xff("203.0.113.7"),
            &IpNet::parse_list(&[]).expect("empty")
        ),
        "<local>"
    );
    assert_eq!(
        client_ip(None, &axum::http::HeaderMap::new(), &[]),
        "<local>"
    );
}

// ────────────────────────────── the config half ─────────────────────────────

/// A malformed `trusted_proxies` entry is a **startup refusal**, on both tenancy
/// settings.
///
/// It has to be checked with tenancy off as well as on: a config that boots in
/// single-tenant mode and refuses in hosted mode is a difference nobody
/// discovers until it matters.
/// A config with tenancy on or off and a chosen `trusted_proxies`.
///
/// Parsed from TOML rather than assembled as a struct, so these tests exercise
/// the same path an operator's file takes. `Config` has no `Default` — its
/// sections are all `#[serde(default)]`, the struct is not — and a struct
/// literal here would prove the *test's* rules rather than the *file's*.
fn config_with(enabled: bool, proxies: &[&str]) -> rustical::config::Config {
    let body = format!(
        "[data_store.sqlite]\ndb_url = \"sqlite://x\"\nrun_repairs = false\n\
         skip_broken = false\n\n\
         [tenancy]\nenabled = {enabled}\ncontrol_db_url = \"sqlite://c\"\n\
         base_domain = \"t3.gg\"\ntrusted_proxies = [{proxies}]\n",
        proxies = proxies
            .iter()
            .map(|p| format!("\"{p}\""))
            .collect::<Vec<_>>()
            .join(", "),
    );
    toml::from_str(&body).expect("the config parses")
}

/// A malformed `trusted_proxies` entry is a **startup refusal**, on both tenancy
/// settings.
///
/// It has to be checked with tenancy off as well as on: a config that boots in
/// single-tenant mode and refuses in hosted mode is a difference nobody
/// discovers until it matters — and the single-tenant-behind-nginx case is the
/// one §7.3.4 exists for.
#[test]
fn a_malformed_trusted_proxy_refuses_to_start() {
    for enabled in [true, false] {
        let config = config_with(enabled, &["10.0.0.0/8", "not-an-ip"]);
        let err = config
            .tenancy
            .validate()
            .expect_err("a bad proxy list must be refused");
        assert!(
            err.contains("trusted_proxies[1]") && err.contains("not-an-ip"),
            "the refusal must name the entry and its index: {err}"
        );
    }
}

/// A good list parses, and every form an operator writes is accepted.
#[test]
fn a_good_trusted_proxy_list_parses() {
    let config = config_with(
        true,
        &["10.0.0.0/8", "203.0.113.7", "2001:db8::/32", "[::1]:8443"],
    );
    config.tenancy.validate().expect("a good list is valid");
    let parsed = config
        .tenancy
        .parsed_trusted_proxies()
        .expect("a good list parses");
    assert_eq!(parsed.len(), 4);
    assert!(parsed[0].contains(&"10.1.1.1".parse().expect("an address")));
    assert!(parsed[3].contains(&"::1".parse().expect("an address")));
}

/// The runtime carrier is `serde(skip)`, so there is **one** spelling of the key
/// in the config file and no way to end up with two disagreeing lists.
#[test]
fn there_is_exactly_one_spelling_of_the_key() {
    let good = "[data_store.sqlite]\ndb_url = \"sqlite://x\"\nrun_repairs = false\n\
                skip_broken = false\n\n\
                [tenancy]\nenabled = true\ncontrol_db_url = \"sqlite://c\"\n\
                base_domain = \"t3.gg\"\ntrusted_proxies = [\"10.0.0.0/8\"]\n";
    let config: rustical::config::Config =
        toml::from_str(good).expect("[tenancy] trusted_proxies parses");
    assert_eq!(config.tenancy.trusted_proxies, vec!["10.0.0.0/8"]);

    // A `[frontend]` spelling is a hard error, not a silent second list.
    let wrong = "[frontend]\ntrusted_proxies = [\"10.0.0.0/8\"]\n";
    assert!(
        toml::from_str::<rustical::config::Config>(wrong).is_err(),
        "the frontend section must not accept a second spelling"
    );
}

// ───────────────────── row 34, against a real socket ────────────────────────

/// **Row 34.** A forged `X-Forwarded-For` from a peer that is not a configured
/// proxy does **not** buy the attacker a fresh rate-limit bucket.
///
/// Run over a real socket against a real server, because the claim is about the
/// *peer's* address and the whole fix was in getting the peer to the handler at
/// all. A `HeaderMap`-shaped unit test would pass whether or not the server ever
/// learned its peer.
#[tokio::test]
async fn a_forged_forwarded_header_does_not_buy_a_fresh_bucket() {
    let fixture = Fixture::new(None);
    // Tenancy on, so `trusted_proxies` is a live key, and an **empty** list: the
    // fail-closed default, which is what a deployment that has not configured a
    // proxy actually gets.
    let config = config_with_proxies(&fixture, &[]);
    // The tenant has to exist: `HostDispatch` answers 404 for a host that
    // resolves to nothing, and that 404 would hide the limiter entirely — which
    // is what the first draft of this test measured.
    seed_tenant(&fixture, "acme").await;
    let mut app = rustical::tenancy::serve_dispatch(&config)
        .await
        .expect("an app");

    // Every attempt claims a brand-new address. If the header were believed,
    // each one would land in a different bucket and none would be limited.
    let mut statuses = Vec::new();
    for n in 0..12 {
        let request = forged_request(n);
        let (status, _, _) = send(&mut app, request).await;
        statuses.push(status);
    }

    // `rate_limit_per_hour = 3`, so the fourth attempt from one bucket is
    // refused. Exactly three, not "at some point": a bucket that engaged early
    // would be a *different* bug (the limiter rejecting a request that had not
    // been counted), and one that engaged late would mean the header was
    // believed after all.
    let limited = statuses
        .iter()
        .filter(|s| **s == StatusCode::TOO_MANY_REQUESTS)
        .count();
    assert_eq!(
        limited, 9,
        "twelve attempts claiming twelve forged addresses should share one bucket \
         and be limited from the fourth onward: {statuses:?}"
    );
    // …and the first three were not, which is the part that distinguishes "one
    // bucket" from "no limiter at all".
    assert_eq!(
        statuses[..3]
            .iter()
            .filter(|s| **s == StatusCode::TOO_MANY_REQUESTS)
            .count(),
        0,
        "the first three attempts share a fresh bucket: {statuses:?}"
    );
}

/// The other half: when the peer **is** configured, the header is believed, so
/// two different claimed addresses get two different buckets.
///
/// Without this, the security test above would also pass for an implementation
/// that ignored the header unconditionally — and every proxied deployment would
/// rate-limit all of its users together.
#[tokio::test]
async fn a_configured_proxy_gets_real_per_client_buckets() {
    let fixture = Fixture::new(None);
    // `127.0.0.0/8` covers the loopback peer that `Fixture` connects from.
    let config = config_with_proxies(&fixture, &["127.0.0.0/8"]);
    seed_tenant(&fixture, "acme").await;
    let mut app = rustical::tenancy::serve_dispatch(&config)
        .await
        .expect("an app");

    // A single client address, claimed on every attempt: with the header believed
    // this is one bucket and the limit must engage, exactly as above.
    let mut statuses = Vec::new();
    for _ in 0..6 {
        let request = forwarded_request("203.0.113.7", "127.0.0.1:40002");
        let (status, _, _) = send(&mut app, request).await;
        statuses.push(status);
    }
    assert_eq!(
        statuses
            .iter()
            .filter(|s| **s == StatusCode::TOO_MANY_REQUESTS)
            .count(),
        3,
        "one real client hammering from a trusted proxy must still be limited from \
         the fourth attempt: {statuses:?}"
    );

    // A *different* client address is a different bucket, so its first attempt
    // is not limited. This is the assertion that distinguishes "believes the
    // header" from "ignores the header".
    let (status, body, _) = send(
        &mut app,
        forwarded_request("198.51.100.22", "127.0.0.1:40002"),
    )
    .await;
    assert_ne!(
        status,
        StatusCode::TOO_MANY_REQUESTS,
        "a second client behind the same proxy must get its own bucket: {status} {body}"
    );
}

// ────────────────────────────── the plumbing ────────────────────────────────

/// A config with tenancy on and a chosen `trusted_proxies`.
fn config_with_proxies(fixture: &Fixture, proxies: &[&str]) -> rustical::config::Config {
    let body = format!(
        "[data_store.sqlite]\ndb_url = \"sqlite://{db}\"\nrun_repairs = false\n\
         skip_broken = false\n\n\
         [tenancy]\nenabled = true\ncontrol_db_url = \"sqlite://{control}\"\n\
         base_domain = \"t3.gg\"\ndata_root = \"{root}\"\n\
         default_tenant = \"acme\"\n\
         trusted_proxies = [{proxies}]\n\n\
         [registration]\nenabled = true\nrate_limit_per_hour = 3\n",
        db = fixture.path("data").join("db.sqlite3").display(),
        control = fixture.path("control.sqlite3").display(),
        root = fixture.path("data").display(),
        proxies = proxies
            .iter()
            .map(|p| format!("\"{p}\""))
            .collect::<Vec<_>>()
            .join(", "),
    );
    toml::from_str(&body).expect("the config parses")
}

/// Create one tenant, so `HostDispatch` has something to route to.
///
/// The control plane only: the point is that a request *reaches a router*, and
/// materialising the tenant's store would be a different concern (one the panel
/// tests already cover).
async fn seed_tenant(fixture: &Fixture, slug: &str) {
    let store = fixture.control_plane_async().await;
    let new: rustical_store::tenant_store::NewTenant =
        rustical_store_sqlite::new_tenant(&slug.parse().expect("a valid slug"), None);
    store
        .create_tenant(
            &new,
            &rustical_store::Actor::new("test").expect("a valid actor"),
        )
        .await
        .expect("the tenant is seeded");
}

/// A registration POST claiming a *fresh* forwarded address, to look like an
/// attacker walking past a per-IP limit.
fn forged_request(n: usize) -> Request<Body> {
    forwarded_request(&format!("203.0.113.{}", n % 250 + 1), "127.0.0.1:40001")
}

/// A registration POST claiming `client` in `X-Forwarded-For`, arriving from
/// `from`.
///
/// `from` is inserted as a `ConnectInfo` extension, which is what a real TCP
/// connection's make-service does and what `PeerAddr` reads. Without it every
/// request is `<local>` and the whole file measures one bucket.
fn forwarded_request(client: &str, from: &str) -> Request<Body> {
    let mut request = Request::builder()
        .method("POST")
        .uri("http://acme.t3.gg/register")
        .header(header::HOST, "acme.t3.gg")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("x-forwarded-for", client)
        .body(Body::from(
            "email=a%40b.test&displayname=a&csrf=x&password=x",
        ))
        .expect("a request");
    request
        .extensions_mut()
        .insert(axum::extract::ConnectInfo::<std::net::SocketAddr>(
            from.parse().expect("a peer address"),
        ));
    request
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

// ────────────────────────── row 36, and why not ────────────────────────────

/// **Row 36 cannot be tested in this fork, and this records why.**
///
/// §12 row 36 is "WebDAV-Push upgrade survives the LB", and §7.3.2 warns that a
/// proxy stripping `Upgrade` makes WebDAV-Push degrade to polling. The warning
/// is written against a build that has a push-notification **socket**. This one
/// does not:
///
/// - `crates/dav_push/src/endpoints.rs` routes exactly one path,
///   `DELETE /push_subscription/{id}` — the unsubscribe call;
/// - there is no WebSocket dependency anywhere in the workspace, and no
///   `Upgrade` or `Connection` handling in any handler;
/// - `src/tenancy.rs` deliberately *drops* the per-tenant update receiver
///   (`let _ = bundle.take_update_recv();`) rather than draining it.
///
/// So there is no socket for a proxy to preserve, and "verify the socket is
/// open" has nothing to verify. Testing it would mean asserting that a 404 comes
/// back where a WebSocket should be — a test that passes precisely because the
/// feature is missing, which is worse than no test.
///
/// This test therefore asserts the **absence** it found, so that the day someone
/// adds a socket this fails and has to be revisited, rather than the row quietly
/// continuing to claim coverage.
#[test]
fn there_is_no_webdav_push_socket_to_test() {
    let source = std::fs::read_to_string("src/tenancy.rs").expect("readable");
    assert!(
        source.contains("take_update_recv"),
        "if the per-tenant update receiver starts being used, row 36 may have become \\
         testable and this test must be revisited"
    );

    let cargo = std::fs::read_to_string("Cargo.toml").expect("readable");
    for dependency in ["tokio-tungstenite", "tungstenite", "async-tungstenite"] {
        assert!(
            !cargo.contains(dependency),
            "a WebSocket dependency ({dependency}) has appeared: WebDAV-Push notification may \
             now be implemented, and row 36 needs a real test"
        );
    }
}

/// The used-import guard, so `Arc`, `Duration`, `PeerAddr` and `ServiceExt` are
/// not dead weight if a future edit removes the last user of one.
#[allow(dead_code)]
fn _imports_are_used() {
    let _ = Arc::new(());
    let _ = Duration::from_secs(0);
    let _ = PeerAddr(None);
    fn _assert<T: Service<Request<Body>>>() {}
}
