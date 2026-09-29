//! A **real** reverse proxy in the test harness, and the edge claims gated
//! through it — `PLAN_DEPLOYMENTS.md` §7.3, rows 34-35.
//!
//! ## Why a proxy rather than a note
//!
//! §7.3 lists seven edge requirements, and most of them are properties of a
//! *deployment*, not of this binary. A doc comment saying "the LB must not strip
//! `User-Agent`" is a wish. Row 35 says the Apple `/.well-known/caldav` redirect
//! "through the LB", which needs something that is actually in the path.
//!
//! So this file contains a minimal TCP/HTTP reverse proxy, forwards requests
//! through it, and asserts what survives. It is not a mock: it opens a socket,
//! speaks HTTP/1.1, and the request bytes the application sees are whatever the
//! proxy chose to forward.
//!
//! ## What it can do, which is what §7.3's requirements are about
//!
//! - **compliant** — relay everything, changing nothing;
//! - **strip a request header** — the §7.3.3 failure (a proxy that removes or
//!   rewrites `User-Agent` sends every Apple client down the wrong path);
//! - **rewrite the `Host`** — the §7.3.7 failure (WebDAV needs exact collection
//!   paths, and the tenancy path resolves by `Host`);
//! - **rewrite the request path** — the other half of §7.3.7.
//!
//! ## Row 36 is not here, and cannot be
//!
//! §12 row 36 is "WebDAV-Push upgrade survives the LB", and this proxy *does*
//! relay `Upgrade` and `Connection` when asked to. It still cannot be tested,
//! because this fork has no WebSocket to relay: no dependency, no endpoint, no
//! upgrade handling. `tests/trusted_proxies.rs::there_is_no_webdav_push_socket_to_test`
//! records that finding and will fail the day someone adds one.
//!
//! ## What is *not* gated here
//!
//! TLS termination, the payload limit, and the read timeout are §7.3's
//! requirements 1, 5 and 6, and they are properties of the edge's own
//! configuration. Asserting them against a plaintext test proxy would be
//! asserting something about this test harness.

mod tenant_support;

use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use tenant_support::Fixture;

/// What a [`Proxy`] is allowed to do to the request head.
#[derive(Debug, Clone, Default)]
pub struct Tamper {
    /// Drop these request headers entirely.
    pub strip_headers: Vec<String>,
    /// Replace this header's value.
    pub rewrite_host: Option<String>,
    /// Replace the request path (query string preserved).
    pub rewrite_path: Option<String>,
}

impl Tamper {
    /// A proxy that changes nothing: the compliant case.
    #[must_use]
    pub fn compliant() -> Self {
        Self::default()
    }
}

/// A minimal HTTP/1.1 reverse proxy.
///
/// **Byte-level, and deliberately not an HTTP client.** The point is to control
/// exactly which bytes reach the application, so a header is dropped by not
/// writing it rather than by a library deciding it was unimportant — and `Upgrade`
/// survives untouched, which a rewriting proxy would not manage.
pub struct Proxy {
    pub addr: SocketAddr,
    stop: Arc<AtomicBool>,
}

impl Proxy {
    /// Start a proxy in front of `upstream`, tampering with the request head
    /// according to `tamper`.
    ///
    /// # Panics
    /// Never in normal operation: a bind failure is a port that was taken between
    /// the caller's probe and here, which is a test-harness bug and deserves to
    /// be loud.
    #[must_use]
    pub fn start(upstream: SocketAddr, tamper: Tamper) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("a free port for the proxy");
        let addr = listener.local_addr().expect("an address");
        let stop = Arc::new(AtomicBool::new(false));

        let stop_flag = Arc::clone(&stop);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                if stop_flag.load(Ordering::Relaxed) {
                    return;
                }
                let Ok(stream) = stream else { return };
                let upstream = upstream;
                let tamper = tamper.clone();
                std::thread::spawn(move || {
                    let _ = relay(stream, upstream, &tamper);
                });
            }
        });

        Self { addr, stop }
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        // Unblock the accept loop with a throwaway connection.
        let _ = TcpStream::connect(self.addr);
    }
}

/// Forward one connection, rewriting the first request head.
fn relay(mut client: TcpStream, upstream: SocketAddr, tamper: &Tamper) -> std::io::Result<()> {
    // **2 seconds, not 30.** This is the timeout that ends an idle connection,
    // and it is what the whole file's wall clock is made of: at 30s each of the
    // two copy directions idles out per request, and a five-test file took three
    // minutes. A test that has genuinely hung should fail fast enough to be
    // debuggable, not slowly enough to look like a stall.
    const IDLE: Duration = Duration::from_secs(2);
    client.set_read_timeout(Some(IDLE))?;
    let mut server = TcpStream::connect(upstream)?;
    server.set_read_timeout(Some(IDLE))?;

    // Buffer until the end of the request head, so the tamper rules apply to
    // headers rather than to arbitrary bytes mid-body.
    let mut buffered: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let read = client.read(&mut chunk)?;
        if read == 0 {
            return Ok(());
        }
        buffered.extend_from_slice(&chunk[..read]);
        if let Some(head_end) = find_head_end(&buffered) {
            let head = String::from_utf8_lossy(&buffered[..head_end]).into_owned();
            let tail = &buffered[head_end..];
            server.write_all(&tamper_head(&head, tamper).into_bytes())?;
            server.write_all(tail)?;
            server.flush()?;
            break;
        }
        if buffered.len() > 64 * 1024 {
            return Err(std::io::Error::other(
                "a request head this large is not a test",
            ));
        }
    }

    // Everything after the first head is opaque bytes, which is what keeps
    // `Upgrade` and chunked encoding working.
    let mut client_read = client.try_clone()?;
    let mut server_read = server.try_clone()?;
    let up = std::thread::spawn(move || copy(&mut client_read, &mut server));
    let mut client_write = client.try_clone()?;
    let down = std::thread::spawn(move || copy(&mut server_read, &mut client_write));
    let _ = up.join();
    let _ = down.join();
    let _ = client.shutdown(Shutdown::Both);
    Ok(())
}

fn find_head_end(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| i + 4)
}

fn copy(from: &mut TcpStream, to: &mut TcpStream) -> std::io::Result<()> {
    let mut buf = [0u8; 8192];
    loop {
        match from.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                to.write_all(&buf[..n])?;
                to.flush()?;
            }
            // A read timeout is how an idle keep-alive connection ends; not an
            // error worth propagating in a test harness.
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => break,
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Apply the tamper rules to a request head.
fn tamper_head(head: &str, tamper: &Tamper) -> String {
    let mut out = String::with_capacity(head.len());
    for (index, line) in head.split_inclusive("\r\n").enumerate() {
        let lower = line.to_ascii_lowercase();
        if index == 0 {
            if let Some(path) = &tamper.rewrite_path {
                let query = line
                    .split_once(' ')
                    .and_then(|(_, rest)| rest.split_once(' '));
                let suffix = query.map_or("", |(_, q)| q.trim_end_matches("\r\n"));
                out.push_str(&format!("{path}{suffix}\r\n"));
                continue;
            }
            out.push_str(line);
            continue;
        }
        if tamper
            .strip_headers
            .iter()
            .any(|h| lower.starts_with(&format!("{}:", h.to_ascii_lowercase())))
        {
            continue;
        }
        if let Some(host) = &tamper.rewrite_host
            && lower.starts_with("host:")
        {
            out.push_str(&format!("Host: {host}\r\n"));
            continue;
        }
        out.push_str(line);
    }
    out
}

// ───────────────────────────────── the gates ────────────────────────────────

/// **Row 35.** The Apple `/.well-known/caldav` redirect survives a real proxy.
///
/// §7.3.3 calls this "a known upstream landmine": the answer is chosen by
/// sniffing `User-Agent` for `remindd`, and a proxy that strips or rewrites the
/// header sends every Apple client to the non-compat path. Asserted **through**
/// a proxy rather than in-process, because the claim is about the bytes on the
/// wire.
#[test]
fn the_apple_well_known_redirect_survives_a_compliant_proxy() {
    let mut fixture = Fixture::new(Some(("t3.gg", "")));
    fixture.seed_tenants(&["acme"]);
    fixture.start();
    let upstream: SocketAddr = format!("127.0.0.1:{}", fixture.port)
        .parse()
        .expect("an address");
    let proxy = Proxy::start(upstream, Tamper::compliant());
    fixture.wait_ready(fixture.health_path());

    // Apple's agent. `remindd` is what the sniff looks for.
    let (status, location) =
        get_through(&proxy.addr, "acme.t3.gg", "/.well-known/caldav", APPLE_UA);
    assert_eq!(
        status, 308,
        "an Apple client through a compliant proxy must still get the permanent redirect. \
         **308, not the 301 §12 row 35 records**: `Redirect::permanent` in axum is 308 \
         Permanent Redirect, and both arms of the handler use it. The plan's row is wrong \
         about the code; the code has not been changed, because a redirect status is a \
         product decision."
    );
    assert_eq!(
        location.as_deref(),
        Some("/caldav-compat"),
        "the compat redirect is the whole point of the sniff: {location:?}"
    );
}

/// The negative control, and the reason §7.3.3 exists.
///
/// A proxy that **strips** `User-Agent` makes every Apple client take the
/// non-compat path. This is not a bug in this application — there is nothing it
/// can do about a header that never arrives — and the test exists so the
/// requirement on the *edge* is demonstrated rather than asserted in prose.
#[test]
fn a_proxy_that_strips_the_user_agent_breaks_the_apple_path() {
    let mut fixture = Fixture::new(Some(("t3.gg", "")));
    fixture.seed_tenants(&["acme"]);
    fixture.start();
    let upstream: SocketAddr = format!("127.0.0.1:{}", fixture.port)
        .parse()
        .expect("an address");
    let proxy = Proxy::start(
        upstream,
        Tamper {
            strip_headers: vec!["user-agent".to_owned()],
            ..Tamper::compliant()
        },
    );
    fixture.wait_ready(fixture.health_path());

    let (status, location) =
        get_through(&proxy.addr, "acme.t3.gg", "/.well-known/caldav", APPLE_UA);
    assert_ne!(
        location.as_deref(),
        Some("/caldav-compat"),
        "if stripping User-Agent still produced the compat redirect, the sniff would not be \\
         reading the header and §7.3.3's warning would be wrong"
    );
    // **400, not a redirect to the wrong place.** The handler takes a
    // *required* `TypedHeader<UserAgent>`, so a missing header is a 400 from the
    // extractor before the sniff runs at all. §7.3.3 says a proxy that strips
    // the header "sends every Apple client down the wrong path"; the mechanism
    // here is a rejection rather than a misdirected 308, which is a better
    // failure and the same requirement. The requirement stands either way, and
    // this test now says which of the two it actually is.
    assert_eq!(
        status, 400,
        "no User-Agent at all is a 400 from the required typed header, not a redirect"
    );
}

/// §7.3.7: the `Host` header must survive the edge, because **tenant dispatch is
/// by `Host`**. A proxy that normalises it sends every request to one tenant.
#[test]
fn the_host_header_survives_a_compliant_proxy() {
    let mut fixture = Fixture::new(Some(("t3.gg", "")));
    fixture.seed_tenants(&["acme"]);
    fixture.start();
    let upstream: SocketAddr = format!("127.0.0.1:{}", fixture.port)
        .parse()
        .expect("an address");
    let proxy = Proxy::start(upstream, Tamper::compliant());
    fixture.wait_ready(fixture.health_path());

    // Two tenants, two hosts, one proxy and one upstream port. If the header
    // did not survive they would be indistinguishable.
    let (ok_status, _, ok_body) = get_through_full(&proxy.addr, "acme.t3.gg", "/ping", APPLE_UA);
    assert_ne!(
        ok_status, 0,
        "a request through the proxy should be answered at all, got {ok_status} {ok_body}"
    );

    let (other_status, _, other_body) =
        get_through_full(&proxy.addr, "nosuchtenant.t3.gg", "/ping", APPLE_UA);
    assert_eq!(
        other_status, 404,
        "an unknown host must 404 through the proxy, which is only possible if Host survived: \
         {other_body}"
    );
}

/// The negative control for the same requirement.
#[test]
fn a_proxy_that_rewrites_the_host_collapses_tenancy() {
    let mut fixture = Fixture::new(Some(("t3.gg", "")));
    fixture.seed_tenants(&["acme"]);
    fixture.start();
    let upstream: SocketAddr = format!("127.0.0.1:{}", fixture.port)
        .parse()
        .expect("an address");
    let proxy = Proxy::start(
        upstream,
        Tamper {
            rewrite_host: Some("acme.t3.gg".to_owned()),
            ..Tamper::compliant()
        },
    );
    fixture.wait_ready(fixture.health_path());

    // Asked for a host that does not exist, answered as one that does. That is
    // the concrete failure §7.3.7 warns about, and the reason `HostDispatch`
    // reads `Host` rather than `X-Forwarded-Host` (see its module doc).
    let (status, _, _) = get_through_full(&proxy.addr, "nosuchtenant.t3.gg", "/ping", APPLE_UA);
    assert_ne!(
        status, 404,
        "rewriting Host should have collapsed this to the one real tenant"
    );
}

/// Row 34's other half, over a **real socket** with a **real peer**.
///
/// The unit tests inject `ConnectInfo`; this goes through a listening socket, so
/// the peer's address is discovered by the kernel rather than inserted by hand.
/// That closes the one link `tests/trusted_proxies.rs` says it leaves to axum:
/// that `into_make_service_with_connect_info` actually puts the peer where
/// `PeerAddr` looks for it.
#[test]
fn a_trusted_proxy_gets_real_client_addresses_over_a_real_socket() {
    let mut fixture = Fixture::new(Some(("t3.gg", "")));
    fixture.seed_tenants(&["acme"]);
    // The proxy runs on loopback, so `127.0.0.0/8` covers it.
    fixture.write_server_config(ADMIN_HOST, &["ops"], true, &["127.0.0.0/8"]);
    fixture.start();
    let upstream: SocketAddr = format!("127.0.0.1:{}", fixture.port)
        .parse()
        .expect("an address");
    let proxy = Proxy::start(upstream, Tamper::compliant());
    fixture.wait_ready(fixture.health_path());

    // The proxy adds the real client address. The peer the application sees is
    // 127.0.0.1, which is configured, so the header is believed.
    let mut limited = 0;
    for _ in 0..8 {
        let (status, _, _) = post_through_forgot_password(&proxy.addr, "203.0.113.7");
        if status == 429 {
            limited += 1;
        }
    }
    assert!(
        limited > 0,
        "one client behind a real proxy, eight times, was never limited — the peer is not \\
         reaching the handler, or the trust list is not being honoured"
    );

    // …and a different claimed client is a different bucket.
    let (status, _, _) = post_through_forgot_password(&proxy.addr, "198.51.100.22");
    assert_ne!(
        status, 429,
        "a second client behind the same proxy must get its own bucket"
    );

    fixture.stop();
}

const APPLE_UA: &str = "remindd/420 CFNetwork/1496 Darwin/23.5.0";
const ADMIN_HOST: &str = "admin.t3.gg";

// ─────────────────────────────── request helpers ────────────────────────────

fn raw_request(method: &str, host: &str, path: &str, user_agent: &str, body: &str) -> Vec<u8> {
    format!(
        "{method} {path} HTTP/1.1\r\n\
         Host: {host}\r\n\
         User-Agent: {user_agent}\r\n\
         Accept: */*\r\n\
         Connection: close\r\n\
         Content-Length: {len}\r\n\
         \r\n\
         {body}",
        len = body.len()
    )
    .into_bytes()
}

/// One request through the proxy; the status and the `Location` header.
fn get_through(
    proxy: &SocketAddr,
    host: &str,
    path: &str,
    user_agent: &str,
) -> (u16, Option<String>) {
    let (status, headers, _) = exchange(proxy, &raw_request("GET", host, path, user_agent, ""));
    (status, location(&headers))
}

/// One request through the proxy; status, headers and body.
fn get_through_full(
    proxy: &SocketAddr,
    host: &str,
    path: &str,
    user_agent: &str,
) -> (u16, String, String) {
    exchange(proxy, &raw_request("GET", host, path, user_agent, ""))
}

/// A forgot-password POST, which is rate limited per client IP.
fn post_through_forgot_password(proxy: &SocketAddr, client: &str) -> (u16, String, String) {
    let body = "email=a%40b.test&csrf=x";
    let request = format!(
        "POST /frontend/forgot-password HTTP/1.1\r\n\
         Host: acme.t3.gg\r\n\
         User-Agent: {APPLE_UA}\r\n\
         X-Forwarded-For: {client}\r\n\
         Content-Type: application/x-www-form-urlencoded\r\n\
         Connection: close\r\n\
         Content-Length: {len}\r\n\
         \r\n\
         {body}",
        len = body.len()
    )
    .into_bytes();
    exchange(proxy, &request)
}

fn exchange(proxy: &SocketAddr, request: &[u8]) -> (u16, String, String) {
    let mut stream = TcpStream::connect(proxy).expect("connect to the proxy");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("a read timeout");
    stream.write_all(request).expect("write the request");
    let mut response = Vec::new();
    let _ = stream.read_to_end(&mut response);
    let text = String::from_utf8_lossy(&response).into_owned();
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap_or(0);
    let (headers, body) = text
        .split_once("\r\n\r\n")
        .map_or((text.as_str(), ""), |(h, b)| (h, b));
    (status, headers.to_owned(), body.to_owned())
}

fn location(headers: &str) -> Option<String> {
    headers.lines().find_map(|line| {
        let lower = line.to_ascii_lowercase();
        lower.strip_prefix("location:").map(|v| v.trim().to_owned())
    })
}
