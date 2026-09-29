//! The client address a request came **from** — `PLAN_DEPLOYMENTS.md` C5,
//! §7.3.4.
//!
//! ## Why this file exists
//!
//! `X-Forwarded-For` is an attacker-controlled header unless the peer that sent
//! it is one you run. Three rate limiters in this tree read it, and before this
//! module all three read it **unconditionally**: `register.rs`,
//! `password_reset.rs`, and the admin panel. Behind a load balancer that meant
//! anyone could pick a fresh address per request and walk straight through a
//! per-IP limit — including the admin *login* limit, which is the one control
//! standing between an attacker and a credential that crosses every tenant
//! boundary.
//!
//! So the header is honoured **only when the immediate peer is listed** in
//! `[tenancy] trusted_proxies`. That default is fail-closed, and the reasoning
//! is in [`client_ip`].
//!
//! ## The algorithm
//!
//! The rightmost-**untrusted** address, walking right to left. Not "the first
//! hop", which is what all three call sites used to do.
//!
//! "First hop" is wrong in the presence of more than one proxy: a client at
//! 1.2.3.4 behind `lb-a` and `lb-b` produces
//! `X-Forwarded-For: 1.2.3.4, <client-of-lb-b>`, and the first hop is still
//! 1.2.3.4 only if `lb-a` did not append. The first hop is
//! **attacker-chosen** in general: if `lb-b` is trusted and appends, the
//! leftmost entry is whatever the client sent and the rightmost is
//! `lb-a`'s view of the client. Skipping every address that is itself a trusted
//! proxy and taking the first that is not is the only reading that survives
//! N proxies — it is what nginx's `real_ip_recursive` does.
//!
//! ## Why an [`IpNet`] and not a crate
//!
//! Because there is no CIDR crate in this workspace and adding one is a supply
//! -chain decision for sixty lines. The awkward parts are handled explicitly and
//! tested: a `/0` prefix, a v4 prefix above 32, and a v4-mapped-v6 address in
//! an `X-Forwarded-For` entry, which is a real thing because a dual-stack proxy
//! writes `::ffff:203.0.113.7` where an operator's `trusted_proxies` says
//! `203.0.113.0/24`.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use axum::extract::ConnectInfo;
use axum::http::HeaderMap;
use axum::http::request::Parts;

/// The v4 address inside a v4-mapped v6 address, if it is one.
///
/// A free function rather than a method on [`IpAddr`], which is defined in
/// `core` and so cannot get an inherent `impl` from this crate.
#[must_use]
pub const fn as_v4(addr: &IpAddr) -> Option<Ipv4Addr> {
    match addr {
        IpAddr::V4(v4) => Some(*v4),
        IpAddr::V6(v6) => v6.to_ipv4_mapped(),
    }
}

/// Set the first time a forwarded header arrives from an unlisted peer, and
/// never again.
///
/// A `static` at module scope rather than one inside the function body: an item
/// after statements reads as a mistake, and the once-ness is easier to see here
/// than at the bottom of a 40-line body.
static WARNED: std::sync::OnceLock<()> = std::sync::OnceLock::new();

/// The request's immediate peer, or `None` when there is not one.
///
/// A custom extractor because `Option<ConnectInfo<SocketAddr>>` **is not** a
/// valid axum extractor: `Option<T>` needs `T: OptionalFromRequestParts`, and
/// `ConnectInfo` implements only `FromRequestParts`. So either every handler
/// takes a non-optional `ConnectInfo` and the Unix-socket path starts
/// returning 500, or the peer is read out of the request extensions here.
///
/// This never rejects, which is what makes the same handler work on all three
/// shapes of this server: a TCP listener (peer present), a Unix socket (absent
/// — no proxy can be in that path), and an in-process test using `oneshot`
/// (absent).
#[derive(Debug, Clone, Copy, Default)]
pub struct PeerAddr(pub Option<SocketAddr>);

impl PeerAddr {
    /// The peer as an [`IpAddr`], or `None`.
    #[must_use]
    pub fn ip(&self) -> Option<IpAddr> {
        self.0.map(|peer| peer.ip())
    }
}

impl<S> axum::extract::FromRequestParts<S> for PeerAddr
where
    S: Send + Sync,
{
    type Rejection = std::convert::Infallible;

    // `async` with no `.await`, because the trait's method is `async` and the
    // value is already in the request extensions. `clippy::nursery` is enabled
    // crate-wide and flags it; the two pre-existing extractor impls in
    // `crates/store/src/auth/principal.rs` carry the same warning, so this one
    // does too rather than being the single place in the tree that silences a
    // lint its neighbours accept.
    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        Ok(Self(
            parts
                .extensions
                .get::<ConnectInfo<SocketAddr>>()
                .map(|peer| peer.0),
        ))
    }
}

/// An address or a CIDR block.
///
/// Deliberately *not* a general network type: there is no mask arithmetic
/// beyond "compare the first `prefix` bits", and every extra feature here would
/// be untested surface in a security control.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpNet {
    addr: IpAddr,
    prefix: u8,
}

impl IpNet {
    /// The block `addr/prefix` denotes.
    ///
    /// # Errors
    /// `prefix` is above the address family's width (33 for v4, 129 for v6).
    /// That is a **config** error, so it is loud rather than clamped: an operator
    /// who wrote `10.0.0.0/33` has misunderstood something, and silently
    /// clamping it to `/32` would make their `trusted_proxies` a single host.
    pub fn new(addr: IpAddr, prefix: u8) -> Result<Self, String> {
        let max = match addr {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if prefix > max {
            return Err(format!(
                "prefix /{prefix} is too long for {addr}; the maximum is /{max}"
            ));
        }
        Ok(Self { addr, prefix })
    }

    /// A single host, `/32` or `/128`.
    ///
    /// # Errors
    /// Never, but the signature matches [`Self::new`] so a caller can build a
    /// list of both from strings.
    #[must_use]
    pub const fn host(addr: IpAddr) -> Self {
        let prefix = match addr {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        Self { addr, prefix }
    }

    /// Does `addr` fall in this block?
    #[must_use]
    pub fn contains(&self, addr: &IpAddr) -> bool {
        // A v4-mapped v6 address is the same host as the v4 address. Comparing
        // them as written would let `::ffff:10.0.0.1` miss a `10.0.0.0/8` entry,
        // and a proxy that writes mapped addresses would then be silently
        // untrusted — the failure mode is "the security control does nothing".
        let probe = match self.addr {
            IpAddr::V4(_) => match as_v4(addr) {
                Some(v4) => IpAddr::V4(v4),
                None => return false,
            },
            // A v6 block holds v6 addresses; the mapped case already went
            // through the v4 arm above, because a v4 block is what an operator
            // writes for a dual-stack proxy.
            IpAddr::V6(_) => *addr,
        };
        let net = self.addr;

        match (net, probe) {
            (IpAddr::V4(net), IpAddr::V4(probe)) => {
                mask_bytes(&net.octets(), &probe.octets(), self.prefix)
            }
            (IpAddr::V6(net), IpAddr::V6(probe)) => {
                mask_bytes(&net.octets(), &probe.octets(), self.prefix)
            }
            // Different families: a v6 block cannot contain a v4 address, and a
            // v4 block cannot contain a v6 one. The v4-mapped case was already
            // handled by `as_v4` above.
            _ => false,
        }
    }

    /// Parse `10.0.0.0/8`, `203.0.113.7`, `2001:db8::/32`, or `[::1]:8443`.
    ///
    /// The bracketed form is accepted because that is how an operator will
    /// naturally write an address they copied out of a URL.
    ///
    /// # Errors
    /// Anything that is not an address, an address with a port, or a block. The
    /// message names the offending string, because this runs at config-parse
    /// time and the operator is looking at a list of their own entries.
    pub fn parse(raw: &str) -> Result<Self, String> {
        let raw = raw.trim();
        if raw.is_empty() {
            return Err("an empty string is not an address or a block".to_owned());
        }

        // Strip an optional port. Two forms, because an operator copying an
        // address out of a URL will write whichever their tooling produced:
        //
        //   `[::1]:8443`  — bracketed v6, unambiguous, `]` is the boundary;
        //   `1.2.3.4:8080` — unbracketed v4, where the `:` must be a port and
        //                    not part of the address.
        //
        // The unbracketed case is only treated as a port when the text before
        // the **last** `:` already parses as an address. Otherwise
        // `2001:db8::1` — which has colons of its own — would be shredded.
        let (addr_part, rest) = match raw.strip_prefix('[') {
            Some(after) => match after.find(']') {
                Some(close) => (&after[..close], Some(&after[close + 1..])),
                None => return Err(format!("{raw:?} has an unclosed '['")),
            },
            None => match raw.rsplit_once(':') {
                Some((before, after))
                    if !after.contains(':')
                        && !after.is_empty()
                        && before.parse::<IpAddr>().is_ok() =>
                {
                    (before, Some(after))
                }
                _ => (raw, None),
            },
        };

        let (addr_str, prefix): (&str, Option<u8>) = match addr_part.split_once('/') {
            Some((a, p)) => {
                let prefix: u8 = p
                    .trim()
                    .parse()
                    .map_err(|_| format!("{raw:?} has a non-numeric prefix {p:?}"))?;
                (a.trim(), Some(prefix))
            }
            None => (addr_part, None),
        };

        let addr: IpAddr = addr_str
            .trim()
            .parse()
            .map_err(|_| format!("{addr_str:?} is not an IP address"))?;

        let net = match prefix {
            Some(prefix) => Self::new(addr, prefix)?,
            None => Self::host(addr),
        };

        // Whatever followed the `]` must be a port, and the port is ignored —
        // `trusted_proxies` is about who may send the header, not about which
        // port they connected to, since a proxy's source port is ephemeral.
        // The bracketed branch keeps the `:` (`[::1]:8443` → `:8443`); the
        // unbracketed branch does not (`1.2.3.4:8443` → `8443`). Tolerate both.
        if let Some(port) = rest {
            let port = port.trim().strip_prefix(':').unwrap_or(port).trim();
            if !port.is_empty() && port.parse::<u16>().is_err() {
                return Err(format!("{raw:?} has a non-numeric port {port:?}"));
            }
        }
        Ok(net)
    }

    /// Parse a whole list, reporting the first bad entry.
    ///
    /// # Errors
    /// The first entry that does not parse, with the index and the text.
    pub fn parse_list(raw: &[String]) -> Result<Vec<Self>, String> {
        raw.iter()
            .enumerate()
            .map(|(i, entry)| Self::parse(entry).map_err(|e| format!("trusted_proxies[{i}]: {e}")))
            .collect()
    }
}

/// Compare the first `prefix` bits of two equal-length octet arrays.
fn mask_bytes(a: &[u8], b: &[u8], prefix: u8) -> bool {
    let whole = (prefix / 8) as usize;
    let bits = prefix % 8;
    if a[..whole] != b[..whole] {
        return false;
    }
    if bits == 0 {
        return true;
    }
    let mask = 0xffu8 << (8 - bits);
    a[whole] & mask == b[whole] & mask
}

/// The bucket key for a rate limiter, or the reason there is not one.
///
/// `String` rather than an address because the rate limiters in this tree key
/// their maps on `String`, and because the "no peer" case has to share a bucket
/// with something.
pub type ClientIp = String;

/// The address to rate-limit by.
///
/// `peer` is the **immediate** connection peer, from `ConnectInfo`. `None`
/// means the transport has no peer address — a Unix socket, or an in-process
/// test — and the honest answer then is that no proxy can be involved, so
/// `X-Forwarded-For` is ignored.
///
/// `trusted` is `[tenancy] trusted_proxies`. **Empty means trust nobody**, and
/// that is the whole security property: a deployment that has not configured it
/// gets rate limiting by real peer address, which is correct but coarse behind a
/// proxy (every client shares the proxy's bucket), and a deployment that *has*
/// configured it gets the real address. The coarse case is loud rather than
/// silent — see [`warn_once_if_header_ignored`].
#[must_use]
pub fn client_ip(peer: Option<SocketAddr>, headers: &HeaderMap, trusted: &[IpNet]) -> ClientIp {
    let Some(peer) = peer else {
        return "<local>".to_owned();
    };
    let peer_ip = peer.ip();

    if trusted.is_empty() || !trusted.iter().any(|net| net.contains(&peer_ip)) {
        return peer_ip.to_string();
    }

    // The peer is a proxy we run, so the header is worth reading. Walk it right
    // to left and take the first address that is not itself one of ours.
    let Some(forwarded) = headers.get("x-forwarded-for") else {
        return peer_ip.to_string();
    };
    let Ok(forwarded) = forwarded.to_str() else {
        return peer_ip.to_string();
    };

    for entry in forwarded.split(',').rev() {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        let Ok(addr) = entry.parse::<IpAddr>() else {
            // A malformed entry ends the walk. Everything to its right is
            // already accounted for; everything to its left was written by a
            // party we have decided not to trust.
            return peer_ip.to_string();
        };
        if !trusted.iter().any(|net| net.contains(&addr)) {
            return addr.to_string();
        }
    }

    // Every hop was one of ours, so the leftmost entry is our own infrastructure
    // reporting itself. The peer is the best answer available.
    peer_ip.to_string()
}

/// Warn **once per process** that a forwarded header arrived from a peer that is
/// not configured as a proxy.
///
/// This exists because the fail-closed default has a real cost: a self-hosted
/// install behind nginx that never sets `trusted_proxies` will rate-limit every
/// client as one address, and will do so silently. The alternative — defaulting
/// to trusting the header — is the vulnerability. So the cost is paid in a log
/// line, and it is one line rather than one per request, because a rate limiter
/// that logs per request is its own denial of service.
///
/// Uses a `OnceLock` rather than a `log` dependency: `tracing` has no
/// "log this once" and adding one for a single call site is not worth it.
pub fn warn_once_if_header_ignored(
    headers: &HeaderMap,
    peer: Option<SocketAddr>,
    trusted: &[IpNet],
) {
    if headers.get("x-forwarded-for").is_none() {
        return;
    }
    let Some(peer) = peer else {
        return;
    };
    if trusted.iter().any(|net| net.contains(&peer.ip())) {
        return;
    }
    if WARNED.set(()).is_ok() {
        tracing::warn!(
            peer = %peer.ip(),
            "a request arrived with an X-Forwarded-For header from a peer that is not in \\
             [tenancy] trusted_proxies, so the header is being ignored. If this server is \\
             behind a reverse proxy, every client currently shares one rate-limit bucket. Add \\
             the proxy's address to [tenancy] trusted_proxies."
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net(raw: &str) -> IpNet {
        IpNet::parse(raw).expect("a valid net")
    }

    #[test]
    fn a_block_contains_its_own_addresses() {
        let block = net("10.0.0.0/8");
        for inside in ["10.0.0.1", "10.1.2.3", "10.255.255.255"] {
            assert!(
                block.contains(&inside.parse().expect("an address")),
                "{inside} should be in 10.0.0.0/8"
            );
        }
        for outside in ["11.0.0.1", "9.255.255.255", "192.168.1.1"] {
            assert!(
                !block.contains(&outside.parse().expect("an address")),
                "{outside} should not be in 10.0.0.0/8"
            );
        }
    }

    #[test]
    fn a_single_host_contains_only_itself() {
        let host = net("203.0.113.7");
        assert!(host.contains(&"203.0.113.7".parse().expect("an address")));
        assert!(!host.contains(&"203.0.113.8".parse().expect("an address")));
    }

    /// A prefix that is not a whole number of bytes: the partial byte has to be
    /// masked, and this is where a hand-rolled implementation usually is wrong.
    #[test]
    fn a_partial_byte_prefix_masks_correctly() {
        let block = net("203.0.113.0/24");
        assert!(block.contains(&"203.0.113.255".parse().expect("an address")));
        assert!(!block.contains(&"203.0.114.0".parse().expect("an address")));

        // /28: the last nibble of the fourth octet is the boundary.
        let block = net("203.0.113.0/28");
        assert!(block.contains(&"203.0.113.15".parse().expect("an address")));
        assert!(!block.contains(&"203.0.113.16".parse().expect("an address")));
    }

    #[test]
    fn a_zero_prefix_matches_everything_of_that_family() {
        let block = net("0.0.0.0/0");
        assert!(block.contains(&"1.2.3.4".parse().expect("an address")));
        assert!(block.contains(&"255.255.255.255".parse().expect("an address")));
        // …but not a v6 address: a v4 `/0` is not "all addresses".
        assert!(!block.contains(&"2001:db8::1".parse().expect("an address")));
    }

    #[test]
    fn ipv6_blocks_work() {
        let block = net("2001:db8::/32");
        assert!(block.contains(&"2001:db8:1234::1".parse().expect("an address")));
        assert!(!block.contains(&"2001:db9::1".parse().expect("an address")));

        let block = net("::1/128");
        assert!(block.contains(&"::1".parse().expect("an address")));
        assert!(!block.contains(&"::2".parse().expect("an address")));
    }

    /// A dual-stack proxy writes `::ffff:203.0.113.7`. If that missed a v4
    /// `trusted_proxies` entry the control would silently do nothing.
    #[test]
    fn a_v4_mapped_address_matches_a_v4_block() {
        let block = net("203.0.113.0/24");
        assert!(
            block.contains(&"::ffff:203.0.113.7".parse().expect("an address")),
            "a v4-mapped address must match the v4 block that contains it"
        );
        assert!(!block.contains(&"::ffff:198.51.100.1".parse().expect("an address")));
    }

    /// `::1` is a v6 loopback, not a mapped v4, and must not collapse into `0.0.0.1`.
    #[test]
    fn the_v6_loopback_is_not_a_mapped_v4() {
        let block = net("0.0.0.0/0");
        assert!(
            !block.contains(&"::1".parse().expect("an address")),
            "::1 must not be treated as 0.0.0.1"
        );
    }

    #[test]
    fn a_prefix_too_long_is_an_error_not_a_clamp() {
        let err = IpNet::new("10.0.0.0".parse().expect("an address"), 33).expect_err("must fail");
        assert!(err.contains("/32"), "{err}");
        let err = IpNet::new("::1".parse().expect("an address"), 129).expect_err("must fail");
        assert!(err.contains("/128"), "{err}");
    }

    /// The forms an operator actually writes. `[addr]/prefix` is deliberately
    /// **not** supported: it is not a shape anyone types, and supporting it would
    /// mean a second parse path through the bracket branch. `2001:db8::/32` is.
    #[test]
    fn ports_and_brackets_parse_and_are_ignored() {
        for raw in [
            "203.0.113.7",
            "203.0.113.7:8080",
            "203.0.113.0/24",
            "[::1]",
            "[::1]:8443",
            "2001:db8::1",
            "2001:db8::/32",
        ] {
            assert!(IpNet::parse(raw).is_ok(), "{raw:?} should parse");
        }
    }

    #[test]
    fn garbage_is_rejected_with_the_offending_text() {
        for raw in [
            "",
            "  ",
            "not-an-ip",
            "10.0.0.0/99",
            "10.0.0.0/abc",
            "1.2.3.4:99999",
        ] {
            assert!(IpNet::parse(raw).is_err(), "{raw:?} should be rejected");
        }
    }
}
