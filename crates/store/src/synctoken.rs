const SYNC_NAMESPACE: &str = "github.com/Bytewheel/Omnical/ns/";

/// Pre-rename namespaces, still accepted on the read path only.
///
/// RFC 6578 makes sync tokens opaque: a client echoes back whatever the
/// server last handed it, so every token minted before the Omnical rename is
/// still in the wild. Rejecting one does not fail the request — both callers
/// do `parse_synctoken(..).unwrap_or(0)`, which silently degrades to
/// `old_synctoken = 0` and re-sends the client's entire collection. Accepting
/// the legacy prefix keeps those syncs incremental; nothing is ever *emitted*
/// under these, so tokens migrate forward one round-trip at a time.
///
/// Safe to delete once no client can still hold a pre-rename token — i.e.
/// after the max sync-token lifetime of every deployed client has elapsed.
const LEGACY_SYNC_NAMESPACES: &[&str] = &["github.com/lennart-k/rustical/ns/"];

#[must_use]
pub fn format_synctoken(synctoken: i64) -> String {
    format!("{SYNC_NAMESPACE}{synctoken}")
}

#[must_use]
pub fn parse_synctoken(synctoken: &str) -> Option<i64> {
    let counter = std::iter::once(SYNC_NAMESPACE)
        .chain(LEGACY_SYNC_NAMESPACES.iter().copied())
        .find_map(|namespace| synctoken.strip_prefix(namespace))?;
    counter.parse::<i64>().ok()
}

#[cfg(test)]
mod tests {
    use super::{format_synctoken, parse_synctoken};

    const LEGACY: &str = "github.com/lennart-k/rustical/ns/";

    #[test]
    fn round_trips_current_namespace() {
        for n in [0, 1, 12, 297, i64::MAX] {
            assert_eq!(parse_synctoken(&format_synctoken(n)), Some(n));
        }
    }

    #[test]
    fn parses_legacy_token_to_same_counter() {
        assert_eq!(parse_synctoken(&format!("{LEGACY}297")), Some(297));
        assert_eq!(parse_synctoken(&format!("{LEGACY}0")), Some(0));
    }

    #[test]
    fn emits_only_the_current_namespace() {
        let token = format_synctoken(297);
        assert!(token.starts_with("github.com/Bytewheel/Omnical/ns/"));
        assert!(!token.contains("lennart-k"));
    }

    #[test]
    fn rejects_unknown_namespaces() {
        assert_eq!(parse_synctoken("github.com/otherproject/ns/5"), None);
        assert_eq!(parse_synctoken(""), None);
        assert_eq!(parse_synctoken("5"), None);
    }

    #[test]
    fn rejects_lookalike_prefixes() {
        // A namespace must match whole-segment: a client must not be able to
        // smuggle a counter past the prefix check.
        assert_eq!(parse_synctoken("github.com/Bytewheel/Omnical/ns2/5"), None);
        assert_eq!(parse_synctoken("github.com/Bytewheel/Omnical/ns/5x"), None);
        assert_eq!(parse_synctoken(&format!("{LEGACY}5x")), None);
        assert_eq!(parse_synctoken(&format!("{LEGACY} 5")), None);
        // Prefix with no counter at all.
        assert_eq!(parse_synctoken(LEGACY), None);
    }

    #[test]
    fn rejects_overflowing_counter() {
        assert_eq!(
            parse_synctoken("github.com/Bytewheel/Omnical/ns/99999999999999999999"),
            None
        );
    }

    /// Pre-existing behaviour, pinned rather than changed: the counter is
    /// whatever `i64::from_str` accepts, so a negative survives parsing. The
    /// changelog query is `synctoken > ?`, so a negative counter matches every
    /// row — the same full re-send the caller's `unwrap_or(0)` fallback already
    /// produces for an unparseable token. Not worth widening a rename's
    /// accept/reject surface to tighten.
    #[test]
    fn negative_counter_parses_and_resyncs() {
        assert_eq!(
            parse_synctoken("github.com/Bytewheel/Omnical/ns/-1"),
            Some(-1)
        );
        assert_eq!(
            parse_synctoken("github.com/lennart-k/rustical/ns/-1"),
            Some(-1)
        );
    }
}
