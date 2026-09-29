//! Who performed a control-plane change — `PLAN_DEPLOYMENTS.md` §6.6.7.
//!
//! ## Why this is a type and not a `&str`
//!
//! Row 33 wants `actor` on every audit row, and the design's rule is that **a
//! mutating action which cannot be attributed does not happen**. That rule is
//! only enforceable if "cannot be attributed" is unrepresentable, so the
//! constructor is the only way to make an `Actor` and it rejects an empty name.
//! A bare `&str` parameter would put the check at every call site, and one of
//! them would eventually be the one that forgot.
//!
//! ## Where an actor comes from
//!
//! - **The panel**: the authenticated admin's name, from the allowlist.
//! - **The CLI**: `--actor`, defaulting to `$OMNICAL_ACTOR`, then `$SUDO_USER`,
//!   then `$USER`. If none of those is set, the command **refuses** — the
//!   fallbacks mean ordinary use is unchanged, and the refusal means the audit
//!   trail cannot silently contain an empty actor.
//!
//! The fallbacks are *not* authentication and are not treated as it: `$USER` is
//! whatever the caller set, so it records "who the shell said this was", which is
//! the honest claim. A panel action, by contrast, is attributable to a
//! credential that was verified against a hash.

use std::fmt;

/// Longest actor name. Bounded because the value is interpolated into log lines
/// and rendered in an audit view; an unbounded one is a log-injection vector.
pub const MAX_ACTOR_LEN: usize = 128;

/// The identity that performed a control-plane mutation.
///
/// Construction validates, so an `Actor` in hand is always attributable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Actor(String);

impl Actor {
    /// # Errors
    /// If the name is empty, longer than [`MAX_ACTOR_LEN`], or contains a control
    /// character. Control characters are refused because this value is written
    /// into a log line and rendered into an HTML audit view, and a name
    /// containing a newline or an escape is how a log line becomes a forged one.
    pub fn new(name: impl Into<String>) -> Result<Self, String> {
        let name = name.into();
        let trimmed = name.trim();
        if trimmed.is_empty() {
            return Err(
                "an actor must be named: a change that cannot be attributed \
                        does not happen"
                    .to_owned(),
            );
        }
        if trimmed.chars().count() > MAX_ACTOR_LEN {
            return Err(format!(
                "an actor name is limited to {MAX_ACTOR_LEN} characters, got {}",
                trimmed.chars().count()
            ));
        }
        if trimmed.chars().any(char::is_control) {
            return Err(
                "an actor name may not contain control characters: it is written to a log line \
                 and rendered in the audit view"
                    .to_owned(),
            );
        }
        Ok(Self(trimmed.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Actor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for Actor {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::{Actor, MAX_ACTOR_LEN};

    #[test]
    fn a_plain_name_is_accepted() {
        assert_eq!(Actor::new("ops").expect("a name").as_str(), "ops");
    }

    #[test]
    fn whitespace_is_trimmed_rather_than_rejected() {
        // An env var with a trailing newline is a normal accident, not an
        // attack; trimming it is friendlier than refusing.
        assert_eq!(Actor::new("  ops\n").expect("a name").as_str(), "ops");
    }

    #[test]
    fn an_unattributable_action_cannot_be_represented() {
        // This is the whole reason `Actor` exists rather than a `&str`.
        for bad in ["", "   ", "\t", "\n", "ops\nroot:x:0:0"] {
            assert!(Actor::new(bad).is_err(), "{bad:?} should be refused");
        }
    }

    #[test]
    fn an_embedded_control_character_is_refused() {
        // A name that can forge a log line is a name that can make the audit
        // trail lie about who did something.
        assert!(Actor::new("ops\u{1b}[31m").is_err());
    }

    #[test]
    fn an_over_long_name_is_refused() {
        assert!(Actor::new("x".repeat(MAX_ACTOR_LEN + 1)).is_err());
        assert!(Actor::new("x".repeat(MAX_ACTOR_LEN)).is_ok());
    }
}
