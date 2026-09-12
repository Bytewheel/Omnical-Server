use crate::error::Error;
use async_trait::async_trait;

/// A single-use registration invitation (Omnical registration extension).
///
/// The `code` is a short human-transcribable random string (12 chars,
/// unambiguous alphabet) that is typed/read aloud, unlike the 64-char token
/// shape. The code is the only credential of a registration, so redemption is
/// atomic and a code can be redeemed exactly once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invite {
    pub id: String,
    pub code: String,
    /// When set, only that exact email address may redeem the invite.
    pub target_email: Option<String>,
    /// Who issued the invite (an admin id or CLI marker).
    pub created_by: String,
    pub created_at: Option<String>,
    /// ISO 8601 UTC (`YYYY-MM-DDTHH:MM:SSZ`); the invite is unusable after it.
    pub expires_at: Option<String>,
    /// Set when the invite has been used (single-use).
    pub used_by: Option<String>,
    pub used_at: Option<String>,
}

/// Data access for single-use registration invitations (Omnical extension).
///
/// Timestamps are ISO 8601 UTC strings; stored `expires_at` values are
/// normalized to the same `YYYY-MM-DDTHH:MM:SSZ` shape so the expiry check in
/// `redeem_invite` is a plain string comparison.
///
/// This is implemented by the SQLite store. The default implementations are
/// no-ops/errors so other (test) stores keep compiling unchanged.
#[async_trait]
pub trait InviteStore: Send + Sync + 'static {
    /// Store a new invite. The caller generates the (unique) code.
    ///
    /// # Errors
    /// - [`Error::ReadOnly`] if the store does not implement invites
    /// - [`Error::AlreadyExists`] if the code is already in use
    async fn add_invite(
        &self,
        _code: &str,
        _target_email: &Option<String>,
        _created_by: &str,
        _expires_at: &Option<String>,
    ) -> Result<String, Error> {
        Err(Error::ReadOnly)
    }

    /// Look an invite up by its code, without consuming it. Used for the
    /// pre-redemption checks (code known vs unknown, email binding).
    ///
    /// # Errors
    /// Any store error (an unknown code is `Ok(None)`, not an error).
    async fn get_invite(&self, _code: &str) -> Result<Option<Invite>, Error> {
        Ok(None)
    }

    /// Atomically mark an invite as used.
    ///
    /// Succeeds only if the code exists, is still unused, and has not expired
    /// (expiry checked against the `now` timestamp, normalized to
    /// `YYYY-MM-DDTHH:MM:SSZ`). This is race-safe: two concurrent redemptions
    /// of the same code yield exactly one success.
    ///
    /// # Errors
    /// - [`Error::NotFound`] if the code is unknown, already used, or expired
    ///   (the registration endpoint maps this to a generic "invalid or expired
    ///   invitation code" response so the outcome does not leak)
    async fn redeem_invite(&self, _code: &str, _used_by: &str, _now: &str) -> Result<(), Error> {
        Err(Error::NotFound)
    }

    /// List invites, optionally including already-redeemed ones.
    ///
    /// # Errors
    /// Any store error (no invites is an empty list, not an error).
    async fn list_invites(&self, _include_used: bool) -> Result<Vec<Invite>, Error> {
        Ok(vec![])
    }

    /// Delete an invite by code (revoke before it is used).
    ///
    /// # Errors
    /// - [`Error::NotFound`] if no invite uses this code or the store does not
    ///   implement invites
    async fn delete_invite(&self, _code: &str) -> Result<(), Error> {
        Err(Error::NotFound)
    }
}
