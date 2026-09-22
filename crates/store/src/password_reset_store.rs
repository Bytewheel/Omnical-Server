use crate::error::Error;
use async_trait::async_trait;

/// A single-use password-reset token (Omnical password-reset extension).
///
/// The emailed link carries a 64-char random token; only its SHA-256 hex
/// digest is stored, so a database leak does not leave behind working reset
/// capabilities. Timestamps are ISO 8601 UTC strings normalized to
/// `YYYY-MM-DDTHH:MM:SSZ` (matching the invite store) so expiry checks are
/// plain string comparisons.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordReset {
    pub id: String,
    /// The principal (email address) the reset was minted for.
    pub principal_id: String,
    /// SHA-256 hex digest of the 64-char token from the emailed link.
    pub token_hash: String,
    pub created_at: Option<String>,
    /// ISO 8601 UTC (`YYYY-MM-DDTHH:MM:SSZ`); the token is unusable after it.
    pub expires_at: String,
    /// Set when the token has been used (single-use).
    pub used_at: Option<String>,
}

/// Data access for single-use password-reset tokens (Omnical extension).
///
/// This is implemented by the SQLite store. The default implementations are
/// no-ops/errors so other (test) stores keep compiling unchanged.
#[async_trait]
pub trait PasswordResetStore: Send + Sync + 'static {
    /// Store a new reset token, superseding every outstanding unused token
    /// of the same principal (a fresh request invalidates older links).
    ///
    /// # Errors
    /// - [`Error::ReadOnly`] if the store does not implement password resets
    /// - [`Error::AlreadyExists`] if the digest is already in use
    async fn add_reset(
        &self,
        _token_hash: &str,
        _principal_id: &str,
        _expires_at: &str,
        _now: &str,
    ) -> Result<String, Error> {
        Err(Error::ReadOnly)
    }

    /// Look a reset up by its token digest, without consuming it. Used for
    /// the pre-redemption display check (the redemption itself is atomic).
    ///
    /// # Errors
    /// Any store error (an unknown digest is `Ok(None)`, not an error).
    async fn get_reset(&self, _token_hash: &str) -> Result<Option<PasswordReset>, Error> {
        Ok(None)
    }

    /// Atomically mark a reset as used and return it.
    ///
    /// Succeeds only if the token exists, is still unused, and has not
    /// expired (expiry checked against the `now` timestamp, normalized to
    /// `YYYY-MM-DDTHH:MM:SSZ`). Race-safe like the invite redemption: two
    /// concurrent redemptions of the same token yield exactly one winner.
    /// A successful redemption also invalidates every other outstanding
    /// unused token of the same principal.
    ///
    /// # Errors
    /// - [`Error::NotFound`] if the token is unknown, already used, or
    ///   expired (the reset endpoints map this to a generic "invalid or
    ///   expired link" response so the outcome does not leak)
    async fn redeem_reset(&self, _token_hash: &str, _now: &str) -> Result<PasswordReset, Error> {
        Err(Error::NotFound)
    }
}
