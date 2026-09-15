use crate::auth::Privilege;
use crate::error::Error;
use async_trait::async_trait;

/// A per-collection guest share (Omnical §17.10 extension).
///
/// One row maps exactly one guest principal (a lightweight `guest-{ulid}`
/// `Individual` without a portal password) to exactly one (owner,
/// collection) pair with a `view`/`edit`/`admin` privilege. The guest
/// authenticates via DAV Basic auth using an app token minted for the guest
/// principal; the `collection_shares` row is the ACL that resolves a guest
/// request to the owner's stored collection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectionShare {
    pub id: String,
    pub owner_principal: String,
    pub collection_id: String,
    /// `"calendar"` | `"addressbook"` — which kind of collection the share
    /// grants access to.
    pub kind: String,
    /// `view`/`edit`/`admin` (see [`Privilege::can_write`]).
    pub privilege: Privilege,
    pub guest_principal: String,
    /// Optional email delivery target; stored for audit even when SMTP is not
    /// configured (the email is then not sent).
    pub target_email: Option<String>,
    /// Who issued the share (an admin id or CLI marker).
    pub created_by: String,
    pub created_at: Option<String>,
    /// Set when the share was revoked. Revoked rows never resolve access.
    pub revoked_at: Option<String>,
}

/// Data access for per-collection guest shares (Omnical extension).
///
/// Implemented by the SQLite store alongside `SqliteCalendarStore` (shares
/// live in the same database). The default implementations are
/// no-ops/errors so other (test) stores keep compiling unchanged.
#[async_trait]
pub trait CollectionShareStore: Send + Sync + 'static {
    /// Store a new share. The caller generates the guest principal id
    /// (`guest-{ulid}`) and mints the guest's app token.
    ///
    /// # Errors
    /// - [`Error::ReadOnly`] if the store does not implement shares
    /// - [`Error::AlreadyExists`] if a share already exists for the guest
    #[allow(clippy::too_many_arguments)]
    async fn add_share(
        &self,
        _owner_principal: &str,
        _collection_id: &str,
        _kind: &str,
        _privilege: Privilege,
        _guest_principal: &str,
        _target_email: &Option<String>,
        _created_by: &str,
    ) -> Result<String, Error> {
        Err(Error::ReadOnly)
    }

    /// Look a share up by its guest principal (active shares only).
    ///
    /// # Errors
    /// Any store error (an unknown guest is `Ok(None)`, not an error).
    async fn get_share_by_guest(&self, _guest_id: &str) -> Result<Option<CollectionShare>, Error> {
        Ok(None)
    }

    /// List active shares for one collection.
    ///
    /// # Errors
    /// Any store error (no shares is an empty list, not an error).
    async fn get_shares_for_collection(
        &self,
        _owner_principal: &str,
        _collection_id: &str,
    ) -> Result<Vec<CollectionShare>, Error> {
        Ok(vec![])
    }

    /// Revoke a share (sets `revoked_at`; the row stays for audit).
    ///
    /// # Errors
    /// - [`Error::NotFound`] if no active share uses this id
    async fn revoke_share(&self, _share_id: &str) -> Result<(), Error> {
        Err(Error::NotFound)
    }

    /// List all active shares issued by one owner.
    ///
    /// # Errors
    /// Any store error (no shares is an empty list, not an error).
    async fn list_guest_shares(
        &self,
        _owner_principal: &str,
    ) -> Result<Vec<CollectionShare>, Error> {
        Ok(vec![])
    }
}
