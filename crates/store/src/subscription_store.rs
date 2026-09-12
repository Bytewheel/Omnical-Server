use crate::error::Error;
use async_trait::async_trait;

/// Which kind of collection a subscription exports (Omnical share-links
/// extension).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubscriptionKind {
    Calendar,
    Addressbook,
}

impl SubscriptionKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Calendar => "calendar",
            Self::Addressbook => "addressbook",
        }
    }
}

impl TryFrom<&str> for SubscriptionKind {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "calendar" => Ok(Self::Calendar),
            "addressbook" => Ok(Self::Addressbook),
            _ => Err(Error::Other(anyhow::anyhow!(
                "unknown subscription kind: '{value}'"
            ))),
        }
    }
}

/// A share-link subscription to one collection (Omnical extension).
///
/// The token is the only credential of the public export URL, so requests
/// carry no username and lookups happen by token alone. It is stored in
/// plaintext (see the `subscriptions` migration for the rationale).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subscription {
    pub id: String,
    pub principal: String,
    pub kind: SubscriptionKind,
    pub collection_id: String,
    pub token: String,
    pub created_at: Option<String>,
}

/// Data access for public read-only subscription feeds ("share links",
/// Omnical extension). The token in the export URL is the only credential.
///
/// This is implemented by the SQLite store. The default implementations are
/// no-ops/errors so other (test) stores keep compiling unchanged.
#[async_trait]
pub trait SubscriptionStore: Send + Sync + 'static {
    /// Store a subscription. The caller generates the token (64-char
    /// alphanumeric, the app-token shape). Duplicated tokens are rejected.
    ///
    /// # Errors
    /// - [`Error::ReadOnly`] if the store does not implement subscriptions
    /// - [`Error::AlreadyExists`] if the token is already in use
    async fn add_subscription(
        &self,
        _principal: &str,
        _kind: SubscriptionKind,
        _collection_id: &str,
        _token: &str,
    ) -> Result<String, Error> {
        Err(Error::ReadOnly)
    }

    /// Look a subscription up by the token of its export URL.
    ///
    /// # Errors
    /// - [`Error::NotFound`] if no subscription uses this token or the store
    ///   does not implement subscriptions
    async fn get_subscription_by_token(&self, _token: &str) -> Result<Subscription, Error> {
        Err(Error::NotFound)
    }

    /// List all subscriptions of a principal.
    ///
    /// # Errors
    /// Any store error (no subscriptions is an empty list, not an error).
    async fn get_subscriptions(&self, _principal: &str) -> Result<Vec<Subscription>, Error> {
        Ok(vec![])
    }

    /// Revoke a subscription (the export URL stops working immediately).
    ///
    /// # Errors
    /// - [`Error::NotFound`] if the principal has no subscription with this
    ///   id or the store does not implement subscriptions
    async fn delete_subscription(&self, _principal: &str, _id: &str) -> Result<(), Error> {
        Err(Error::NotFound)
    }
}
