use crate::{
    Secret,
    auth::{PrincipalType, Privilege, UnauthorizedError},
};
use axum::extract::{FromRequestParts, OptionalFromRequestParts};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::convert::Infallible;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AppToken {
    pub id: String,
    pub name: String,
    pub token: Secret<String>,
    pub created_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Principal {
    pub id: String,
    pub displayname: Option<String>,
    #[serde(default)]
    pub principal_type: PrincipalType,
    #[serde(skip_serializing)]
    pub password: Option<Secret<String>>,
    #[serde(default)]
    pub memberships: Vec<String>,
    /// When set, the next portal login must show a forced password-change
    /// page before any other portal section. Used for the one-time nudge on a
    /// user's first-ever calendar/group join; cleared once the password is
    /// changed.
    #[serde(default)]
    pub needs_password_change: bool,
    /// Per-group privileges of the memberships (Omnical §17.9.2): maps a
    /// group principal id to the [`Privilege`] the user holds there. Loaded
    /// by the store; a missing entry means the pre-privilege default
    /// ([`Privilege::Edit`]). When a user impersonates `user$group` the auth
    /// middleware stamps the impersonated principal with `{group: privilege}`
    /// so write checks inherit the acting user's privilege.
    #[serde(default, skip_serializing)]
    pub privileges: BTreeMap<String, Privilege>,
}

impl Principal {
    /// Returns true if the user is either
    /// - the principal itself
    /// - has full access to the prinicpal (is member)
    #[must_use]
    pub fn is_principal(&self, principal: &str) -> bool {
        if self.id == principal {
            return true;
        }
        self.memberships
            .iter()
            .any(|membership| membership == principal)
    }

    /// Returns all principals the user implements
    pub fn memberships(&self) -> Vec<&str> {
        std::iter::once(self.id.as_str())
            .chain(self.memberships.iter().map(String::as_ref))
            .collect()
    }

    pub fn memberships_without_self(&self) -> Vec<&str> {
        self.memberships.iter().map(String::as_str).collect()
    }

    /// The privilege the user holds over `principal`: `Admin` over
    /// themselves, their stored privilege for memberships (defaulting to
    /// `Edit`), `View` for principals they have no access to at all.
    #[must_use]
    pub fn privilege_for(&self, principal: &str) -> Privilege {
        if self.id == principal {
            return self
                .privileges
                .get(principal)
                .copied()
                .unwrap_or(Privilege::Admin);
        }
        if self.memberships.iter().any(|m| m == principal) {
            return self
                .privileges
                .get(principal)
                .copied()
                .unwrap_or(Privilege::Edit);
        }
        Privilege::View
    }

    /// Whether the user may modify the collections of `principal` (own
    /// collections, or memberships with `edit`/`admin` privilege).
    #[must_use]
    pub fn can_write(&self, principal: &str) -> bool {
        self.privilege_for(principal).can_write()
    }

    /// Whether the user may manage `principal`'s members (invites, privilege
    /// and membership changes): themselves, or a membership with `admin`
    /// privilege.
    #[must_use]
    pub fn is_admin(&self, principal: &str) -> bool {
        self.privilege_for(principal).can_admin()
    }
}

impl rustical_dav::Principal for Principal {
    fn get_id(&self) -> &str {
        &self.id
    }
}

impl<S: Send + Sync + Clone> FromRequestParts<S> for Principal {
    type Rejection = UnauthorizedError;

    async fn from_request_parts(
        parts: &mut http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<Self>()
            .cloned()
            .ok_or(UnauthorizedError)
    }
}

impl<S: Send + Sync + Clone> OptionalFromRequestParts<S> for Principal {
    type Rejection = Infallible;

    async fn from_request_parts(
        parts: &mut http::request::Parts,
        _state: &S,
    ) -> Result<Option<Self>, Self::Rejection> {
        Ok(parts.extensions.get::<Self>().cloned())
    }
}
