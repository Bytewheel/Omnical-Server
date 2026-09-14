pub mod middleware;
mod principal;
use crate::error::Error;
use async_trait::async_trait;

mod principal_type;
pub use principal_type::*;

mod error;
pub use error::UnauthorizedError;

pub use principal::{AppToken, Principal};

/// The `AuthenticationProvider` is the principal store for rustical.
#[async_trait]
pub trait AuthenticationProvider: Send + Sync + 'static {
    /// Returns a list of all principals
    async fn get_principals(&self) -> Result<Vec<Principal>, Error>;

    /// Returns a principal by its `id` as an `Option<Principal>`.
    /// If the principal does not exist `Ok(None)` is returned.
    async fn get_principal(&self, id: &str) -> Result<Option<Principal>, Error>;

    async fn remove_principal(&self, id: &str) -> Result<(), Error>;

    /// Inserts a principal and upserts it if `overwrite=true`.
    /// Ignores `Principal.membership` field which is instead managed
    /// via the `*_membership´ methods.
    async fn insert_principal(&self, user: Principal, overwrite: bool) -> Result<(), Error>;

    /// Validates a password input for a principal.
    /// If the password input is correct returns `Ok(Some(principal))`.
    async fn validate_password(
        &self,
        user_id: &str,
        password_input: &str,
    ) -> Result<Option<Principal>, Error> {
        let user: Principal = match self.get_principal(user_id).await? {
            Some(user) => user,
            None => return Ok(None),
        };
        let Some(password) = &user.password else {
            return Ok(None);
        };

        if password_auth::verify_password(password_input, password.as_ref()).is_ok() {
            return Ok(Some(user));
        }
        Ok(None)
    }

    /// Validates an app token for a given principal id.
    async fn validate_app_token(
        &self,
        user_id: &str,
        token: &str,
    ) -> Result<Option<Principal>, Error> {
        // Allow to specify the token id to use to make validation faster
        // Doesn't match the whole length of the token id to keep the length in bounds
        // Example: asd_selgkh
        // where the app token id starts with asd and its value is selgkh
        let (token_id_prefix, token) = token.split_once('_').unwrap_or(("", token));

        for app_token in &self.get_app_tokens(user_id).await? {
            // Wrong token id
            if !app_token.id.starts_with(token_id_prefix) {
                continue;
            }
            if password_auth::verify_password(token, app_token.token.as_ref()).is_ok() {
                return self.get_principal(user_id).await;
            }
        }
        Ok(None)
    }

    /// Returns a token identifier
    async fn add_app_token(
        &self,
        user_id: &str,
        name: String,
        token: String,
    ) -> Result<String, Error>;
    async fn remove_app_token(&self, user_id: &str, token_id: &str) -> Result<(), Error>;

    async fn get_app_tokens(&self, principal: &str) -> Result<Vec<AppToken>, Error>;

    async fn add_membership(&self, principal: &str, member_of: &str) -> Result<(), Error>;

    async fn remove_membership(&self, principal: &str, member_of: &str) -> Result<(), Error>;

    /// Updates a principal's stored password hash. Used by the portal
    /// password-change flow (and anything else that must rotate a password
    /// without touching the rest of the principal).
    ///
    /// # Errors
    /// - [`Error::ReadOnly`] if the store does not implement password updates
    async fn update_password(&self, _principal: &str, _password_hash: &str) -> Result<(), Error> {
        Err(Error::ReadOnly)
    }

    /// Gets the `needs_password_change` flag of a principal.
    ///
    /// # Errors
    /// Any store error.
    async fn get_needs_password_change(&self, _principal: &str) -> Result<bool, Error> {
        Ok(false)
    }

    /// Sets the `needs_password_change` flag of a principal (forced
    /// password-change nudge, cleared by the store when the password is
    /// updated). The default is a no-op so non-SQLite (test) stores keep
    /// compiling; the SQLite store persists the change.
    ///
    /// # Errors
    /// Any store error.
    async fn set_needs_password_change(&self, _principal: &str, _value: bool) -> Result<(), Error> {
        Ok(())
    }

    async fn list_members(&self, principal: &str) -> Result<Vec<String>, Error>;

    async fn list_groups_for_user(&self, user_id: &str) -> Result<Vec<(String, String)>, Error> {
        let _ = user_id;
        Ok(Vec::new())
    }

    async fn get_group_owner(&self, group_id: &str) -> Result<Option<String>, Error> {
        let _ = group_id;
        Ok(None)
    }

    async fn set_group_owner(&self, group_id: &str, owner_id: &str) -> Result<(), Error> {
        let _ = (group_id, owner_id);
        Ok(())
    }

    async fn search_users(&self, query: &str) -> Result<Vec<(String, String)>, Error> {
        let _ = query;
        Ok(Vec::new())
    }
}

pub use middleware::AuthenticationMiddleware;
