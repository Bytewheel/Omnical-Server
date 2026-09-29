#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
pub mod addressbook;
pub mod addressbook_store;
mod calendar_source_store;
pub mod calendar_store;
pub mod error;
pub use error::Error;
pub mod actor;
pub mod admin_store;
pub mod auth;
mod calendar;
mod collection_share_store;
mod combined_calendar_store;
mod invite_store;
mod password_reset_store;
mod scheduling_store;
mod secret;
mod subscription_store;
pub mod synctoken;
pub mod tenant;
pub mod tenant_store;

#[cfg(test)]
pub mod tests;

pub use actor::Actor;
pub use addressbook_store::*;
pub use admin_store::{AdminCredential, AdminStanding};
pub use calendar_source_store::*;
pub use calendar_store::*;
pub use collection_share_store::*;
pub use combined_calendar_store::{CombinedCalendarStore, PrefixedCalendarStore};
pub use invite_store::*;
pub use password_reset_store::*;
pub use scheduling_store::*;
pub use secret::Secret;
pub use subscription_store::*;
pub use tenant::{Tenant, TenantId, TenantStatus};
pub use tenant_store::{NewTenant, TenantQuota, TenantStore};

pub use addressbook::Addressbook;
pub use calendar::{Calendar, CalendarMetadata};

#[derive(Debug, Clone)]
pub enum CollectionOperationInfo {
    // Sync-Token increased
    Content { sync_token: String },
    // Collection deleted
    Delete,
}

#[derive(Debug, Clone)]
pub struct CollectionOperation {
    pub topic: String,
    pub data: CollectionOperationInfo,
}

#[derive(Default, Debug, Clone)]
pub struct CollectionMetadata {
    pub len: usize,
    pub deleted_len: usize,
    pub size: u64,
    pub deleted_size: u64,
}
