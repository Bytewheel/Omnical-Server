pub mod error;

use axum::Router;
use rustical_store::CalendarStore;
use rustical_store::{AddressbookStore, PrefixedCalendarStore, auth::AuthenticationProvider};
use std::sync::Arc;

mod collections;
mod groups;
mod members;
mod users;

pub struct ApiState<AP, CS, AS> {
    pub auth_provider: Arc<AP>,
    pub cal_store: Arc<CS>,
    pub addr_store: Arc<AS>,
}

impl<AP, CS, AS> Clone for ApiState<AP, CS, AS> {
    fn clone(&self) -> Self {
        Self {
            auth_provider: Arc::clone(&self.auth_provider),
            cal_store: Arc::clone(&self.cal_store),
            addr_store: Arc::clone(&self.addr_store),
        }
    }
}

impl<AP, CS, AS> ApiState<AP, CS, AS> {
    pub fn new(auth_provider: Arc<AP>, cal_store: Arc<CS>, addr_store: Arc<AS>) -> Self {
        Self {
            auth_provider,
            cal_store,
            addr_store,
        }
    }
}

pub fn api_router<
    AP: AuthenticationProvider,
    CS: CalendarStore,
    AS: AddressbookStore + PrefixedCalendarStore,
>(
    auth_provider: Arc<AP>,
    cal_store: Arc<CS>,
    addr_store: Arc<AS>,
) -> Router<()> {
    let state = ApiState::new(auth_provider, cal_store, addr_store);

    Router::new()
        .merge(groups::groups_router())
        .merge(members::members_router())
        .merge(users::users_router())
        .merge(collections::collections_router())
        .with_state(state)
}
