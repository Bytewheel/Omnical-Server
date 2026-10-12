#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::missing_errors_doc, clippy::missing_panics_doc)]
use axum::{Extension, Router};
use derive_more::Constructor;
use http::Uri;
use principal::PrincipalResourceService;
use rustical_dav::resource::{PrincipalUri, ResourceService};
use rustical_dav::resources::RootResourceService;
use rustical_dav::rfc_3986_percent_encode;
use rustical_dav_push::DavPushStore;
use rustical_scheduling::Scheduler;
use rustical_store::CalendarStore;
use rustical_store::auth::middleware::AuthenticationLayer;
use rustical_store::auth::{AuthenticationProvider, Principal};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

mod dailyview;

pub mod calendar;
pub mod calendar_object;
pub mod error;
pub mod principal;
pub mod scheduling;
pub use error::Error;

#[derive(Debug, Clone, Constructor)]
pub struct CalDavPrincipalUri(&'static str);

impl PrincipalUri for CalDavPrincipalUri {
    fn principal_collection(&self) -> Uri {
        Uri::builder()
            .path_and_query(format!("{}/principal/", self.0))
            .build()
            .unwrap()
    }
    fn principal_uri(&self, principal: &str) -> Uri {
        let principal = rfc_3986_percent_encode(principal);
        Uri::builder()
            .path_and_query(format!("{}{}/", self.principal_collection(), principal))
            .build()
            .unwrap()
    }
}

pub fn caldav_router<AP: AuthenticationProvider, C: CalendarStore, DP: DavPushStore>(
    prefix: &'static str,
    auth_provider: Arc<AP>,
    store: Arc<C>,
    dav_push_store: Arc<DP>,
    simplified_home_set: bool,
    config: Arc<CalDavConfig>,
    scheduler: Option<Arc<Scheduler>>,
) -> Router {
    Router::new().nest(
        prefix,
        RootResourceService::<_, Principal, CalDavPrincipalUri>::new(PrincipalResourceService {
            auth_provider: auth_provider.clone(),
            dav_push_store,
            cal_store: store,
            simplified_home_set,
            config,
            scheduler,
        })
        .axum_router()
        .layer(AuthenticationLayer::new(auth_provider))
        .layer(Extension(CalDavPrincipalUri(prefix))),
    )
}

const fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct CalDavConfig {
    #[serde(default = "default_true")]
    rfc7809: bool,
    /// Omnical: the timezone for the `DailyView` (Punkt MP02) shim — see the
    /// `dailyview` module. Arms both wire rewrites for that client's
    /// User-Agent (all-day events served as local-midnight DATE-TIMEs;
    /// recurring events served as their first in-window occurrence) on the
    /// GET and REPORT paths. Absent (the default) disables the rewrites, and
    /// every client receives the canonical data.
    #[serde(default)]
    dailyview_timezone: Option<String>,
}

impl CalDavConfig {
    /// A config with the `DailyView` all-day shim armed for `timezone` — the
    /// cross-crate constructor the shim's tests use (`rfc7809` stays
    /// upstream's private field, so functional record update does not
    /// compile outside this crate).
    #[must_use]
    pub fn with_dailyview_timezone(timezone: &str) -> Self {
        Self {
            dailyview_timezone: Some(timezone.to_owned()),
            ..Self::default()
        }
    }

    /// The armed `DailyView`-shim timezone, if any (see the `dailyview`
    /// module).
    #[must_use]
    pub fn dailyview_timezone(&self) -> Option<&str> {
        self.dailyview_timezone.as_deref()
    }
}

impl Default for CalDavConfig {
    fn default() -> Self {
        Self {
            rfc7809: true,
            dailyview_timezone: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::CalDavPrincipalUri;
    use rustical_dav::resource::PrincipalUri;

    #[rstest::rstest]
    #[case("user", "/caldav/principal/user/")]
    #[case("user with space", "/caldav/principal/user%20with%20space/")]
    #[case("asd@asd.de", "/caldav/principal/asd%40asd.de/")]
    fn test_principal_uri_encoding(#[case] principal: &str, #[case] output: &str) {
        assert_eq!(
            CalDavPrincipalUri("/caldav").principal_uri(principal),
            output
        );
    }
}
