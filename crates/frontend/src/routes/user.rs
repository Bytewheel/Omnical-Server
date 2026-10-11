use std::{convert::Infallible, sync::Arc};

use crate::pages::user::{Section, UserPage};
use crate::routes::addressbooks::{AddressbooksExtras, build_addressbooks_section};
use crate::routes::calendar::{CalendarsExtras, build_calendars_section, resolve_base_url};
use crate::routes::download::HawkBookApk;
use crate::routes::groups::build_groups_section;
use crate::routes::linked_platforms::build_linked_platforms_section;
use askama::Template;
use askama_web::WebTemplate;
use axum::{
    extract::{FromRequestParts, Path},
    response::{IntoResponse, Redirect, Response},
};
use axum_extra::TypedHeader;
use axum_extra::typed_header::TypedHeaderRejection;
use headers::{HeaderMapExt, Host, UserAgent};
use http::{HeaderMap, StatusCode, request::Parts};
use rustical_store::{
    AddressbookStore, CalendarSourceStore, CalendarStore, CollectionShareStore, InviteStore,
    PrefixedCalendarStore, SubscriptionStore,
    auth::{AppToken, AuthenticationProvider, Principal},
};

impl Section for ProfileSection {
    fn name() -> &'static str {
        "profile"
    }
}

/// A just-regenerated app token shown once on the profile page: the token's
/// (unchanged) name plus the new secret — old one-time banner pattern, same
/// as the calendars credentials.
pub struct RegeneratedToken {
    pub name: String,
    pub token: String,
}

/// The collapsible profile section a legacy tab URL pre-expands.
///
/// The former Calendars / Addressbooks / Groups / Linked-platforms pages are
/// collapsible sections of the profile page now; their URLs stay valid as
/// deep links (old bookmarks, the frozen integration suite, and the POST
/// redirects that anchor a tile), and each renders this very page with its
/// section expanded.
#[derive(Clone, Copy, Default)]
pub enum ProfileAnchor {
    /// The plain profile URL: every section renders collapsed.
    #[default]
    None,
    Calendars,
    Addressbooks,
    Groups,
    LinkedPlatforms,
}

/// One-time banners carried by a profile render, per embedded section. All
/// default on a plain page load; each minting POST sets exactly the fields of
/// the section it was posted from, and a section holding a banner renders
/// expanded so a one-time secret cannot be missed inside a collapsed heading.
#[derive(Default)]
pub struct ProfileExtras {
    pub anchor: ProfileAnchor,
    /// The regenerate route's one-time app-token banner.
    pub regenerated: Option<RegeneratedToken>,
    /// The Calendars section's banners (credentials, invites, errors).
    pub calendars: CalendarsExtras,
    /// The Addressbooks section's banners (credentials, errors).
    pub addressbooks: AddressbooksExtras,
    /// The Linked-platforms section's error banner.
    pub linked_platforms_error: Option<String>,
}

/// Every store the unified profile page reads. An extractor so the deep-link
/// GETs and the banner-re-rendering POSTs take one argument instead of eight
/// `Extension`s; every field is layered onto the user router by
/// `frontend_router`, exactly as the individual handlers used to extract it.
pub struct ProfileDeps<AP, CS, AS> {
    pub auth_provider: Arc<AP>,
    pub cal_store: Arc<CS>,
    pub addr_store: Arc<AS>,
    pub share_store: Arc<dyn CollectionShareStore>,
    pub sub_store: Option<Arc<dyn SubscriptionStore>>,
    pub invite_store: Arc<dyn InviteStore>,
    pub source_store: Arc<dyn CalendarSourceStore>,
}

// Hand-rolled because `#[derive(Clone)]` would bound `AP`/`CS`/`AS` by
// `Clone` — the stores are not `Clone`, only their `Arc`s are.
impl<AP, CS, AS> Clone for ProfileDeps<AP, CS, AS> {
    fn clone(&self) -> Self {
        Self {
            auth_provider: Arc::clone(&self.auth_provider),
            cal_store: Arc::clone(&self.cal_store),
            addr_store: Arc::clone(&self.addr_store),
            share_store: Arc::clone(&self.share_store),
            sub_store: self.sub_store.clone(),
            invite_store: Arc::clone(&self.invite_store),
            source_store: Arc::clone(&self.source_store),
        }
    }
}

/// `parts.extensions.get::<Arc<T>>().cloned()`, with the message that makes a
/// None mean what it is: a wiring bug in `frontend_router`, not a user error.
fn layered<T>(parts: &Parts) -> Arc<T>
where
    T: ?Sized + Send + Sync + 'static,
{
    parts
        .extensions
        .get::<Arc<T>>()
        .cloned()
        .expect("every profile store is layered by frontend_router")
}

// `async` with no `.await` — the values are already in the request
// extensions; removing `async` would change axum's trait signature (the same
// `#[allow]` pair as the `PeerAddr` extractor in client_ip.rs).
#[allow(unknown_lints, clippy::unknown_lints)]
#[allow(clippy::unused_async_trait_impl)]
impl<AP, CS, AS, S> FromRequestParts<S> for ProfileDeps<AP, CS, AS>
where
    AP: AuthenticationProvider,
    CS: CalendarStore,
    AS: AddressbookStore + PrefixedCalendarStore,
    S: Send + Sync,
{
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        Ok(Self {
            auth_provider: layered::<AP>(parts),
            cal_store: layered::<CS>(parts),
            addr_store: layered::<AS>(parts),
            share_store: layered::<dyn CollectionShareStore>(parts),
            sub_store: parts
                .extensions
                .get::<Option<Arc<dyn SubscriptionStore>>>()
                .cloned()
                .expect("frontend_router layers the subscription store"),
            invite_store: layered::<dyn InviteStore>(parts),
            source_store: layered::<dyn CalendarSourceStore>(parts),
        })
    }
}

/// The request-scoped inputs of the profile page: the `[subscriptions]
/// public_url` (else the request's own `Host`), the headers (the Android
/// user-agent check of the `HawkBook` link), and the `HawkBook` APK's `sha256`
/// from the startup read. Extracted as one unit for the same reason as
/// [`ProfileDeps`].
///
/// `host` is `None` for a request that carried no `Host` header **and** has
/// a configured `public_url` (in-process test requests are shaped like that,
/// and the configured public URL wins over the request's own host anyway).
/// A request with neither keeps the old bare-`TypedHeader<Host>` behaviour
/// of the handlers that needed the host: rejected, because the page would
/// print its endpoints from it.
#[derive(Clone)]
pub struct ProfileRequest {
    pub public_url: String,
    pub host: Option<Host>,
    pub headers: HeaderMap,
    pub hawkbook_apk_sha256: Option<String>,
}

impl<S: Send + Sync> FromRequestParts<S> for ProfileRequest {
    type Rejection = TypedHeaderRejection;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let host = TypedHeader::<Host>::from_request_parts(parts, state).await;
        let public_url = parts
            .extensions
            .get::<String>()
            .cloned()
            .expect("frontend_router layers the subscriptions public URL");
        let host = match host {
            Ok(TypedHeader(host)) => Some(host),
            Err(rejection) if public_url.is_empty() => return Err(rejection),
            Err(_) => None,
        };
        Ok(Self {
            public_url,
            host,
            headers: parts.headers.clone(),
            hawkbook_apk_sha256: parts
                .extensions
                .get::<Option<HawkBookApk>>()
                .cloned()
                .flatten()
                .map(|apk| apk.sha256_hex()),
        })
    }
}

/// One embedded section of the profile page: its pre-rendered HTML plus
/// whether the collapsible heading renders expanded.
pub struct ProfileSectionHtml {
    pub html: String,
    pub open: bool,
}

#[derive(Template, WebTemplate)]
#[template(path = "components/sections/profile_section.html")]
pub struct ProfileSection {
    pub user: Principal,
    pub app_tokens: Vec<AppToken>,
    /// Hostname for the Android deep link (the `at.bitfire.davdroid` package
    /// and `davx5` scheme are what the stock app and our HawkBook/DavX fork
    /// both register, so one link serves both).
    pub hawkbook_hostname: Option<String>,
    /// `CalDAV` endpoint printed in the per-client instructions.
    pub caldav_url: String,
    /// `CardDAV` endpoint printed in the per-client instructions.
    pub carddav_url: String,
    /// One-time banner payload of a Regenerate action (`None` on a plain
    /// page load).
    pub regenerated: Option<RegeneratedToken>,
    /// sha256 of the `HawkBook` APK this deployment serves at
    /// `/frontend/download/hawkbook.apk`, straight from the startup read
    /// (`HawkBookApk`), so the intro prints a checksum the download route
    /// provably serves. `None` ⇒ unconfigured (or unreadable at startup):
    /// no link, no checksum.
    pub hawkbook_apk_sha256: Option<String>,
    /// Whether the App-tokens heading renders expanded (the regenerated
    /// banner forces it).
    pub app_tokens_open: bool,
    pub calendars: ProfileSectionHtml,
    pub addressbooks: ProfileSectionHtml,
    pub groups: ProfileSectionHtml,
    pub linked_platforms: ProfileSectionHtml,
}

/// The shared profile-page renderer: the page that used to be five tabs
/// (profile, Calendars, Addressbooks, Groups, Linked platforms). Every
/// section renders inside its own collapsible heading; the `extras` banners
/// and the deep-link `anchor` decide which headings render expanded.
pub async fn render_profile_page<
    AP: AuthenticationProvider,
    CS: CalendarStore,
    AS: AddressbookStore + PrefixedCalendarStore,
>(
    deps: &ProfileDeps<AP, CS, AS>,
    req: &ProfileRequest,
    user: &Principal,
    extras: ProfileExtras,
) -> Response {
    let ProfileExtras {
        anchor,
        regenerated,
        calendars: calendars_extras,
        addressbooks: addressbooks_extras,
        linked_platforms_error,
    } = extras;

    let app_tokens_open = regenerated.is_some();

    let hawkbook_hostname = req
        .headers
        .typed_get::<UserAgent>()
        .is_some_and(|ua| ua.as_str().contains("Android"))
        .then_some(req.host.as_ref())
        .flatten()
        .map(ToString::to_string);

    let base_url = resolve_base_url(&req.public_url, req.host.as_ref());

    // A section holding a one-time banner renders expanded, as does the
    // section a legacy tab URL deep-links into: a banner the user cannot see
    // is not shown, and an anchor inside a collapsed `<details>` cannot
    // scroll anywhere.
    let calendars_open =
        matches!(anchor, ProfileAnchor::Calendars) || calendars_extras.has_banner();
    let addressbooks_open =
        matches!(anchor, ProfileAnchor::Addressbooks) || addressbooks_extras.has_banner();
    let groups_open = matches!(anchor, ProfileAnchor::Groups);
    let linked_platforms_open =
        matches!(anchor, ProfileAnchor::LinkedPlatforms) || linked_platforms_error.is_some();

    let calendars_section = build_calendars_section(
        &deps.cal_store,
        &deps.share_store,
        deps.sub_store.as_ref(),
        &deps.invite_store,
        &base_url,
        user,
        calendars_extras,
    )
    .await;
    let addressbooks_section = build_addressbooks_section(
        &deps.addr_store,
        &deps.share_store,
        deps.sub_store.as_ref(),
        &base_url,
        user,
        addressbooks_extras,
    )
    .await;
    let groups_section =
        build_groups_section(&deps.auth_provider, &deps.cal_store, &deps.addr_store, user).await;
    let linked_platforms_section = build_linked_platforms_section(
        &deps.cal_store,
        &deps.source_store,
        user,
        linked_platforms_error,
    )
    .await;

    // Askama `render` only fails on writer errors, and the writer is a
    // `String`; every branch below is the same "cannot fail in practice"
    // `unwrap` as the AppleConfig render in app_token.rs.
    let profile_section = ProfileSection {
        user: user.clone(),
        app_tokens: deps.auth_provider.get_app_tokens(&user.id).await.unwrap(),
        hawkbook_hostname,
        caldav_url: format!("{base_url}/caldav"),
        carddav_url: format!("{base_url}/carddav"),
        regenerated,
        hawkbook_apk_sha256: req.hawkbook_apk_sha256.clone(),
        app_tokens_open,
        calendars: ProfileSectionHtml {
            html: calendars_section.render().unwrap(),
            open: calendars_open,
        },
        addressbooks: ProfileSectionHtml {
            html: addressbooks_section.render().unwrap(),
            open: addressbooks_open,
        },
        groups: ProfileSectionHtml {
            html: groups_section.render().unwrap(),
            open: groups_open,
        },
        linked_platforms: ProfileSectionHtml {
            html: linked_platforms_section.render().unwrap(),
            open: linked_platforms_open,
        },
    };

    UserPage {
        section: profile_section,
        user: user.clone(),
    }
    .into_response()
}

pub async fn route_user_named<
    AP: AuthenticationProvider,
    CS: CalendarStore,
    AS: AddressbookStore + PrefixedCalendarStore,
>(
    Path(user_id): Path<String>,
    deps: ProfileDeps<AP, CS, AS>,
    req: ProfileRequest,
    user: Principal,
) -> impl IntoResponse {
    if user_id != user.id {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    render_profile_page(&deps, &req, &user, ProfileExtras::default()).await
}

pub async fn route_get_home(user: Principal) -> Redirect {
    Redirect::to(&format!("/frontend/user/{}", user.id))
}

pub async fn route_root(user: Option<Principal>) -> Redirect {
    match user {
        Some(user) => route_get_home(user).await,
        None => Redirect::to("/frontend/login"),
    }
}
