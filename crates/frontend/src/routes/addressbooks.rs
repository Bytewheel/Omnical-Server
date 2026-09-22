use askama::Template;
use askama_web::WebTemplate;
use axum::{
    Extension,
    extract::Path,
    response::{IntoResponse, Response},
};
use axum_extra::TypedHeader;
use headers::Host;
use http::StatusCode;
use rustical_store::{
    Addressbook, AddressbookStore, Calendar, CollectionMetadata, PrefixedCalendarStore,
    SubscriptionKind, SubscriptionStore, auth::Principal,
};
use std::sync::Arc;

use crate::pages::user::{Section, UserPage};
use crate::url_builder::export_url;

impl Section for AddressbooksSection {
    fn name() -> &'static str {
        "addressbooks"
    }
}

/// One addressbook tile of the Addressbooks screen: the rendered addressbook
/// plus its credential-less share-link data (PLAN.md §17.15 — the addressbook
/// half of the old Share tab's share-link block; invites and guest shares are
/// calendar-only).
pub struct AddressbookTile {
    pub meta: CollectionMetadata,
    pub birthday_cal: Option<Calendar>,
    pub addressbook: Addressbook,
    /// The addressbook's share-link URL (`/export/{token}.vcf`), when a
    /// subscription exists — `None` otherwise.
    pub subscribe_url: Option<String>,
    /// Subscription id of the share link (for Revoke).
    pub sub_id: Option<String>,
    /// When the share link was minted.
    pub sub_created_at: Option<String>,
    /// True when the acting user may create the share link here (owner, or
    /// `edit`/`admin` of the owning group — §17.9.2).
    pub can_subscribe: bool,
}

#[derive(Template, WebTemplate)]
#[template(path = "components/sections/addressbooks_section.html")]
pub struct AddressbooksSection {
    pub user: Principal,
    pub addressbooks: Vec<AddressbookTile>,
    pub deleted_addressbooks: Vec<(CollectionMetadata, Option<Calendar>, Addressbook)>,
    pub error: Option<String>,
}

/// Resolve the base URL share links are printed with: the configured
/// `[subscriptions] public_url`, else the request's own host.
fn resolve_base_url(public_url: &str, host: &Host) -> String {
    if public_url.is_empty() {
        format!("https://{host}")
    } else {
        public_url.to_owned()
    }
}

/// The shared Addressbooks-screen renderer: lists the user's addressbooks
/// with their share-link blocks plus an error banner (§17.15).
pub async fn render_addressbooks_page<AS: AddressbookStore + PrefixedCalendarStore>(
    addr_store: &Arc<AS>,
    sub_store: Option<&Arc<dyn SubscriptionStore>>,
    base_url: &str,
    user: &Principal,
    error: Option<String>,
) -> Response {
    let mut addressbooks = vec![];
    for group in user.memberships() {
        addressbooks.extend(addr_store.get_addressbooks(group).await.unwrap());
    }

    let mut addressbook_infos = vec![];
    for addressbook in addressbooks {
        let birthday_id = format!("{}{}", AS::PREFIX, addressbook.id);
        let birthday_cal = match addr_store
            .get_calendar(&addressbook.principal, &birthday_id, true)
            .await
        {
            Ok(cal) => Some(cal),
            Err(rustical_store::Error::NotFound) => None,
            err => Some(err.unwrap()),
        };
        let can_subscribe = sub_store.is_some() && user.can_write(&addressbook.principal);
        let sub = match sub_store {
            Some(store) => store
                .get_subscriptions(&addressbook.principal)
                .await
                .unwrap_or_default()
                .into_iter()
                .find(|s| {
                    s.kind == SubscriptionKind::Addressbook && s.collection_id == addressbook.id
                }),
            None => None,
        };
        addressbook_infos.push(AddressbookTile {
            meta: addr_store
                .addressbook_metadata(&addressbook.principal, &addressbook.id)
                .await
                .unwrap(),
            birthday_cal,
            addressbook,
            subscribe_url: sub.as_ref().map(|s| export_url(base_url, &s.token, s.kind)),
            sub_id: sub.as_ref().map(|s| s.id.clone()),
            sub_created_at: sub.and_then(|s| s.created_at),
            can_subscribe,
        });
    }

    let mut deleted_addressbooks = vec![];
    for group in user.memberships() {
        deleted_addressbooks.extend(addr_store.get_deleted_addressbooks(group).await.unwrap());
    }

    let mut deleted_addressbook_infos = vec![];
    for addressbook in deleted_addressbooks {
        let birthday_id = format!("{}{}", AS::PREFIX, addressbook.id);
        let birthday_cal = match addr_store
            .get_calendar(&addressbook.principal, &birthday_id, true)
            .await
        {
            Ok(cal) => Some(cal),
            Err(rustical_store::Error::NotFound) => None,
            err => Some(err.unwrap()),
        };
        deleted_addressbook_infos.push((
            addr_store
                .addressbook_metadata(&addressbook.principal, &addressbook.id)
                .await
                .unwrap(),
            birthday_cal,
            addressbook,
        ));
    }

    UserPage {
        section: AddressbooksSection {
            user: user.clone(),
            addressbooks: addressbook_infos,
            deleted_addressbooks: deleted_addressbook_infos,
            error,
        },
        user: user.clone(),
    }
    .into_response()
}

pub async fn route_addressbooks<AS: AddressbookStore + PrefixedCalendarStore>(
    Path(user_id): Path<String>,
    Extension(addr_store): Extension<Arc<AS>>,
    Extension(sub_store): Extension<Option<Arc<dyn SubscriptionStore>>>,
    Extension(public_url): Extension<String>,
    TypedHeader(host): TypedHeader<Host>,
    user: Principal,
) -> impl IntoResponse {
    if user_id != user.id {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let base_url = resolve_base_url(&public_url, &host);
    render_addressbooks_page(&addr_store, sub_store.as_ref(), &base_url, &user, None).await
}
