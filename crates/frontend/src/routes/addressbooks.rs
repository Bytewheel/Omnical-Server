use askama::Template;
use askama_web::WebTemplate;
use axum::{
    Extension,
    extract::{Form, Path},
    response::{IntoResponse, Redirect, Response},
};
use axum_extra::TypedHeader;
use headers::Host;
use http::StatusCode;
use rustical_scheduling::{SmtpAccount, mime, smtp};
use rustical_store::{
    Addressbook, AddressbookStore, Calendar, CollectionMetadata, CollectionShareStore,
    PrefixedCalendarStore, SubscriptionKind, SubscriptionStore,
    auth::{AuthenticationProvider, Principal, PrincipalType, Privilege},
};
use serde::Deserialize;
use std::sync::Arc;
use uuid::Uuid;

use crate::pages::user::{Section, UserPage};
use crate::routes::app_token::generate_app_token;
use crate::routes::calendar::{GuestShareEntry, resolve_base_url};
use crate::url_builder::export_url;

impl Section for AddressbooksSection {
    fn name() -> &'static str {
        "addressbooks"
    }
}

/// One addressbook tile of the Addressbooks screen: the rendered addressbook
/// plus its credential-less share-link data (PLAN.md §17.15 — the addressbook
/// half of the old Share tab's share-link block) and its minted full-access
/// `CardDAV` credentials (`PLAN_NEXT_AGENT_WEB_CALENDAR_UI.md` — the addressbook
/// counterpart of the calendar "Generate credentials", §17.12.1).
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
    /// True when the acting user may mint/revoke full-access credentials for
    /// the tile (owner, or admin of the owning group — §17.12.1).
    pub can_generate: bool,
    /// Active full-access credentials minted for this addressbook (§17.12.1),
    /// each with its own Revoke control.
    pub guest_shares: Vec<GuestShareEntry>,
}

#[derive(Template, WebTemplate)]
#[template(path = "components/sections/addressbooks_section.html")]
pub struct AddressbooksSection {
    pub user: Principal,
    pub addressbooks: Vec<AddressbookTile>,
    pub deleted_addressbooks: Vec<(CollectionMetadata, Option<Calendar>, Addressbook)>,
    pub carddav_url: String,
    /// §17.12.1: just-minted credential banner (server URL / username / app
    /// token), shown once.
    pub credential_server_url: Option<String>,
    pub credential_username: Option<String>,
    pub credential_token: Option<String>,
    pub credential_addressbook_id: Option<String>,
    pub credential_email: Option<String>,
    pub error: Option<String>,
}

/// One-time banner payloads of the Addressbooks screen — all `None` on a plain
/// page load; the credentials POST sets exactly the credential fields.
#[derive(Default)]
pub struct AddressbooksExtras {
    pub error: Option<String>,
    pub credential_server_url: Option<String>,
    pub credential_username: Option<String>,
    pub credential_token: Option<String>,
    pub credential_addressbook_id: Option<String>,
    pub credential_email: Option<String>,
}

/// The shared Addressbooks-screen renderer: lists the user's addressbooks
/// with their share-link and credential blocks plus an error banner (§17.15,
/// §17.12.1).
#[allow(clippy::too_many_lines)]
pub async fn render_addressbooks_page<AS: AddressbookStore + PrefixedCalendarStore>(
    addr_store: &Arc<AS>,
    share_store: &Arc<dyn CollectionShareStore>,
    sub_store: Option<&Arc<dyn SubscriptionStore>>,
    base_url: &str,
    user: &Principal,
    extras: AddressbooksExtras,
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
        // §17.12.1: credential minting is member management — owner, or
        // `admin` privilege in the owning group.
        let can_generate =
            addressbook.principal == user.id || user.is_admin(&addressbook.principal);
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
        let guest_shares = share_store
            .get_shares_for_collection(&addressbook.principal, &addressbook.id)
            .await
            .unwrap_or_default()
            .into_iter()
            .map(|share| GuestShareEntry {
                share_id: share.id,
                guest_principal: share.guest_principal,
                privilege: share.privilege.as_str(),
                target_email: share.target_email,
                created_at: share.created_at,
                can_manage: can_generate,
            })
            .collect();
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
            can_generate,
            guest_shares,
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

    let AddressbooksExtras {
        error,
        credential_server_url,
        credential_username,
        credential_token,
        credential_addressbook_id,
        credential_email,
    } = extras;

    UserPage {
        section: AddressbooksSection {
            user: user.clone(),
            addressbooks: addressbook_infos,
            deleted_addressbooks: deleted_addressbook_infos,
            carddav_url: format!("{base_url}/carddav"),
            credential_server_url,
            credential_username,
            credential_token,
            credential_addressbook_id,
            credential_email,
            error,
        },
        user: user.clone(),
    }
    .into_response()
}

pub async fn route_addressbooks<AS: AddressbookStore + PrefixedCalendarStore>(
    Path(user_id): Path<String>,
    Extension(addr_store): Extension<Arc<AS>>,
    Extension(share_store): Extension<Arc<dyn CollectionShareStore>>,
    Extension(sub_store): Extension<Option<Arc<dyn SubscriptionStore>>>,
    Extension(public_url): Extension<String>,
    TypedHeader(host): TypedHeader<Host>,
    user: Principal,
) -> impl IntoResponse {
    if user_id != user.id {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let base_url = resolve_base_url(&public_url, &host);
    render_addressbooks_page(
        &addr_store,
        &share_store,
        sub_store.as_ref(),
        &base_url,
        &user,
        AddressbooksExtras::default(),
    )
    .await
}

#[derive(Debug, Clone, Deserialize)]
pub struct AddressbookCredentialsForm {
    /// The owner principal of the addressbook (`user`'s own id, or a group the
    /// user admins).
    pub principal: String,
    pub addressbook_id: String,
    /// Optional delivery target; stored for audit and emailed when SMTP is
    /// configured (same behavior as the calendar credentials).
    #[serde(default)]
    pub email: Option<String>,
}

/// POST /{user}/addressbook/credentials — mint full-access (`admin`)
/// `CardDAV` credentials for one addressbook and show them once on the
/// Addressbooks screen (Omnical §17.12.1, the addressbook counterpart of the
/// calendar "Generate credentials").
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub async fn route_addressbook_credentials<
    AP: AuthenticationProvider,
    AS: AddressbookStore + PrefixedCalendarStore,
>(
    Path(user_id): Path<String>,
    Extension(auth_provider): Extension<Arc<AP>>,
    Extension(addr_store): Extension<Arc<AS>>,
    Extension(share_store): Extension<Arc<dyn CollectionShareStore>>,
    Extension(sub_store): Extension<Option<Arc<dyn SubscriptionStore>>>,
    Extension(public_url): Extension<String>,
    Extension(smtp_accounts): Extension<Vec<SmtpAccount>>,
    TypedHeader(host): TypedHeader<Host>,
    user: Principal,
    Form(form): Form<AddressbookCredentialsForm>,
) -> Response {
    if user_id != user.id {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    let base_url = resolve_base_url(&public_url, &host);

    // Only the owner — or a group admin — may mint credentials for a group
    // addressbook; the minted credential always carries `admin` privilege
    // (§17.12.1, same ownership rule as the calendar credentials).
    if form.principal != user.id && !user.is_admin(&form.principal) {
        return (
            StatusCode::FORBIDDEN,
            "You can only generate credentials for your own or your groups' addressbooks.",
        )
            .into_response();
    }

    let page_error = |error: String| {
        let addr_store = addr_store.clone();
        let share_store = share_store.clone();
        let sub_store = sub_store.clone();
        let base_url = base_url.clone();
        let user = user.clone();
        async move {
            render_addressbooks_page(
                &addr_store,
                &share_store,
                sub_store.as_ref(),
                &base_url,
                &user,
                AddressbooksExtras {
                    error: Some(error),
                    ..AddressbooksExtras::default()
                },
            )
            .await
        }
    };

    if form.addressbook_id.is_empty() {
        return page_error("No addressbook specified.".to_owned()).await;
    }

    // Fail fast on a wrong addressbook id (same discipline as the calendar
    // credentials route).
    if addr_store
        .get_addressbook(&form.principal, &form.addressbook_id, false)
        .await
        .is_err()
    {
        return page_error(format!(
            "No such addressbook '{}' for '{}'.",
            form.addressbook_id, form.principal
        ))
        .await;
    }

    // Validate the optional email (same as the calendar credentials).
    let email: Option<String> = match form
        .email
        .as_deref()
        .map(str::trim)
        .filter(|e| !e.is_empty())
    {
        Some(e) if !e.contains('@') => {
            return page_error("Please enter a valid email address.".to_owned()).await;
        }
        Some(e) => Some(e.to_lowercase()),
        None => None,
    };

    // 1. Create the guest principal (no portal password, no memberships).
    let guest_id = format!("guest-{}", Uuid::new_v4());
    if let Err(err) = auth_provider
        .insert_principal(
            Principal {
                id: guest_id.clone(),
                displayname: Some(format!("Guest of {}", form.addressbook_id)),
                memberships: vec![],
                password: None,
                principal_type: PrincipalType::Individual,
                needs_password_change: false,
                privileges: std::collections::BTreeMap::new(),
            },
            false,
        )
        .await
    {
        return page_error(format!("Could not create guest principal: {err}")).await;
    }

    // 2. Mint an app token → the DAV credential (`{id4}_{secret}`).
    let token_secret = generate_app_token();
    let mut token_id = match auth_provider
        .add_app_token(
            &guest_id,
            format!("{} guest", form.addressbook_id),
            token_secret.clone(),
        )
        .await
    {
        Ok(id) => id,
        Err(err) => {
            return page_error(format!("Could not mint app token: {err}")).await;
        }
    };
    token_id.truncate(4);
    let credential = format!("{token_id}_{token_secret}");

    // 3. Persist the share row — always `admin` (full read/write/admin).
    if let Err(err) = share_store
        .add_share(
            &form.principal,
            &form.addressbook_id,
            "addressbook",
            Privilege::Admin,
            &guest_id,
            &email,
            &user.id,
        )
        .await
    {
        return page_error(format!("Could not create addressbook credential: {err}")).await;
    }

    let server_url = format!("{base_url}/carddav");

    // 4. Optionally deliver the credential by email (same as the calendar
    //    credentials: without SMTP the mint still succeeds; the share row
    //    keeps `target_email` for audit, the credential stays in the banner).
    if let (Some(to), Some(account)) = (email.as_deref(), smtp_accounts.first()) {
        let message = mime::build_guest_invite(
            account,
            to,
            &server_url,
            &guest_id,
            &credential,
            &form.addressbook_id,
            &user.id,
            None,
        );
        let account = account.clone();
        let to = to.to_owned();
        tokio::spawn(async move {
            match smtp::send_mail(&account, &account.identity, &to, &message).await {
                Ok(()) => tracing::debug!("emailed addressbook credentials to {to}"),
                Err(err) => {
                    tracing::warn!("could not email addressbook credentials: {err}");
                }
            }
        });
    }

    render_addressbooks_page(
        &addr_store,
        &share_store,
        sub_store.as_ref(),
        &base_url,
        &user,
        AddressbooksExtras {
            credential_server_url: Some(server_url),
            credential_username: Some(guest_id),
            credential_token: Some(credential),
            credential_addressbook_id: Some(form.addressbook_id),
            credential_email: email,
            ..AddressbooksExtras::default()
        },
    )
    .await
}

#[derive(Debug, Clone, Deserialize)]
pub struct AddressbookCredentialsRevokeForm {
    /// The owner principal of the addressbook the credential was minted for
    /// (used for the ownership gate, same as minting).
    pub principal: String,
}

/// POST /{user}/addressbook/credentials/{id}/revoke — revoke an active
/// full-access credential minted on the Addressbooks screen. Owner /
/// group-admin only, same rule as minting.
pub async fn route_addressbook_credentials_revoke(
    Path((user_id, share_id)): Path<(String, String)>,
    Extension(share_store): Extension<Arc<dyn CollectionShareStore>>,
    user: Principal,
    Form(form): Form<AddressbookCredentialsRevokeForm>,
) -> Response {
    if user_id != user.id {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let owned = form.principal == user.id || user.is_admin(&form.principal);
    if !owned {
        return (
            StatusCode::FORBIDDEN,
            "You can only revoke credentials of your own or your groups' addressbooks.",
        )
            .into_response();
    }
    let _ = share_store.revoke_share(&share_id).await;
    Redirect::to(&format!("/frontend/user/{}/addressbook", user.id)).into_response()
}
