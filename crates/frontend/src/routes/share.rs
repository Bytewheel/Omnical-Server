use std::{str::FromStr, sync::Arc};

use crate::pages::user::{Section, UserPage};
use crate::url_builder::export_url;
use askama::Template;
use askama_web::WebTemplate;
use axum::extract::Path;
use axum::response::{IntoResponse, Redirect, Response};
use axum::{Extension, Form};
use axum_extra::extract::TypedHeader;
use headers::Host;
use http::StatusCode;
use rustical_scheduling::{SmtpAccount, mime, smtp};
use rustical_store::{
    AddressbookStore, CalendarStore, CollectionShareStore, Invite, InviteStore, SubscriptionKind,
    SubscriptionStore,
    auth::{AuthenticationProvider, Principal, Privilege},
};
use serde::Deserialize;
use uuid::Uuid;

use super::app_token::generate_app_token;

impl Section for ShareSection {
    fn name() -> &'static str {
        "share"
    }
}

/// One unredeemed registration invite link shown on the collection tile it
/// was minted for (PLAN.md §17.9.1).
pub struct InviteLink {
    pub code: String,
    /// Full `{base}/register?code=…` URL.
    pub url: String,
    /// The email the invite is bound to, if any.
    pub invited_email: Option<String>,
    pub created_at: Option<String>,
}

/// One active guest share on a calendar tile (Omnical §17.10): the guest
/// username and their privilege level, with revoke for admins.
pub struct GuestShareEntry {
    pub share_id: String,
    pub guest_principal: String,
    /// `view`/`edit`/`admin` (see [`Privilege::can_write`]).
    pub privilege: &'static str,
    /// The email the credential was delivered to, if any.
    pub target_email: Option<String>,
    pub created_at: Option<String>,
    /// Whether the acting user may revoke (or mint) guest shares here:
    /// `admin` privilege in the owning principal (same rule as invites).
    pub can_manage: bool,
}

/// One shareable collection row of the Share page: the existing share link
/// with its full export URL (plus Revoke), or a "Create share link" button
/// when none exists yet (PLAN.md §17.8.4).
pub struct ShareEntry {
    /// Display name of the collection.
    pub displayname: String,
    /// Owner label: the user's own id, or the group's display name.
    pub owner_label: String,
    /// The principal the collection (and its subscription) belongs to.
    pub principal: String,
    /// `calendar` or `addressbook`.
    pub kind: &'static str,
    pub collection_id: String,
    /// Full export URL — `None` when no share link exists yet.
    pub url: Option<String>,
    /// Subscription id (needed by Revoke) — `None` when no share link exists.
    pub sub_id: Option<String>,
    pub created_at: Option<String>,
    /// Unredeemed registration invite links minted for this collection.
    pub invites: Vec<InviteLink>,
    /// Active guest shares on this collection (calendar tiles only).
    pub guest_shares: Vec<GuestShareEntry>,
    /// Whether the acting user may mint invites for this tile: always true
    /// for their own collections, otherwise `admin` privilege in the group
    /// (Omnical §17.9.2).
    pub can_invite: bool,
}

#[derive(Template, WebTemplate)]
#[template(path = "components/sections/share_section.html")]
pub struct ShareSection {
    pub user: Principal,
    pub entries: Vec<ShareEntry>,
    /// Whether the subscriptions extension is enabled (share links servable).
    pub enabled: bool,
    pub error: Option<String>,
    /// When set, show the newly created invite link.
    pub invite_url: Option<String>,
    pub invited_email: Option<String>,
    /// When set, show a just-minted guest credential (one-time banner).
    pub guest_share_server_url: Option<String>,
    pub guest_share_username: Option<String>,
    pub guest_share_credential: Option<String>,
    pub guest_share_calendar_id: Option<String>,
    /// The principal the just-minted credential is bound to (to locate the
    /// correct tile on the Share page).
    pub guest_share_principal: Option<String>,
    /// The `target_email` the just-minted credential is bound to (for the
    /// banner copy), if one was provided.
    pub guest_share_email: Option<String>,
    /// When set, show the just-minted invite link inside the matching tile.
    pub invite_collection_id: Option<String>,
    /// The principal the invite was created for (to locate the correct tile).
    pub invite_principal: Option<String>,
}

/// The principals whose collections this user may share: their own, plus
/// every group where they hold `edit`/`admin` privilege (Omnical §17.9.2 —
/// `view` members can read the collections but neither create share links
/// nor invites).
async fn shareable_principals<AP: AuthenticationProvider>(
    auth_provider: &Arc<AP>,
    user: &Principal,
) -> Vec<(String, String)> {
    let mut principals = vec![(user.id.clone(), user.id.clone())];
    for (group_id, displayname) in auth_provider
        .list_groups_for_user(&user.id)
        .await
        .unwrap_or_default()
    {
        if user.can_write(&group_id) {
            principals.push((group_id, displayname));
        }
    }
    principals
}

/// The unredeemed invite links of a collection tile, if the invite store is
/// present: invites are attributed per tile via `collection_id` (+ `kind`);
/// group-collection invites carry the group as `target_group`, own-collection
/// invites carry none (PLAN.md §17.9.1).
fn tile_invite_links(
    invites: &[Invite],
    principal: &str,
    user: &Principal,
    collection_id: &str,
    base_url: &str,
) -> Vec<InviteLink> {
    invites
        .iter()
        .filter(|invite| {
            invite.kind.as_deref() == Some("calendar")
                && invite.collection_id.as_deref() == Some(collection_id)
                && if principal == user.id {
                    invite.target_group.is_none()
                } else {
                    invite.target_group.as_deref() == Some(principal)
                }
        })
        .map(|invite| InviteLink {
            code: invite.code.clone(),
            url: format!("{base_url}/register?code={}", invite.code),
            invited_email: invite.target_email.clone(),
            created_at: invite.created_at.clone(),
        })
        .collect()
}

async fn build_share_entries<
    AP: AuthenticationProvider,
    CS: CalendarStore,
    AS: AddressbookStore,
>(
    auth_provider: &Arc<AP>,
    cal_store: &Arc<CS>,
    addr_store: &Arc<AS>,
    sub_store: Option<&Arc<dyn SubscriptionStore>>,
    invite_store: Option<&Arc<dyn InviteStore>>,
    share_store: Option<&Arc<dyn CollectionShareStore>>,
    user: &Principal,
    base_url: &str,
) -> Vec<ShareEntry> {
    let mut entries = Vec::new();
    let invites = match invite_store {
        Some(store) => store.list_invites(false).await.unwrap_or_default(),
        None => vec![],
    };
    for (principal, owner_label) in shareable_principals(auth_provider, user).await {
        let subscriptions = match sub_store {
            Some(store) => store
                .get_subscriptions(&principal)
                .await
                .unwrap_or_default(),
            None => vec![],
        };
        let can_invite = principal == user.id || user.is_admin(&principal);

        for cal in cal_store
            .get_calendars(&principal)
            .await
            .unwrap_or_default()
        {
            let sub = subscriptions
                .iter()
                .find(|s| s.kind == SubscriptionKind::Calendar && s.collection_id == cal.id);
            let guest_shares = match share_store {
                Some(store) => store
                    .get_shares_for_collection(&principal, &cal.id)
                    .await
                    .unwrap_or_default()
                    .into_iter()
                    .map(|share| GuestShareEntry {
                        share_id: share.id,
                        guest_principal: share.guest_principal,
                        privilege: share.privilege.as_str(),
                        target_email: share.target_email,
                        created_at: share.created_at,
                        can_manage: can_invite,
                    })
                    .collect(),
                None => Vec::new(),
            };
            entries.push(ShareEntry {
                displayname: cal
                    .meta
                    .displayname
                    .clone()
                    .unwrap_or_else(|| cal.id.clone()),
                owner_label: owner_label.clone(),
                principal: principal.clone(),
                kind: "calendar",
                collection_id: cal.id.clone(),
                url: sub.map(|s| export_url(base_url, &s.token, s.kind)),
                sub_id: sub.map(|s| s.id.clone()),
                created_at: sub.and_then(|s| s.created_at.clone()),
                invites: tile_invite_links(&invites, &principal, user, &cal.id, base_url),
                guest_shares,
                can_invite,
            });
        }

        for ab in addr_store
            .get_addressbooks(&principal)
            .await
            .unwrap_or_default()
        {
            let sub = subscriptions
                .iter()
                .find(|s| s.kind == SubscriptionKind::Addressbook && s.collection_id == ab.id);
            entries.push(ShareEntry {
                displayname: ab.displayname.clone().unwrap_or_else(|| ab.id.clone()),
                owner_label: owner_label.clone(),
                principal: principal.clone(),
                kind: "addressbook",
                collection_id: ab.id.clone(),
                url: sub.map(|s| export_url(base_url, &s.token, s.kind)),
                sub_id: sub.map(|s| s.id.clone()),
                created_at: sub.and_then(|s| s.created_at.clone()),
                // Invites are calendar-only today (§17.9.1).
                invites: Vec::new(),
                // Guest shares are calendar-only too (§17.10).
                guest_shares: Vec::new(),
                can_invite,
            });
        }
    }
    entries
}

/// Resolve the base URL share links are printed with: the configured
/// `[subscriptions] public_url` (passed in by `make_app`, computed with the
/// same `public_base_url` as the CLI), else the request's own host.
fn resolve_base_url(public_url: &str, host: &Host) -> String {
    if public_url.is_empty() {
        format!("https://{host}")
    } else {
        public_url.to_owned()
    }
}

#[allow(clippy::too_many_arguments)]
async fn share_page<AP: AuthenticationProvider, CS: CalendarStore, AS: AddressbookStore>(
    auth_provider: &Arc<AP>,
    cal_store: &Arc<CS>,
    addr_store: &Arc<AS>,
    sub_store: Option<&Arc<dyn SubscriptionStore>>,
    invite_store: Option<&Arc<dyn InviteStore>>,
    share_store: Option<&Arc<dyn CollectionShareStore>>,
    public_url: &str,
    host: &Host,
    user: &Principal,
    error: Option<String>,
) -> Response {
    let base_url = resolve_base_url(public_url, host);
    let entries = build_share_entries(
        auth_provider,
        cal_store,
        addr_store,
        sub_store,
        invite_store,
        share_store,
        user,
        &base_url,
    )
    .await;
    UserPage {
        section: ShareSection {
            user: user.clone(),
            entries,
            enabled: sub_store.is_some(),
            error,
            invite_url: None,
            invited_email: None,
            guest_share_server_url: None,
            guest_share_username: None,
            guest_share_credential: None,
            guest_share_calendar_id: None,
            guest_share_principal: None,
            guest_share_email: None,
            invite_collection_id: None,
            invite_principal: None,
        },
        user: user.clone(),
    }
    .into_response()
}

#[allow(clippy::too_many_arguments)]
pub async fn route_get_share<
    AP: AuthenticationProvider,
    CS: CalendarStore,
    AS: AddressbookStore,
>(
    Path(user_id): Path<String>,
    Extension(auth_provider): Extension<Arc<AP>>,
    Extension(cal_store): Extension<Arc<CS>>,
    Extension(addr_store): Extension<Arc<AS>>,
    Extension(sub_store): Extension<Option<Arc<dyn SubscriptionStore>>>,
    Extension(invite_store): Extension<Arc<dyn InviteStore>>,
    Extension(share_store): Extension<Arc<dyn CollectionShareStore>>,
    Extension(public_url): Extension<String>,
    TypedHeader(host): TypedHeader<Host>,
    user: Principal,
) -> Response {
    if user_id != user.id {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    share_page(
        &auth_provider,
        &cal_store,
        &addr_store,
        sub_store.as_ref(),
        Some(&invite_store),
        Some(&share_store),
        &public_url,
        &host,
        &user,
        None,
    )
    .await
}

#[derive(Debug, Clone, Deserialize)]
pub struct CreateShareForm {
    pub principal: String,
    pub kind: String,
    pub collection_id: String,
}

/// POST /{user}/share/create — mint a share link for one of the user's own
/// or owned-group collections. The token is the app-token shape (64-char
/// alphanumeric); the URL is byte-identical to the `subscriptions add` CLI
/// (same token shape, same shared `export_url` builder).
#[allow(clippy::too_many_arguments)]
pub async fn route_share_create<
    AP: AuthenticationProvider,
    CS: CalendarStore,
    AS: AddressbookStore,
>(
    Path(user_id): Path<String>,
    Extension(auth_provider): Extension<Arc<AP>>,
    Extension(cal_store): Extension<Arc<CS>>,
    Extension(addr_store): Extension<Arc<AS>>,
    Extension(sub_store): Extension<Option<Arc<dyn SubscriptionStore>>>,
    Extension(invite_store): Extension<Arc<dyn InviteStore>>,
    Extension(share_store): Extension<Arc<dyn CollectionShareStore>>,
    Extension(public_url): Extension<String>,
    TypedHeader(host): TypedHeader<Host>,
    user: Principal,
    Form(form): Form<CreateShareForm>,
) -> Response {
    if user_id != user.id {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    let Some(sub_store) = sub_store else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "Share links are disabled on this server.",
        )
            .into_response();
    };

    // Ownership: the user's own principal, or a group where they hold
    // `edit`/`admin` privilege (Omnical §17.9.2).
    let owned = form.principal == user.id || user.can_write(&form.principal);
    if !owned {
        return (
            StatusCode::FORBIDDEN,
            "You can only create share links for your own or your groups' collections.",
        )
            .into_response();
    }

    let Ok(kind) = SubscriptionKind::try_from(form.kind.as_str()) else {
        return (
            StatusCode::BAD_REQUEST,
            "Unknown collection kind — must be 'calendar' or 'addressbook'.",
        )
            .into_response();
    };

    // Fail fast on a wrong collection id instead of creating a URL that
    // 404s forever (same discipline as `subscriptions add`).
    let collection_exists = match kind {
        SubscriptionKind::Calendar => cal_store
            .get_calendar(&form.principal, &form.collection_id, false)
            .await
            .is_ok(),
        SubscriptionKind::Addressbook => addr_store
            .get_addressbook(&form.principal, &form.collection_id, false)
            .await
            .is_ok(),
    };
    if !collection_exists {
        return (
            StatusCode::NOT_FOUND,
            format!(
                "No such {} '{}' for '{}'.",
                kind.as_str(),
                form.collection_id,
                form.principal
            ),
        )
            .into_response();
    }

    let token = generate_app_token();
    match sub_store
        .add_subscription(&form.principal, kind, &form.collection_id, &token)
        .await
    {
        Ok(_) => Redirect::to(&format!("/frontend/user/{}/share", user.id)).into_response(),
        Err(err) => {
            share_page(
                &auth_provider,
                &cal_store,
                &addr_store,
                Some(&sub_store),
                Some(&invite_store),
                Some(&share_store),
                &public_url,
                &host,
                &user,
                Some(format!("Could not create the share link: {err}")),
            )
            .await
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct RevokeShareForm {
    pub principal: String,
}

/// POST /{user}/share/{id}/revoke — remove a share link of the user's own or
/// an owned-group principal (the URL stops working immediately).
pub async fn route_share_revoke<AP: AuthenticationProvider>(
    Path((user_id, id)): Path<(String, String)>,
    Extension(auth_provider): Extension<Arc<AP>>,
    Extension(sub_store): Extension<Option<Arc<dyn SubscriptionStore>>>,
    user: Principal,
    Form(form): Form<RevokeShareForm>,
) -> Response {
    if user_id != user.id {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let owned = form.principal == user.id || user.can_write(&form.principal);
    if !owned {
        return (
            StatusCode::FORBIDDEN,
            "You can only revoke share links of your own or your groups' collections.",
        )
            .into_response();
    }
    if let Some(store) = sub_store {
        let _ = store.delete_subscription(&form.principal, &id).await;
    }
    Redirect::to(&format!("/frontend/user/{}/share", user.id)).into_response()
}

/// Invite code alphabet (unambiguous: no 0/O/1/l/I) and length.
const CODE_ALPHABET: &[u8] = b"abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";
const CODE_LENGTH: usize = 12;

fn generate_invite_code() -> String {
    use rand::RngExt;
    let mut rng = rand::rng();
    (0..CODE_LENGTH)
        .map(|_| CODE_ALPHABET[rng.random_range(0..CODE_ALPHABET.len())] as char)
        .collect()
}

#[derive(Debug, Clone, Deserialize)]
pub struct SendInviteForm {
    pub principal: String,
    /// The collection the invite is minted for (shown on its tile, §17.9.1).
    pub collection_id: String,
    pub kind: String,
    /// Optional invitee email. `None` (or blank — the "Generate invite link"
    /// form posts no `email` field) mints an unbound invite: a registration
    /// link anyone can use.
    #[serde(default)]
    pub email: Option<String>,
}

/// POST /{user}/share/invite — create a one-time invite code tied to a group
/// and return the registration link. The caller copies the link and sends it
/// to the invitee.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub async fn route_share_invite<
    AP: AuthenticationProvider,
    CS: CalendarStore,
    AS: AddressbookStore,
>(
    Path(user_id): Path<String>,
    Extension(auth_provider): Extension<Arc<AP>>,
    Extension(cal_store): Extension<Arc<CS>>,
    Extension(addr_store): Extension<Arc<AS>>,
    Extension(sub_store): Extension<Option<Arc<dyn SubscriptionStore>>>,
    Extension(public_url): Extension<String>,
    Extension(invite_store): Extension<Arc<dyn InviteStore>>,
    Extension(share_store): Extension<Arc<dyn CollectionShareStore>>,
    TypedHeader(host): TypedHeader<Host>,
    user: Principal,
    Form(form): Form<SendInviteForm>,
) -> Response {
    if user_id != user.id {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    // Ownership check: the user's own principal or a group where they hold
    // `admin` privilege (Omnical §17.9.2 — minting invites is member
    // management).
    let owned = form.principal == user.id || user.is_admin(&form.principal);
    if !owned {
        return (
            StatusCode::FORBIDDEN,
            "You can only send invites for your own or your groups' collections.",
        )
            .into_response();
    }

    // An unbound ("generate link") invite carries no email; the name of the
    // group principal is enough. A provided-but-invalid email is still an
    // error.
    let email = form
        .email
        .as_deref()
        .map(str::trim)
        .filter(|e| !e.is_empty())
        .map(str::to_lowercase);
    if let Some(email) = email.as_deref()
        && !email.contains('@')
    {
        return share_page(
            &auth_provider,
            &cal_store,
            &addr_store,
            sub_store.as_ref(),
            Some(&invite_store),
            Some(&share_store),
            &public_url,
            &host,
            &user,
            Some("Please enter a valid email address.".to_owned()),
        )
        .await;
    }

    // Invites are calendar-only today (§17.9.1 keeps the surface as-is).
    if form.kind != "calendar" {
        return share_page(
            &auth_provider,
            &cal_store,
            &addr_store,
            sub_store.as_ref(),
            Some(&invite_store),
            Some(&share_store),
            &public_url,
            &host,
            &user,
            Some("Invites are only supported for calendars.".to_owned()),
        )
        .await;
    }
    // Fail fast on a wrong collection id (same discipline as share create).
    if cal_store
        .get_calendar(&form.principal, &form.collection_id, false)
        .await
        .is_err()
    {
        return share_page(
            &auth_provider,
            &cal_store,
            &addr_store,
            sub_store.as_ref(),
            Some(&invite_store),
            Some(&share_store),
            &public_url,
            &host,
            &user,
            Some(format!(
                "No such calendar '{}' for '{}'.",
                form.collection_id, form.principal
            )),
        )
        .await;
    }

    let code = generate_invite_code();
    let target_group = if form.principal == user.id {
        None
    } else {
        Some(form.principal.clone())
    };

    if let Err(err) = invite_store
        .add_invite(
            &code,
            &email,
            &target_group,
            &user.id,
            &None,
            &Some(form.collection_id.clone()),
            &Some(form.kind.clone()),
        )
        .await
    {
        return share_page(
            &auth_provider,
            &cal_store,
            &addr_store,
            sub_store.as_ref(),
            Some(&invite_store),
            Some(&share_store),
            &public_url,
            &host,
            &user,
            Some(format!("Could not create invite: {err}")),
        )
        .await;
    }

    let base_url = resolve_base_url(&public_url, &host);
    let invite_url = format!("{base_url}/register?code={code}");
    share_page_with_invite(
        &auth_provider,
        &cal_store,
        &addr_store,
        sub_store.as_ref(),
        Some(&invite_store),
        Some(&share_store),
        &public_url,
        &host,
        &user,
        &invite_url,
        email.as_deref(),
        &form.collection_id,
        &form.principal,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn share_page_with_invite<
    AP: AuthenticationProvider,
    CS: CalendarStore,
    AS: AddressbookStore,
>(
    auth_provider: &Arc<AP>,
    cal_store: &Arc<CS>,
    addr_store: &Arc<AS>,
    sub_store: Option<&Arc<dyn SubscriptionStore>>,
    invite_store: Option<&Arc<dyn InviteStore>>,
    share_store: Option<&Arc<dyn CollectionShareStore>>,
    public_url: &str,
    host: &Host,
    user: &Principal,
    invite_url: &str,
    invited_email: Option<&str>,
    collection_id: &str,
    principal: &str,
) -> Response {
    let base_url = resolve_base_url(public_url, host);
    let entries = build_share_entries(
        auth_provider,
        cal_store,
        addr_store,
        sub_store,
        invite_store,
        share_store,
        user,
        &base_url,
    )
    .await;
    UserPage {
        section: ShareSection {
            user: user.clone(),
            entries,
            enabled: sub_store.is_some(),
            error: None,
            invite_url: Some(invite_url.to_owned()),
            invited_email: invited_email.map(ToOwned::to_owned),
            guest_share_server_url: None,
            guest_share_username: None,
            guest_share_credential: None,
            guest_share_calendar_id: None,
            guest_share_principal: None,
            guest_share_email: None,
            invite_collection_id: Some(collection_id.to_owned()),
            invite_principal: Some(principal.to_owned()),
        },
        user: user.clone(),
    }
    .into_response()
}

#[derive(Debug, Clone, Deserialize)]
pub struct RevokeInviteForm {
    pub principal: String,
}

/// POST /{user}/share/invite/{code}/revoke — revoke an unredeemed invite
/// shown on a collection tile (the registration link stops working).
pub async fn route_share_invite_revoke<AP: AuthenticationProvider>(
    Path((user_id, code)): Path<(String, String)>,
    Extension(auth_provider): Extension<Arc<AP>>,
    Extension(invite_store): Extension<Arc<dyn InviteStore>>,
    user: Principal,
    Form(form): Form<RevokeInviteForm>,
) -> Response {
    if user_id != user.id {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let owned = form.principal == user.id || user.is_admin(&form.principal);
    if !owned {
        return (
            StatusCode::FORBIDDEN,
            "You can only revoke invites of your own or your groups' collections.",
        )
            .into_response();
    }
    let _ = invite_store.delete_invite(&code).await;
    Redirect::to(&format!("/frontend/user/{}/share", user.id)).into_response()
}

#[derive(Debug, Clone, Deserialize)]
pub struct GuestInviteForm {
    pub principal: String,
    /// Which calendar the share targets.  The form always posts `kind=calendar`
    /// as a hidden field (V1 guest shares are calendar-only).
    pub collection_id: String,
    pub privilege: String,
    /// Optional delivery email.  Empty / absent mints a share with no email —
    /// the sender delivers the credential out of band.
    #[serde(default)]
    pub email: Option<String>,
}

/// POST /{user}/share/guest-invite — mint a per-calendar guest invite
/// (PLAN §17.10.6).  The flow is:
///   1. Verify `user` is admin over the requested principal.
///   2. Create a lightweight `guest-{uuid}` principal (password: `None`).
///   3. Mint an app token and build the DAV credential (`{id4}_{secret}`).
///   4. Persist a `collection_shares` row.
///   5. Optionally send the credential to `target_email`.
///   6. Re-render the Share page with a one-time credential banner.
#[allow(clippy::too_many_arguments)]
pub async fn route_share_guest_invite<
    AP: AuthenticationProvider,
    CS: CalendarStore,
    AS: AddressbookStore,
>(
    Path(user_id): Path<String>,
    Extension(auth_provider): Extension<Arc<AP>>,
    Extension(cal_store): Extension<Arc<CS>>,
    Extension(addr_store): Extension<Arc<AS>>,
    Extension(sub_store): Extension<Option<Arc<dyn SubscriptionStore>>>,
    Extension(invite_store): Extension<Arc<dyn InviteStore>>,
    Extension(share_store): Extension<Arc<dyn CollectionShareStore>>,
    Extension(smtp_accounts): Extension<Vec<SmtpAccount>>,
    Extension(public_url): Extension<String>,
    TypedHeader(host): TypedHeader<Host>,
    user: Principal,
    Form(form): Form<GuestInviteForm>,
) -> Response {
    if user_id != user.id {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    // Ownership: the user's own principal, or a group where they hold
    // `admin` privilege (§17.10.6 — minting guests is member management).
    let owned = form.principal == user.id || user.is_admin(&form.principal);
    if !owned {
        return (
            StatusCode::FORBIDDEN,
            "You can only create guest invites for your own or your groups' collections.",
        )
            .into_response();
    }

    let privilege = match Privilege::from_str(&form.privilege) {
        Ok(p) => p,
        Err(msg) => {
            return share_page(
                &auth_provider,
                &cal_store,
                &addr_store,
                sub_store.as_ref(),
                Some(&invite_store),
                Some(&share_store),
                &public_url,
                &host,
                &user,
                Some(msg),
            )
            .await;
        }
    };

    // V1 is calendar-only (§17.10.1 table shape — `kind` is a field, but
    // the portal form does not expose it today).
    if form.collection_id.is_empty() {
        return share_page(
            &auth_provider,
            &cal_store,
            &addr_store,
            sub_store.as_ref(),
            Some(&invite_store),
            Some(&share_store),
            &public_url,
            &host,
            &user,
            Some("No collection specified.".to_owned()),
        )
        .await;
    }

    // Fail fast on wrong collection id (same discipline as share create).
    if cal_store
        .get_calendar(&form.principal, &form.collection_id, false)
        .await
        .is_err()
    {
        return share_page(
            &auth_provider,
            &cal_store,
            &addr_store,
            sub_store.as_ref(),
            Some(&invite_store),
            Some(&share_store),
            &public_url,
            &host,
            &user,
            Some(format!(
                "No such calendar '{}' for '{}'.",
                form.collection_id, form.principal
            )),
        )
        .await;
    }

    // Validate optional email (same as route_share_invite).
    let email: Option<String> = match form
        .email
        .as_deref()
        .map(str::trim)
        .filter(|e| !e.is_empty())
    {
        Some(e) if !e.contains('@') => {
            return share_page(
                &auth_provider,
                &cal_store,
                &addr_store,
                sub_store.as_ref(),
                Some(&invite_store),
                Some(&share_store),
                &public_url,
                &host,
                &user,
                Some("Please enter a valid email address.".to_owned()),
            )
            .await;
        }
        Some(e) => Some(e.to_lowercase()),
        None => None,
    };

    // 1. Create guest principal.
    let guest_id = format!("guest-{}", Uuid::new_v4());
    if let Err(err) = auth_provider
        .insert_principal(
            rustical_store::auth::Principal {
                id: guest_id.clone(),
                displayname: Some(format!("Guest of {}", form.collection_id)),
                memberships: vec![],
                password: None,
                principal_type: rustical_store::auth::PrincipalType::Individual,
                needs_password_change: false,
                privileges: Default::default(),
            },
            false,
        )
        .await
    {
        return share_page(
            &auth_provider,
            &cal_store,
            &addr_store,
            sub_store.as_ref(),
            Some(&invite_store),
            Some(&share_store),
            &public_url,
            &host,
            &user,
            Some(format!("Could not create guest principal: {err}")),
        )
        .await;
    }

    // 2. Mint app token → DAV credential.
    let token_secret = generate_app_token();
    let mut token_id = match auth_provider
        .add_app_token(
            &guest_id,
            format!("{} guest", form.collection_id),
            token_secret.clone(),
        )
        .await
    {
        Ok(id) => id,
        Err(err) => {
            return share_page(
                &auth_provider,
                &cal_store,
                &addr_store,
                sub_store.as_ref(),
                Some(&invite_store),
                Some(&share_store),
                &public_url,
                &host,
                &user,
                Some(format!("Could not mint app token: {err}")),
            )
            .await;
        }
    };
    token_id.truncate(4);
    let credential = format!("{token_id}_{token_secret}");

    // 3. Persist the share row.
    if let Err(err) = share_store
        .add_share(
            &form.principal,
            &form.collection_id,
            "calendar",
            privilege,
            &guest_id,
            &email,
            &user.id,
        )
        .await
    {
        return share_page(
            &auth_provider,
            &cal_store,
            &addr_store,
            sub_store.as_ref(),
            Some(&invite_store),
            Some(&share_store),
            &public_url,
            &host,
            &user,
            Some(format!("Could not create guest share: {err}")),
        )
        .await;
    }

    let base_url = resolve_base_url(&public_url, &host);
    let server_url = format!("{base_url}/caldav");

    // 4. Optionally deliver the credential by email (Omnical §17.10.7):
    //    when an SMTP account is configured and an email was provided,
    //    `send_mail` sends the plaintext setup. Without SMTP the invite
    //    still succeeds — the share row keeps `target_email` for audit and
    //    the credential stays on the Share page (one-time banner).
    if let (Some(to), Some(account)) = (email.as_deref(), smtp_accounts.first()) {
        let message = mime::build_guest_invite(
            account,
            to,
            &server_url,
            &guest_id,
            &credential,
            &form.collection_id,
            &user.id,
        );
        let account = account.clone();
        let to = to.to_owned();
        tokio::spawn(async move {
            match smtp::send_mail(&account, &account.identity, &to, &message).await {
                Ok(()) => tracing::debug!("emailed guest share credential to {to}"),
                Err(err) => {
                    tracing::warn!("could not email guest share credential: {err}");
                }
            }
        });
    }

    share_page_with_guest_credential(
        &auth_provider,
        &cal_store,
        &addr_store,
        sub_store.as_ref(),
        Some(&invite_store),
        Some(&share_store),
        &public_url,
        &host,
        &user,
        &guest_id,
        &credential,
        &server_url,
        &form.principal,
        &form.collection_id,
        email.as_deref(),
    )
    .await
}

#[derive(Debug, Clone, Deserialize)]
pub struct RevokeGuestShareForm {
    pub principal: String,
}

/// POST /{user}/share/guest-invite/{id}/revoke — revoke an active guest
/// share (sets `revoked_at`; the row stays for audit).
pub async fn route_share_guest_revoke<AP: AuthenticationProvider>(
    Path((user_id, id)): Path<(String, String)>,
    Extension(_auth_provider): Extension<Arc<AP>>,
    Extension(share_store): Extension<Arc<dyn CollectionShareStore>>,
    user: Principal,
    Form(form): Form<RevokeGuestShareForm>,
) -> Response {
    if user_id != user.id {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let owned = form.principal == user.id || user.is_admin(&form.principal);
    if !owned {
        return (
            StatusCode::FORBIDDEN,
            "You can only revoke guest shares of your own or your groups' collections.",
        )
            .into_response();
    }
    let _ = share_store.revoke_share(&id).await;
    Redirect::to(&format!("/frontend/user/{}/share", user.id)).into_response()
}

#[allow(clippy::too_many_arguments)]
async fn share_page_with_guest_credential<
    AP: AuthenticationProvider,
    CS: CalendarStore,
    AS: AddressbookStore,
>(
    auth_provider: &Arc<AP>,
    cal_store: &Arc<CS>,
    addr_store: &Arc<AS>,
    sub_store: Option<&Arc<dyn SubscriptionStore>>,
    invite_store: Option<&Arc<dyn InviteStore>>,
    share_store: Option<&Arc<dyn CollectionShareStore>>,
    public_url: &str,
    host: &Host,
    user: &Principal,
    guest_username: &str,
    credential: &str,
    server_url: &str,
    principal: &str,
    calendar_id: &str,
    email: Option<&str>,
) -> Response {
    let base_url = resolve_base_url(public_url, host);
    let entries = build_share_entries(
        auth_provider,
        cal_store,
        addr_store,
        sub_store,
        invite_store,
        share_store,
        user,
        &base_url,
    )
    .await;
    UserPage {
        section: ShareSection {
            user: user.clone(),
            entries,
            enabled: sub_store.is_some(),
            error: None,
            invite_url: None,
            invited_email: None,
            guest_share_server_url: Some(server_url.to_owned()),
            guest_share_username: Some(guest_username.to_owned()),
            guest_share_credential: Some(credential.to_owned()),
            guest_share_calendar_id: Some(calendar_id.to_owned()),
            guest_share_principal: Some(principal.to_owned()),
            guest_share_email: email.map(ToOwned::to_owned),
            invite_collection_id: None,
            invite_principal: None,
        },
        user: user.clone(),
    }
    .into_response()
}
