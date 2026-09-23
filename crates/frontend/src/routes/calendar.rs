use crate::pages::DefaultLayoutData;
use crate::pages::user::{Section, UserPage};
use crate::routes::app_token::generate_app_token;
use crate::routes::share::ensure_subscribe_url;
use crate::url_builder::export_url;
use askama::Template;
use askama_web::WebTemplate;
use axum::{
    Extension, Form,
    extract::Path,
    response::{IntoResponse, Redirect, Response},
};
use axum_extra::TypedHeader;
use headers::{Host, Referer};
use http::StatusCode;
use rustical_scheduling::{SmtpAccount, mime, smtp};
use rustical_store::{
    Calendar, CalendarStore, CollectionMetadata, CollectionShareStore, Invite, InviteStore,
    SubscriptionKind, SubscriptionStore,
    auth::{AuthenticationProvider, Principal, PrincipalType, Privilege},
};
use serde::Deserialize;
use std::sync::Arc;
use uuid::Uuid;

impl Section for CalendarsSection {
    fn name() -> &'static str {
        "calendars"
    }
}

/// One unredeemed registration invite link shown on the calendar tile it
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

/// One calendar tile of the Calendars screen: the rendered calendar plus the
/// per-tile sharing data (subscribe link, credentials, invites — PLAN.md
/// §17.15 folds the old Share tab into this tile).
pub struct CalendarTile {
    pub meta: CollectionMetadata,
    pub calendar: Calendar,
    /// True when the acting user may mint/revoke full-access credentials for
    /// the tile (owner, or admin of the owning group).
    pub can_generate: bool,
    /// True when the acting user may mint registration invites and guest
    /// shares for the tile (owner, or admin of the owning group — §17.9.2).
    pub can_invite: bool,
    /// The calendar's credential-less subscribe-link URL
    /// (`/export/{token}.ics`), when a subscription exists (§17.7).
    pub subscribe_url: Option<String>,
    /// The same URL with the `webcal://` scheme — display variant only, the
    /// stored token keeps working over plain https (§17.15).
    pub subscribe_url_webcal: Option<String>,
    /// Subscription id of the subscribe link (for Revoke) — `None` when the
    /// calendar has no link yet.
    pub sub_id: Option<String>,
    /// When the subscribe link was minted.
    pub sub_created_at: Option<String>,
    /// True when the acting user may create the calendar's subscribe link
    /// here (owner, or `edit`/`admin` of the owning group — §17.9.2).
    pub can_subscribe: bool,
    /// Active credentials minted for this calendar (Omnical §17.12), each with
    /// its own Revoke control.
    pub guest_shares: Vec<GuestShareEntry>,
    /// Unredeemed registration invite links minted for this calendar
    /// (§17.9.1) — empty unless the user may manage them.
    pub invites: Vec<InviteLink>,
}

/// One-time banner payloads of the Calendars screen — all `None` on a plain
/// page load; each minting POST sets exactly one of them.
#[derive(Default)]
pub struct CalendarsExtras {
    pub error: Option<String>,
    /// §17.12: just-minted calendar credential.
    pub credential_server_url: Option<String>,
    pub credential_username: Option<String>,
    pub credential_token: Option<String>,
    pub credential_calendar_id: Option<String>,
    pub credential_email: Option<String>,
    /// §17.10: just-minted guest-share credential (one-time banner, shown on
    /// the minted calendar's tile only).
    pub guest_share_server_url: Option<String>,
    pub guest_share_username: Option<String>,
    pub guest_share_credential: Option<String>,
    pub guest_share_calendar_id: Option<String>,
    pub guest_share_principal: Option<String>,
    pub guest_share_email: Option<String>,
    /// Subscribe link of the same calendar, minted alongside (§17.8).
    pub guest_share_subscribe_url: Option<String>,
    /// §17.9: just-minted registration invite (one-time banner, shown on
    /// the minted calendar's tile only).
    pub invite_url: Option<String>,
    pub invited_email: Option<String>,
    pub invite_collection_id: Option<String>,
    pub invite_principal: Option<String>,
}

#[derive(Template, WebTemplate)]
#[template(path = "components/sections/calendars_section.html")]
pub struct CalendarsSection {
    pub user: Principal,
    pub calendars: Vec<CalendarTile>,
    pub deleted_calendars: Vec<(CollectionMetadata, Calendar)>,
    /// `CalDAV` endpoint printed in the per-client instructions (§17.15).
    pub caldav_url: String,
    pub credential_server_url: Option<String>,
    pub credential_username: Option<String>,
    pub credential_token: Option<String>,
    pub credential_calendar_id: Option<String>,
    /// The `target_email` the credential was delivered to, if one was given.
    pub credential_email: Option<String>,
    pub guest_share_server_url: Option<String>,
    pub guest_share_username: Option<String>,
    pub guest_share_credential: Option<String>,
    pub guest_share_calendar_id: Option<String>,
    pub guest_share_principal: Option<String>,
    pub guest_share_email: Option<String>,
    pub guest_share_subscribe_url: Option<String>,
    pub invite_url: Option<String>,
    pub invited_email: Option<String>,
    pub invite_collection_id: Option<String>,
    pub invite_principal: Option<String>,
    pub error: Option<String>,
}

/// The `webcal://` display variant of an https/http export URL (scheme swap
/// only — the token itself is never rewritten, §17.15).
fn webcal_variant(url: &str) -> String {
    url.strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .map_or_else(|| url.to_owned(), |rest| format!("webcal://{rest}"))
}

/// The unredeemed invite links of a calendar tile: invites are attributed per
/// tile via `collection_id` (+ `kind`); group-collection invites carry the
/// group as `target_group`, own-collection invites carry none (§17.9.1).
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

/// The shared Calendars-screen renderer: lists the user's calendars with the
/// per-tile sharing blocks (subscribe link, full-access credentials, invites
/// — §17.15) plus one-time banners.
#[allow(clippy::too_many_lines)]
pub async fn render_calendars_page<CS: CalendarStore>(
    cal_store: &Arc<CS>,
    share_store: &Arc<dyn CollectionShareStore>,
    sub_store: Option<&Arc<dyn SubscriptionStore>>,
    invite_store: &Arc<dyn InviteStore>,
    base_url: &str,
    user: &Principal,
    extras: CalendarsExtras,
) -> Response {
    let mut calendars = vec![];
    for group in user.memberships() {
        calendars.extend(cal_store.get_calendars(group).await.unwrap());
    }

    let invites = invite_store.list_invites(false).await.unwrap_or_default();

    let mut calendar_infos = vec![];
    for calendar in calendars {
        let can_generate = user.is_admin(&calendar.principal);
        // Invite/guest-share minting is member management: owner, or `admin`
        // privilege in the group (§17.9.2).
        let can_invite = calendar.principal == user.id || user.is_admin(&calendar.principal);
        // Subscribe-link creation: owner, or `edit`/`admin` group members
        // (§17.9.2).
        let can_subscribe = sub_store.is_some() && user.can_write(&calendar.principal);
        // The calendar's existing subscribe link, if any (§17.7).
        let sub = match sub_store {
            Some(store) => store
                .get_subscriptions(&calendar.principal)
                .await
                .unwrap_or_default()
                .into_iter()
                .find(|s| s.kind == SubscriptionKind::Calendar && s.collection_id == calendar.id),
            None => None,
        };
        let guest_shares = share_store
            .get_shares_for_collection(&calendar.principal, &calendar.id)
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
            .collect();
        // Invite links are only shown where the user may mint them: a
        // view-only group member must not see the group's registration URLs.
        let invites = if can_invite {
            tile_invite_links(&invites, &calendar.principal, user, &calendar.id, base_url)
        } else {
            Vec::new()
        };
        calendar_infos.push(CalendarTile {
            meta: cal_store
                .calendar_metadata(&calendar.principal, &calendar.id)
                .await
                .unwrap(),
            calendar,
            can_generate,
            can_invite,
            subscribe_url: sub.as_ref().map(|s| export_url(base_url, &s.token, s.kind)),
            subscribe_url_webcal: sub
                .as_ref()
                .map(|s| webcal_variant(&export_url(base_url, &s.token, s.kind))),
            sub_id: sub.as_ref().map(|s| s.id.clone()),
            sub_created_at: sub.and_then(|s| s.created_at),
            can_subscribe,
            guest_shares,
            invites,
        });
    }

    let mut deleted_calendars = vec![];
    for group in user.memberships() {
        deleted_calendars.extend(cal_store.get_deleted_calendars(group).await.unwrap());
    }

    let mut deleted_calendar_infos = vec![];
    for calendar in deleted_calendars {
        deleted_calendar_infos.push((
            cal_store
                .calendar_metadata(&calendar.principal, &calendar.id)
                .await
                .unwrap(),
            calendar,
        ));
    }

    let CalendarsExtras {
        error,
        credential_server_url,
        credential_username,
        credential_token,
        credential_calendar_id,
        credential_email,
        guest_share_server_url,
        guest_share_username,
        guest_share_credential,
        guest_share_calendar_id,
        guest_share_principal,
        guest_share_email,
        guest_share_subscribe_url,
        invite_url,
        invited_email,
        invite_collection_id,
        invite_principal,
    } = extras;

    UserPage {
        section: CalendarsSection {
            user: user.clone(),
            calendars: calendar_infos,
            deleted_calendars: deleted_calendar_infos,
            caldav_url: format!("{base_url}/caldav"),
            credential_server_url,
            credential_username,
            credential_token,
            credential_calendar_id,
            credential_email,
            guest_share_server_url,
            guest_share_username,
            guest_share_credential,
            guest_share_calendar_id,
            guest_share_principal,
            guest_share_email,
            guest_share_subscribe_url,
            invite_url,
            invited_email,
            invite_collection_id,
            invite_principal,
            error,
        },
        user: user.clone(),
    }
    .into_response()
}

#[allow(clippy::too_many_arguments)]
pub async fn route_calendars<CS: CalendarStore>(
    Path(user_id): Path<String>,
    Extension(cal_store): Extension<Arc<CS>>,
    Extension(share_store): Extension<Arc<dyn CollectionShareStore>>,
    Extension(sub_store): Extension<Option<Arc<dyn SubscriptionStore>>>,
    Extension(invite_store): Extension<Arc<dyn InviteStore>>,
    Extension(public_url): Extension<String>,
    TypedHeader(host): TypedHeader<Host>,
    user: Principal,
) -> impl IntoResponse {
    if user_id != user.id {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let base_url = resolve_base_url(&public_url, &host);
    render_calendars_page(
        &cal_store,
        &share_store,
        sub_store.as_ref(),
        &invite_store,
        &base_url,
        &user,
        CalendarsExtras::default(),
    )
    .await
}

#[derive(Template, WebTemplate)]
#[template(path = "pages/calendar.html")]
struct CalendarPage {
    calendar: Calendar,
    user: Principal,
    /// `CalDAV` endpoint printed in the per-client instructions (§17.15).
    caldav_url: String,
    /// The calendar's existing credential-less subscribe link
    /// (`/export/{token}.ics`), when a subscription exists (§17.7).
    subscribe_url: Option<String>,
    /// The same URL with the `webcal://` scheme — display variant only, the
    /// stored token keeps working over plain https (§17.15).
    subscribe_url_webcal: Option<String>,
}

impl DefaultLayoutData for CalendarPage {
    fn get_user(&self) -> Option<&Principal> {
        Some(&self.user)
    }
}

pub async fn route_calendar<CS: CalendarStore>(
    Path((owner, cal_id)): Path<(String, String)>,
    Extension(store): Extension<Arc<CS>>,
    Extension(sub_store): Extension<Option<Arc<dyn SubscriptionStore>>>,
    Extension(public_url): Extension<String>,
    TypedHeader(host): TypedHeader<Host>,
    user: Principal,
) -> Result<Response, rustical_store::Error> {
    if !user.is_principal(&owner) {
        return Ok(StatusCode::UNAUTHORIZED.into_response());
    }
    let calendar = store.get_calendar(&owner, &cal_id, true).await?;
    let base_url = resolve_base_url(&public_url, &host);
    // The calendar's existing subscribe link, if any (same lookup as the
    // Calendars screen, §17.7).
    let sub = match &sub_store {
        Some(sub_store) => sub_store
            .get_subscriptions(&owner)
            .await
            .unwrap_or_default()
            .into_iter()
            .find(|s| s.kind == SubscriptionKind::Calendar && s.collection_id == cal_id),
        None => None,
    };
    let subscribe_url = sub
        .as_ref()
        .map(|s| export_url(&base_url, &s.token, s.kind));
    let subscribe_url_webcal = subscribe_url.as_deref().map(webcal_variant);
    Ok(CalendarPage {
        calendar,
        user,
        caldav_url: format!("{base_url}/caldav"),
        subscribe_url,
        subscribe_url_webcal,
    }
    .into_response())
}

pub async fn route_calendar_restore<CS: CalendarStore>(
    Path((owner, cal_id)): Path<(String, String)>,
    Extension(store): Extension<Arc<CS>>,
    user: Principal,
    referer: Option<TypedHeader<Referer>>,
) -> Result<Response, rustical_store::Error> {
    if !user.is_principal(&owner) {
        return Ok(StatusCode::UNAUTHORIZED.into_response());
    }
    store.restore_calendar(&owner, &cal_id).await?;
    Ok(referer.map_or_else(
        || (StatusCode::CREATED, "Restored").into_response(),
        |referer| Redirect::to(&referer.to_string()).into_response(),
    ))
}

#[derive(Debug, Clone, Deserialize)]
pub struct CalendarCredentialsForm {
    /// The owner principal of the calendar (`user`'s own id, or a group the
    /// user admins).
    pub principal: String,
    pub calendar_id: String,
    /// Optional delivery target; stored for audit and emailed when SMTP is
    /// configured (same behavior as the guest-share invite).
    #[serde(default)]
    pub email: Option<String>,
}

/// Resolve the base URL the credential's server URL is printed with: the
/// configured `[subscriptions] public_url`, else the request's own host
/// (mirrors the share-route logic).
pub(super) fn resolve_base_url(public_url: &str, host: &Host) -> String {
    if public_url.is_empty() {
        format!("https://{host}")
    } else {
        public_url.to_owned()
    }
}

/// POST /{user}/calendar/credentials — mint full-access (`admin`)
/// `CalDAV` credentials for one calendar and show them once on the
/// Calendars screen.
///
/// The credential is a fresh `guest-{uuid}` principal + app token scoped by a
/// `collection_shares` row to exactly this calendar with `admin` privilege —
/// the same mechanism the guest-share invite uses, but the privilege is
/// always `admin` (full read/write/admin) and the surface is per-calendar.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub async fn route_calendar_credentials<AP: AuthenticationProvider, CS: CalendarStore>(
    Path(user_id): Path<String>,
    Extension(auth_provider): Extension<Arc<AP>>,
    Extension(cal_store): Extension<Arc<CS>>,
    Extension(share_store): Extension<Arc<dyn CollectionShareStore>>,
    Extension(sub_store): Extension<Option<Arc<dyn SubscriptionStore>>>,
    Extension(invite_store): Extension<Arc<dyn InviteStore>>,
    Extension(smtp_accounts): Extension<Vec<SmtpAccount>>,
    Extension(public_url): Extension<String>,
    TypedHeader(host): TypedHeader<Host>,
    user: Principal,
    Form(form): Form<CalendarCredentialsForm>,
) -> Response {
    if user_id != user.id {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    let base_url = resolve_base_url(&public_url, &host);

    // Only the owner — or a group admin — may mint credentials for a group
    // calendar; the minted credential always carries `admin` privilege
    // (Omnical §17.10.6 ownership rule).
    if form.principal != user.id && !user.is_admin(&form.principal) {
        return (
            StatusCode::FORBIDDEN,
            "You can only generate credentials for your own or your groups' calendars.",
        )
            .into_response();
    }

    if form.calendar_id.is_empty() {
        return render_calendars_page(
            &cal_store,
            &share_store,
            sub_store.as_ref(),
            &invite_store,
            &base_url,
            &user,
            CalendarsExtras {
                error: Some("No calendar specified.".to_owned()),
                ..CalendarsExtras::default()
            },
        )
        .await;
    }

    // Fail fast on a wrong calendar id (same discipline as the share routes).
    if cal_store
        .get_calendar(&form.principal, &form.calendar_id, false)
        .await
        .is_err()
    {
        return render_calendars_page(
            &cal_store,
            &share_store,
            sub_store.as_ref(),
            &invite_store,
            &base_url,
            &user,
            CalendarsExtras {
                error: Some(format!(
                    "No such calendar '{}' for '{}'.",
                    form.calendar_id, form.principal
                )),
                ..CalendarsExtras::default()
            },
        )
        .await;
    }

    // Validate the optional email (same as the guest-share invite).
    let email: Option<String> = match form
        .email
        .as_deref()
        .map(str::trim)
        .filter(|e| !e.is_empty())
    {
        Some(e) if !e.contains('@') => {
            return render_calendars_page(
                &cal_store,
                &share_store,
                sub_store.as_ref(),
                &invite_store,
                &base_url,
                &user,
                CalendarsExtras {
                    error: Some("Please enter a valid email address.".to_owned()),
                    ..CalendarsExtras::default()
                },
            )
            .await;
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
                displayname: Some(format!("Guest of {}", form.calendar_id)),
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
        return render_calendars_page(
            &cal_store,
            &share_store,
            sub_store.as_ref(),
            &invite_store,
            &base_url,
            &user,
            CalendarsExtras {
                error: Some(format!("Could not create guest principal: {err}")),
                ..CalendarsExtras::default()
            },
        )
        .await;
    }

    // 2. Mint an app token → the DAV credential (`{id4}_{secret}`).
    let token_secret = generate_app_token();
    let mut token_id = match auth_provider
        .add_app_token(
            &guest_id,
            format!("{} guest", form.calendar_id),
            token_secret.clone(),
        )
        .await
    {
        Ok(id) => id,
        Err(err) => {
            return render_calendars_page(
                &cal_store,
                &share_store,
                sub_store.as_ref(),
                &invite_store,
                &base_url,
                &user,
                CalendarsExtras {
                    error: Some(format!("Could not mint app token: {err}")),
                    ..CalendarsExtras::default()
                },
            )
            .await;
        }
    };
    token_id.truncate(4);
    let credential = format!("{token_id}_{token_secret}");

    // 3. Persist the share row — always `admin` (full read/write/admin).
    if let Err(err) = share_store
        .add_share(
            &form.principal,
            &form.calendar_id,
            "calendar",
            Privilege::Admin,
            &guest_id,
            &email,
            &user.id,
        )
        .await
    {
        return render_calendars_page(
            &cal_store,
            &share_store,
            sub_store.as_ref(),
            &invite_store,
            &base_url,
            &user,
            CalendarsExtras {
                error: Some(format!("Could not create calendar credential: {err}")),
                ..CalendarsExtras::default()
            },
        )
        .await;
    }

    let server_url = format!("{base_url}/caldav");

    // 4. Optionally deliver the credential by email (Omnical §17.10.7): when
    //    SMTP is configured and an email was provided, `send_mail` sends the
    //    plaintext setup; without SMTP the mint still succeeds (the share row
    //    keeps `target_email` for audit, the credential stays in the banner).
    if let (Some(to), Some(account)) = (email.as_deref(), smtp_accounts.first()) {
        let message = mime::build_guest_invite(
            account,
            to,
            &server_url,
            &guest_id,
            &credential,
            &form.calendar_id,
            &user.id,
            None,
        );
        let account = account.clone();
        let to = to.to_owned();
        tokio::spawn(async move {
            match smtp::send_mail(&account, &account.identity, &to, &message).await {
                Ok(()) => tracing::debug!("emailed calendar credentials to {to}"),
                Err(err) => {
                    tracing::warn!("could not email calendar credentials: {err}");
                }
            }
        });
    }

    render_calendars_page(
        &cal_store,
        &share_store,
        sub_store.as_ref(),
        &invite_store,
        &base_url,
        &user,
        CalendarsExtras {
            credential_server_url: Some(server_url),
            credential_username: Some(guest_id),
            credential_token: Some(credential),
            credential_calendar_id: Some(form.calendar_id),
            credential_email: email,
            ..CalendarsExtras::default()
        },
    )
    .await
}

#[derive(Debug, Clone, Deserialize)]
pub struct CalendarCredentialsRevokeForm {
    /// The owner principal of the calendar the credential was minted for (used
    /// for the ownership gate, same as minting).
    pub principal: String,
}

/// POST /{user}/calendar/credentials/{id}/revoke — revoke an active
/// credential minted on the Calendars screen (sets `revoked_at`; the share
/// row stays for audit). Owner / group-admin only, same rule as minting.
pub async fn route_calendar_credentials_revoke(
    Path((user_id, share_id)): Path<(String, String)>,
    Extension(share_store): Extension<Arc<dyn CollectionShareStore>>,
    user: Principal,
    Form(form): Form<CalendarCredentialsRevokeForm>,
) -> Response {
    if user_id != user.id {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let owned = form.principal == user.id || user.is_admin(&form.principal);
    if !owned {
        return (
            StatusCode::FORBIDDEN,
            "You can only revoke credentials of your own or your groups' calendars.",
        )
            .into_response();
    }
    let _ = share_store.revoke_share(&share_id).await;
    Redirect::to(&format!("/frontend/user/{}/calendar", user.id)).into_response()
}

#[derive(Debug, Clone, Deserialize)]
pub struct CalendarSubscribeForm {
    /// The owner principal of the calendar (`user`'s own id, or a group the
    /// user may write).
    pub principal: String,
    pub calendar_id: String,
}

/// POST /{user}/calendar/subscribe — mint (or reuse) the calendar's
/// credential-less subscribe link from the Calendars screen (PLAN.md §17.7):
/// the same `/export/{token}.ics` URL the share routes mint, surfaced where
/// the calendar itself is listed. Reuses the existing subscription when one
/// already exists, so the URL stays stable.
#[allow(clippy::too_many_arguments)]
pub async fn route_calendar_subscribe<CS: CalendarStore>(
    Path(user_id): Path<String>,
    Extension(cal_store): Extension<Arc<CS>>,
    Extension(share_store): Extension<Arc<dyn CollectionShareStore>>,
    Extension(sub_store): Extension<Option<Arc<dyn SubscriptionStore>>>,
    Extension(invite_store): Extension<Arc<dyn InviteStore>>,
    Extension(public_url): Extension<String>,
    TypedHeader(host): TypedHeader<Host>,
    user: Principal,
    Form(form): Form<CalendarSubscribeForm>,
) -> Response {
    if user_id != user.id {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    let base_url = resolve_base_url(&public_url, &host);

    let Some(sub_store) = sub_store else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "Share links are disabled on this server ([subscriptions] enabled = false).",
        )
            .into_response();
    };

    // Ownership: the user's own principal, or a group where they hold
    // `edit`/`admin` privilege (same rule as the share routes).
    if form.principal != user.id && !user.can_write(&form.principal) {
        return (
            StatusCode::FORBIDDEN,
            "You can only create share links for your own or your groups' calendars.",
        )
            .into_response();
    }

    let page_error = {
        let cal_store = cal_store.clone();
        let share_store = share_store.clone();
        let sub_store = sub_store.clone();
        let invite_store = invite_store.clone();
        let base_url = base_url.clone();
        let user = user.clone();
        move |msg: String| async move {
            render_calendars_page(
                &cal_store,
                &share_store,
                Some(&sub_store),
                &invite_store,
                &base_url,
                &user,
                CalendarsExtras {
                    error: Some(msg),
                    ..CalendarsExtras::default()
                },
            )
            .await
        }
    };

    if form.calendar_id.is_empty() {
        return page_error("No calendar specified.".to_owned()).await;
    }

    // Fail fast on a wrong calendar id (same discipline as the share routes).
    if cal_store
        .get_calendar(&form.principal, &form.calendar_id, false)
        .await
        .is_err()
    {
        return page_error(format!(
            "No such calendar '{}' for '{}'.",
            form.calendar_id, form.principal
        ))
        .await;
    }

    // Mint or reuse; a minting failure surfaces as an error banner (the
    // calendar tile simply stays without a subscribe link).
    if ensure_subscribe_url(
        Some(&sub_store),
        &form.principal,
        &form.calendar_id,
        &base_url,
    )
    .await
    .is_none()
    {
        return page_error("Could not create the share link.".to_owned()).await;
    }

    Redirect::to(&format!(
        "/frontend/user/{}/calendar#cal-{}",
        user.id, form.calendar_id
    ))
    .into_response()
}
