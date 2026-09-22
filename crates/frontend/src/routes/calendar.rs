use crate::pages::DefaultLayoutData;
use crate::pages::user::{Section, UserPage};
use crate::routes::app_token::generate_app_token;
use crate::routes::share::{GuestShareEntry, ensure_subscribe_url};
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
    Calendar, CalendarStore, CollectionMetadata, CollectionShareStore, SubscriptionKind,
    SubscriptionStore,
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

/// One calendar tile of the Calendars screen: the rendered calendar plus the
/// per-tile data the section needs (mint flag + active credentials).
pub struct CalendarTile {
    pub meta: CollectionMetadata,
    pub calendar: Calendar,
    /// True when the acting user may mint/revoke full-access credentials for
    /// the tile (owner, or admin of the owning group).
    pub can_generate: bool,
    /// The calendar's credential-less share-link URL (`/export/{token}.ics`),
    /// when a subscription exists (PLAN.md §17.7 — shown right on the
    /// Calendars screen so users never have to visit the Share page for it).
    pub subscribe_url: Option<String>,
    /// Subscription id of the share link (for Revoke) — `None` when the
    /// calendar has no share link yet.
    pub sub_id: Option<String>,
    /// True when the acting user may create the calendar's share link here
    /// (owner, or `edit`/`admin` of the owning group — same rule as the Share
    /// page's "Create share link").
    pub can_subscribe: bool,
    /// Active credentials minted for this calendar (Omnical §17.12), each with
    /// its own Revoke control.
    pub guest_shares: Vec<GuestShareEntry>,
}

#[derive(Template, WebTemplate)]
#[template(path = "components/sections/calendars_section.html")]
pub struct CalendarsSection {
    pub user: Principal,
    pub calendars: Vec<CalendarTile>,
    pub deleted_calendars: Vec<(CollectionMetadata, Calendar)>,
    /// When set, show the just-minted calendar credential (one-time banner).
    pub credential_server_url: Option<String>,
    pub credential_username: Option<String>,
    pub credential_token: Option<String>,
    pub credential_calendar_id: Option<String>,
    /// The `target_email` the credential was delivered to, if one was given.
    pub credential_email: Option<String>,
    pub error: Option<String>,
}

/// The shared Calendars-screen renderer: lists the user's calendars (with the
/// per-tile credential-minting flag, share-link URL and active credentials)
/// plus one-time credential/error banners.
#[allow(clippy::too_many_arguments)]
async fn render_calendars_page<CS: CalendarStore>(
    cal_store: &Arc<CS>,
    share_store: &Arc<dyn CollectionShareStore>,
    sub_store: Option<&Arc<dyn SubscriptionStore>>,
    base_url: &str,
    user: &Principal,
    credential_server_url: Option<String>,
    credential_username: Option<String>,
    credential_token: Option<String>,
    credential_calendar_id: Option<String>,
    credential_email: Option<String>,
    error: Option<String>,
) -> Response {
    let mut calendars = vec![];
    for group in user.memberships() {
        calendars.extend(cal_store.get_calendars(group).await.unwrap());
    }

    let mut calendar_infos = vec![];
    for calendar in calendars {
        let can_generate = user.is_admin(&calendar.principal);
        // Share-link creation follows the Share page's rule: owner, or
        // `edit`/`admin` group members (§17.9.2).
        let can_subscribe = sub_store.is_some() && user.can_write(&calendar.principal);
        // The calendar's existing share link, if any (§17.7) — looked up per
        // owner principal like the Share page does.
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
                can_manage: can_generate,
            })
            .collect();
        calendar_infos.push(CalendarTile {
            meta: cal_store
                .calendar_metadata(&calendar.principal, &calendar.id)
                .await
                .unwrap(),
            calendar,
            can_generate,
            subscribe_url: sub.as_ref().map(|s| export_url(base_url, &s.token, s.kind)),
            sub_id: sub.as_ref().map(|s| s.id.clone()),
            can_subscribe,
            guest_shares,
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

    UserPage {
        section: CalendarsSection {
            user: user.clone(),
            calendars: calendar_infos,
            deleted_calendars: deleted_calendar_infos,
            credential_server_url,
            credential_username,
            credential_token,
            credential_calendar_id,
            credential_email,
            error,
        },
        user: user.clone(),
    }
    .into_response()
}

pub async fn route_calendars<CS: CalendarStore>(
    Path(user_id): Path<String>,
    Extension(cal_store): Extension<Arc<CS>>,
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
    render_calendars_page(
        &cal_store,
        &share_store,
        sub_store.as_ref(),
        &base_url,
        &user,
        None,
        None,
        None,
        None,
        None,
        None,
    )
    .await
}

#[derive(Template, WebTemplate)]
#[template(path = "pages/calendar.html")]
struct CalendarPage {
    calendar: Calendar,
    user: Principal,
}

impl DefaultLayoutData for CalendarPage {
    fn get_user(&self) -> Option<&Principal> {
        Some(&self.user)
    }
}

pub async fn route_calendar<C: CalendarStore>(
    Path((owner, cal_id)): Path<(String, String)>,
    Extension(store): Extension<Arc<C>>,
    user: Principal,
) -> Result<Response, rustical_store::Error> {
    if !user.is_principal(&owner) {
        return Ok(StatusCode::UNAUTHORIZED.into_response());
    }
    Ok(CalendarPage {
        calendar: store.get_calendar(&owner, &cal_id, true).await?,
        user,
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
    /// configured (same behavior as the Share page guest invite).
    #[serde(default)]
    pub email: Option<String>,
}

/// Resolve the base URL the credential's server URL is printed with: the
/// configured `[subscriptions] public_url`, else the request's own host
/// (mirrors the Share page [`crate::routes::share`] logic).
fn resolve_base_url(public_url: &str, host: &Host) -> String {
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
/// the same mechanism the Share page guest invite uses, but the privilege is
/// always `admin` (full read/write/admin) and the surface is per-calendar.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub async fn route_calendar_credentials<AP: AuthenticationProvider, CS: CalendarStore>(
    Path(user_id): Path<String>,
    Extension(auth_provider): Extension<Arc<AP>>,
    Extension(cal_store): Extension<Arc<CS>>,
    Extension(share_store): Extension<Arc<dyn CollectionShareStore>>,
    Extension(sub_store): Extension<Option<Arc<dyn SubscriptionStore>>>,
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
            &base_url,
            &user,
            None,
            None,
            None,
            None,
            None,
            Some("No calendar specified.".to_owned()),
        )
        .await;
    }

    // Fail fast on a wrong collection id (same discipline as the Share page).
    if cal_store
        .get_calendar(&form.principal, &form.calendar_id, false)
        .await
        .is_err()
    {
        return render_calendars_page(
            &cal_store,
            &share_store,
            sub_store.as_ref(),
            &base_url,
            &user,
            None,
            None,
            None,
            None,
            None,
            Some(format!(
                "No such calendar '{}' for '{}'.",
                form.calendar_id, form.principal
            )),
        )
        .await;
    }

    // Validate the optional email (same as the Share page guest invite).
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
                &base_url,
                &user,
                None,
                None,
                None,
                None,
                None,
                Some("Please enter a valid email address.".to_owned()),
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
            &base_url,
            &user,
            None,
            None,
            None,
            None,
            None,
            Some(format!("Could not create guest principal: {err}")),
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
                &base_url,
                &user,
                None,
                None,
                None,
                None,
                None,
                Some(format!("Could not mint app token: {err}")),
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
            &base_url,
            &user,
            None,
            None,
            None,
            None,
            None,
            Some(format!("Could not create calendar credential: {err}")),
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
        &base_url,
        &user,
        Some(server_url),
        Some(guest_id),
        Some(credential),
        Some(form.calendar_id),
        email,
        None,
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
/// credential-less share link from the Calendars screen (PLAN.md §17.7):
/// the same `/export/{token}.ics` URL the Share page mints, surfaced where
/// the calendar itself is listed. Reuses the existing subscription when one
/// already exists, so the URL stays stable.
pub async fn route_calendar_subscribe<CS: CalendarStore>(
    Path(user_id): Path<String>,
    Extension(cal_store): Extension<Arc<CS>>,
    Extension(share_store): Extension<Arc<dyn CollectionShareStore>>,
    Extension(sub_store): Extension<Option<Arc<dyn SubscriptionStore>>>,
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
    // `edit`/`admin` privilege (same rule as the Share page's share links).
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
        let base_url = base_url.clone();
        let user = user.clone();
        move |msg: String| async move {
            render_calendars_page(
                &cal_store,
                &share_store,
                Some(&sub_store),
                &base_url,
                &user,
                None,
                None,
                None,
                None,
                None,
                Some(msg),
            )
            .await
        }
    };

    if form.calendar_id.is_empty() {
        return page_error("No calendar specified.".to_owned()).await;
    }

    // Fail fast on a wrong collection id (same discipline as the Share page).
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
    // calendar tile simply stays without a share link).
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

    Redirect::to(&format!("/frontend/user/{}/calendar", user.id)).into_response()
}
