use std::{str::FromStr, sync::Arc};

use crate::routes::addressbooks::AddressbooksExtras;
use crate::routes::calendar::{CalendarsExtras, resolve_base_url};
use crate::routes::user::{ProfileDeps, ProfileExtras, ProfileRequest, render_profile_page};
use axum::extract::Path;
use axum::response::{IntoResponse, Redirect, Response};
use axum::{Extension, Form};
use http::StatusCode;
use rustical_scheduling::{SmtpAccount, mime, smtp};
use rustical_store::{
    AddressbookStore, CalendarStore, CollectionShareStore, InviteStore, PrefixedCalendarStore,
    SubscriptionKind, SubscriptionStore,
    auth::{AuthenticationProvider, Principal, Privilege},
};
use serde::Deserialize;
use uuid::Uuid;

use super::app_token::generate_app_token;

#[derive(Debug, Clone, Deserialize)]
pub struct CreateShareForm {
    pub principal: String,
    pub kind: String,
    pub collection_id: String,
}

/// POST /{user}/share/create — mint a share link for one of the user's own
/// or owned-group collections. The token is the app-token shape (64-char
/// alphanumeric); the URL is byte-identical to the `subscriptions add` CLI
/// (same token shape, same shared `export_url` builder). Redirects back to
/// the Calendars (calendar) or Addressbooks (addressbook) section the form
/// was posted from (PLAN.md §17.15 — the Share tab is gone), and errors
/// re-render the unified profile page with the banner in that section.
#[allow(clippy::too_many_lines)]
pub async fn route_share_create<
    AP: AuthenticationProvider,
    CS: CalendarStore,
    AS: AddressbookStore + PrefixedCalendarStore,
>(
    Path(user_id): Path<String>,
    deps: ProfileDeps<AP, CS, AS>,
    req: ProfileRequest,
    user: Principal,
    Form(form): Form<CreateShareForm>,
) -> Response {
    if user_id != user.id {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    let Some(sub_store) = deps.sub_store.clone() else {
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
        SubscriptionKind::Calendar => deps
            .cal_store
            .get_calendar(&form.principal, &form.collection_id, false)
            .await
            .is_ok(),
        SubscriptionKind::Addressbook => deps
            .addr_store
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
        Ok(_) => {
            let location = match kind {
                SubscriptionKind::Calendar => {
                    format!(
                        "/frontend/user/{}/calendar#cal-{}",
                        user.id, form.collection_id
                    )
                }
                SubscriptionKind::Addressbook => format!(
                    "/frontend/user/{}/addressbook#ab-{}",
                    user.id, form.collection_id
                ),
            };
            Redirect::to(&location).into_response()
        }
        Err(err) => {
            let error = format!("Could not create the share link: {err}");
            match kind {
                SubscriptionKind::Calendar => {
                    render_profile_page(
                        &deps,
                        &req,
                        &user,
                        ProfileExtras {
                            calendars: CalendarsExtras {
                                error: Some(error),
                                ..CalendarsExtras::default()
                            },
                            ..ProfileExtras::default()
                        },
                    )
                    .await
                }
                SubscriptionKind::Addressbook => {
                    render_profile_page(
                        &deps,
                        &req,
                        &user,
                        ProfileExtras {
                            addressbooks: AddressbooksExtras {
                                error: Some(error),
                                ..AddressbooksExtras::default()
                            },
                            ..ProfileExtras::default()
                        },
                    )
                    .await
                }
            }
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct RevokeShareForm {
    pub principal: String,
}

/// POST /{user}/share/{id}/revoke — remove a share link of the user's own or
/// an owned-group principal (the URL stops working immediately). Redirects
/// back to the tab the collection lives on (kind learned from the
/// subscription itself).
pub async fn route_share_revoke(
    Path((user_id, id)): Path<(String, String)>,
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
    // Learn the subscription's kind + collection before deleting it, so the
    // redirect lands on the right tab at the right tile.
    let target = match &sub_store {
        Some(store) => store
            .get_subscriptions(&form.principal)
            .await
            .unwrap_or_default()
            .into_iter()
            .find(|s| s.id == id)
            .map(|s| (s.kind, s.collection_id)),
        None => None,
    };
    if let Some(store) = &sub_store {
        let _ = store.delete_subscription(&form.principal, &id).await;
    }
    let location = match target {
        Some((SubscriptionKind::Calendar, collection_id)) => {
            format!("/frontend/user/{}/calendar#cal-{}", user.id, collection_id)
        }
        Some((SubscriptionKind::Addressbook, collection_id)) => {
            format!(
                "/frontend/user/{}/addressbook#ab-{}",
                user.id, collection_id
            )
        }
        None => format!("/frontend/user/{}/calendar", user.id),
    };
    Redirect::to(&location).into_response()
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
/// to the invitee. The profile page re-renders with the link in the minted
/// calendar's tile (one-time banner, §17.15).
pub async fn route_share_invite<
    AP: AuthenticationProvider,
    CS: CalendarStore,
    AS: AddressbookStore + PrefixedCalendarStore,
>(
    Path(user_id): Path<String>,
    deps: ProfileDeps<AP, CS, AS>,
    req: ProfileRequest,
    user: Principal,
    Form(form): Form<SendInviteForm>,
) -> Response {
    if user_id != user.id {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    let base_url = resolve_base_url(&req.public_url, req.host.as_ref());
    let page_error = |msg: String| {
        let deps = deps.clone();
        let req = req.clone();
        let user = user.clone();
        async move {
            render_profile_page(
                &deps,
                &req,
                &user,
                ProfileExtras {
                    calendars: CalendarsExtras {
                        error: Some(msg),
                        ..CalendarsExtras::default()
                    },
                    ..ProfileExtras::default()
                },
            )
            .await
        }
    };

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
        return page_error("Please enter a valid email address.".to_owned()).await;
    }

    // Invites are calendar-only today (§17.9.1 keeps the surface as-is).
    if form.kind != "calendar" {
        return page_error("Invites are only supported for calendars.".to_owned()).await;
    }
    // Fail fast on a wrong collection id (same discipline as share create).
    // Fail fast on a wrong collection id (same discipline as share create).
    if deps
        .cal_store
        .get_calendar(&form.principal, &form.collection_id, false)
        .await
        .is_err()
    {
        return page_error(format!(
            "No such calendar '{}' for '{}'.",
            form.collection_id, form.principal
        ))
        .await;
    }

    let code = generate_invite_code();
    let target_group = if form.principal == user.id {
        None
    } else {
        Some(form.principal.clone())
    };

    if let Err(err) = deps
        .invite_store
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
        return page_error(format!("Could not create invite: {err}")).await;
    }

    let invite_url = format!("{base_url}/register?code={code}");
    render_profile_page(
        &deps,
        &req,
        &user,
        ProfileExtras {
            calendars: CalendarsExtras {
                invite_url: Some(invite_url),
                invited_email: email,
                invite_collection_id: Some(form.collection_id.clone()),
                invite_principal: Some(form.principal.clone()),
                ..CalendarsExtras::default()
            },
            ..ProfileExtras::default()
        },
    )
    .await
}

#[derive(Debug, Clone, Deserialize)]
pub struct RevokeInviteForm {
    pub principal: String,
}

/// POST /{user}/share/invite/{code}/revoke — revoke an unredeemed invite
/// shown on a calendar tile (the registration link stops working).
pub async fn route_share_invite_revoke(
    Path((user_id, code)): Path<(String, String)>,
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
    // Remember the tile the invite belongs to so the redirect can anchor it.
    let collection_id = invite_store
        .get_invite(&code)
        .await
        .ok()
        .flatten()
        .and_then(|invite| invite.collection_id);
    let _ = invite_store.delete_invite(&code).await;
    let location = match collection_id {
        Some(collection_id) => format!("/frontend/user/{}/calendar#cal-{}", user.id, collection_id),
        None => format!("/frontend/user/{}/calendar", user.id),
    };
    Redirect::to(&location).into_response()
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
///   6. Re-render the profile page with a one-time credential banner on the
///      minted calendar's tile (§17.15).
#[allow(clippy::too_many_lines)]
pub async fn route_share_guest_invite<
    AP: AuthenticationProvider,
    CS: CalendarStore,
    AS: AddressbookStore + PrefixedCalendarStore,
>(
    Path(user_id): Path<String>,
    deps: ProfileDeps<AP, CS, AS>,
    req: ProfileRequest,
    Extension(smtp_accounts): Extension<Vec<SmtpAccount>>,
    user: Principal,
    Form(form): Form<GuestInviteForm>,
) -> Response {
    if user_id != user.id {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    let base_url = resolve_base_url(&req.public_url, req.host.as_ref());
    let page_error = |msg: String| {
        let deps = deps.clone();
        let req = req.clone();
        let user = user.clone();
        async move {
            render_profile_page(
                &deps,
                &req,
                &user,
                ProfileExtras {
                    calendars: CalendarsExtras {
                        error: Some(msg),
                        ..CalendarsExtras::default()
                    },
                    ..ProfileExtras::default()
                },
            )
            .await
        }
    };

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
        Err(msg) => return page_error(msg).await,
    };

    // V1 is calendar-only (§17.10.1 table shape — `kind` is a field, but
    // the portal form does not expose it today).
    if form.collection_id.is_empty() {
        return page_error("No collection specified.".to_owned()).await;
    }

    // Fail fast on wrong collection id (same discipline as share create).
    if deps
        .cal_store
        .get_calendar(&form.principal, &form.collection_id, false)
        .await
        .is_err()
    {
        return page_error(format!(
            "No such calendar '{}' for '{}'.",
            form.collection_id, form.principal
        ))
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
            return page_error("Please enter a valid email address.".to_owned()).await;
        }
        Some(e) => Some(e.to_lowercase()),
        None => None,
    };

    // 1. Create guest principal.
    let guest_id = format!("guest-{}", Uuid::new_v4());
    if let Err(err) = deps
        .auth_provider
        .insert_principal(
            rustical_store::auth::Principal {
                id: guest_id.clone(),
                displayname: Some(format!("Guest of {}", form.collection_id)),
                memberships: vec![],
                password: None,
                principal_type: rustical_store::auth::PrincipalType::Individual,
                needs_password_change: false,
                privileges: std::collections::BTreeMap::new(),
            },
            false,
        )
        .await
    {
        return page_error(format!("Could not create guest principal: {err}")).await;
    }

    // 2. Mint app token → DAV credential.
    let token_secret = generate_app_token();
    let mut token_id = match deps
        .auth_provider
        .add_app_token(
            &guest_id,
            format!("{} guest", form.collection_id),
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

    // 3. Persist the share row.
    if let Err(err) = deps
        .share_store
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
        return page_error(format!("Could not create guest share: {err}")).await;
    }

    let server_url = format!("{base_url}/caldav");

    // 3b. A credential-less subscribe link for the same calendar (Google
    //     "From URL", webcal — §17.8): reuse the calendar's share link when
    //     one already exists, otherwise mint one. When subscriptions are
    //     disabled the guest email simply omits this section.
    let subscribe_url = ensure_subscribe_url(
        deps.sub_store.as_ref(),
        &form.principal,
        &form.collection_id,
        &base_url,
    )
    .await;

    // 4. Optionally deliver the credential by email (Omnical §17.10.7):
    //    when an SMTP account is configured and an email was provided,
    //    `send_mail` sends the plaintext setup (with the credential-less
    //    subscribe link when available). Without SMTP the invite still
    //    succeeds — the share row keeps `target_email` for audit and the
    //    credential stays on the Calendars screen (one-time banner).
    if let (Some(to), Some(account)) = (email.as_deref(), smtp_accounts.first()) {
        let message = mime::build_guest_invite(
            account,
            to,
            &server_url,
            &guest_id,
            &credential,
            &form.collection_id,
            &user.id,
            subscribe_url.as_deref(),
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

    render_profile_page(
        &deps,
        &req,
        &user,
        ProfileExtras {
            calendars: CalendarsExtras {
                guest_share_server_url: Some(server_url),
                guest_share_username: Some(guest_id),
                guest_share_credential: Some(credential),
                guest_share_calendar_id: Some(form.collection_id.clone()),
                guest_share_principal: Some(form.principal.clone()),
                guest_share_email: email,
                guest_share_subscribe_url: subscribe_url,
                ..CalendarsExtras::default()
            },
            ..ProfileExtras::default()
        },
    )
    .await
}

/// Return the `/export/{token}.ics` URL of a calendar's share link, reusing
/// the existing subscription when one exists and minting a new token
/// otherwise (same discipline as the Calendars screen's "Create subscribe
/// link"). `None` when subscriptions are disabled or minting fails — the
/// caller falls back to credentials-only.
pub(super) async fn ensure_subscribe_url(
    sub_store: Option<&Arc<dyn SubscriptionStore>>,
    principal: &str,
    collection_id: &str,
    base_url: &str,
) -> Option<String> {
    let store = sub_store?;
    let existing = store
        .get_subscriptions(principal)
        .await
        .unwrap_or_default()
        .into_iter()
        .find(|s| s.kind == SubscriptionKind::Calendar && s.collection_id == collection_id);
    let token = if let Some(sub) = existing {
        sub.token
    } else {
        let token = generate_app_token();
        if store
            .add_subscription(principal, SubscriptionKind::Calendar, collection_id, &token)
            .await
            .is_err()
        {
            return None;
        }
        token
    };
    Some(crate::url_builder::export_url(
        base_url,
        &token,
        SubscriptionKind::Calendar,
    ))
}

#[derive(Debug, Clone, Deserialize)]
pub struct RevokeGuestShareForm {
    pub principal: String,
}

/// POST /{user}/share/guest-invite/{id}/revoke — revoke an active guest
/// share (sets `revoked_at`; the row stays for audit).
pub async fn route_share_guest_revoke(
    Path((user_id, id)): Path<(String, String)>,
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
    Redirect::to(&format!("/frontend/user/{}/calendar", user.id)).into_response()
}
