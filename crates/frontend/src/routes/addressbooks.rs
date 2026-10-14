use askama::Template;
use axum::{
    Extension,
    extract::{Form, Path},
    response::{IntoResponse, Redirect, Response},
};
use caldata::component::{Component as _, ComponentMut as _};
use caldata::parser::ParserOptions;
use caldata::{VcardParser, component::VcardContact};
use http::StatusCode;
use rustical_scheduling::{SmtpAccount, mime, smtp};
use rustical_store::{
    Addressbook, AddressbookReadStore, AddressbookStore, AddressbookWriteStore, Calendar,
    CalendarStore, CollectionMetadata, CollectionShareStore, PrefixedCalendarStore,
    SubscriptionKind, SubscriptionStore,
    auth::{AuthenticationProvider, Principal, PrincipalType, Privilege},
};
use serde::Deserialize;
use std::sync::Arc;
use uuid::Uuid;

use crate::routes::app_token::generate_app_token;
use crate::routes::calendar::{GuestShareEntry, resolve_base_url};
use crate::routes::user::{
    ProfileAnchor, ProfileDeps, ProfileExtras, ProfileRequest, render_profile_page,
};
use crate::url_builder::export_url;

/// One addressbook tile of the profile's Addressbooks section: the rendered
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
    /// §18.43: true when the acting user may import contacts into this
    /// book (owner, or `edit`/`admin` of the owning group) — the same
    /// write rule the import route enforces.
    pub can_import: bool,
    /// Active full-access credentials minted for this addressbook (§17.12.1),
    /// each with its own Revoke control.
    pub guest_shares: Vec<GuestShareEntry>,
}

#[derive(Template)]
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

/// One-time banner payloads of the Addressbooks section — all `None` on a
/// plain page load; the credentials POST sets exactly the credential fields.
#[derive(Default)]
pub struct AddressbooksExtras {
    pub error: Option<String>,
    pub credential_server_url: Option<String>,
    pub credential_username: Option<String>,
    pub credential_token: Option<String>,
    pub credential_addressbook_id: Option<String>,
    pub credential_email: Option<String>,
}

impl AddressbooksExtras {
    /// True when any one-time banner is set — the profile page expands the
    /// Addressbooks heading for a render that carries one.
    #[must_use]
    pub const fn has_banner(&self) -> bool {
        self.error.is_some() || self.credential_server_url.is_some()
    }
}

/// The shared Addressbooks-section builder: lists the user's addressbooks
/// with their share-link and credential blocks plus an error banner (§17.15,
/// §17.12.1). Rendered into the profile page's collapsible Addressbooks
/// heading.
#[allow(clippy::too_many_lines)]
pub async fn build_addressbooks_section<AS: AddressbookStore + PrefixedCalendarStore>(
    addr_store: &Arc<AS>,
    share_store: &Arc<dyn CollectionShareStore>,
    sub_store: Option<&Arc<dyn SubscriptionStore>>,
    base_url: &str,
    user: &Principal,
    extras: AddressbooksExtras,
) -> AddressbooksSection {
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
        // §18.43: importing contacts is writing them — the same rule as
        // the route's gate.
        let can_import = user.can_write(&addressbook.principal);
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
            can_import,
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

    AddressbooksSection {
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
    }
}

/// GET /{user}/addressbook — the former Addressbooks tab: the same unified
/// profile page with its Addressbooks heading expanded.
pub async fn route_addressbooks<
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
    render_profile_page(
        &deps,
        &req,
        &user,
        ProfileExtras {
            anchor: ProfileAnchor::Addressbooks,
            ..ProfileExtras::default()
        },
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
#[allow(clippy::too_many_lines)]
pub async fn route_addressbook_credentials<
    AP: AuthenticationProvider,
    CS: CalendarStore,
    AS: AddressbookStore + PrefixedCalendarStore,
>(
    Path(user_id): Path<String>,
    deps: ProfileDeps<AP, CS, AS>,
    req: ProfileRequest,
    Extension(smtp_accounts): Extension<Vec<SmtpAccount>>,
    user: Principal,
    Form(form): Form<AddressbookCredentialsForm>,
) -> Response {
    if user_id != user.id {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    let base_url = resolve_base_url(&req.public_url, req.host.as_ref());

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

    // Every error path below re-renders the unified profile page with the
    // banner in its Addressbooks section (which the banner expands).
    let page_error = |error: String| {
        let deps = deps.clone();
        let req = req.clone();
        let user = user.clone();
        async move {
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
    };

    if form.addressbook_id.is_empty() {
        return page_error("No addressbook specified.".to_owned()).await;
    }

    // Fail fast on a wrong addressbook id (same discipline as the calendar
    // credentials route).
    if deps
        .addr_store
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
    if let Err(err) = deps
        .auth_provider
        .insert_principal(
            Principal {
                id: guest_id.clone(),
                displayname: Some(format!("Guest of {}", form.addressbook_id)),
                memberships: vec![],
                password: None,
                principal_type: PrincipalType::Individual,
                needs_password_change: false,
                timezone: String::new(),
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
    let mut token_id = match deps
        .auth_provider
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
    if let Err(err) = deps
        .share_store
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

    render_profile_page(
        &deps,
        &req,
        &user,
        ProfileExtras {
            addressbooks: AddressbooksExtras {
                credential_server_url: Some(server_url),
                credential_username: Some(guest_id),
                credential_token: Some(credential),
                credential_addressbook_id: Some(form.addressbook_id),
                credential_email: email,
                ..AddressbooksExtras::default()
            },
            ..ProfileExtras::default()
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

/// The contacts-import result, as the plain phrase the dialog prints:
/// how many contacts were added, how many were skipped because they
/// were already in the book (matched by their vCard `UID`), how many
/// CSV rows carried no usable contact at all, and how many the store
/// refused.
#[derive(Debug, Default)]
pub struct ContactsImportOutcome {
    pub imported: usize,
    pub skipped_existing: usize,
    pub skipped_empty: usize,
    pub failed: usize,
}

use std::fmt::Write as _;

impl ContactsImportOutcome {
    /// The one-line summary a non-technical user reads: counts first,
    /// jargon never.
    #[must_use]
    pub fn summary(&self) -> String {
        let mut out = if self.imported == 1 {
            "Added 1 contact.".to_owned()
        } else {
            format!("Added {} contacts.", self.imported)
        };
        if self.skipped_existing > 0 {
            let which = if self.skipped_existing == 1 {
                "that was"
            } else {
                "that were"
            };
            let skipped = self.skipped_existing;
            let _ = write!(
                out,
                " Skipped {skipped} {which} already in this addressbook."
            );
        }
        if self.skipped_empty > 0 {
            let (what, them) = if self.skipped_empty == 1 {
                ("row", "it")
            } else {
                ("rows", "them")
            };
            let ignored = self.skipped_empty;
            let _ = write!(
                out,
                " Ignored {ignored} {what} with nothing recognizable in {them}."
            );
        }
        if self.failed > 0 {
            let failed = self.failed;
            let _ = write!(
                out,
                " {failed} could not be stored (the server log says why)."
            );
        }
        out
    }
}

/// One contact as the fields every producer can express in some
/// spelling — the CSV path's field view, and what the summary counts
/// on. The vCard path never reduces a card to this (that would lose
/// BDAY/ADR/PHOTO/…); it keeps the whole card.
#[derive(Debug, Default)]
struct ParsedContact {
    given: String,
    family: String,
    full_name: String,
    emails: Vec<String>,
    phones: Vec<String>,
    organization: String,
    note: String,
}

impl ParsedContact {
    /// A row is a contact when it has something to show: a name, or a
    /// way to reach them.
    #[must_use]
    const fn is_usable(&self) -> bool {
        !(self.full_name.is_empty()
            && self.given.is_empty()
            && self.family.is_empty()
            && self.emails.is_empty()
            && self.phones.is_empty())
    }

    /// The `FN:` value: the full name if given, else given + family.
    #[must_use]
    fn display_name(&self) -> String {
        if !self.full_name.is_empty() {
            return self.full_name.clone();
        }
        let joined = [self.given.as_str(), self.family.as_str()]
            .iter()
            .filter(|part| !part.is_empty())
            .copied()
            .collect::<Vec<_>>()
            .join(" ");
        if joined.is_empty() {
            self.emails.first().cloned().unwrap_or_default()
        } else {
            joined
        }
    }

    /// The vCard text of this contact, `VERSION:3.0`, with `uid` as its
    /// `UID`. Values escaped per RFC 6350 (`\` first, then `;`, `,` and
    /// newlines as `\n`) — a value that breaks the line format would
    /// break every client that reads it back.
    fn to_vcard(&self, uid: &str) -> String {
        let esc = |value: &str| -> String {
            value
                .replace('\\', "\\\\")
                .replace(';', "\\;")
                .replace(',', "\\,")
                .replace(['\r', '\n'], "\\n")
        };
        let mut out = String::from("BEGIN:VCARD\r\nVERSION:3.0\r\n");
        let family = esc(&self.family);
        let given = esc(&self.given);
        let _ = write!(out, "N:{family};{given};;;\r\n");
        let display = esc(&self.display_name());
        let _ = write!(out, "FN:{display}\r\n");
        for email in &self.emails {
            let email = esc(email);
            let _ = write!(out, "EMAIL:{email}\r\n");
        }
        for phone in &self.phones {
            let phone = esc(phone);
            let _ = write!(out, "TEL:{phone}\r\n");
        }
        if !self.organization.is_empty() {
            let organization = esc(&self.organization);
            let _ = write!(out, "ORG:{organization}\r\n");
        }
        if !self.note.is_empty() {
            let note = esc(&self.note);
            let _ = write!(out, "NOTE:{note}\r\n");
        }
        let _ = write!(out, "UID:{uid}\r\n");
        out.push_str("END:VCARD\r\n");
        out
    }
}

/// One thing an import file contributes: either a whole vCard from a
/// `.vcf` file (kept intact — every property survives), or a row of a
/// contacts CSV (reduced to [`ParsedContact`], from which a vCard is
/// built).
enum ImportCandidate {
    Card(VcardContact),
    Row(ParsedContact),
}

/// The `VcardContact` with a UID, or `None` when `build` refuses the
/// stamp (a card the parser accepted but the builder rejects — never
/// seen, and the honest response is to skip it, not to import a card
/// whose uid-less row would orphan on the next import).
fn stamp_uid(card: VcardContact, uid: &str) -> Option<VcardContact> {
    let mut builder = card.mutable();
    builder.add_content_line(caldata::parser::ContentLine {
        name: "UID".to_owned(),
        value: uid.to_owned(),
        ..Default::default()
    });
    builder.build(&ParserOptions::default(), None).ok()
}

/// The `VcardContact` of one vCard text block (the CSV path's built
/// card), or `None` when it does not parse.
fn card_from_vcard_text(text: &str) -> Option<VcardContact> {
    VcardParser::from_slice(text.as_bytes())
        .next()
        .and_then(Result::ok)
}

/// Parse the rows of an RFC-4180-ish CSV: quoted fields, escaped
/// quotes (`""`), commas and newlines inside quotes, CRLF or LF line
/// ends. Hand-rolled because a `csv` crate is not a workspace
/// dependency and the two producers this exists for (Google's and
/// Outlook's contact exports) are plain quoted CSV. All-empty rows
/// are KEPT, not dropped here: a row of empty cells is a real row the
/// user can see in their spreadsheet, and the import's summary says
/// "Ignored N rows with nothing recognizable in them" — dropping them
/// silently here would make that count a lie.
fn csv_rows(body: &str) -> Vec<Vec<String>> {
    let mut rows: Vec<Vec<String>> = Vec::new();
    let mut row: Vec<String> = Vec::new();
    let mut field = String::new();
    let mut in_quotes = false;
    let mut chars = body.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            '"' if in_quotes && chars.peek() == Some(&'"') => {
                chars.next();
                field.push('"');
            }
            '"' => in_quotes = !in_quotes,
            ',' if !in_quotes => row.push(std::mem::take(&mut field)),
            '\r' if !in_quotes && chars.peek() == Some(&'\n') => {
                chars.next();
                row.push(std::mem::take(&mut field));
                rows.push(std::mem::take(&mut row));
            }
            '\n' if !in_quotes => {
                row.push(std::mem::take(&mut field));
                rows.push(std::mem::take(&mut row));
            }
            other => field.push(other),
        }
    }
    if !field.is_empty() || !row.is_empty() {
        row.push(field);
        rows.push(row);
    }
    rows
}

/// The contacts of a contacts CSV (Google's and Outlook's export
/// formats). The first row is the header; every later row is one
/// contact. Columns are found by keyword, case-insensitively, so both
/// spellings work (`E-mail 1 - Value`, `E-mail Address`; `Phone 1 -
/// Value`, `Mobile Phone`); `Type` columns are excluded, unknown
/// columns are ignored (the address book is moving, not the file
/// format), and all of a kind are imported (every email, every phone
/// number — a contact with three emails keeps three).
fn contacts_from_csv(body: &str) -> Vec<ImportCandidate> {
    let mut rows = csv_rows(body).into_iter();
    let Some(header) = rows.next() else {
        return Vec::new();
    };
    let lower = |cell: &str| cell.trim().to_ascii_lowercase();
    let is_type_column = |cell: &str| lower(cell).contains("type");
    // The exact-name "Name" column (Google's display name) — matched by
    // equality, not containment, so "Given Name"/"Company Name"/… do not
    // shadow it.
    let full = header
        .iter()
        .position(|cell| lower(cell) == "name" || lower(cell) == "full name");
    let given = header
        .iter()
        .position(|cell| lower(cell).contains("given name") || lower(cell).contains("first name"));
    let family = header.iter().position(|cell| {
        lower(cell).contains("family name")
            || lower(cell).contains("last name")
            || lower(cell).contains("surname")
    });
    let organization = header
        .iter()
        .position(|cell| lower(cell).contains("organization") || lower(cell).contains("company"));
    let note = header.iter().position(|cell| lower(cell).contains("note"));
    let email_cols: Vec<usize> = header
        .iter()
        .enumerate()
        .filter(|(_, cell)| {
            let lower = lower(cell);
            !is_type_column(cell)
                && (lower.contains("mail") || lower.contains("e-mail"))
                && (lower.contains("value") || lower.contains("address"))
        })
        .map(|(index, _)| index)
        .collect();
    let phone_cols: Vec<usize> = header
        .iter()
        .enumerate()
        .filter(|(_, cell)| {
            let lower = lower(cell);
            !is_type_column(cell)
                && (lower.contains("phone")
                    || lower.contains("mobile")
                    || lower.contains("telephone"))
                && (lower.contains("value") || lower.contains("phone"))
        })
        .map(|(index, _)| index)
        .collect();

    rows.map(|row| {
        let cell = |index: Option<usize>| -> String {
            index
                .and_then(|index| row.get(index))
                .map(|value| value.trim().to_owned())
                .unwrap_or_default()
        };
        let values = |cols: &[usize]| -> Vec<String> {
            cols.iter()
                .filter_map(|col| row.get(*col))
                .map(|value| value.trim().to_owned())
                .filter(|value| !value.is_empty())
                .collect()
        };
        ImportCandidate::Row(ParsedContact {
            given: cell(given),
            family: cell(family),
            full_name: cell(full),
            emails: values(&email_cols),
            phones: values(&phone_cols),
            organization: cell(organization),
            note: cell(note),
        })
    })
    .collect()
}

/// The contacts of a vCard file: every `BEGIN:VCARD` block, kept whole
/// (the file's own properties — birthday, address, photo, … — are the
/// point of an import). A card that fails to parse is skipped, not
/// fatal: one producer's broken line must not cost the user the other
/// 500 contacts behind it.
fn contacts_from_vcf(body: &str) -> Vec<ImportCandidate> {
    caldata::VcardParser::from_slice(body.as_bytes())
        .filter_map(Result::ok)
        .map(ImportCandidate::Card)
        .collect()
}

/// POST `/{user}/addressbook/import/{principal}/{addressbook_id}` — the
/// "Import contacts" button (Addressbooks section): bring contacts in
/// from a file exported by another service — Google, Apple, Outlook,
/// Nextcloud, a phone — as vCard (`.vcf`, which every one of them can
/// export) or a contacts CSV (Google's and Outlook's export formats).
/// The verb rides a STATIC path segment (like `credentials`, unlike
/// the calendar `…/restore` shape): the contact-object POST route owns
/// the literal `contacts` one position deeper, and matchit prefers the
/// static segment — so a `…/{principal}/{addressbook_id}/import` shape
/// would have routed the default `contacts` book's imports into the
/// contact-edit form handler (a 415), not here.
///
/// The file arrives as the raw request body (the house `Lit`-component
/// `fetch`-the-`File` pattern, like `import-calendar-form` — no
/// multipart), so the destination rides in the URL and the body is
/// the whole file. vCard vs CSV is sniffed off the first non-blank
/// content: `BEGIN:VCARD` is unambiguous, and no CSV export starts
/// with it.
///
/// Duplicate handling: a contact whose vCard `UID` already exists in
/// the destination book is **skipped**, never overwritten. An import is
/// a move-in, not a merge — and a `.vcf` re-exported after a sync
/// contains every contact you already have, so the safe default for a
/// button is "skip what I know, add what I don't". Re-importing the
/// same file is a no-op.
///
/// Response: a plain-text phrase (the Lit dialog shows it verbatim),
/// `200` on any outcome that is not a gate failure — including "added
/// zero", because the file *was* processed, it just had nothing new —
/// and `400` when no contact parses out of the file at all (it is
/// neither a vCard export nor a contacts CSV).
///
/// Gates: `user_id == user.id`; `principal == user.id ||
/// user.can_write(principal)` (importing is writing); the addressbook
/// exists. No CSRF token: profile POSTs don't carry one (session
/// `SameSite=Lax` + these gates — the credentials/subscribe pattern).
pub async fn route_post_contacts_import<AS: AddressbookStore + PrefixedCalendarStore>(
    Path((user_id, principal, addressbook_id)): Path<(String, String, String)>,
    Extension(addr_store): Extension<Arc<AS>>,
    user: Principal,
    body: String,
) -> Response {
    if user_id != user.id {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    if principal != user.id && !user.can_write(&principal) {
        return (
            StatusCode::FORBIDDEN,
            "You can only import into your own addressbook, or a group addressbook you may edit.",
        )
            .into_response();
    }

    // Fail fast on a wrong addressbook (the share routes' discipline).
    if addr_store
        .get_addressbook(&principal, &addressbook_id, false)
        .await
        .is_err()
    {
        return (
            StatusCode::NOT_FOUND,
            "No such addressbook for this account.",
        )
            .into_response();
    }

    // BOM-tolerant sniff: a vCard file always opens with BEGIN:VCARD.
    let sniff = body.trim_start_matches(['\u{feff}', ' ', '\t', '\r', '\n']);
    let candidates: Vec<ImportCandidate> = if sniff.to_ascii_uppercase().starts_with("BEGIN:VCARD")
    {
        contacts_from_vcf(&body)
    } else {
        contacts_from_csv(&body)
    };

    // Neither format: the sniff chose CSV and the CSV path parsed no
    // contact out of it — the file is neither a vCard export nor a
    // contacts CSV. A gate-style plain-language answer, not "added
    // zero" (the file was not processed, it was unrecognizable).
    if candidates.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            "No contacts found in that file. Export your contacts from the other service \
             as a vCard file (.vcf) or a contacts CSV file (a Google or Outlook export), \
             then try again.",
        )
            .into_response();
    }

    // The ids already in the book: one read, then a set-membership test
    // per contact — not a query per contact. UFCS because `AS` is also
    // a `PrefixedCalendarStore` (a `CalendarStore`), and the calendar
    // `get_objects` is a different method with the same name.
    let existing: std::collections::HashSet<String> =
        AddressbookReadStore::get_objects(&*addr_store, &principal, &addressbook_id)
            .await
            .unwrap_or_default()
            .into_iter()
            .map(|(object_id, _)| object_id)
            .collect();

    let mut outcome = ContactsImportOutcome::default();
    for candidate in candidates {
        // Resolve to (uid, card). The vcf path keeps the whole card and
        // stamps a uid only when the file's card lacks one (the CSV
        // path's cards are built here, with their uid).
        let (uid, card) = match candidate {
            ImportCandidate::Card(card) => {
                let source_uid = card.get_uid().filter(|uid| !uid.is_empty());
                if let Some(uid) = source_uid {
                    (uid.to_owned(), card)
                } else {
                    let uid = format!("imported-{}", Uuid::new_v4());
                    if let Some(card) = stamp_uid(card, &uid) {
                        (uid, card)
                    } else {
                        outcome.failed += 1;
                        continue;
                    }
                }
            }
            ImportCandidate::Row(contact) => {
                if !contact.is_usable() {
                    outcome.skipped_empty += 1;
                    continue;
                }
                let uid = format!("imported-{}", Uuid::new_v4());
                if let Some(card) = card_from_vcard_text(&contact.to_vcard(&uid)) {
                    (uid, card)
                } else {
                    // A card built by this own code not parsing is
                    // this code's bug, not the file's.
                    outcome.failed += 1;
                    continue;
                }
            }
        };

        if existing.contains(&uid) {
            outcome.skipped_existing += 1;
            continue;
        }
        // UFCS again — `put_object` is ambiguous for the same reason.
        match AddressbookWriteStore::put_object(
            &*addr_store,
            &principal,
            &addressbook_id,
            &uid,
            rustical_ical::AddressObject::from(card),
            false,
        )
        .await
        {
            Ok(()) => outcome.imported += 1,
            // A concurrent import landed the same uid first — the
            // set above is a snapshot. That is a skip, not a failure.
            Err(rustical_store::Error::AlreadyExists) => outcome.skipped_existing += 1,
            Err(error) => {
                tracing::warn!(?error, "could not store an imported contact");
                outcome.failed += 1;
            }
        }
    }

    (StatusCode::OK, outcome.summary()).into_response()
}

#[cfg(test)]
mod contacts_import_tests {
    use crate::routes::test_rig::Rig;
    use axum::body::Body as AxBody;
    use headers::{Authorization, HeaderMapExt};
    use http::{Method, Request, StatusCode};
    use rustical_store::Addressbook;
    use rustical_store::AddressbookWriteStore;
    use tower::ServiceExt;

    /// The rig's addressbook for `user` — the default contacts book's
    /// shape (the production store creates it on provisioning). UFCS:
    /// `SqliteAddressbookStore` is also a `PrefixedCalendarStore`, so a
    /// bare `insert_addressbook` call is ambiguous.
    async fn insert_addressbook(rig: &Rig, principal: &str, id: &str) {
        AddressbookWriteStore::insert_addressbook(
            &*rig.addr_store,
            Addressbook {
                principal: principal.to_owned(),
                id: id.to_owned(),
                displayname: Some("Contacts".to_owned()),
                description: None,
                deleted_at: None,
                synctoken: 0,
                push_topic: uuid::Uuid::new_v4().to_string(),
            },
        )
        .await
        .unwrap();
    }

    /// §18.43: a `.vcf` import adds every card (whole), skips cards
    /// whose `UID` is already present, and answers with the plain
    /// phrase the dialog shows.
    #[tokio::test]
    async fn vcf_import_adds_skips_duplicates_and_answers_plainly() {
        let rig = Rig::new().await;
        insert_addressbook(&rig, "user", "contacts").await;

        let vcf = "BEGIN:VCARD\r\nVERSION:3.0\r\nN:Doe;Jane;;;\r\nFN:Jane Doe\r\n\
                   EMAIL:jane@example.com\r\nUID:source-uid-1\r\nEND:VCARD\r\n\
                   BEGIN:VCARD\r\nVERSION:3.0\r\nN:Doe;John;;;\r\nFN:John Doe\r\n\
                   TEL:+15551234\r\nBDAY:1980-01-02\r\nUID:source-uid-2\r\nEND:VCARD\r\n";
        let (status, body) = rig
            .post_body("/frontend/user/user/addressbook/import/user/contacts", vcf)
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body, "Added 2 contacts.");

        // Both landed; the vCard's own fields survived (the point of the
        // vcf path — no lossy re-render).
        let stored: String =
            sqlx::query_scalar("SELECT vcf FROM addressobjects WHERE id = 'source-uid-1'")
                .fetch_one(&rig.db)
                .await
                .unwrap();
        assert!(stored.contains("EMAIL:jane@example.com"), "{stored}");
        let birthday: String =
            sqlx::query_scalar("SELECT vcf FROM addressobjects WHERE id = 'source-uid-2'")
                .fetch_one(&rig.db)
                .await
                .unwrap();
        assert!(
            birthday.contains("BDAY") || birthday.contains("BDAY:1980"),
            "the vcf path keeps the whole card: {birthday}"
        );

        // Re-import: both UIDs known — skipped, added zero, no new rows.
        let (status, body) = rig
            .post_body("/frontend/user/user/addressbook/import/user/contacts", vcf)
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            body,
            "Added 0 contacts. Skipped 2 that were already in this addressbook."
        );
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM addressobjects")
            .fetch_one(&rig.db)
            .await
            .unwrap();
        assert_eq!(count, 2, "a re-import must not duplicate");
    }

    /// §18.43: the Google/Outlook CSV shapes — header matched by keyword
    /// (both spellings), `Type` columns ignored, unusable rows counted,
    /// quoted commas survived.
    #[tokio::test]
    async fn google_csv_import_maps_columns_and_skips_empty_rows() {
        let rig = Rig::new().await;
        insert_addressbook(&rig, "user", "contacts").await;

        let csv = "Given Name,Family Name,Name,E-mail 1 - Type,E-mail 1 - Value,Phone 1 - Type,Phone 1 - Value,Organization 1 - Value,Notes\r\n\
                   Jane,Doe,Jane Doe,home,jane@example.com,mobile,+1 555 0123,Acme Inc,\"likes tea, not coffee\"\r\n\
                   ,,,,,,,,";
        let (status, body) = rig
            .post_body("/frontend/user/user/addressbook/import/user/contacts", csv)
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            body,
            "Added 1 contact. Ignored 1 row with nothing recognizable in it."
        );

        let stored: String = sqlx::query_scalar(
            "SELECT vcf FROM addressobjects WHERE vcf LIKE '%jane@example.com%'",
        )
        .fetch_one(&rig.db)
        .await
        .unwrap();
        // Every kind landed: name parts, the email, the phone, the org,
        // the note (with its quoted comma unescaped back to a comma).
        assert!(stored.contains("N:Doe;Jane"), "{stored}");
        assert!(stored.contains("FN:Jane Doe"), "{stored}");
        assert!(stored.contains("EMAIL:jane@example.com"), "{stored}");
        assert!(stored.contains("TEL:+1 555 0123"), "{stored}");
        assert!(stored.contains("ORG:Acme Inc"), "{stored}");
        assert!(
            stored.contains("NOTE:likes tea\\, not coffee"),
            "the note's comma is escaped in the vCard: {stored}"
        );
    }

    /// §18.43: the gates — a mismatched path-user 401s, a missing
    /// addressbook 404s, a non-vCard non-CSV body answers 400 with the
    /// plain-language error.
    #[tokio::test]
    async fn import_gates_and_error_phrases() {
        let rig = Rig::new().await;
        insert_addressbook(&rig, "user", "contacts").await;

        // Wrong path-user: 401 before anything else.
        let body = "BEGIN:VCARD\r\nEND:VCARD\r\n";
        let mut req = Request::builder()
            .method(Method::POST)
            .uri("/frontend/user/other/addressbook/import/user/contacts")
            .body(AxBody::from(body))
            .unwrap();
        req.headers_mut()
            .typed_insert(Authorization::basic("user", "pass"));
        let resp = rig.router.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        // Another principal the user cannot write: 403.
        rig.insert_user("other").await;
        let (status, _) = rig
            .post_body(
                "/frontend/user/user/addressbook/import/other/contacts",
                body,
            )
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        // A missing addressbook: 404.
        let (status, phrase) = rig
            .post_body(
                "/frontend/user/user/addressbook/import/user/no-such-book",
                body,
            )
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{phrase}");

        // Neither vCard nor CSV: 400, and the phrase says what to do.
        // (A header-looking CSV with a data row *parses* — `name,email`
        // matches the Name column and the row imports — so the body
        // here is a header-only CSV: zero candidates, the 400 branch.)
        let (status, phrase) = rig
            .post_body(
                "/frontend/user/user/addressbook/import/user/contacts",
                "garbage",
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{phrase}");
        assert!(
            phrase.contains("No contacts found"),
            "the error names the formats: {phrase}"
        );
    }
}
