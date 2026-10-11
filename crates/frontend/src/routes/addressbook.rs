use std::sync::Arc;

use askama::Template;
use askama_web::WebTemplate;
use axum::{
    Extension,
    extract::{Form, Path},
    response::{IntoResponse, Redirect, Response},
};
use axum_extra::TypedHeader;
use caldata::component::Component;
use headers::Referer;
use http::StatusCode;
use rustical_ical::AddressObject;
use rustical_store::{Addressbook, AddressbookStore, auth::Principal};
use serde::Deserialize;
use uuid::Uuid;

use crate::pages::DefaultLayoutData;
use crate::pages::user::{Section, UserPage};
use crate::routes::calendar_view::{split_calendar_value, text_prop};

#[derive(Template, WebTemplate)]
#[template(path = "pages/addressbook.html")]
struct AddressbookPage {
    addressbook: Addressbook,
    user: Principal,
}

impl DefaultLayoutData for AddressbookPage {
    fn get_user(&self) -> Option<&Principal> {
        Some(&self.user)
    }
}

/// One contact rendered in a contacts list.
pub struct ContactItem {
    pub name: String,
    pub email: Option<String>,
    pub phone: Option<String>,
    /// The addressbook the contact lives in (display label; the aggregate
    /// Contacts page shows it per row).
    pub addressbook_name: String,
    /// The edit form URL for this contact's underlying object.
    pub href: String,
    /// The delete POST URL.
    pub delete_href: String,
    /// False (no controls rendered) when the user cannot write the owning
    /// principal.
    pub editable: bool,
}

/// Build one [`ContactItem`] out of a stored vCard: name / email / phone plus
/// the per-object action URLs (the same shape the Tasks list uses).
fn contact_item(
    addressbook_name: &str,
    owner: &str,
    addrbook_id: &str,
    object_id: &str,
    object: &AddressObject,
    editable: bool,
) -> ContactItem {
    let card = object.get_vcard();
    let name = card
        .full_name
        .first()
        .map(|fn_prop| fn_prop.0.as_str())
        .filter(|s| !s.is_empty())
        .map_or_else(|| "(no name)".to_owned(), ToOwned::to_owned);
    let props = card.get_properties();
    ContactItem {
        name,
        email: text_prop(props, "EMAIL").map(ToOwned::to_owned),
        phone: text_prop(props, "TEL").map(ToOwned::to_owned),
        addressbook_name: addressbook_name.to_owned(),
        href: format!("/frontend/user/{owner}/addressbook/{addrbook_id}/contacts/{object_id}/edit"),
        delete_href: format!(
            "/frontend/user/{owner}/addressbook/{addrbook_id}/contacts/{object_id}/delete"
        ),
        editable,
    }
}

#[derive(Template, WebTemplate)]
#[template(path = "pages/contacts.html")]
pub struct ContactsPage {
    pub addressbook: Addressbook,
    pub user: Principal,
    pub contacts: Vec<ContactItem>,
    /// The new-contact form URL — always present (the form itself gates).
    pub new_href: String,
    pub can_create: bool,
}

impl DefaultLayoutData for ContactsPage {
    fn get_user(&self) -> Option<&Principal> {
        Some(&self.user)
    }
}

pub async fn route_addressbook<AS: AddressbookStore>(
    Path((owner, addrbook_id)): Path<(String, String)>,
    Extension(store): Extension<Arc<AS>>,
    user: Principal,
) -> Result<Response, rustical_store::Error> {
    if !user.is_principal(&owner) {
        return Ok(StatusCode::UNAUTHORIZED.into_response());
    }
    Ok(AddressbookPage {
        addressbook: store.get_addressbook(&owner, &addrbook_id, true).await?,
        user,
    }
    .into_response())
}

/// Contacts list for one addressbook, with create/edit/delete controls for
/// principals the user can write. The `AddressbookStore` has no read-only
/// mirrors (PLAN §6 risk 3), so the gate is membership + `can_write` only.
pub async fn route_addressbook_contacts<AS: AddressbookStore>(
    Path((owner, addrbook_id)): Path<(String, String)>,
    Extension(store): Extension<Arc<AS>>,
    user: Principal,
) -> Result<Response, rustical_store::Error> {
    if !user.is_principal(&owner) {
        return Ok(StatusCode::UNAUTHORIZED.into_response());
    }
    let addressbook = store.get_addressbook(&owner, &addrbook_id, true).await?;
    let editable = user.can_write(&owner);
    let addressbook_name = addressbook
        .displayname
        .clone()
        .unwrap_or_else(|| addressbook.id.clone());
    let mut contacts = Vec::new();
    for (object_id, object) in store.get_objects(&owner, &addrbook_id).await? {
        contacts.push(contact_item(
            &addressbook_name,
            &owner,
            &addrbook_id,
            &object_id,
            &object,
            editable,
        ));
    }
    contacts.sort_by_key(|c| c.name.to_lowercase());
    Ok(ContactsPage {
        addressbook,
        user,
        contacts,
        new_href: format!("/frontend/user/{owner}/addressbook/{addrbook_id}/contacts/new"),
        can_create: editable,
    }
    .into_response())
}

// ---------------------------------------------------------------------------
// The aggregate Contacts page (the contacts counterpart of the Tasks tab).
// ---------------------------------------------------------------------------

/// The contacts list shown as the portal's "Contacts" tab, across every
/// addressbook of the user's own principal and their groups.
#[derive(Template, WebTemplate)]
#[template(path = "components/sections/contacts_section.html")]
pub struct ContactsSection {
    pub contacts: Vec<ContactItem>,
    /// The new-contact form URL — always present (the form itself gates).
    pub new_href: String,
    pub can_create: bool,
}

impl Section for ContactsSection {
    fn name() -> &'static str {
        "contacts"
    }
}

/// Every addressbook of the user's own principal and their groups (same
/// walk as the Tasks page's `user_calendars`).
async fn user_addressbooks<AS: AddressbookStore>(
    store: &Arc<AS>,
    user: &Principal,
) -> Result<Vec<Addressbook>, rustical_store::Error> {
    let mut addressbooks = Vec::new();
    for group in user.memberships() {
        addressbooks.extend(store.get_addressbooks(group).await?);
    }
    Ok(addressbooks)
}

/// GET /{user}/contacts — the aggregate contacts list.
pub async fn route_contacts<AS: AddressbookStore>(
    Path(user_id): Path<String>,
    Extension(store): Extension<Arc<AS>>,
    user: Principal,
) -> Result<Response, rustical_store::Error> {
    if user_id != user.id {
        return Ok(StatusCode::UNAUTHORIZED.into_response());
    }

    let mut can_create = false;
    let mut contacts = Vec::new();
    for addressbook in user_addressbooks(&store, &user).await? {
        let editable = user.can_write(&addressbook.principal);
        can_create |= editable;
        let addressbook_name = addressbook
            .displayname
            .clone()
            .unwrap_or_else(|| addressbook.id.clone());
        for (object_id, object) in store
            .get_objects(&addressbook.principal, &addressbook.id)
            .await?
        {
            contacts.push(contact_item(
                &addressbook_name,
                &addressbook.principal,
                &addressbook.id,
                &object_id,
                &object,
                editable,
            ));
        }
    }
    contacts.sort_by_key(|c| c.name.to_lowercase());

    Ok(UserPage {
        user: user.clone(),
        section: ContactsSection {
            contacts,
            new_href: format!("/frontend/user/{user_id}/contacts/new"),
            can_create,
        },
    }
    .into_response())
}

pub async fn route_addressbook_restore<AS: AddressbookStore>(
    Path((owner, addressbook_id)): Path<(String, String)>,
    Extension(store): Extension<Arc<AS>>,
    user: Principal,
    referer: Option<TypedHeader<Referer>>,
) -> Result<Response, rustical_store::Error> {
    if !user.is_principal(&owner) {
        return Ok(StatusCode::UNAUTHORIZED.into_response());
    }
    store.restore_addressbook(&owner, &addressbook_id).await?;
    Ok(referer.map_or_else(
        || (StatusCode::CREATED, "Restored").into_response(),
        |referer| Redirect::to(&referer.to_string()).into_response(),
    ))
}

// ---------------------------------------------------------------------------
// Contact create / edit / delete.
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Deserialize)]
pub struct ContactForm {
    /// `principal|addr_id` for the aggregate form; scoped by the URL
    /// otherwise (same convention as the task form's calendar picker).
    #[serde(default)]
    pub addressbook: Option<String>,
    /// Full name (FN).
    pub name: String,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub phone: Option<String>,
    #[serde(default)]
    pub note: Option<String>,
}

/// One addressbook offered by the contact form's addressbook picker.
pub struct ContactFormOption {
    /// `principal|addr_id`.
    pub value: String,
    pub label: String,
}

#[derive(Template, WebTemplate)]
#[template(path = "pages/contact_form.html")]
pub struct ContactFormPage {
    pub title: String,
    pub action: String,
    pub addressbooks: Vec<ContactFormOption>,
    pub name: String,
    pub email: String,
    pub phone: String,
    pub note: String,
}

impl DefaultLayoutData for ContactFormPage {
    fn get_user(&self) -> Option<&Principal> {
        None
    }
}

/// Escape a vCard text value (RFC 6350 backslash, semicolon, comma, newline).
#[must_use]
fn vcf_escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '\\' => escaped.push_str("\\\\"),
            ';' => escaped.push_str("\\;"),
            ',' => escaped.push_str("\\,"),
            '\n' => escaped.push_str("\\n"),
            '\r' => {}
            _ => escaped.push(c),
        }
    }
    escaped
}

fn build_vcf(form: &ContactForm, uid: &str) -> String {
    let mut vcf = String::from("BEGIN:VCARD\r\nVERSION:4.0\r\n");
    vcf.push_str("FN:");
    if form.name.trim().is_empty() {
        vcf.push_str("(no name)");
    } else {
        vcf.push_str(&vcf_escape(form.name.trim()));
    }
    vcf.push_str("\r\nN:");
    vcf.push_str(&vcf_escape(form.name.trim()));
    vcf.push_str(";;;;\r\n");
    if let Some(email) = form
        .email
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        vcf.push_str("EMAIL:");
        vcf.push_str(&vcf_escape(email));
        vcf.push_str("\r\n");
    }
    if let Some(phone) = form
        .phone
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        vcf.push_str("TEL:");
        vcf.push_str(&vcf_escape(phone));
        vcf.push_str("\r\n");
    }
    if let Some(note) = form
        .note
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        vcf.push_str("NOTE:");
        vcf.push_str(&vcf_escape(note));
        vcf.push_str("\r\n");
    }
    vcf.push_str("UID:");
    vcf.push_str(&vcf_escape(uid));
    vcf.push_str("\r\nEND:VCARD\r\n");
    vcf
}

/// Contact mutations posted from a per-addressbook form land back on that
/// addressbook's contacts list (frozen integration suite pins this
/// redirect); the aggregate form below has its own redirect.
fn contacts_redirect(owner: &str, addrbook_id: &str) -> Response {
    Redirect::to(&format!(
        "/frontend/user/{owner}/addressbook/{addrbook_id}/contacts"
    ))
    .into_response()
}

/// The addressbooks offered by the aggregate form's picker: writable ones,
/// with group books prefixed by their principal (the section titles'
/// convention).
async fn contact_form_options<AS: AddressbookStore>(
    store: &Arc<AS>,
    user: &Principal,
) -> Result<Vec<ContactFormOption>, rustical_store::Error> {
    Ok(user_addressbooks(store, user)
        .await?
        .into_iter()
        .filter(|ab| user.can_write(&ab.principal))
        .map(|ab| {
            let displayname = ab.displayname.clone().unwrap_or_else(|| ab.id.clone());
            let label = if ab.principal == user.id {
                displayname
            } else {
                format!("{}/{}", ab.principal, displayname)
            };
            ContactFormOption {
                value: format!("{}|{}", ab.principal, ab.id),
                label,
            }
        })
        .collect())
}

/// Shared builder for the contact form (same pattern as the task form's
/// `render_task_form`): `fixed` pins the form to one addressbook (the
/// per-addressbook new/edit routes), `None` offers the picker.
async fn render_contact_form<AS: AddressbookStore>(
    store: &Arc<AS>,
    user: &Principal,
    title: String,
    action: String,
    fixed: Option<(&str, &str)>,
    defaults: &ContactForm,
) -> Result<Response, rustical_store::Error> {
    let addressbooks = if let Some((principal, addr_id)) = fixed {
        vec![ContactFormOption {
            value: format!("{principal}|{addr_id}"),
            label: addr_id.to_owned(),
        }]
    } else {
        contact_form_options(store, user).await?
    };
    Ok(ContactFormPage {
        title,
        action,
        addressbooks,
        name: defaults.name.clone(),
        email: defaults.email.clone().unwrap_or_default(),
        phone: defaults.phone.clone().unwrap_or_default(),
        note: defaults.note.clone().unwrap_or_default(),
    }
    .into_response())
}

pub async fn route_addressbook_contacts_new<AS: AddressbookStore>(
    Path((owner, addrbook_id)): Path<(String, String)>,
    Extension(store): Extension<Arc<AS>>,
    user: Principal,
) -> Result<Response, rustical_store::Error> {
    if !user.is_principal(&owner) {
        return Ok(StatusCode::UNAUTHORIZED.into_response());
    }
    if !user.can_write(&owner) {
        return Ok(StatusCode::FORBIDDEN.into_response());
    }
    // Touch the store so a nonexistent book 404s rather than rendering a
    // form that can never submit.
    store.get_addressbook(&owner, &addrbook_id, true).await?;
    render_contact_form(
        &store,
        &user,
        "New contact".to_owned(),
        format!("/frontend/user/{owner}/addressbook/{addrbook_id}/contacts"),
        Some((&owner, &addrbook_id)),
        &ContactForm::default(),
    )
    .await
}

pub async fn route_addressbook_contacts_create<AS: AddressbookStore>(
    Path((owner, addrbook_id)): Path<(String, String)>,
    Extension(store): Extension<Arc<AS>>,
    user: Principal,
    Form(form): Form<ContactForm>,
) -> Result<Response, rustical_store::Error> {
    if !user.is_principal(&owner) {
        return Ok(StatusCode::UNAUTHORIZED.into_response());
    }
    if !user.can_write(&owner) {
        return Ok(StatusCode::FORBIDDEN.into_response());
    }
    store.get_addressbook(&owner, &addrbook_id, true).await?;
    let object_id = Uuid::new_v4().to_string();
    let uid = format!("{object_id}@omnical");
    let object = AddressObject::from_vcf(build_vcf(&form, &uid))
        .map_err(|err| rustical_store::Error::Other(err.into()))?;
    store
        .put_object(&owner, &addrbook_id, &object_id, object, false)
        .await?;
    Ok(contacts_redirect(&owner, &addrbook_id))
}

/// GET /{user}/contacts/new — the aggregate form with the addressbook
/// picker (only reachable in practice when a writable addressbook exists;
/// the list's "New contact" button is gated by `can_create`).
pub async fn route_contacts_new<AS: AddressbookStore>(
    Path(user_id): Path<String>,
    Extension(store): Extension<Arc<AS>>,
    user: Principal,
) -> Result<Response, rustical_store::Error> {
    if user_id != user.id {
        return Ok(StatusCode::UNAUTHORIZED.into_response());
    }
    render_contact_form(
        &store,
        &user,
        "New contact".to_owned(),
        format!("/frontend/user/{user_id}/contacts"),
        None,
        &ContactForm::default(),
    )
    .await
}

/// POST /{user}/contacts — create a contact in the addressbook the
/// aggregate form's picker selected (the counterpart of the task form's
/// aggregate POST).
pub async fn route_contacts_create<AS: AddressbookStore>(
    Path(user_id): Path<String>,
    Extension(store): Extension<Arc<AS>>,
    user: Principal,
    Form(form): Form<ContactForm>,
) -> Result<Response, rustical_store::Error> {
    if user_id != user.id {
        return Ok(StatusCode::UNAUTHORIZED.into_response());
    }
    let Some((principal, addrbook_id)) = form.addressbook.as_deref().and_then(split_calendar_value)
    else {
        return Ok(StatusCode::BAD_REQUEST.into_response());
    };
    if !user.is_principal(principal) || !user.can_write(principal) {
        return Ok(StatusCode::FORBIDDEN.into_response());
    }
    store.get_addressbook(principal, addrbook_id, true).await?;
    let object_id = Uuid::new_v4().to_string();
    let uid = format!("{object_id}@omnical");
    let object = AddressObject::from_vcf(build_vcf(&form, &uid))
        .map_err(|err| rustical_store::Error::Other(err.into()))?;
    store
        .put_object(principal, addrbook_id, &object_id, object, false)
        .await?;
    // The aggregate form lands back on the aggregate list (the same
    // discipline as the task form's `submit_redirect`).
    Ok(Redirect::to(&format!("/frontend/user/{}/contacts", user.id)).into_response())
}

pub async fn route_contact_edit<AS: AddressbookStore>(
    Path((owner, addrbook_id, object_id)): Path<(String, String, String)>,
    Extension(store): Extension<Arc<AS>>,
    user: Principal,
) -> Result<Response, rustical_store::Error> {
    if !user.is_principal(&owner) {
        return Ok(StatusCode::UNAUTHORIZED.into_response());
    }
    if !user.can_write(&owner) {
        return Ok(StatusCode::FORBIDDEN.into_response());
    }
    let object = store
        .get_object(&owner, &addrbook_id, &object_id, false)
        .await?;
    let card = object.get_vcard();
    let props = card.get_properties();
    let name = card
        .full_name
        .first()
        .map(|fn_prop| fn_prop.0.as_str())
        .unwrap_or_default()
        .to_owned();
    let defaults = ContactForm {
        name,
        email: text_prop(props, "EMAIL").map(ToOwned::to_owned),
        phone: text_prop(props, "TEL").map(ToOwned::to_owned),
        note: text_prop(props, "NOTE").map(ToOwned::to_owned),
        ..ContactForm::default()
    };
    render_contact_form(
        &store,
        &user,
        "Edit contact".to_owned(),
        format!("/frontend/user/{owner}/addressbook/{addrbook_id}/contacts/{object_id}"),
        Some((&owner, &addrbook_id)),
        &defaults,
    )
    .await
}

pub async fn route_contact_update<AS: AddressbookStore>(
    Path((owner, addrbook_id, object_id)): Path<(String, String, String)>,
    Extension(store): Extension<Arc<AS>>,
    user: Principal,
    Form(form): Form<ContactForm>,
) -> Result<Response, rustical_store::Error> {
    if !user.is_principal(&owner) {
        return Ok(StatusCode::UNAUTHORIZED.into_response());
    }
    if !user.can_write(&owner) {
        return Ok(StatusCode::FORBIDDEN.into_response());
    }
    let original = store
        .get_object(&owner, &addrbook_id, &object_id, false)
        .await?;
    let uid = original
        .get_vcard()
        .get_uid()
        .unwrap_or_default()
        .to_owned();
    let object = AddressObject::from_vcf(build_vcf(&form, &uid))
        .map_err(|err| rustical_store::Error::Other(err.into()))?;
    store
        .put_object(&owner, &addrbook_id, &object_id, object, true)
        .await?;
    Ok(contacts_redirect(&owner, &addrbook_id))
}

pub async fn route_contact_delete<AS: AddressbookStore>(
    Path((owner, addrbook_id, object_id)): Path<(String, String, String)>,
    Extension(store): Extension<Arc<AS>>,
    user: Principal,
) -> Result<Response, rustical_store::Error> {
    if !user.is_principal(&owner) {
        return Ok(StatusCode::UNAUTHORIZED.into_response());
    }
    if !user.can_write(&owner) {
        return Ok(StatusCode::FORBIDDEN.into_response());
    }
    store
        .delete_object(&owner, &addrbook_id, &object_id, true)
        .await?;
    Ok(contacts_redirect(&owner, &addrbook_id))
}
