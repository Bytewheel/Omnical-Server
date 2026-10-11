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
use crate::routes::calendar_view::text_prop;

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

/// One contact rendered in the contacts list.
pub struct ContactItem {
    pub name: String,
    pub email: Option<String>,
    pub phone: Option<String>,
    /// The edit form URL for this contact's underlying object.
    pub href: String,
    /// The delete POST URL.
    pub delete_href: String,
    /// False (no controls rendered) when the user cannot write the owning
    /// principal.
    pub editable: bool,
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
    let mut contacts = Vec::new();
    for (object_id, object) in store.get_objects(&owner, &addrbook_id).await? {
        let card = object.get_vcard();
        let name = card
            .full_name
            .first()
            .map(|fn_prop| fn_prop.0.as_str())
            .filter(|s| !s.is_empty())
            .map_or_else(|| "(no name)".to_owned(), ToOwned::to_owned);
        let props = card.get_properties();
        let email = text_prop(props, "EMAIL").map(ToOwned::to_owned);
        let phone = text_prop(props, "TEL").map(ToOwned::to_owned);
        contacts.push(ContactItem {
            name,
            email,
            phone,
            href: format!(
                "/frontend/user/{owner}/addressbook/{addrbook_id}/contacts/{object_id}/edit"
            ),
            delete_href: format!(
                "/frontend/user/{owner}/addressbook/{addrbook_id}/contacts/{object_id}/delete"
            ),
            editable,
        });
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
    /// Full name (FN).
    pub name: String,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub phone: Option<String>,
    #[serde(default)]
    pub note: Option<String>,
}

#[derive(Template, WebTemplate)]
#[template(path = "pages/contact_form.html")]
pub struct ContactFormPage {
    pub title: String,
    pub action: String,
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

fn contacts_redirect(owner: &str, addrbook_id: &str) -> Response {
    Redirect::to(&format!(
        "/frontend/user/{owner}/addressbook/{addrbook_id}/contacts"
    ))
    .into_response()
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
    Ok(ContactFormPage {
        title: "New contact".to_owned(),
        action: format!("/frontend/user/{owner}/addressbook/{addrbook_id}/contacts"),
        name: String::new(),
        email: String::new(),
        phone: String::new(),
        note: String::new(),
    }
    .into_response())
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
    Ok(ContactFormPage {
        title: "Edit contact".to_owned(),
        action: format!("/frontend/user/{owner}/addressbook/{addrbook_id}/contacts/{object_id}"),
        name,
        email: text_prop(props, "EMAIL").unwrap_or_default().to_owned(),
        phone: text_prop(props, "TEL").unwrap_or_default().to_owned(),
        note: text_prop(props, "NOTE").unwrap_or_default().to_owned(),
    }
    .into_response())
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
