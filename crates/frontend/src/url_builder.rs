//! Shared URL builder for share feeds — single source of truth so the portal
//! and CLI print byte-identical export URLs.
use rustical_store::SubscriptionKind;

/// Resolve the base URL export URLs are printed with: the configured public
/// URL if set, else the HTTP bind address. Empty when the server binds a
/// Unix socket, in which case only the path is printed.
#[must_use]
pub fn public_base_url(subscriptions_public_url: Option<&str>, http_bind: Option<&str>) -> String {
    subscriptions_public_url.map_or_else(
        || http_bind.map_or_else(String::new, |addr| format!("http://{addr}")),
        |url| url.trim_end_matches('/').to_owned(),
    )
}

/// The full export URL of a subscription (path only if `base_url` is empty).
#[must_use]
pub fn export_url(base_url: &str, token: &str, kind: SubscriptionKind) -> String {
    let extension = match kind {
        SubscriptionKind::Calendar => "ics",
        SubscriptionKind::Addressbook => "vcf",
    };
    format!("{base_url}/export/{token}.{extension}")
}
