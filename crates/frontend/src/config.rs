use serde::{Deserialize, Serialize};
use std::path::PathBuf;

const fn default_true() -> bool {
    true
}

const fn default_min_password_length() -> usize {
    12
}

#[derive(Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct FrontendConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_true")]
    pub allow_password_login: bool,
    /// Minimum accepted password length for the portal password-change form
    /// (mirrors `[registration] min_password_length`).
    #[serde(default = "default_min_password_length")]
    pub min_password_length: usize,
    /// The `HawkBook` Android package (the `DAVx⁵` fork the per-client
    /// instructions keep naming) this deployment serves at
    /// `/frontend/download/hawkbook.apk`. The route and the sha256 the
    /// profile intro prints are both derived from this one file, so the
    /// download link and the checksum cannot drift apart.
    ///
    /// Unset (or the file missing at startup) ⇒ the route 404s and the intro
    /// omits the download sentence — the page never links at something it
    /// cannot serve.
    ///
    /// Not embedded in the binary like `public/assets` on purpose: an APK is
    /// ~18 MB, the whole build is gated at 35 MiB, and the router's overlay
    /// cannot hold two copies of it.
    #[serde(default)]
    pub hawkbook_apk: Option<PathBuf>,
    /// The directory holding this deployment's holiday `.ics` sets and their
    /// `holidays.toml` manifest — the "add holidays" dropdown of the
    /// create-calendar modal reads its groups and sets from it, and a
    /// selection is merged into the new calendar as a copy (the same
    /// semantics as a linked platform: a `holidays://{set}` source is
    /// recorded per set, so Refresh keeps the copy updatable by UID when
    /// the `.ics` files are regenerated).
    ///
    /// Unset ⇒ `/_holidays.json` answers an empty list and imports answer
    /// "no holiday sets on this server" — the modal then shows nothing to
    /// select, which is honest, not broken.
    ///
    /// Files are read from disk at import/refresh time (never an HTTP
    /// self-fetch: the linked-platform engine's fetch is HTTPS-only with an
    /// SSRF guard, and making the router fetch its own flash over TLS just
    /// to hand it back would be a certificate dance for bytes it already
    /// has), so a regenerated set is picked up without a restart.
    #[serde(default)]
    pub holidays_dir: Option<PathBuf>,
    /// `[tenancy] trusted_proxies`, already parsed (C5, §7.3.4).
    ///
    /// **`serde(skip)`, and that is the point.** The operator-facing key is
    /// `[tenancy] trusted_proxies` and lives there; this field is the runtime
    /// carrier, so there is exactly one spelling in the config file and
    /// `deny_unknown_fields` cannot be used to end up with two disagreeing
    /// lists. It is skipped in both directions: a `[frontend] trusted_proxies`
    /// key is an error, not a silent override.
    ///
    /// On `FrontendConfig` because this section is **not** per-tenant
    /// overridable (§3.6's merge reaches `scheduling`, `subscriptions` and
    /// `registration`, not `frontend`) — and the trust list is a property of the
    /// *deployment* anyway: it says which load balancers sit in front of this
    /// process, which is the same answer for every tenant the process serves.
    /// Per-tenant would be a privilege-escalation shape, since a tenant could
    /// then widen the set of peers whose `X-Forwarded-For` is believed.
    ///
    /// Empty means trust nobody, and it is skipped into a `Default` so a caller
    /// that never heard of C5 — the pinned integration suite, for one — is
    /// **safe** by construction rather than accidentally.
    #[serde(skip)]
    pub trusted_proxies: Vec<crate::client_ip::IpNet>,
}

impl Default for FrontendConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            allow_password_login: true,
            min_password_length: default_min_password_length(),
            trusted_proxies: Vec::new(),
            hawkbook_apk: None,
            holidays_dir: None,
        }
    }
}
