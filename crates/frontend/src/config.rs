use serde::{Deserialize, Serialize};

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
        }
    }
}
