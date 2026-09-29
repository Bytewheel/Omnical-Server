//! §3.6's per-tenant config merge: global config ← `tenants.config_json`.
//!
//! ## Why this file exists, and why it is here rather than in `§6.3`
//!
//! The plan files the merge as item 10 and the scoping gate as item 9, and **the
//! two cannot be done in that order.** Rows 26-28 are about `export_`, `rsvp_`
//! and `register_`, and under tenancy those three routers were not mounted *at
//! all*: `app_config_for` set `scheduler: None` and `subscriptions: None`, so
//! `/export/{token}.ics` returned 404 for every tenant including its own.
//!
//! Row 26's gate is "`/export/{token}.ics` returns 200 in its own tenant and 404
//! in the other". The first half of that is not a scoping property, it is a
//! *mounting* property, and mounting needs a per-tenant `SubscriptionStore` and
//! a per-tenant `Scheduler` — which is the merge. So the merge arrives with item
//! 9, and rows 30-31 (item 10) remain as its own gate.
//!
//! ## The direction of the merge
//!
//! Global config is the **base**; the tenant's blob **overrides** it key by key.
//! An absent key inherits. That direction is what makes the blob sparse and
//! cheap: a tenant who overrides nothing has `{}` and behaves exactly like the
//! single-tenant install.
//!
//! ## What is deliberately not merged
//!
//! `scheduling.imap` is not read here. It configures the *ingestion poller*,
//! which `cmd_serve` spawns once for the process; making it per-tenant means
//! spawning a poller per tenant, which is a §7 wave-3 decision (one is fine while
//! the process is single-tenant, N is a different cost). Ignoring it is recorded
//! in `§3.6`'s terms as a known gap, and a tenant whose blob sets it gets the
//! global value — the safe direction, since it polls the mailbox the operator
//! configured.

use crate::config::{RegistrationConfig, SubscriptionsConfig};
use rustical_scheduling::SchedulingConfig;
use serde_json::Value;

/// The subset of §3.6's override keys this build honours.
///
/// Named explicitly rather than deserialising the whole config type from the
/// blob: `deny_unknown_fields` on the config structs means a tenant blob with a
/// typo would otherwise be able to *fail the request*, and a typo in an
/// operator's JSON should not take a tenant offline. An unknown key is ignored
/// and logged.
#[derive(Debug, Default, Clone)]
pub struct Overrides {
    /// §3.6: the RSVP HMAC key. Per-tenant for a reason — see
    /// [`crate::rsvp`]: a shared key means one tenant can forge another's
    /// `/rsvp/{token}` links, which is item 9's row 27.
    pub rsvp_secret: Option<String>,
    /// §3.6: every tenant's subscribe links must point at its own host.
    pub subscriptions_public_url: Option<String>,
    /// §3.6: per-tenant open/closed, invite-required, rate limits.
    pub registration_enabled: Option<bool>,
    pub registration_invite_required: Option<bool>,
    /// §3.6: each tenant's invites must come from its own identity.
    pub smtp: Option<Vec<rustical_scheduling::SmtpAccount>>,
}

impl Overrides {
    /// Read the keys this build honours out of a tenant's `config_json`.
    ///
    /// # Errors
    /// Never, deliberately. A blob that does not parse, or a key of the wrong
    /// type, yields `Overrides::default()` and the tenant inherits the global
    /// config. The alternative — propagating the parse failure into the request
    /// path — would let a stray comma in an operator's JSON turn into a 500 for
    /// every request to that tenant, and would break RSVP links already mailed
    /// out. Wrong-but-working beats right-but-broken here; the operator gets a
    /// `warn!` instead.
    #[must_use]
    pub fn parse(config_json: &str) -> Self {
        let Ok(value) = serde_json::from_str::<Value>(config_json) else {
            tracing::warn!(
                "a tenant's config_json does not parse; the global configuration is used \
                 unchanged for that tenant"
            );
            return Self::default();
        };
        let mut out = Self::default();

        if let Some(secret) = value.get("rsvp_secret").and_then(Value::as_str) {
            out.rsvp_secret = Some(secret.to_owned());
        } else if value.get("rsvp_secret").is_some() {
            tracing::warn!("a tenant's rsvp_secret is not a string; the global value is used");
        }

        // The blob is flat-ish, and both spellings are accepted: a flat
        // `subscriptions.public_url` and a nested `{"subscriptions":
        // {"public_url": …}}`. The nested shape is what the §3.6 table reads
        // like, and the flat one is what an operator writes.
        let nested_subscriptions = value.get("subscriptions");
        out.subscriptions_public_url = nested_subscriptions
            .and_then(|s| s.get("public_url"))
            .or_else(|| value.get("subscriptions_public_url"))
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);

        let nested_registration = value.get("registration");
        out.registration_enabled = nested_registration
            .and_then(|r| r.get("enabled"))
            .or_else(|| value.get("registration_enabled"))
            .and_then(Value::as_bool);
        out.registration_invite_required = nested_registration
            .and_then(|r| r.get("invite_required"))
            .or_else(|| value.get("registration_invite_required"))
            .and_then(Value::as_bool);

        // `scheduling.smtp` is a list of account objects; anything that is not a
        // list of objects is ignored rather than half-applied.
        let smtp = value
            .get("scheduling")
            .and_then(|s| s.get("smtp"))
            .or_else(|| value.get("smtp"));
        if let Some(list) = smtp.and_then(Value::as_array) {
            match serde_json::from_value::<Vec<rustical_scheduling::SmtpAccount>>(Value::Array(
                list.clone(),
            )) {
                Ok(accounts) => out.smtp = Some(accounts),
                Err(e) => tracing::warn!(
                    error = %e,
                    "a tenant's scheduling.smtp override does not deserialise; the global \
                     SMTP identities are used"
                ),
            }
        } else if smtp.is_some() {
            tracing::warn!("a tenant's scheduling.smtp override is not a list; ignored");
        }

        out
    }

    /// The scheduling config for this tenant: the global one, with the tenant's
    /// overrides applied.
    ///
    /// Note that `rsvp_base_url` is *not* overridable per tenant. The RSVP link a
    /// tenant's own invitations carry has to point at that tenant's host, and the
    /// global `subscriptions.public_url` is already per-tenant after the merge
    /// above — but `rsvp_base_url` defaults from it in `build_extensions`, so
    /// leaving it alone is what makes the two agree. Making it separately
    /// overridable would be a way to have a tenant's mailed links point
    /// somewhere its own page is not.
    #[must_use]
    pub fn scheduling(&self, global: &SchedulingConfig) -> SchedulingConfig {
        let mut out = global.clone();
        if let Some(secret) = &self.rsvp_secret {
            out.rsvp_secret = Some(secret.clone());
        }
        if let Some(smtp) = &self.smtp {
            out.smtp.clone_from(smtp);
        }
        out
    }

    /// The subscriptions config for this tenant.
    #[must_use]
    pub fn subscriptions(&self, global: &SubscriptionsConfig) -> SubscriptionsConfig {
        let mut out = global.clone();
        if let Some(url) = &self.subscriptions_public_url {
            out.public_url = Some(url.clone());
        }
        out
    }

    /// The registration config for this tenant.
    #[must_use]
    pub fn registration(&self, global: &RegistrationConfig) -> RegistrationConfig {
        let mut out = global.clone();
        if let Some(enabled) = self.registration_enabled {
            out.enabled = enabled;
        }
        if let Some(required) = self.registration_invite_required {
            out.invite_required = required;
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::Overrides;
    use rustical_scheduling::SchedulingConfig;

    #[test]
    fn an_empty_blob_inherits_everything() {
        let o = Overrides::parse("{}");
        assert!(o.rsvp_secret.is_none());
        assert!(o.subscriptions_public_url.is_none());
        assert!(o.registration_enabled.is_none());
        assert!(o.smtp.is_none());
    }

    #[test]
    fn a_flat_rsvp_secret_is_read() {
        assert_eq!(
            Overrides::parse(r#"{"rsvp_secret":"own"}"#)
                .rsvp_secret
                .as_deref(),
            Some("own")
        );
    }

    #[test]
    fn a_malformed_blob_inherits_rather_than_failing() {
        // The property that keeps a stray comma from becoming a 500 storm.
        for bad in ["{not json", "", "[1,2,3]", "null"] {
            let o = Overrides::parse(bad);
            assert!(o.rsvp_secret.is_none(), "{bad:?} produced {o:?}");
        }
    }

    #[test]
    fn a_wrongly_typed_key_is_ignored_rather_than_applied() {
        // An operator writing `rsvp_secret: 42` gets the global secret, not a
        // crash and not the string "42" as an HMAC key.
        let o = Overrides::parse(r#"{"rsvp_secret":42}"#);
        assert!(o.rsvp_secret.is_none());
        let o = Overrides::parse(r#"{"registration":{"enabled":"yes"}}"#);
        assert!(o.registration_enabled.is_none());
    }

    #[test]
    fn both_spellings_of_a_nested_key_are_accepted() {
        let nested = r#"{"subscriptions":{"public_url":"https://acme.example"}}"#;
        let flat = r#"{"subscriptions_public_url":"https://acme.example"}"#;
        assert_eq!(
            Overrides::parse(nested).subscriptions_public_url.as_deref(),
            Some("https://acme.example")
        );
        assert_eq!(
            Overrides::parse(flat).subscriptions_public_url.as_deref(),
            Some("https://acme.example")
        );
    }

    #[test]
    fn scheduling_takes_the_tenants_secret_over_the_global_one() {
        let global = SchedulingConfig {
            rsvp_secret: Some("global".to_owned()),
            ..SchedulingConfig::default()
        };
        let own = Overrides::parse(r#"{"rsvp_secret":"own"}"#);
        assert_eq!(own.scheduling(&global).rsvp_secret.as_deref(), Some("own"));
        // And with no override the global one is kept, which is the single-tenant
        // path unchanged.
        let none = Overrides::parse("{}");
        assert_eq!(
            none.scheduling(&global).rsvp_secret.as_deref(),
            Some("global")
        );
    }
}
