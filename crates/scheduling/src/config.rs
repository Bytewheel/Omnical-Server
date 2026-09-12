use std::path::PathBuf;

use serde::{Deserialize, Serialize};

fn default_mailbox() -> String {
    "INBOX".to_owned()
}

fn default_true() -> bool {
    true
}

fn default_imap_poll_secs() -> u64 {
    120
}

/// SMTP account used to send invitations for one organizer identity.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SmtpAccount {
    /// The identity (email address) invitations are sent *from*.
    /// Must match the ORGANIZER address of events whose invitations
    /// should be delivered through this account.
    pub identity: String,
    pub host: String,
    pub port: u16,
    /// SMTP username (may differ from the identity, e.g. shared mailboxes)
    pub username: String,
    pub password: String,
    /// Display name used in the From header (optional)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub displayname: Option<String>,
}

/// IMAP mailbox polled for inbound iMIP replies (RFC 6047) for one identity.
///
/// External attendees (and local users without a principal yet) answer
/// invitations by email; their `METHOD:REPLY` messages land in the
/// organizer's mailbox on the external mail provider. The ingestion loop
/// polls each configured mailbox and feeds the replies into the scheduler.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ImapAccount {
    /// The identity this mailbox belongs to. Must match the ORGANIZER
    /// address of the events whose replies arrive here (usually one of
    /// the `[[scheduling.smtp]]` identities) and be a local principal —
    /// replies for anyone else are ignored.
    pub identity: String,
    pub host: String,
    /// Implicit-TLS (IMAPS) port; STARTTLS is not supported.
    pub port: u16,
    pub username: String,
    pub password: String,
    /// Mailbox to poll.
    #[serde(default = "default_mailbox")]
    pub mailbox: String,
    /// Mark ingested messages as `\Seen`. Replies are machine messages —
    /// the user "sees" the response on the event and in the scheduling
    /// inbox. Non-scheduling mail is never touched either way.
    #[serde(default = "default_true")]
    pub mark_seen: bool,
    /// PEM file with additional trust anchors for the TLS handshake
    /// (added to the webpki roots). For providers that serve an
    /// incomplete chain — e.g. `imap.novo-ordo.com:993` omits its
    /// Sectigo intermediate, which fails every poll with
    /// `invalid peer certificate: UnknownIssuer`. Recommended content:
    /// the missing intermediate (survives annual leaf renewals).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_file: Option<PathBuf>,
}

/// Omnical RFC 6638 (scheduling) extension configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct SchedulingConfig {
    /// Master switch: advertises scheduling support to clients and enables
    /// implicit scheduling on PUT/DELETE.
    pub enabled: bool,
    /// SMTP accounts per organizer identity.
    #[serde(default)]
    pub smtp: Vec<SmtpAccount>,
    /// IMAP mailboxes polled for inbound iMIP replies. Empty (the
    /// default) disables the ingestion loop entirely.
    #[serde(default)]
    pub imap: Vec<ImapAccount>,
    /// Seconds between IMAP polls (floored to 30 in code).
    #[serde(default = "default_imap_poll_secs")]
    pub imap_poll_secs: u64,
    /// HMAC-SHA256 secret signing the one-click RSVP link tokens emitted
    /// in invitation emails. Links are only minted while this *and*
    /// `rsvp_base_url` are set; changing it invalidates all outstanding
    /// links (the endpoint then answers 404 until fresh invites are sent).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rsvp_secret: Option<String>,
    /// Absolute public base URL of this server as used in RSVP links
    /// (e.g. `https://host:8443`). The server wiring falls back to the
    /// `[subscriptions] public_url` when this is unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rsvp_base_url: Option<String>,
}

impl Default for SchedulingConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            smtp: vec![],
            imap: vec![],
            imap_poll_secs: default_imap_poll_secs(),
            rsvp_secret: None,
            rsvp_base_url: None,
        }
    }
}

impl SchedulingConfig {
    /// Whether invitations can be emailed for `identity`.
    #[must_use]
    pub fn smtp_account(&self, identity: &str) -> Option<&SmtpAccount> {
        self.smtp
            .iter()
            .find(|account| account.identity.eq_ignore_ascii_case(identity))
    }

    /// Whether invitation emails should carry one-click RSVP links:
    /// both the signing secret and a public base URL must be configured.
    #[must_use]
    pub const fn rsvp_links_enabled(&self) -> bool {
        self.rsvp_secret.is_some() && self.rsvp_base_url.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn imap_defaults() {
        // Old configs (no [scheduling.imap]) keep parsing with sane defaults
        let config: SchedulingConfig = toml::from_str("").unwrap();
        assert!(config.imap.is_empty());
        assert_eq!(config.imap_poll_secs, 120);
        assert_eq!(config.rsvp_secret, None);
        assert_eq!(config.rsvp_base_url, None);
        assert!(!config.rsvp_links_enabled());

        // An account table (as it appears under [[scheduling.imap]] in the
        // full config) keeps parsing with the per-account defaults
        let account: ImapAccount = toml::from_str(
            "identity = \"a@example.com\"
             host = \"imap.example.com\"
             port = 993
             username = \"a@example.com\"
             password = \"secret\"",
        )
        .unwrap();
        assert_eq!(account.mailbox, "INBOX");
        assert!(account.mark_seen);
        assert_eq!(account.ca_file, None);
    }

    #[test]
    fn imap_ca_file_parses() {
        let account: ImapAccount = toml::from_str(
            "identity = \"a@novo-ordo.com\"
             host = \"imap.novo-ordo.com\"
             port = 993
             username = \"a@novo-ordo.com\"
             password = \"secret\"
             ca_file = \"/etc/rustical/certs/imap-novo-ordo.pem\"",
        )
        .unwrap();
        assert_eq!(
            account.ca_file,
            Some(PathBuf::from("/etc/rustical/certs/imap-novo-ordo.pem"))
        );
    }

    #[test]
    fn rsvp_link_config() {
        // Links require BOTH the secret and a base URL; either alone is
        // not enough (there is nothing useful to link to / nothing to
        // sign with). Keys are flat because this parses the *contents*
        // of a [scheduling] section.
        let secret_only: SchedulingConfig = toml::from_str("rsvp_secret = \"s3cret\"").unwrap();
        assert!(!secret_only.rsvp_links_enabled());

        let config: SchedulingConfig = toml::from_str(
            "rsvp_secret = \"s3cret\"\n\
             rsvp_base_url = \"https://cal.example.com:8443\"",
        )
        .unwrap();
        assert!(config.rsvp_links_enabled());
        assert_eq!(config.rsvp_secret.as_deref(), Some("s3cret"));
        assert_eq!(
            config.rsvp_base_url.as_deref(),
            Some("https://cal.example.com:8443")
        );
    }
}
