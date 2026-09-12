use core::num::NonZeroU32;
use std::{path::PathBuf, str::FromStr};

use anyhow::anyhow;
use reqwest::Url;
use rustical_caldav::CalDavConfig;
use rustical_frontend::FrontendConfig;
use rustical_oidc::OidcConfig;
use rustical_scheduling::SchedulingConfig;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields, default)]
pub struct HttpConfig {
    pub bind: Option<String>,
    // host, port are deprecated
    pub host: Option<String>,
    pub port: Option<u16>,
    pub session_cookie_samesite_strict: bool,
    pub payload_limit_mb: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpBindConfig {
    Tcp(String),
    Unix(PathBuf),
}

impl FromStr for HttpBindConfig {
    type Err = anyhow::Error;

    fn from_str(address: &str) -> Result<Self, Self::Err> {
        // This is incredibly janky but given the comprehensive tests I think we can justify it
        let Ok(url) = address.parse::<Url>() else {
            return Ok(Self::Tcp(address.to_string()));
        };

        Ok(match url.scheme() {
            "unix" => {
                if url.host_str().is_some() || url.port().is_some() {
                    return Err(anyhow!(
                        "Invalid URL in http.bind config: unix: url cannot contain a host. You probably used double slashes, use unix:///absolute/path or unix:/absolute/path"
                    ));
                }
                Self::Unix(url.path().parse()?)
            }
            "http" => {
                if url.path() != "/" {
                    return Err(anyhow!(
                        "Invalid URL in http.bind config: http URL cannot contain a path"
                    ));
                }
                let Some(host) = url.host_str() else {
                    return Err(anyhow!("Invalid URL in http.bind config: host missing"));
                };
                let Some(port) = url.port() else {
                    return Err(anyhow!(
                        "Error in http.bind config: Please explicitly specify a port"
                    ));
                };
                Self::Tcp(format!("{host}:{port}"))
            }
            scheme => {
                // localhost:1234 will become scheme=localhost, path=1234
                if let Ok(port) = url.path().parse::<u16>()
                    && address == format!("{scheme}:{port}")
                {
                    return Ok(Self::Tcp(address.to_string()));
                }

                return Err(anyhow!(
                    "Error in http.bind config: Invalid schema: {scheme}. If it is a hostname explicitly specify a port such as {scheme}:4000"
                ));
            }
        })
    }
}

#[cfg(test)]
mod bind_config {
    use crate::config::HttpBindConfig;
    use rstest::rstest;
    use std::str::FromStr;

    #[rstest]
    #[case("unix:///run/rustical/socket", HttpBindConfig::Unix("/run/rustical/socket".parse().unwrap()))]
    #[case("http://[::]:4000", HttpBindConfig::Tcp("[::]:4000".to_string()))]
    #[case("[::]:4000", HttpBindConfig::Tcp("[::]:4000".to_string()))]
    #[case("example.com:4000", HttpBindConfig::Tcp("example.com:4000".to_string()))]
    #[case("172.10.10.1:4000", HttpBindConfig::Tcp("172.10.10.1:4000".to_string()))]
    #[case("localhost:1234", HttpBindConfig::Tcp("localhost:1234".to_string()))]
    #[case("http://localhost:1234", HttpBindConfig::Tcp("localhost:1234".to_string()))]
    // Unix relative paths
    #[case(
        "unix:asd/asd",
        HttpBindConfig::Unix("asd/asd".parse().unwrap())
    )]
    #[case(
        "unix:asd",
        HttpBindConfig::Unix("asd".parse().unwrap())
    )]
    // Unix absolute path
    #[case(
        "unix:/asd",
        HttpBindConfig::Unix("/asd".parse().unwrap())
    )]
    #[case(
        "unix:/asd/asd",
        HttpBindConfig::Unix("/asd/asd".parse().unwrap())
    )]
    fn test_parse_http_bind_valid(#[case] address: &str, #[case] out: HttpBindConfig) {
        assert_eq!(HttpBindConfig::from_str(address).unwrap(), out);
    }

    #[rstest]
    #[case("unix://asd/run/rustical/socket")]
    #[case("http://[::]:4000/asdlkj")]
    #[case("http://localhost")]
    #[case("https://localhost:4000")]
    #[case("localhost:1234/asd")]
    #[case("unix://hallo:123/run/rustical/socket")]
    fn test_parse_http_bind_invalid(#[case] address: &str) {
        assert!(HttpBindConfig::from_str(address).is_err());
    }

    #[rstest]
    #[case(
        "unix://:123/run/rustical/socket",
        HttpBindConfig::Tcp("unix://:123/run/rustical/socket".to_string())
    )]
    #[case("localhost", HttpBindConfig::Tcp("localhost".to_string()))]
    fn test_parse_http_bind_invalid_but_will_fail_anyway(
        #[case] address: &str,
        #[case] out: HttpBindConfig,
    ) {
        assert_eq!(HttpBindConfig::from_str(address).unwrap(), out);
    }
}

impl HttpConfig {
    fn address(&self) -> anyhow::Result<String> {
        if let Some(ref host) = self.host {
            let port = self.port.unwrap_or(4000);
            tracing::warn!(
                "Using http.host/port is deprecated and will be removed in the future. Please instead use http.bind"
            );
            return Ok(format!("{host}:{port}"));
        }

        if let Some(port) = self.port {
            let host = self.host.as_deref().unwrap_or("[::]");
            tracing::warn!(
                "Using http.host/port is deprecated and will be removed in the future. Please instead use http.bind"
            );
            return Ok(format!("{host}:{port}"));
        }

        if let Some(ref address) = self.bind {
            return Ok(address.clone());
        }

        Err(anyhow!(
            "http.bind is not configured (this should not happen since it has a default)"
        ))
    }

    #[allow(clippy::missing_errors_doc)]
    pub fn bind_config(&self) -> anyhow::Result<HttpBindConfig> {
        HttpBindConfig::from_str(&self.address()?)
    }
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            bind: Some("[::]:4000".to_owned()),
            host: None,
            port: None,
            session_cookie_samesite_strict: false,
            payload_limit_mb: 4,
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct SqliteDataStoreConfig {
    pub db_url: String,
    #[serde(default = "default_true")]
    pub run_repairs: bool,
    #[serde(default = "default_true")]
    pub skip_broken: bool,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
pub enum DataStoreConfig {
    Sqlite(SqliteDataStoreConfig),
}

#[derive(Debug, Deserialize, Serialize, Default, Clone)]
#[serde(deny_unknown_fields, default)]
pub struct TracingConfig {
    pub opentelemetry: bool,
}

const fn default_true() -> bool {
    true
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields, default)]
pub struct DavPushConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    // Allowed Push servers, accepts any by default
    // Specify as URL origins
    pub allowed_push_servers: Option<Vec<String>>,
}

impl Default for DavPushConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            allowed_push_servers: None,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct NextcloudLoginConfig {
    pub enabled: bool,
}

impl Default for NextcloudLoginConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(deny_unknown_fields, default)]
pub struct MaintenanceConfig {
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trash_retention_days: Option<NonZeroU32>,
}

/// Omnical share-links extension (PLAN.md §17.7): public read-only
/// subscription export feeds for calendars and addressbooks.
///
/// While disabled (the default) the build behaves byte-for-byte like the
/// current one: no `/export/*` routes are mounted and the `subscriptions`
/// CLI's tokens do not serve anything.
#[derive(Debug, Deserialize, Serialize, Clone, Default)]
#[serde(deny_unknown_fields, default)]
pub struct SubscriptionsConfig {
    /// Master switch: mounts the unauthenticated `/export/<token>.{ics,vcf}`
    /// routes (the token in the URL is the only credential).
    pub enabled: bool,
    /// Public base URL the `subscriptions` CLI prints for export feeds (e.g.
    /// `https://0115d8cf.duckdns.org:8443`). Falls back to the HTTP bind
    /// address when unset, which is not necessarily publicly reachable (the
    /// production deployment fronts this server with a TLS tunnel).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_url: Option<String>,
}

/// Omnical self-service registration extension (PLAN.md §17.8).
///
/// While disabled (the default) the build behaves byte-for-byte like the
/// current one: no `/register` routes are mounted and no registration state
/// is constructed. When enabled, invite-gated registration provisions a full
/// account (principal, app tokens, seed collections, share feed) and
/// auto-logs the new user in.
#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields, default)]
pub struct RegistrationConfig {
    /// Master switch: mounts the public `/register` form and POST handler.
    pub enabled: bool,
    /// Require a single-use invitation code (issued via `rustical invites`)
    /// before an account is provisioned. When `false` the form skips the
    /// invite field entirely.
    pub invite_required: bool,
    /// Minimum accepted password length.
    pub min_password_length: usize,
    /// Client app-token names created automatically for every new registrant.
    /// These are shown (and then never again) on the success card.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub auto_app_tokens: Vec<String>,
    /// Create `personal` calendar + addressbook share feeds for every new
    /// registrant (requires `[subscriptions] enabled = true` to serve them).
    pub auto_subscription: bool,
    /// Group the new principal is joined to on registration (unset = no group).
    #[serde(skip_serializing_if = "String::is_empty")]
    pub default_group: String,
    /// Max registrations per client IP (by `X-Forwarded-For` first hop, else
    /// a single global bucket) within a sliding one hour window.
    pub rate_limit_per_hour: u32,
}

impl Default for RegistrationConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            invite_required: true,
            min_password_length: 12,
            auto_app_tokens: vec![
                "vdirsyncer".to_owned(),
                "davx5".to_owned(),
                "thunderbird".to_owned(),
                "apple".to_owned(),
                "i3status".to_owned(),
            ],
            auto_subscription: true,
            default_group: String::new(),
            rate_limit_per_hour: 10,
        }
    }
}

#[derive(Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub data_store: DataStoreConfig,
    #[serde(default)]
    pub http: HttpConfig,
    #[serde(default)]
    pub frontend: FrontendConfig,
    #[serde(default)]
    pub oidc: Option<OidcConfig>,
    #[serde(default)]
    pub tracing: TracingConfig,
    #[serde(default)]
    pub dav_push: DavPushConfig,
    #[serde(default)]
    pub nextcloud_login: NextcloudLoginConfig,
    #[serde(default)]
    pub caldav: CalDavConfig,
    #[serde(default)]
    pub scheduling: SchedulingConfig,
    #[serde(default)]
    pub subscriptions: SubscriptionsConfig,
    #[serde(default)]
    pub registration: RegistrationConfig,
    #[serde(default)]
    pub maintenance: MaintenanceConfig,
}
