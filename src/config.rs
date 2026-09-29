use core::num::NonZeroU32;
use std::{path::PathBuf, str::FromStr};

use crate::host_dispatch::normalise_host;
use anyhow::anyhow;
use reqwest::Url;
use rustical_caldav::CalDavConfig;
use rustical_frontend::FrontendConfig;
use rustical_oidc::OidcConfig;
use rustical_scheduling::SchedulingConfig;
use rustical_store::tenant::{MAX_SLUG_LEN, TenantId};
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

/// Multi-tenancy — `PLAN_DEPLOYMENTS.md` §3.6.
///
/// ## `enabled = false` must mean "exactly as today"
///
/// That is §3.6's own wording and it is the property that let §8 and §9 ship
/// without waiting for §6. It is enforced structurally rather than by
/// discipline: `cmd_serve` builds [`make_app`](crate::app::make_app) and serves
/// it with **no dispatch layer at all** when this is false, so there is no code
/// path in which tenancy is "on but not routing".
///
/// ## What is deliberately missing
///
/// §3.6 lists eight keys. Six are here. Two are **not**, and both omissions are
/// deliberate rather than oversights — the common thread is that both would
/// parse and then do nothing in this tree, and a config key that is accepted and
/// ignored is worse than a missing one, because the operator has no way to tell
/// which they are looking at:
///
/// - **`trusted_proxies`** (C5, §7.3.4) is the `X-Forwarded-Host` / `X-Forwarded-For`
///   trust list. It is a *security* knob, and the code that honours it does not
///   exist yet. An operator who set it would get a rate-limit bypass while their
///   config claimed otherwise. It arrives with §7.3.4, and §3.6's "MUST be set
///   for hosted" is about that commit, not this one.
/// - **`[tenancy.sessions]`** (C4, §3.7) selects a `SessionStore`. The
///   `session-redis` cargo feature does not exist in this tree, so
///   `store = "redis"` would be a literal that deserialises and is then never
///   read. It arrives with `crates/store_redis`.
///
/// A user who has read the plan and written `store = "redis"` gets a hard
/// `unknown field` error from `deny_unknown_fields` rather than a silent no-op,
/// which is the correct failure: loud, immediate, and pointing at the fix.
#[derive(Deserialize, Serialize, Clone, Debug, Default)]
#[serde(deny_unknown_fields, default)]
pub struct TenancyConfig {
    /// Master switch. `false` — the default — keeps single-tenant behaviour.
    pub enabled: bool,
    /// N=1 self-host/appliance: every `Host` lands on this tenant. The one
    /// setting that makes dispatch useful *without* any DNS, which is why §3.3
    /// puts it at match 4 rather than treating it as a special case: on a LAN
    /// the request's `Host` is whatever the router's own hostname happened to
    /// be, and resolving that to a tenant is the whole point of an appliance.
    pub default_tenant: String,
    /// Hosted: `{slug}.{base_domain}` resolution (§3.3 match 2).
    pub base_domain: String,
    /// Hosted: the bare apex domain, which has no tenant of its own.
    pub default_domain: String,
    /// Where per-tenant store files live. Defaults to the directory of the
    /// configured `db_url`, so the N=1 case keeps exactly today's path — no
    /// migration, no surprise (§3.4).
    pub data_root: String,
    /// §3.5's LRU size. `0` is coerced to 1 by
    /// [`StoreBundleCache::new`](crate::store_bundle::StoreBundleCache::new)
    /// rather than honoured.
    pub max_cached_tenants: usize,
    /// The control plane's own database — a **different file** from any tenant
    /// store, on purpose (§3.4).
    pub control_db_url: String,
    /// The one host the admin panel answers on (§6.6.2). **Empty means there is
    /// no panel** — not a panel on every host, and not a panel on a default
    /// path. Absence has to mean absence, or a self-hosted install acquires a
    /// cross-tenant control surface by upgrading and nothing announces it.
    pub admin_host: String,
    /// Platform-admin **names**, and nothing else: no hash, no secret, so this
    /// list is reviewable in version control and a rename is a one-line deploy
    /// (§6.6.3).
    ///
    /// This list is **authoritative**. A name with a valid credential row in
    /// `control.sqlite3` that is absent here can never authenticate, which is
    /// the whole reason the two halves live in different places: it is what
    /// stops anyone who can write the control plane — the file holding every
    /// tenant's SMTP password (§3.6) — from promoting themselves.
    pub platform_admins: Vec<String>,
    /// The operator's assertion that this deployment is single-instance
    /// (§6.6.4).
    ///
    /// **This is a claim, not a check, and the distinction is the point.**
    /// Nothing in this tree can count how many copies of the server are
    /// running, or tell whether `data_root` is on shared storage — so the only
    /// honest implementation of "refuse to serve a panel unless single-instance"
    /// is to require the operator to say so. It is set by hand and reviewed
    /// like any other config change.
    ///
    /// A guessed check ("is this a local filesystem?") would look like a
    /// guarantee and be wrong in exactly the cases that matter. When the
    /// control plane becomes shared (§7, C7) this key becomes a real check and
    /// goes away.
    pub admin_single_instance_acknowledged: bool,
}

impl Config {
    /// This config with a tenant's `config_json` merged over it (§3.6).
    ///
    /// The direction is global ← tenant: the tenant's keys override, and
    /// anything absent inherits. That is what makes a tenant's blob sparse — a
    /// tenant who overrides nothing has `{}` and behaves exactly like the
    /// single-tenant install.
    ///
    /// Deliberately **not** on `TenancyConfig`: the merge reaches into
    /// `scheduling`, `subscriptions` and `registration`, which are the caller's
    /// business, and a method on the tenancy section that rewrote three other
    /// sections would be a pleasant surprise.
    ///
    /// `runtimes` note: this is pure data manipulation, so it is callable from
    /// anywhere including a CLI that has no async context.
    #[must_use]
    pub fn with_tenant_overrides(&self, tenant: &rustical_store::Tenant) -> Self {
        let overrides = crate::tenant_overrides::Overrides::parse(&tenant.config_json);
        let mut out = self.clone();
        out.scheduling = overrides.scheduling(&self.scheduling);
        out.subscriptions = overrides.subscriptions(&self.subscriptions);
        out.registration = overrides.registration(&self.registration);
        out
    }
}

impl TenancyConfig {
    /// The store path for a tenant: `<data_root>/tenants/<tenant_id>/db.sqlite3`
    /// (§3.4).
    ///
    /// The **id**, not the slug: a slug can be renamed when a customer rebrands,
    /// and renaming a directory that a running server has open is a different
    /// class of problem from renaming a row.
    #[must_use]
    pub fn tenant_db_path(&self, data_root: &std::path::Path, tenant_id: &str) -> String {
        data_root
            .join("tenants")
            .join(tenant_id)
            .join("db.sqlite3")
            .to_string_lossy()
            .into_owned()
    }

    /// Where tenant store files live: `[tenancy] data_root`, else the directory
    /// of the configured `db_url` (§3.4).
    ///
    /// **One definition, two callers.** The server's per-tenant build
    /// (`crate::tenancy`) and `rustical tenant create` (`crate::commands::tenants`)
    /// both need it, and if they ever disagreed the failure would be silent and
    /// confusing in a specific way: `tenant create` would prepare one path, the
    /// server would open another, and the tenant would appear to exist while
    /// every request to it failed. The default is also what keeps the N=1 case
    /// on exactly today's path — no migration, no surprise.
    ///
    /// # Errors
    /// If `data_root` is unset and the data store is not SQLite, since a
    /// per-tenant path cannot be derived from it. The message names the setting
    /// to add rather than only reporting that derivation failed.
    pub fn data_root(&self, data_store: &DataStoreConfig) -> Result<std::path::PathBuf, String> {
        if !self.data_root.is_empty() {
            return Ok(std::path::PathBuf::from(&self.data_root));
        }
        // A `match` rather than a `let ... else`, because the fallback arm is
        // unreachable while `DataStoreConfig` has one variant and it is kept on
        // purpose: if a Postgres variant is added (§7 wave 3) this turns a wrong
        // store path into a startup error naming the missing setting.
        let sqlite = match data_store {
            DataStoreConfig::Sqlite(sqlite) => sqlite,
            #[allow(
                unreachable_patterns,
                reason = "kept for when DataStoreConfig grows a variant"
            )]
            other => {
                return Err(format!(
                    "[tenancy] data_root is unset and the data store is {other:?}, so a \
                     per-tenant store path cannot be derived. Set [tenancy] data_root."
                ));
            }
        };
        // Strip the SQLx scheme and any query, so a `db_url` of
        // `sqlite:///var/lib/omnical/db.sqlite3?mode=rwc` yields `/var/lib/omnical`
        // rather than a directory literally containing `?mode=rwc`.
        let path = sqlite
            .db_url
            .split('?')
            .next()
            .unwrap_or(sqlite.db_url.as_str())
            .trim_start_matches("sqlite://");
        std::path::Path::new(path).parent().map_or_else(
            || Err(format!("could not derive a tenant data_root from {path}")),
            |parent| Ok(parent.to_path_buf()),
        )
    }

    /// Create a tenant's store directory and return the path to its database.
    ///
    /// §3.4 writes the convention as `<data_root>/tenants/<tenant_id>/db.sqlite3`,
    /// and the missing half of that sentence is that **SQLite will not create
    /// the directory**. `create_db_pool` sets `create_if_missing(true)`, which
    /// creates a *file*, not the two directories above it — so without this, the
    /// very first request for a brand-new tenant fails with
    /// `unable to open database file` (SQLite code 14) and every subsequent one
    /// fails the same way. A tenant that cannot serve is worse than a tenant
    /// that does not exist, because the 500 looks like our bug rather than a
    /// missing `mkdir`.
    ///
    /// `create_dir_all`, not `create_dir`, because the parent may not exist on a
    /// first install.
    ///
    /// # Errors
    /// The `io::Error` from `create_dir_all`, with the path in the message.
    pub fn ensure_tenant_store_dir(
        &self,
        data_root: &std::path::Path,
        tenant_id: &TenantId,
    ) -> Result<std::path::PathBuf, String> {
        let dir = data_root.join("tenants").join(tenant_id.as_str());
        std::fs::create_dir_all(&dir).map_err(|e| {
            format!(
                "could not create the store directory {}: {e}",
                dir.display()
            )
        })?;
        Ok(dir.join("db.sqlite3"))
    }

    /// Reject a tenancy configuration that cannot work, with a message that
    /// says what to change.
    ///
    /// Called once at startup. A misconfiguration found on the first request is
    /// a 500 for one unlucky tenant; found here it is a refusal to boot, which
    /// is the only useful time to learn that `base_domain` is set on an
    /// appliance.
    ///
    /// # Errors
    /// A message naming the offending key.
    pub fn validate(&self) -> Result<(), String> {
        if !self.enabled {
            // Every other key is inert while tenancy is off, and an operator who
            // set `base_domain` and left `enabled = false` has almost certainly
            // made a mistake worth naming — but this is a warning, not a refusal:
            // a staged rollout turns tenancy on in a second commit.
            return Ok(());
        }
        if self.default_tenant.is_empty() && self.base_domain.is_empty() {
            return Err(
                "[tenancy] is enabled but neither default_tenant nor base_domain is set, so no \
                 Host header can resolve to a tenant. For a self-hosted or appliance install set \
                 default_tenant; for a hosted deployment set base_domain."
                    .to_owned(),
            );
        }
        if !self.default_tenant.is_empty() && self.default_tenant.parse::<TenantId>().is_err() {
            return Err(format!(
                "[tenancy] default_tenant = {:?} is not a valid tenant id: slugs are \
                 [a-z0-9-]{{1,{}}}",
                self.default_tenant, MAX_SLUG_LEN
            ));
        }
        if self.control_db_url.is_empty() {
            return Err(
                "[tenancy] control_db_url must be set; the control plane is a separate \
                        database from any tenant store (§3.4)"
                    .to_owned(),
            );
        }
        self.validate_admin()?;
        Ok(())
    }

    /// The `admin_host` rules (§6.6.2, §6.6.4).
    ///
    /// Split out from [`Self::validate`] because it is the one part that is about
    /// a *security* boundary rather than about making dispatch work, and the
    /// error messages have to justify themselves on different grounds.
    ///
    /// Two of these are startup refusals on purpose. A panel that is configured
    /// but unacknowledged, or acknowledged but unreachable, is a cross-tenant
    /// control surface in a state nobody chose.
    fn validate_admin(&self) -> Result<(), String> {
        // The whole block is inert without a host, and that has to be the way
        // every other key behaves here: an operator mid-migration may have set
        // `platform_admins` before deciding on a host, and that is a normal
        // order of operations rather than a mistake.
        if self.admin_host.is_empty() {
            return Ok(());
        }

        if !self.admin_single_instance_acknowledged {
            return Err(format!(
                "[tenancy] admin_host = {:?} is set but admin_single_instance_acknowledged is \
                 not. The admin panel's credential and session stores are per-process and its \
                 control plane is a per-instance SQLite file, so with more than one instance a \
                 tenant created on one does not resolve on another and an admin's session is lost \
                 whenever the load balancer routes them elsewhere. Nothing in this program can \
                 count its own instances or tell whether data_root is on shared storage, so this \
                 key is your assertion, not a probe. Set \
                 admin_single_instance_acknowledged = true if this deployment really is \
                 single-instance; if it is not, the panel must stay off until the control plane \
                 and sessions are shared (§7).",
                self.admin_host
            ));
        }

        if self.platform_admins.is_empty() {
            // Not a cosmetic check. `tenant admin add` refuses any name that is
            // not in `platform_admins`, so with an empty list there is no way to
            // create the first credential: the panel would be reserved, healthy,
            // and permanently unauthenticatable, with no error at any point
            // after boot.
            return Err(format!(
                "[tenancy] admin_host = {:?} is set but platform_admins is empty. Names live in \
                 this list and hashes live in the control plane, and the list is authoritative, \
                 so an empty one means no admin can ever authenticate. Add at least one name to \
                 [tenancy] platform_admins.",
                self.admin_host
            ));
        }

        if self
            .platform_admins
            .iter()
            .any(|name| name.trim().is_empty())
        {
            return Err(
                "[tenancy] platform_admins contains an empty name. Every entry is an exact, \
                 case-sensitive match against a credential row and an --actor string, so a \
                 blank one can never authenticate and only hides a typo."
                    .to_owned(),
            );
        }

        // Compared normalised, because this is how the panel router will match it
        // (§6.6.1's `ADMIN.EXAMPLE.COM:8443`). Catching the mismatch at boot is
        // the difference between an obvious refusal and an operator staring at
        // a 404 wondering which side of the split is misconfigured.
        if self.normalised_admin_host().is_empty() {
            return Err(format!(
                "[tenancy] admin_host = {:?} normalises to nothing, so it can never match a Host \
                 header.",
                self.admin_host
            ));
        }
        if !self.base_domain.is_empty()
            && self.normalised_admin_host() == normalise_host(&self.base_domain)
        {
            return Err(format!(
                "[tenancy] admin_host = {:?} is also base_domain. Every tenant resolves under \
                 base_domain, so serving the panel from the apex would put a cross-tenant control \
                 surface one hostname away from every customer.",
                self.admin_host
            ));
        }
        Ok(())
    }

    /// `admin_host` reduced to the form the router matches on: lowercased, with
    /// any port and a single trailing dot removed.
    ///
    /// The same reduction [`normalise_host`](crate::host_dispatch::normalise_host)
    /// applies to a request's `Host`, so that `ADMIN.EXAMPLE.COM:8443` from a
    /// client still reaches the panel (§6.6.1).
    #[must_use]
    pub fn normalised_admin_host(&self) -> String {
        normalise_host(&self.admin_host)
    }

    /// Is `host` the admin host? An empty `admin_host` matches nothing, so
    /// "unset" and "set to something no request carries" behave identically —
    /// which is what makes absence mean absence.
    #[must_use]
    pub fn is_admin_host(&self, host: &str) -> bool {
        let admin = self.normalised_admin_host();
        !admin.is_empty() && admin == normalise_host(host)
    }
}

#[derive(Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub data_store: DataStoreConfig,
    #[serde(default)]
    pub tenancy: TenancyConfig,
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

impl Config {
    /// What a fresh install starts from.
    ///
    /// Shared by `rustical gen-config` and `rustical setup` on purpose:
    /// `PLAN_DEPLOYMENTS.md` §8.3 requires the two config paths not to
    /// diverge, and the only way to guarantee that is for both to build the
    /// same value rather than two hand-maintained literals.
    #[must_use]
    pub fn default_config() -> Self {
        Self {
            tenancy: TenancyConfig::default(),
            http: HttpConfig::default(),
            caldav: CalDavConfig::default(),
            data_store: DataStoreConfig::Sqlite(SqliteDataStoreConfig {
                db_url: "/var/lib/rustical/db.sqlite3".to_owned(),
                run_repairs: true,
                skip_broken: true,
            }),
            tracing: TracingConfig::default(),
            frontend: FrontendConfig {
                enabled: true,
                allow_password_login: true,
                ..FrontendConfig::default()
            },
            oidc: None,
            dav_push: DavPushConfig::default(),
            nextcloud_login: NextcloudLoginConfig::default(),
            scheduling: SchedulingConfig::default(),
            subscriptions: SubscriptionsConfig::default(),
            registration: RegistrationConfig::default(),
            maintenance: MaintenanceConfig::default(),
        }
    }

    /// The SQLite file this config points at, or `None` for an in-memory
    /// database. `db_url` may be a `sqlite://` URL with options, so it is
    /// parsed the same way the server parses it rather than string-matched.
    #[must_use]
    pub fn sqlite_db_path(&self) -> Option<std::path::PathBuf> {
        let DataStoreConfig::Sqlite(SqliteDataStoreConfig { db_url, .. }) = &self.data_store;
        let options: sqlx::sqlite::SqliteConnectOptions = db_url.parse().ok()?;
        let path = options.get_filename().to_path_buf();
        (!path.as_os_str().is_empty()).then_some(path)
    }
}
