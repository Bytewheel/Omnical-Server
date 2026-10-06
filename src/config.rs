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

impl SqliteDataStoreConfig {
    /// **The one place that turns `db_url` into a filesystem path.**
    ///
    /// Every caller that needs the file rather than a connection needs this:
    /// `rustical backup`/`restore`/`upgrade`, the setup wizard's default data
    /// directory, and the appliance panel. Two copies of this question is how
    /// `file:` came to be handled correctly in one of them (`resolve_database_path`
    /// refused it) and wrongly in the other (`sqlite_db_path` returned
    /// `"file:/usr/local/share/rustical/db.sqlite3"` as if the colon were part
    /// of a filename), which on the deployed appliance means `backup` reports
    /// "nothing to back up" while the wizard would have opened a second,
    /// differently-named database. One definition, so it cannot drift.
    ///
    /// # Why sqlx is not enough on its own
    ///
    /// `SqliteConnectOptions::get_filename` strips a `sqlite://` or `sqlite:`
    /// scheme, splits off the query string and percent-decodes — all of which we
    /// want, because the server opens the URL through the very same parse and a
    /// hand-rolled prefix chop would disagree with it about `%20` in a filename.
    ///
    /// What it does *not* strip is `file:`, because `file:` is not a scheme sqlx
    /// knows: it falls through into the filename whole. SQLite itself then
    /// consumes it, because it passes the filename to `sqlite3_open_v2` with URI
    /// handling on. Measured against sqlx 0.9 and SQLite, with the file each URL
    /// actually created:
    ///
    /// ```text
    /// file:/srv/db.sqlite3        sqlx filename = "file:/srv/db.sqlite3"   opens /srv/db.sqlite3
    /// file:///srv/db.sqlite3      sqlx filename = "file:///srv/db.sqlite3" opens /srv/db.sqlite3
    /// file:/srv/a%20b.db          sqlx filename = "file:/srv/a b.db"        opens /srv/a b.db
    /// sqlite:/srv/db.sqlite3      sqlx filename = "/srv/db.sqlite3"         opens /srv/db.sqlite3
    /// ```
    ///
    /// So the `file:` prefix is stripped **here**, after sqlx has done the part it
    /// is good at. Stripping it before parsing would break the percent-decoding
    /// above, and ignoring it is the bug this function exists to remove.
    ///
    /// # Errors
    ///
    /// `Err` with the reason, never with a guessed path:
    ///
    /// - `db_url` does not parse as a SQLite URL at all;
    /// - it names an in-memory database (`:memory:`, `?mode=memory`). sqlx
    ///   invents a synthetic `file:sqlx-in-memory-N` filename for those; checked
    ///   *before* the `file:` strip, or the caller is handed a path that does not
    ///   exist under a name sqlx made up;
    /// - the `file:` form has an authority (`file://host/path`), which SQLite
    ///   rejects outright with "invalid uri authority" — reported here rather
    ///   than turned into a plausible-looking relative path;
    /// - what remains is empty, still carries a `:`, or is not UTF-8. A surviving
    ///   colon means the scheme is somebody else's (`postgres://`, `mysql://` —
    ///   both of which sqlx happily parses and hands back whole), and that is
    ///   exactly the case the old guard in `resolve_database_path` was written
    ///   for. It is kept, and it now fires for the right reason.
    pub fn database_file(&self) -> Result<PathBuf, &'static str> {
        let options: sqlx::sqlite::SqliteConnectOptions = self
            .db_url
            .parse()
            .map_err(|_| "data_store.sqlite.db_url is not a usable SQLite URL")?;

        // sqlx has no public getter for `in_memory`, and its marker is a
        // filename, so ask the URL the same way sqlx's parser does rather than
        // pattern-matching `sqlx-in-memory-`. `tests/config_db_url.rs` pins this
        // against sqlx itself, so a sqlx that changes its mind fails the build
        // rather than shipping a wrong path.
        if names_an_in_memory_database(&self.db_url) {
            return Err("data_store.sqlite.db_url is an in-memory database");
        }

        let raw = options
            .get_filename()
            .to_str()
            .ok_or("data_store.sqlite.db_url is not valid UTF-8")?;

        // Not a scheme sqlx strips, so it arrives intact. URI schemes are
        // case-insensitive; sqlx's own `trim_start_matches` is not, which is
        // another reason this is not delegated.
        //
        // The `//` handling is scoped to the `file:` branch on purpose: only a
        // URL with a scheme has an authority component. A path handed to SQLite
        // directly may well start with two slashes (`sqlite:////srv/db` reduces
        // to `//srv/db` above), and that is an ordinary Linux path, not a host.
        let path = match strip_prefix_ignore_ascii_case(raw, "file:") {
            Some(rest) => match rest.strip_prefix("//") {
                // `file:///x` is the empty authority plus an absolute path.
                Some(after_authority) => match after_authority.find('/') {
                    Some(0) => after_authority,
                    _ => {
                        return Err(
                            "data_store.sqlite.db_url names a file:// host, which SQLite rejects",
                        );
                    }
                },
                None => rest,
            },
            None => raw,
        };

        if path.is_empty() {
            return Err("data_store.sqlite.db_url names no file");
        }
        if path.contains(':') {
            return Err(
                "data_store.sqlite.db_url is not a file path — it is another backend's URL",
            );
        }
        if path.contains('\0') {
            return Err("data_store.sqlite.db_url contains a NUL byte");
        }
        Ok(PathBuf::from(path))
    }
}

/// `true` when `db_url` is one of the spellings sqlx turns into a purely
/// in-memory database, and therefore names no file.
///
/// Deliberately mirrors `sqlx_sqlite`'s parser rather than inspecting
/// `get_filename()`: the parser is what decides, and its rules are small and
/// explicit — `:memory:` as the whole database part, or `mode=memory` in the
/// query.
fn names_an_in_memory_database(db_url: &str) -> bool {
    let rest = db_url
        .trim_start()
        .trim_start_matches("sqlite://")
        .trim_start_matches("sqlite:");
    let mut parts = rest.splitn(2, '?');
    let database = parts.next().unwrap_or_default();
    if database == ":memory:" {
        return true;
    }
    parts.next().is_some_and(|params| {
        params
            .split('&')
            .any(|pair| pair == "mode=memory" || pair == "mode=memory%20")
    })
}

fn strip_prefix_ignore_ascii_case<'a>(value: &'a str, prefix: &str) -> Option<&'a str> {
    let head = value.get(..prefix.len())?;
    head.eq_ignore_ascii_case(prefix)
        .then(|| &value[prefix.len()..])
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

/// The appliance panel (item 14, §9.4): Data / Network / Firmware.
///
/// **Disabled by default, and the default has to mean absent.** A self-hosted
/// install that upgrades must not acquire a panel that can replace its database
/// and flash its firmware because a new config section was added — the same
/// reasoning §6.6.2 gives for `admin_host` being empty. An operator opts in by
/// setting `enabled = true` **and** naming a database, because the panel's one
/// dangerous action needs a target and a panel that guesses its target is worse
/// than no panel.
///
/// The paths are absolute and configured, never derived from a `Host` header or
/// a tenant id. That is what keeps "the panel touches one database" a property
/// rather than an intention.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(deny_unknown_fields, default)]
pub struct ApplianceConfig {
    /// Master switch. `false` — the default — means no appliance panel is
    /// mounted at all, on any host.
    pub enabled: bool,
    /// The database the Data section manages. **Required** when `enabled`.
    ///
    /// On a tenancy install this is `<data_root>/tenants/<tenant-id>/db.sqlite3`
    /// (§3.4) — the *tenant's* store, named explicitly by the operator. The
    /// panel never derives it from a slug and never enumerates tenants; a
    /// restore names the file it will replace, and an operator who wants a
    /// different one edits this line.
    pub database: String,
    /// Where restore points are listed from. Defaults to `backups/` beside the
    /// database, which is where `cmd_backup` and `rustical backup-all` write.
    pub backup_dir: String,
    /// Where firmware images are listed from. Defaults to `/tmp` on a
    /// development host and is normally set to the directory an operator drops
    /// an image into. There is no default on an appliance: an image directory
    /// that does not exist lists nothing, which is the correct behaviour.
    pub firmware_dir: String,
    /// The filesystem whose free space gates a flash. Defaults to `/`, which is
    /// the overlay on `OpenWrt`.
    pub overlay_mount: String,
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
/// account (principal, seed collections, share feed) and auto-logs the new
/// user in.
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
/// - **`trusted_proxies`** (C5, §7.3.4) *was* in this list, as a key that
///   parsed and did nothing. It is honoured now, and it is **fail-closed**: an
///   empty list means no peer may set `X-Forwarded-For`. See
///   [`TenancyConfig::trusted_proxies`] for the trade and the one-line warning
///   that makes the coarse case visible.
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
    /// Further hosts the panel also answers on.
    ///
    /// Additive rather than a change of type: `admin_host` stays a `String`, so
    /// every existing config, test and rendered deployment keeps working
    /// untouched and a single-host install is still the common case. An
    /// appliance typically needs two — its own hostname and one routable name
    /// — and making that a config change alone would have meant either widening
    /// this to a list (breaking every config that sets it) or encoding a second
    /// host in a string where `normalise_host` cannot see the boundary.
    ///
    /// The panel is still reserved: every host here is checked against
    /// `tenant_hosts` at startup exactly as `admin_host` is, so adding one
    /// cannot make a tenant unreachable on that hostname.
    #[serde(default)]
    pub admin_hosts: Vec<String>,
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
    /// Peers whose `X-Forwarded-For` header this server will believe (C5,
    /// §7.3.4).
    ///
    /// Each entry is an address or a CIDR block: `"10.0.0.0/8"`,
    /// `"203.0.113.7"`, `"[::1]:8443"`. A malformed entry is a **startup
    /// refusal** rather than a warning, because a `trusted_proxies` that
    /// silently dropped its one bad line would leave a deployment looking
    /// configured and being unprotected.
    ///
    /// ## Empty means trust nobody, and that is the security property
    ///
    /// Three rate limiters in this tree read `X-Forwarded-For`: registration,
    /// password reset, and the admin panel's login. Before this key existed all
    /// three read it unconditionally, so behind a load balancer anyone could put
    /// a fresh address in the header on every request and walk through a per-IP
    /// limit — including the admin login limit, which guards the one credential
    /// that crosses every tenant boundary.
    ///
    /// The alternative default — honour the header unless told otherwise — *is*
    /// the vulnerability, so it is not the default. An install with no
    /// `trusted_proxies` behind a reverse proxy therefore rate-limits every
    /// client as one address. That is coarse but **safe**, and it is not silent:
    /// a request carrying the header from an unlisted peer logs one warning per
    /// process naming this key, because a rate limiter that logged per request
    /// would be its own denial of service.
    ///
    /// Not gated on [`Self::enabled`]. A single-tenant self-hosted install
    /// behind nginx needs this exactly as much as a hosted one, and
    /// `validate()` returns early when tenancy is off — so gating the *code* on
    /// `enabled` would leave the most common self-hosting shape unprotected.
    pub trusted_proxies: Vec<String>,

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
    ///
    /// **No `self`, on purpose.** The shape depends on nothing in the
    /// configuration, and taking `&self` invited the specific bug this had: a
    /// caller that only had a `data_root` in hand had to reach for a
    /// `TenancyConfig` it did not otherwise need, and two of them (`backup-all`
    /// and the usage job) instead wrote their own `{data_root}/{id}.sqlite3` —
    /// a second answer, wrong, in a file the server never reads. So the deployed
    /// appliance's `backup-all` reported `no database at
    /// /usr/local/share/rustical/<uuid>.sqlite3` for a tenant whose data was
    /// sitting right there under `tenants/<uuid>/db.sqlite3`.
    ///
    /// Four definitions of this path is what it took to get that wrong: this
    /// one, `ensure_tenant_store_dir` (which the server actually uses, and which
    /// now calls this), and the two wrong copies, both now deleted.
    #[must_use]
    pub fn tenant_db_path(data_root: &std::path::Path, tenant_id: &str) -> String {
        data_root
            .join("tenants")
            .join(tenant_id)
            .join("db.sqlite3")
            .to_string_lossy()
            .into_owned()
    }

    /// The directory holding a tenant's store, created if absent.
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
    /// This is the copy the **server** uses, and it now takes its filename from
    /// `tenant_db_path` rather than joining `db.sqlite3` itself, so the layout
    /// has exactly one definition.
    ///
    /// `create_dir_all`, not `create_dir`, because the parent may not exist on
    /// a first install.
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
        Ok(std::path::PathBuf::from(Self::tenant_db_path(
            data_root,
            tenant_id.as_str(),
        )))
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
        // **Before** the `!enabled` early return, deliberately.
        //
        // `trusted_proxies` is honoured whether or not tenancy is on (a
        // single-tenant install behind nginx is the common case), so its
        // validity has to be checked on the same footing. A malformed entry that
        // is only caught when tenancy is enabled is a config that boots in one
        // mode and refuses in another, which is the kind of difference nobody
        // discovers until it matters.
        self.parsed_trusted_proxies()?;

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
        //
        // Tested against the *normalised* list, not `admin_host`, because a
        // config that sets only `admin_hosts` has an empty `admin_host` and
        // must still be held to every rule below. Checking the raw field is
        // what would let `admin_hosts = [""]` skip validation entirely.
        let hosts = self.normalised_admin_hosts();
        // A host that was configured but reduces to nothing used to be a
        // startup refusal. `normalised_admin_hosts` drops those entries, so
        // without this the drop would turn a loud misconfiguration into a
        // silently absent panel — the exact failure mode the emptiness guard
        // below exists to prevent, reached by the other road.
        for raw in std::iter::once(&self.admin_host).chain(self.admin_hosts.iter()) {
            if !raw.is_empty() && normalise_host(raw).is_empty() {
                return Err(format!(
                    "[tenancy] admin_host = {raw:?} normalises to nothing, so it can never match a \
                     Host header."
                ));
            }
        }
        if hosts.is_empty() {
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
        //
        // Checked for **every** host, not just `admin_host`: adding a second
        // name is exactly the change that could put the panel on the apex
        // while the first host sat safely outside `base_domain`.
        if !self.base_domain.is_empty() {
            let apex = normalise_host(&self.base_domain);
            if let Some(offender) = hosts.iter().find(|host| *host == &apex) {
                return Err(format!(
                    "[tenancy] admin_host = {offender:?} is also base_domain. Every tenant \
                     resolves under base_domain, so serving the panel from the apex would put a \
                     cross-tenant control surface one hostname away from every customer."
                ));
            }
        }
        Ok(())
    }

    /// `[tenancy] trusted_proxies` parsed into blocks (C5, §7.3.4).
    ///
    /// Parsed on demand rather than cached, because a `Config` is cloned per
    /// tenant (§3.6) and a cache would have to be either shared-and-locked or
    /// recomputed anyway. The list is a handful of entries, read once per
    /// request that needs it, and parsing four IP addresses is not a cost worth
    /// designing around.
    ///
    /// # Errors
    /// The first entry that does not parse, naming its index. Called from
    /// [`Self::validate`], so this is a **startup refusal** — a proxy list that
    /// quietly dropped a line would leave a deployment looking configured and
    /// being unprotected, which is the failure mode C5 is about.
    pub fn parsed_trusted_proxies(
        &self,
    ) -> Result<Vec<rustical_frontend::client_ip::IpNet>, String> {
        rustical_frontend::client_ip::IpNet::parse_list(&self.trusted_proxies)
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

    /// Every host the panel answers on, normalised the same way, in a stable
    /// order and deduplicated.
    ///
    /// `admin_host` comes first so the single-host case is byte-identical to
    /// what it always was — every error message that interpolates
    /// `normalised_admin_host()` keeps reading the same for a one-host config,
    /// which is the overwhelming majority and the one in the existing tests.
    #[must_use]
    pub fn normalised_admin_hosts(&self) -> Vec<String> {
        let mut hosts: Vec<String> = std::iter::once(&self.admin_host)
            .chain(self.admin_hosts.iter())
            .map(|host| normalise_host(host))
            .filter(|host| !host.is_empty())
            .collect();
        hosts.dedup();
        hosts
    }

    /// Is `host` one of the admin hosts? An empty configuration matches
    /// nothing, so "unset" and "set to something no request carries" behave
    /// identically — which is what makes absence mean absence.
    #[must_use]
    pub fn is_admin_host(&self, host: &str) -> bool {
        let host = normalise_host(host);
        // An empty `Host` header must never match, even against a configured
        // host: `normalise_host("")` is `""`, and a config whose host list
        // contains an entry that also normalises to `""` was already refused by
        // `validate_admin`.
        !host.is_empty()
            && self
                .normalised_admin_hosts()
                .iter()
                .any(|admin| admin == &host)
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
    /// The appliance panel. Absent from every existing config, and
    /// `enabled = false` when present, so a self-hosted install is unchanged.
    #[serde(default)]
    pub appliance: ApplianceConfig,
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
            appliance: ApplianceConfig::default(),
        }
    }

    /// The SQLite file this config points at, or `None` when `db_url` names no
    /// file at all (an in-memory database, or a URL some other backend owns).
    #[must_use]
    pub fn sqlite_db_path(&self) -> Option<std::path::PathBuf> {
        let DataStoreConfig::Sqlite(sqlite) = &self.data_store;
        sqlite.database_file().ok()
    }

    /// The appliance panel's paths, resolved, or a refusal naming what to set.
    ///
    /// **A startup refusal, not a warning.** An enabled panel with no database
    /// would render a Data section with nothing to restore into, and its one
    /// button would be a restore with no target. Booting into that state and
    /// discovering it at the moment an operator needs a restore is the worst
    /// time to find out.
    ///
    /// # Errors
    /// A message naming the missing or nonsensical setting.
    pub fn appliance_paths(&self) -> Result<AppliancePaths, String> {
        let appliance = &self.appliance;
        if !appliance.enabled {
            return Err("[appliance] enabled = false, so there is no appliance panel".to_owned());
        }
        if appliance.database.trim().is_empty() {
            return Err(
                "[appliance] enabled = true needs a database — the file the Data section's \
                 restore will replace. Set [appliance] database to an absolute path."
                    .to_owned(),
            );
        }
        let database = std::path::PathBuf::from(&appliance.database);
        if !database.is_absolute() {
            return Err(format!(
                "[appliance] database = {:?} is not absolute. The panel must name one specific \
                 database, and a relative path resolves against whatever directory the service \
                 happens to be started in",
                appliance.database
            ));
        }
        // The default is the directory `cmd_backup` writes to, so an operator
        // who has been backing up by hand sees their archives with no extra
        // configuration.
        let backup_dir = if appliance.backup_dir.trim().is_empty() {
            database
                .parent()
                .unwrap_or_else(|| std::path::Path::new("/"))
                .join("backups")
        } else {
            std::path::PathBuf::from(&appliance.backup_dir)
        };
        if !backup_dir.is_absolute() {
            return Err(format!(
                "[appliance] backup_dir = {:?} is not absolute",
                appliance.backup_dir
            ));
        }
        // The single most important check here. A backup directory that contains
        // the live database means the restore-point listing would offer the live
        // database as something to restore *over itself*, and a safety copy
        // would be written into the directory being listed.
        if backup_dir
            == database
                .parent()
                .unwrap_or_else(|| std::path::Path::new("/"))
        {
            return Err(format!(
                "[appliance] backup_dir ({}) is the directory holding the live database. Restore \
                 points and the live database must not share a directory",
                backup_dir.display()
            ));
        }
        Ok(AppliancePaths {
            database,
            backup_dir,
            firmware_dir: std::path::PathBuf::from(if appliance.firmware_dir.trim().is_empty() {
                "/tmp"
            } else {
                appliance.firmware_dir.as_str()
            }),
            overlay_mount: std::path::PathBuf::from(if appliance.overlay_mount.trim().is_empty() {
                "/"
            } else {
                appliance.overlay_mount.as_str()
            }),
        })
    }
}

/// The appliance panel's resolved paths.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliancePaths {
    pub database: std::path::PathBuf,
    pub backup_dir: std::path::PathBuf,
    pub firmware_dir: std::path::PathBuf,
    pub overlay_mount: std::path::PathBuf,
}
