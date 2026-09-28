//! `rustical setup` — the first-run wizard (`PLAN_DEPLOYMENTS.md` §8.2).
//!
//! §8.2's premise is the whole reason this command exists. An operator must
//! not have to know the exact key names in `config.toml` — `gen-config` prints
//! them, which is documentation, not an install path — and then run
//! `principals create` by hand. Every self-hoster hits that as a support call.
//!
//! Two rules shape the implementation:
//!
//! * **Idempotent and re-runnable.** A second run *edits*. Every prompt shows
//!   the current value as its default and an empty answer keeps it, stored
//!   secrets are never re-asked or shown, and the administrator is created
//!   only when it does not exist — a re-run never resets a password, never
//!   rotates the RSVP secret and never touches the data directory.
//! * **No secret reaches stdout, ever.** The SMTP/IMAP passwords are typed
//!   with echo off and land only in the 0600 config; the RSVP secret is
//!   generated and written, not printed. The same discipline as
//!   `scripts/render-router-config.sh:9-12`, except that here the file is
//!   written directly, because its mode is part of the contract.
//!
//! The config it writes is the server's own `Config` type, serialised by
//! `toml::to_string_pretty`, and it starts from `Config::default_config()` —
//! the same value `gen-config` prints. §8.3's rule ("the two must not
//! diverge") therefore holds by construction rather than by review, and the
//! `deny_unknown_fields` round-trip is a property of the type.
use crate::config::{Config, DataStoreConfig, HttpBindConfig, SqliteDataStoreConfig};
use anyhow::{Context, Result, anyhow, bail};
use clap::Parser;
use rand::RngExt;
use rustical_scheduling::{ImapAccount, SmtpAccount};
use rustical_store::auth::{AuthenticationProvider, Principal, PrincipalType};
use rustical_store_sqlite::{SqlitePrincipalStore, create_db_pool};
use std::collections::BTreeMap;
use std::io::{BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::str::FromStr;

const DEFAULT_DATA_DIR: &str = "/var/lib/omnical";
const DEFAULT_BIND: &str = "0.0.0.0:4000";
const DEFAULT_ADMIN: &str = "admin@localhost";
/// The floor for the administrator's password, mirroring
/// `[registration] min_password_length`'s default. A config that lowered that
/// value does not get to lower the admin password with it.
const MIN_ADMIN_PASSWORD: usize = 12;
/// How many times a prompt re-asks before giving up on unusable input. Stops a
/// typo in an unattended run from turning into an infinite loop.
const MAX_PROMPT_ATTEMPTS: usize = 5;

/// How the operator intends to terminate TLS.
///
/// **This writes no config key.** `Config` has no TLS section, because TLS is
/// somebody else's job: a reverse proxy in front, or the separate `dav-tls`
/// binary. The answer only selects which next steps get printed, which is the
/// only thing it can honestly do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsChoice {
    /// A reverse proxy (Caddy, nginx, traefik) terminates TLS for this server.
    Proxy,
    /// The `dav-tls` front end from this repo, appliance-style.
    DavTls,
    /// Plain HTTP — a private network, or an install not yet exposed.
    None,
}

impl TlsChoice {
    const OPTIONS: &'static str = "(c) reverse proxy  (d) dav-tls  (n) none";
    const DEFAULT: Self = Self::Proxy;

    /// The key this choice is answered with. Derived from the choice itself so
    /// the printed `[default: x]` can never disagree with the answer actually
    /// taken on an empty line.
    const fn key(self) -> char {
        match self {
            Self::Proxy => 'c',
            Self::DavTls => 'd',
            Self::None => 'n',
        }
    }

    const fn parse(letter: char) -> Option<Self> {
        match letter {
            'c' => Some(Self::Proxy),
            'd' => Some(Self::DavTls),
            'n' => Some(Self::None),
            _ => None,
        }
    }
}

/// How new accounts may be created.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistrationChoice {
    /// No `/register` route at all.
    Closed,
    /// `/register` needs a single-use code from `rustical invites`.
    InviteOnly,
    /// `/register` is open to anyone who can reach the server.
    Open,
}

impl RegistrationChoice {
    const OPTIONS: &'static str = "(i) invite-only  (o) open  (c) closed";

    const fn key(self) -> char {
        match self {
            Self::InviteOnly => 'i',
            Self::Open => 'o',
            Self::Closed => 'c',
        }
    }

    const fn parse(letter: char) -> Option<Self> {
        match letter {
            'i' => Some(Self::InviteOnly),
            'o' => Some(Self::Open),
            'c' => Some(Self::Closed),
            _ => None,
        }
    }

    const fn apply(self, config: &mut crate::config::RegistrationConfig) {
        config.enabled = !matches!(self, Self::Closed);
        config.invite_required = matches!(self, Self::InviteOnly);
    }

    /// The reverse mapping, for a re-run over an existing config. Total by
    /// construction: enabled without invite-required *is* open.
    const fn from_config(config: &crate::config::RegistrationConfig) -> Self {
        if !config.enabled {
            Self::Closed
        } else if config.invite_required {
            Self::InviteOnly
        } else {
            Self::Open
        }
    }
}

/// What the wizard did, for the caller's reporting and for the tests.
/// Deliberately carries no secrets — not even a fingerprint of one.
#[derive(Debug, Clone)]
pub struct SetupReport {
    pub config_file: PathBuf,
    pub data_dir: PathBuf,
    pub db_path: PathBuf,
    pub bind: String,
    pub admin: String,
    /// `false` when the administrator already existed and was left alone.
    pub admin_created: bool,
    pub tls: TlsChoice,
    pub registration: RegistrationChoice,
    /// `true` when a new RSVP secret was generated. A re-run keeps the old one,
    /// because rotating it invalidates every outstanding RSVP link.
    pub rsvp_secret_generated: bool,
    pub public_url: Option<String>,
}

#[derive(Debug, Parser)]
pub struct SetupArgs {}

/// Interactive entry point: stdin in, stdout out, no secret printed.
///
/// `future_not_send` is allowed rather than fixed: the only thing held across
/// an await is the stdin lock, and this future is awaited directly by `main`
/// and never spawned, so `Send` buys nothing here.
#[allow(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::future_not_send
)]
pub async fn cmd_setup(_args: SetupArgs, config_file: &Path) -> Result<()> {
    let stdin = std::io::stdin();
    let interactive = stdin.is_terminal();
    let mut input = stdin.lock();
    let mut output = std::io::stdout();
    run_setup(&mut input, &mut output, config_file, interactive).await?;
    Ok(())
}

/// The wizard, with its input and output injected.
///
/// `interactive` only decides whether secrets are read with echo disabled; the
/// questions and the answers are otherwise identical, which is what makes a
/// piped-stdin test meaningful.
#[allow(
    clippy::too_many_lines,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc
)]
pub async fn run_setup(
    input: &mut impl BufRead,
    output: &mut impl Write,
    config_file: &Path,
    interactive: bool,
) -> Result<SetupReport> {
    let existing = load_existing_config(config_file)?;
    writeln!(output, "Omnical setup — {}", config_file.display())?;
    if existing.is_some() {
        writeln!(
            output,
            "An existing configuration was found. Press enter to keep any value in [brackets]."
        )?;
    } else {
        writeln!(output, "Press enter to accept any value in [brackets].")?;
    }
    writeln!(output)?;

    let reloading = existing.is_some();
    let mut config = existing.clone().unwrap_or_else(Config::default_config);

    // 1. Data directory — everything else follows from it.
    let default_data_dir = config
        .sqlite_db_path()
        .and_then(|db| db.parent().map(Path::to_path_buf))
        .unwrap_or_else(|| PathBuf::from(DEFAULT_DATA_DIR));
    let data_dir = prompt_text(
        input,
        output,
        "1. Data directory",
        &default_data_dir.to_string_lossy(),
        |answer| {
            if answer.is_empty() {
                Err(anyhow!("a data directory is required"))
            } else {
                Ok(())
            }
        },
    )?;
    let data_dir = PathBuf::from(data_dir);
    let db_path = data_dir.join("db.sqlite3");
    config.data_store = DataStoreConfig::Sqlite(SqliteDataStoreConfig {
        db_url: db_path.to_string_lossy().into_owned(),
        run_repairs: true,
        skip_broken: true,
    });

    // 2. Listen address. A fresh install gets the documented default; a
    // re-run keeps whatever the config already says, because changing the bind
    // under a running service is exactly the surprise a re-run must not cause.
    let bind = prompt_text(
        input,
        output,
        "2. Address to listen on",
        if reloading {
            config.http.bind.as_deref().unwrap_or(DEFAULT_BIND)
        } else {
            DEFAULT_BIND
        },
        |answer| HttpBindConfig::from_str(answer).map(|_| ()),
    )?;
    config.http.bind = Some(bind.clone());
    // `http.host` / `http.port` are a *deprecated* bind override in 0.16.1:
    // they take precedence over `bind` and make the server try to bind the
    // wrong address (see the router config's own comment). Cleared so a
    // re-run over a config that has them cannot inherit them.
    config.http.host = None;
    config.http.port = None;

    // 3. Public URL — the base every client-facing link is built from.
    let public_url = prompt_optional_text(
        input,
        output,
        "3. Public URL (blank if this server is not reachable yet)",
        config.subscriptions.public_url.clone(),
        |answer| {
            url::Url::parse(answer)
                .map(|_| ())
                .map_err(anyhow::Error::from)
        },
    )?;
    if public_url.is_some() {
        // Public share feeds need a public base to be worth mounting at all.
        config.subscriptions.enabled = true;
    }
    config.subscriptions.public_url = public_url.clone();
    // RSVP links fall back to the share-link base URL unless pinned; leave an
    // existing pin alone.
    if config.scheduling.rsvp_base_url.is_none() {
        config.scheduling.rsvp_base_url = public_url.clone();
    }

    // 4. TLS — advice only, see `TlsChoice`.
    let tls = prompt_choice(
        input,
        output,
        "4. How is TLS terminated?",
        TlsChoice::OPTIONS,
        TlsChoice::DEFAULT,
        TlsChoice::key,
        TlsChoice::parse,
    )?;

    // 5 + 6. Mail. Both optional, and a re-run keeps what is configured
    // without ever showing or re-asking for a stored password.
    let (smtp, imap) = prompt_mail(
        input,
        output,
        &config.scheduling.smtp,
        &config.scheduling.imap,
        interactive,
    )?;
    config.scheduling.smtp = smtp;
    config.scheduling.imap = imap;
    config.scheduling.enabled = !config.scheduling.smtp.is_empty();

    // 7. Registration.
    let default_registration = RegistrationChoice::from_config(&config.registration);
    let registration = prompt_choice(
        input,
        output,
        "7. Registration",
        RegistrationChoice::OPTIONS,
        default_registration,
        RegistrationChoice::key,
        RegistrationChoice::parse,
    )?;
    registration.apply(&mut config.registration);

    // The RSVP secret is the one secret this command ever *creates*. It is
    // written to the config and never printed.
    let rsvp_secret_generated = config.scheduling.rsvp_secret.is_none();
    if rsvp_secret_generated {
        config.scheduling.rsvp_secret = Some(generate_rsvp_secret());
    }

    // The config is written before the database is touched: if the migration
    // or the administrator step then fails, the operator has a file to look at,
    // and re-running is the documented fix — the same path as a first run.
    write_config(config_file, &config)?;
    writeln!(output, "\nWrote {}", config_file.display())?;

    create_data_dir(&data_dir)?;
    let pool = create_db_pool(&db_path.to_string_lossy(), true)
        .await
        .with_context(|| {
            format!(
                "preparing the database at {} — is the data directory writable by this user?",
                db_path.display()
            )
        })?;
    let principal_store = SqlitePrincipalStore::new(pool.clone());

    // 8. The first administrator — asked last, because the answer depends on
    // what the database already holds. Asking it earlier is how a wizard
    // invites you to create a *second* admin on a re-run.
    let min_password_length = config.registration.min_password_length;
    let (admin, admin_created) = ensure_administrator(
        input,
        output,
        &principal_store,
        interactive,
        min_password_length,
    )
    .await?;

    pool.close().await;

    let report = SetupReport {
        config_file: config_file.to_path_buf(),
        data_dir,
        db_path,
        bind,
        admin,
        admin_created,
        tls,
        registration,
        rsvp_secret_generated,
        public_url,
    };
    print_next_steps(output, &report)?;
    Ok(report)
}

/// Returns `(admin id, created?)`.
async fn ensure_administrator(
    input: &mut impl BufRead,
    output: &mut impl Write,
    principal_store: &SqlitePrincipalStore,
    interactive: bool,
    min_password_length: usize,
) -> Result<(String, bool)> {
    let mut existing: Vec<String> = principal_store
        .get_principals()
        .await?
        .into_iter()
        .map(|principal| principal.id)
        .collect();
    existing.sort();
    // Default to an account that already exists, so pressing enter on a re-run
    // is a no-op rather than the creation of a second administrator.
    let default_admin = existing
        .first()
        .cloned()
        .unwrap_or_else(|| DEFAULT_ADMIN.to_owned());

    let admin = prompt_text(
        input,
        output,
        "8. Administrator email address",
        &default_admin,
        |answer| {
            if answer.contains('@') && answer.len() > 3 {
                Ok(())
            } else {
                Err(anyhow!("that does not look like an email address"))
            }
        },
    )?;

    if let Some(principal) = principal_store.get_principal(&admin).await? {
        writeln!(
            output,
            "Administrator {admin} already exists — left untouched. Change the password with\n\
                 `rustical principals edit {admin} --password`."
        )?;
        // A principal with no password can only sign in through OIDC. Offer
        // to set one, but never overwrite a password that is already set.
        if principal.password.is_none() {
            let password =
                prompt_new_password(input, output, &admin, interactive, min_password_length)?;
            principal_store
                .insert_principal(
                    Principal {
                        id: admin.clone(),
                        password: Some(hash_password(&password)),
                        ..principal
                    },
                    true,
                )
                .await?;
            writeln!(output, "Password set for {admin}.")?;
        }
        return Ok((admin, false));
    }

    let password = prompt_new_password(input, output, &admin, interactive, min_password_length)?;
    principal_store
        .insert_principal(
            Principal {
                id: admin.clone(),
                displayname: None,
                memberships: vec![],
                password: Some(hash_password(&password)),
                principal_type: PrincipalType::Individual,
                needs_password_change: false,
                privileges: BTreeMap::default(),
            },
            false,
        )
        .await?;
    writeln!(output, "Created administrator {admin}.")?;
    Ok((admin, true))
}

fn load_existing_config(config_file: &Path) -> Result<Option<Config>> {
    if !config_file.is_file() {
        return Ok(None);
    }
    let text = std::fs::read_to_string(config_file)
        .with_context(|| format!("reading {}", config_file.display()))?;
    let config: Config = toml::from_str(&text).with_context(|| {
        format!(
            "{} exists but does not parse as a rustical config. Fix it or move it aside and \
             re-run — the wizard will not overwrite a file it does not understand",
            config_file.display()
        )
    })?;
    Ok(Some(config))
}

/// Write the config atomically at 0600. It holds the SMTP and IMAP passwords
/// in cleartext, so the mode is part of the contract — the same protection
/// class as the TLS key (§8.6).
fn write_config(config_file: &Path, config: &Config) -> Result<()> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    if let Some(parent) = config_file.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    let body = toml::to_string_pretty(config).context("rendering the config")?;
    let mut rendered = String::from(
        "# Written by `rustical setup`. Re-run it to edit, or edit this file directly:\n\
         # it is exactly the schema `rustical gen-config` prints.\n\
         # It contains mail passwords in cleartext — keep it 0600.\n\n",
    );
    rendered.push_str(&body);

    // A temp file in the same directory, then a rename: a crash mid-write
    // cannot leave a truncated config for the next start to trip over.
    let temp = config_file.with_extension("toml.setup-tmp");
    {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&temp)
            .with_context(|| format!("creating {}", temp.display()))?;
        file.write_all(rendered.as_bytes())?;
        file.flush()?;
    }
    std::fs::set_permissions(&temp, std::fs::Permissions::from_mode(0o600))?;
    std::fs::rename(&temp, config_file)
        .with_context(|| format!("replacing {}", config_file.display()))?;
    Ok(())
}

fn create_data_dir(data_dir: &Path) -> Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(data_dir)
        .with_context(|| {
            format!(
                "creating the data directory {} — run as a user that can own it, or \
                 pre-create it and re-run",
                data_dir.display()
            )
        })
}

fn generate_rsvp_secret() -> String {
    let mut bytes = [0_u8; 32];
    rand::rng().fill(&mut bytes);
    hex::encode(bytes)
}

fn hash_password(password: &str) -> rustical_store::Secret<String> {
    use argon2::password_hash::{PasswordHasher, SaltString, rand_core::OsRng};
    let salt = SaltString::generate(OsRng);
    rustical_store::Secret::from(
        argon2::Argon2::default()
            .hash_password(password.as_bytes(), &salt)
            .expect("hashing a password of any length cannot fail")
            .to_string(),
    )
}

fn print_next_steps(output: &mut impl Write, report: &SetupReport) -> Result<()> {
    writeln!(output, "\nDone. Next steps:")?;
    writeln!(
        output,
        "  1. Start the server:  rustical --config-file {} serve",
        report.config_file.display()
    )?;
    match report.tls {
        TlsChoice::Proxy => writeln!(
            output,
            "  2. Point a reverse proxy at {bind} and give it the hostname from the public\n\
             \x20    URL — clients only ever see that URL.",
            bind = report.bind
        )?,
        TlsChoice::DavTls => writeln!(
            output,
            "  2. Put dav-tls (see dav-tls/ in the build repo) in front of {bind}; it is what\n\
             \x20    serves /.well-known for the clients that need it.",
            bind = report.bind
        )?,
        TlsChoice::None => writeln!(
            output,
            "  2. No TLS is configured. Do not put this on a network you do not trust until\n\
             \x20    a proxy or dav-tls terminates TLS."
        )?,
    }
    let base = report
        .public_url
        .clone()
        .unwrap_or_else(|| format!("http://<this host>:{}", bind_port(&report.bind)));
    writeln!(
        output,
        "  3. Sign in as {admin} at {base}/frontend, then add a client from the calendar\n\
         \x20    page — it carries the per-client instructions, and /.well-known/caldav is\n\
         \x20    what apps autodiscover.",
        admin = report.admin
    )?;
    if report.rsvp_secret_generated {
        writeln!(
            output,
            "  4. An RSVP-link secret was generated into the config. Keep it: changing it\n\
             \x20    invalidates every invitation link already sent."
        )?;
    }
    writeln!(
        output,
        "\nRe-run this wizard at any time to edit these answers. It will not reset the\n\
         administrator's password and will not touch the data directory."
    )?;
    Ok(())
}

fn bind_port(bind: &str) -> &str {
    bind.rsplit(':').next().unwrap_or("4000")
}

// --- prompts --------------------------------------------------------------

/// Ask until the answer validates. An empty answer takes the default.
fn prompt_text(
    input: &mut impl BufRead,
    output: &mut impl Write,
    label: &str,
    default: &str,
    validate: impl Fn(&str) -> Result<()>,
) -> Result<String> {
    for attempt in 1..=MAX_PROMPT_ATTEMPTS {
        write!(output, "{label} [{default}]: ")?;
        output.flush()?;
        let Some(answer) = read_line(input)? else {
            bail!("input ended while waiting for an answer to: {label}");
        };
        let answer = answer.trim();
        let answer = if answer.is_empty() { default } else { answer };
        match validate(answer) {
            Ok(()) => return Ok(answer.to_owned()),
            Err(reason) => writeln!(output, "  {reason} ({attempt}/{MAX_PROMPT_ATTEMPTS})")?,
        }
    }
    bail!("giving up on: {label}")
}

/// Like `prompt_text`, but an empty answer is a real answer ("none") when
/// there is no default, and means "keep the default" when there is one.
fn prompt_optional_text(
    input: &mut impl BufRead,
    output: &mut impl Write,
    label: &str,
    default: Option<String>,
    validate: impl Fn(&str) -> Result<()>,
) -> Result<Option<String>> {
    let shown = default.clone().unwrap_or_default();
    for attempt in 1..=MAX_PROMPT_ATTEMPTS {
        write!(output, "{label} [{shown}]: ")?;
        output.flush()?;
        let Some(answer) = read_line(input)? else {
            bail!("input ended while waiting for an answer to: {label}");
        };
        let answer = answer.trim().to_owned();
        if answer.is_empty() {
            return Ok(default);
        }
        match validate(&answer) {
            Ok(()) => return Ok(Some(answer)),
            Err(reason) => writeln!(output, "  {reason} ({attempt}/{MAX_PROMPT_ATTEMPTS})")?,
        }
    }
    bail!("giving up on: {label}")
}

/// A one-letter choice. Read as a whole line rather than a single keystroke,
/// which is what keeps the wizard scriptable from a pipe.
fn prompt_choice<T: Copy>(
    input: &mut impl BufRead,
    output: &mut impl Write,
    label: &str,
    options: &str,
    default: T,
    key: impl Fn(T) -> char,
    parse: impl Fn(char) -> Option<T>,
) -> Result<T> {
    for attempt in 1..=MAX_PROMPT_ATTEMPTS {
        writeln!(output, "{label} — {options}  [default: {}]", key(default))?;
        write!(output, "  > ")?;
        output.flush()?;
        let Some(answer) = read_line(input)? else {
            bail!("input ended while waiting for an answer to: {label}");
        };
        let answer = answer.trim();
        if answer.is_empty() {
            return Ok(default);
        }
        let letter = answer
            .chars()
            .next()
            .unwrap_or_default()
            .to_ascii_lowercase();
        if let Some(choice) = parse(letter) {
            return Ok(choice);
        }
        writeln!(
            output,
            "  '{letter}' is not one of the options ({attempt}/{MAX_PROMPT_ATTEMPTS})"
        )?;
    }
    bail!("giving up on: {label}")
}

/// A password for a new administrator: typed twice, masked on a terminal, and
/// never echoed anywhere else. It is returned to the caller and written only
/// into the database, as a hash — the config never holds it.
fn prompt_new_password(
    input: &mut impl BufRead,
    output: &mut impl Write,
    admin: &str,
    interactive: bool,
    min_password_length: usize,
) -> Result<String> {
    let minimum = min_password_length.max(MIN_ADMIN_PASSWORD);
    for attempt in 1..=MAX_PROMPT_ATTEMPTS {
        let password = read_secret(input, output, &format!("Password for {admin}"), interactive)?;
        if password.chars().count() < minimum {
            writeln!(
                output,
                "  too short — at least {minimum} characters ({attempt}/{MAX_PROMPT_ATTEMPTS})"
            )?;
            continue;
        }
        let confirm = read_secret(input, output, "Confirm password", interactive)?;
        if confirm != password {
            writeln!(
                output,
                "  the two passwords differ ({attempt}/{MAX_PROMPT_ATTEMPTS})"
            )?;
            continue;
        }
        return Ok(password);
    }
    bail!("giving up on the administrator password")
}

/// Read one secret. On a terminal the echo is off; from a pipe the line is read
/// as-is, which is what makes the wizard testable and scriptable.
fn read_secret(
    input: &mut impl BufRead,
    output: &mut impl Write,
    label: &str,
    interactive: bool,
) -> Result<String> {
    if interactive {
        // `rpassword` owns the terminal here, so it also prints the prompt.
        return rpassword::prompt_password(format!("{label}: ")).context("reading a password");
    }
    write!(output, "{label}: ")?;
    output.flush()?;
    let Some(answer) = read_line(input)? else {
        bail!("input ended while waiting for {label}");
    };
    Ok(answer.trim_end().to_owned())
}

/// `None` at end of input, so a truncated script fails loudly instead of
/// silently taking defaults.
fn read_line(input: &mut impl BufRead) -> Result<Option<String>> {
    let mut line = String::new();
    if input.read_line(&mut line)? == 0 {
        return Ok(None);
    }
    Ok(Some(line))
}

// --- optional mail accounts ----------------------------------------------

/// Both mail steps, in the order the wizard asks them. Returns the configured
/// SMTP and IMAP accounts.
fn prompt_mail(
    input: &mut impl BufRead,
    output: &mut impl Write,
    smtp: &[SmtpAccount],
    imap: &[ImapAccount],
    interactive: bool,
) -> Result<(Vec<SmtpAccount>, Vec<ImapAccount>)> {
    let smtp = if smtp.is_empty() {
        if prompt_yes_no(input, output, "5. Send invitations over SMTP?", false)? {
            vec![prompt_smtp(input, output, interactive)?]
        } else {
            vec![]
        }
    } else if prompt_yes_no(
        input,
        output,
        &format!(
            "5. Keep the {count} configured SMTP account(s) ({identity})?",
            count = smtp.len(),
            identity = smtp[0].identity
        ),
        true,
    )? {
        if prompt_yes_no(
            input,
            output,
            "     Replace it with a different account?",
            false,
        )? {
            vec![prompt_smtp(input, output, interactive)?]
        } else {
            smtp.to_vec()
        }
    } else {
        vec![]
    };

    let imap = if imap.is_empty() {
        if prompt_yes_no(
            input,
            output,
            "6. Poll an IMAP mailbox for replies to invitations?",
            false,
        )? {
            vec![prompt_imap(input, output, interactive)?]
        } else {
            vec![]
        }
    } else if prompt_yes_no(
        input,
        output,
        &format!(
            "6. Keep the {count} configured IMAP account(s) ({identity})?",
            count = imap.len(),
            identity = imap[0].identity
        ),
        true,
    )? {
        if prompt_yes_no(
            input,
            output,
            "     Replace it with a different mailbox?",
            false,
        )? {
            vec![prompt_imap(input, output, interactive)?]
        } else {
            imap.to_vec()
        }
    } else {
        vec![]
    };

    Ok((smtp, imap))
}

fn prompt_smtp(
    input: &mut impl BufRead,
    output: &mut impl Write,
    interactive: bool,
) -> Result<SmtpAccount> {
    let identity = prompt_email(
        input,
        output,
        "     From address (invitations are sent as this)",
    )?;
    let host = prompt_text(input, output, "     SMTP host", "localhost", |answer| {
        if answer.contains(' ') {
            Err(anyhow!("a host name has no spaces"))
        } else {
            Ok(())
        }
    })?;
    let port = prompt_port(input, output, "     SMTP port", 587)?;
    let username = prompt_text(input, output, "     SMTP username", &identity, |_| Ok(()))?;
    let password = read_secret(input, output, "     SMTP password", interactive)?;
    Ok(SmtpAccount {
        identity,
        host,
        port,
        username,
        password,
        displayname: None,
    })
}

fn prompt_imap(
    input: &mut impl BufRead,
    output: &mut impl Write,
    interactive: bool,
) -> Result<ImapAccount> {
    let identity = prompt_email(
        input,
        output,
        "     Mailbox owner (the identity whose replies arrive here)",
    )?;
    let host = prompt_text(input, output, "     IMAP host", "localhost", |answer| {
        if answer.contains(' ') {
            Err(anyhow!("a host name has no spaces"))
        } else {
            Ok(())
        }
    })?;
    let port = prompt_port(input, output, "     IMAP port (implicit TLS)", 993)?;
    let username = prompt_text(input, output, "     IMAP username", &identity, |_| Ok(()))?;
    let password = read_secret(input, output, "     IMAP password", interactive)?;
    Ok(ImapAccount {
        identity,
        host,
        port,
        username,
        password,
        mailbox: "INBOX".to_owned(),
        mark_seen: true,
        ca_file: None,
    })
}

fn prompt_email(input: &mut impl BufRead, output: &mut impl Write, label: &str) -> Result<String> {
    prompt_text(input, output, label, DEFAULT_ADMIN, |answer| {
        if answer.contains('@') && answer.len() > 3 {
            Ok(())
        } else {
            Err(anyhow!("that does not look like an email address"))
        }
    })
}

fn prompt_port(
    input: &mut impl BufRead,
    output: &mut impl Write,
    label: &str,
    default: u16,
) -> Result<u16> {
    let answer = prompt_text(
        input,
        output,
        label,
        &default.to_string(),
        |answer| match answer.parse::<u16>() {
            Ok(port) if port > 0 => Ok(()),
            Ok(_) => Err(anyhow!("a port is 1-65535")),
            Err(_) => Err(anyhow!("not a number")),
        },
    )?;
    answer.parse().map_err(|_| anyhow!("not a number"))
}

fn prompt_yes_no(
    input: &mut impl BufRead,
    output: &mut impl Write,
    label: &str,
    default: bool,
) -> Result<bool> {
    let shown = if default { "Y/n" } else { "y/N" };
    for attempt in 1..=MAX_PROMPT_ATTEMPTS {
        write!(output, "{label} [{shown}]: ")?;
        output.flush()?;
        let Some(answer) = read_line(input)? else {
            bail!("input ended while waiting for an answer to: {label}");
        };
        match answer.trim().to_ascii_lowercase().as_str() {
            "" => return Ok(default),
            "y" | "yes" => return Ok(true),
            "n" | "no" => return Ok(false),
            _ => writeln!(output, "  answer y or n ({attempt}/{MAX_PROMPT_ATTEMPTS})")?,
        }
    }
    bail!("giving up on: {label}")
}

#[cfg(test)]
mod tests {
    use super::{
        RegistrationChoice, TlsChoice, generate_rsvp_secret, prompt_choice, prompt_text,
        prompt_yes_no,
    };
    use crate::config::RegistrationConfig;
    use anyhow::anyhow;
    use std::io::Cursor;

    /// A stdin made of the given answers, one per line. An empty slice is a
    /// genuinely empty stdin, which is what the end-of-input tests need.
    fn scripted(answers: &[&str]) -> Cursor<Vec<u8>> {
        if answers.is_empty() {
            return Cursor::new(Vec::new());
        }
        let mut text = answers.join("\n");
        text.push('\n');
        Cursor::new(text.into_bytes())
    }

    fn tls_parser(letter: char) -> Option<TlsChoice> {
        TlsChoice::parse(letter)
    }

    #[test]
    fn test_prompt_text_takes_the_default_on_empty() {
        let mut input = scripted(&["", "typed"]);
        let mut output = Vec::new();
        assert_eq!(
            prompt_text(&mut input, &mut output, "Label", "fallback", |_| Ok(())).unwrap(),
            "fallback"
        );
        assert_eq!(
            prompt_text(&mut input, &mut output, "Label", "fallback", |_| Ok(())).unwrap(),
            "typed"
        );
        let printed = String::from_utf8(output).unwrap();
        assert!(printed.contains("Label [fallback]"), "{printed}");
    }

    #[test]
    fn test_prompt_text_reasks_an_invalid_answer() {
        let mut input = scripted(&["nonsense", "good@example.com"]);
        let mut output = Vec::new();
        let answer = prompt_text(
            &mut input,
            &mut output,
            "Email",
            "admin@localhost",
            |answer| {
                if answer.contains('@') {
                    Ok(())
                } else {
                    Err(anyhow!("not an email"))
                }
            },
        )
        .unwrap();
        assert_eq!(answer, "good@example.com");
        let printed = String::from_utf8(output).unwrap();
        assert!(printed.contains("not an email (1/5)"), "{printed}");
    }

    #[test]
    fn test_prompt_text_gives_up_rather_than_looping() {
        let mut input = scripted(&["a", "b", "c", "d", "e", "f"]);
        let mut output = Vec::new();
        let error = prompt_text(&mut input, &mut output, "Label", "x", |_| {
            Err(anyhow!("never good"))
        })
        .unwrap_err()
        .to_string();
        assert!(error.contains("giving up"), "{error}");
    }

    #[test]
    fn test_prompt_text_fails_loudly_at_end_of_input() {
        let mut input = scripted(&[]);
        let mut output = Vec::new();
        let error = prompt_text(&mut input, &mut output, "Label", "fallback", |_| Ok(()))
            .unwrap_err()
            .to_string();
        assert!(error.contains("input ended"), "{error}");
    }

    #[test]
    fn test_prompt_choice_default_explicit_and_rejection() {
        let mut input = scripted(&["", "d", "zzz", "c"]);
        let mut output = Vec::new();
        let ask = |input: &mut Cursor<Vec<u8>>, output: &mut Vec<u8>| {
            prompt_choice(
                input,
                output,
                "4. How is TLS terminated?",
                TlsChoice::OPTIONS,
                TlsChoice::DEFAULT,
                TlsChoice::key,
                tls_parser,
            )
            .unwrap()
        };
        assert_eq!(
            ask(&mut input, &mut output),
            TlsChoice::Proxy,
            "empty takes the default"
        );
        assert_eq!(ask(&mut input, &mut output), TlsChoice::DavTls);
        assert_eq!(
            ask(&mut input, &mut output),
            TlsChoice::Proxy,
            "'z' must be rejected, so the next line's default is taken"
        );
        let printed = String::from_utf8(output).unwrap();
        assert!(
            printed.contains("'z' is not one of the options"),
            "{printed}"
        );
    }

    #[test]
    fn test_prompt_yes_no() {
        let mut input = scripted(&["", "n", "YES", "no", "maybe", "y"]);
        let mut output = Vec::new();
        assert!(prompt_yes_no(&mut input, &mut output, "SMTP?", true).unwrap());
        assert!(!prompt_yes_no(&mut input, &mut output, "SMTP?", true).unwrap());
        assert!(prompt_yes_no(&mut input, &mut output, "SMTP?", false).unwrap());
        assert!(!prompt_yes_no(&mut input, &mut output, "SMTP?", true).unwrap());
        assert!(
            prompt_yes_no(&mut input, &mut output, "SMTP?", false).unwrap(),
            "an unparseable answer is re-asked, then 'y' is taken"
        );
        let printed = String::from_utf8(output).unwrap();
        assert!(printed.contains("answer y or n"), "{printed}");
    }

    #[test]
    fn test_registration_choice_round_trips_through_the_config() {
        for choice in [
            RegistrationChoice::Closed,
            RegistrationChoice::InviteOnly,
            RegistrationChoice::Open,
        ] {
            let mut config = RegistrationConfig::default();
            choice.apply(&mut config);
            assert_eq!(RegistrationChoice::from_config(&config), choice);
        }
    }

    #[test]
    fn test_registration_choice_reads_a_disabled_config() {
        // The router's own config has registration off; a wizard re-run over it
        // must offer "closed", not "invite-only".
        let config = RegistrationConfig {
            enabled: false,
            ..RegistrationConfig::default()
        };
        assert_eq!(
            RegistrationChoice::from_config(&config),
            RegistrationChoice::Closed
        );
    }

    #[test]
    fn test_rsvp_secret_is_32_random_bytes_hex() {
        let secret = generate_rsvp_secret();
        assert_eq!(secret.len(), 64, "{secret}");
        assert!(secret.chars().all(|c| c.is_ascii_hexdigit()), "{secret}");
        assert_ne!(secret, generate_rsvp_secret());
    }

    #[test]
    fn test_bind_port() {
        assert_eq!(super::bind_port("0.0.0.0:4000"), "4000");
        assert_eq!(super::bind_port("127.0.0.1:8443"), "8443");
        assert_eq!(super::bind_port("[::]:4000"), "4000");
    }
}
