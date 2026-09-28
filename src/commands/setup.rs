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
use crate::register::seed_collections;
use anyhow::{Context, Result, anyhow, bail};
use clap::Parser;
use rand::RngExt;
use rustical_scheduling::{ImapAccount, SmtpAccount};
use rustical_store::auth::{AuthenticationProvider, Principal, PrincipalType};
use rustical_store_sqlite::{
    SqliteAddressbookStore, SqliteCalendarStore, SqlitePrincipalStore, create_db_pool,
};
use sqlx::SqlitePool;
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

    /// The same question answered by a flag or an `OMNICAL_SETUP_*` variable.
    ///
    /// A `.env` file or a provisioning manifest says `proxy`, not `c`, so both
    /// are accepted; `parse` stays the char parser the interactive prompt
    /// needs. Kept adjacent to `OPTIONS` on purpose — the two must not drift,
    /// and a test asserts that every letter in `OPTIONS` parses.
    #[must_use]
    pub fn parse_word(answer: &str) -> Option<Self> {
        match answer.trim().to_ascii_lowercase().as_str() {
            "c" | "p" | "proxy" | "reverse-proxy" | "caddy" | "nginx" => Some(Self::Proxy),
            "d" | "dav-tls" | "davtls" => Some(Self::DavTls),
            "n" | "none" => Some(Self::None),
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

    /// The same question answered by a flag or an `OMNICAL_SETUP_*` variable.
    /// See [`TlsChoice::parse_word`] for why both spellings exist.
    #[must_use]
    pub fn parse_word(answer: &str) -> Option<Self> {
        match answer.trim().to_ascii_lowercase().as_str() {
            "i" | "invite-only" | "invite_only" | "invite" | "invites" => Some(Self::InviteOnly),
            "o" | "open" => Some(Self::Open),
            "c" | "closed" | "close" => Some(Self::Closed),
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
    /// `true` when nothing was prompted: every answer came from a flag or an
    /// `OMNICAL_SETUP_*` variable. Reported so a caller (and a test) can tell
    /// an unattended run from a scripted-stdin one.
    pub unattended: bool,
}

#[derive(Debug, Parser)]
pub struct SetupArgs {
    /// Take every answer from the options below instead of prompting
    ///
    /// The options are `env`-backed so a container or a provisioning system can
    /// answer them with no shell in the image. A question with no answer is an
    /// error naming the variable to set — never a default, and never a prompt.
    /// Unattended is opt-in, so nothing about the interactive wizard changes
    /// unless you ask for it.
    #[arg(long, env = "OMNICAL_SETUP_UNATTENDED")]
    pub unattended: bool,
    /// Where to keep db.sqlite3 (e.g. /var/lib/omnical)
    #[arg(long, env = "OMNICAL_SETUP_DATA_DIR")]
    pub data_dir: Option<String>,
    /// Address to listen on (e.g. `0.0.0.0:4000`, or `unix:/run/omnical.sock`)
    #[arg(long, env = "OMNICAL_SETUP_BIND")]
    pub bind: Option<String>,
    /// Public https:// URL clients will use. Unset = not reachable yet, and
    /// the share feeds stay off. Never cleared by an unattended run.
    #[arg(long, env = "OMNICAL_SETUP_PUBLIC_URL")]
    pub public_url: Option<String>,
    /// Who terminates TLS: proxy, dav-tls or none. Advice only — it selects
    /// the next steps that get printed, and writes no config key.
    #[arg(long, env = "OMNICAL_SETUP_TLS")]
    pub tls: Option<String>,
    /// How accounts may be created: invite-only, open or closed
    #[arg(long, env = "OMNICAL_SETUP_REGISTRATION")]
    pub registration: Option<String>,
    /// The first administrator's email address
    #[arg(long, env = "OMNICAL_SETUP_ADMIN_EMAIL")]
    pub admin_email: Option<String>,
    /// The first administrator's password, 12 characters or more
    ///
    /// **Environment only, deliberately not a flag.** An administrator password
    /// on a command line is visible in `ps` to every user on the host; an
    /// environment variable is not, and is still the right channel for the
    /// unattended path. It is read only when the account is actually being
    /// created, so it can be removed from the environment after the first run.
    #[arg(long, env = "OMNICAL_SETUP_ADMIN_PASSWORD", hide = true)]
    pub admin_password: Option<String>,
}

/// The pre-answered questions of an unattended run.
///
/// A question is required — `--unattended` errors rather than defaulting — with
/// one exception: the public URL, which is optional because "not reachable yet"
/// is a real state for a first install behind a proxy that does not exist. See
/// the `run_setup_with` body for the one asymmetry, which is that an unattended
/// run may *set or keep* the public URL but never clear it.
///
/// **Why the `OMNICAL_SETUP_` prefix and not `RUSTICAL_`:** the server's config
/// is read by figment as `RUSTICAL_*` with `__` as the section separator
/// (`main.rs:22`), and every struct in `config.rs` is `deny_unknown_fields`. A
/// wizard answer smuggled in as `RUSTICAL_SETUP__DATA_DIR` would therefore be
/// a *config parse error* the moment the same environment reached `rustical
/// serve` — which is precisely what happens in a Compose file, where the setup
/// service and the server service share one environment block. A separate
/// namespace cannot collide.
#[derive(Debug, Default, Clone)]
pub struct SetupAnswers {
    /// Opt in to the no-prompt path. See [`SetupArgs::unattended`].
    pub unattended: bool,
    pub data_dir: Option<String>,
    pub bind: Option<String>,
    pub public_url: Option<String>,
    pub tls: Option<String>,
    pub registration: Option<String>,
    pub admin_email: Option<String>,
    pub admin_password: Option<String>,
}

impl SetupAnswers {
    /// From parsed CLI args. The environment is already folded in by clap, so
    /// this is the single place the two input channels meet — and therefore the
    /// single place the `--unattended` rule is enforced.
    ///
    /// **The answers are discarded unless `--unattended` is set**, and that is
    /// not tidiness. These flags are `env`-backed, so clap fills them in from
    /// `OMNICAL_SETUP_*` *whether or not* unattended was asked for: an
    /// `OMNICAL_SETUP_DATA_DIR` in the environment silently pre-answers question
    /// 1 of the **interactive** wizard. Everything downstream then shifts by one
    /// line of a piped answer script, and because `HttpBindConfig::from_str`
    /// accepts almost any string as a host, the *next* answer — a filesystem
    /// path — is accepted as the listen address. The result is a config with
    /// `bind = "/var/lib/omnical"` and a server that cannot start, produced by
    /// a run that reported success at every step. `install.sh` sets exactly
    /// that variable, and it is how this was found: the §18.7 self-host gate
    /// ran the attended path by hand, and the wizard's own step 2 printed the
    /// data directory where the bind address should have been.
    #[must_use]
    pub fn from_args(args: &SetupArgs) -> Self {
        if !args.unattended {
            return Self::default();
        }
        Self {
            unattended: true,
            data_dir: args.data_dir.clone(),
            bind: args.bind.clone(),
            public_url: args.public_url.clone(),
            tls: args.tls.clone(),
            registration: args.registration.clone(),
            admin_email: args.admin_email.clone(),
            admin_password: args.admin_password.clone(),
        }
    }
}

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
pub async fn cmd_setup(args: SetupArgs, config_file: &Path) -> Result<()> {
    let stdin = std::io::stdin();
    let interactive = stdin.is_terminal();
    let mut input = stdin.lock();
    let mut output = std::io::stdout();
    let answers = SetupAnswers::from_args(&args);
    run_setup_with(&mut input, &mut output, config_file, interactive, &answers).await?;
    Ok(())
}

/// The wizard with nothing pre-answered, i.e. every question is asked.
///
/// This is the historical entry point and stays exactly as it was: the
/// unattended path is reachable only by asking for it, so no existing caller —
/// and no existing test — can change behaviour by accident.
#[allow(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::future_not_send
)]
pub async fn run_setup(
    input: &mut impl BufRead,
    output: &mut impl Write,
    config_file: &Path,
    interactive: bool,
) -> Result<SetupReport> {
    run_setup_with(
        input,
        output,
        config_file,
        interactive,
        &SetupAnswers::default(),
    )
    .await
}

/// The wizard, with its input and output injected.
///
/// `interactive` only decides whether secrets are read with echo disabled; the
/// questions and the answers are otherwise identical, which is what makes a
/// piped-stdin test meaningful. `answers` pre-answers individual questions, and
/// `answers.unattended` removes the possibility of a prompt entirely: a
/// question with no answer is then an error naming the flag that would answer
/// it, never a silent default.
#[allow(
    clippy::too_many_lines,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc
)]
pub async fn run_setup_with(
    input: &mut impl BufRead,
    output: &mut impl Write,
    config_file: &Path,
    interactive: bool,
    answers: &SetupAnswers,
) -> Result<SetupReport> {
    let existing = load_existing_config(config_file)?;
    writeln!(output, "Omnical setup — {}", config_file.display())?;
    if answers.unattended {
        // Said out loud because this line is the only evidence, in a container
        // log, of *how* the config that is about to be written was decided.
        writeln!(
            output,
            "Unattended: every question is answered by a flag or an OMNICAL_SETUP_* \
             variable. Nothing will be prompted, and a missing answer is an error."
        )?;
    } else if existing.is_some() {
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
    let data_dir = match preanswered(
        answers.data_dir.as_deref(),
        FLAG_DATA_DIR,
        answers.unattended,
        |answer| {
            if answer.is_empty() {
                Err(anyhow!("a data directory is required"))
            } else {
                Ok(())
            }
        },
    )? {
        Some(answer) => answer,
        None => prompt_text(
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
        )?,
    };
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
    let bind = match preanswered(
        answers.bind.as_deref(),
        FLAG_BIND,
        answers.unattended,
        |answer| HttpBindConfig::from_str(answer).map(|_| ()),
    )? {
        Some(answer) => answer,
        None => prompt_text(
            input,
            output,
            "2. Address to listen on",
            if reloading {
                config.http.bind.as_deref().unwrap_or(DEFAULT_BIND)
            } else {
                DEFAULT_BIND
            },
            |answer| HttpBindConfig::from_str(answer).map(|_| ()),
        )?,
    };
    config.http.bind = Some(bind.clone());
    // `http.host` / `http.port` are a *deprecated* bind override in 0.16.1:
    // they take precedence over `bind` and make the server try to bind the
    // wrong address (see the router config's own comment). Cleared so a
    // re-run over a config that has them cannot inherit them.
    config.http.host = None;
    config.http.port = None;

    // 3. Public URL — the base every client-facing link is built from.
    //
    // The one *optional* answer, and it is asymmetric on purpose: an unattended
    // run can set the public URL or leave it alone, but it can never **clear**
    // one. Clearing it is an attended edit, because the unattended surface is
    // the one a container restart re-runs for months — a variable that quietly
    // deletes a working public URL on the next `docker compose up` would be the
    // worst possible behaviour for a provisioning path, and there is no
    // unattended caller that needs to clear it.
    let public_url = match answers.public_url.as_deref() {
        Some(answer) if !answer.trim().is_empty() => Some(validate_url(FLAG_PUBLIC_URL, answer)?),
        Some(_) => config.subscriptions.public_url.clone(),
        None if answers.unattended => config.subscriptions.public_url.clone(),
        None => prompt_optional_text(
            input,
            output,
            "3. Public URL (blank if this server is not reachable yet)",
            config.subscriptions.public_url.clone(),
            |answer| validate_url("3. Public URL", answer).map(|_| ()),
        )?,
    };
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
    let tls = match preanswered(
        answers.tls.as_deref(),
        FLAG_TLS,
        answers.unattended,
        |answer| parse_tls(answer).map(|_| ()),
    )? {
        Some(answer) => parse_tls(&answer)?,
        None => prompt_choice(
            input,
            output,
            "4. How is TLS terminated?",
            TlsChoice::OPTIONS,
            TlsChoice::DEFAULT,
            TlsChoice::key,
            TlsChoice::parse,
        )?,
    };

    // 5 + 6. Mail. Both optional, and a re-run keeps what is configured
    // without ever showing or re-asking for a stored password.
    //
    // An unattended run does not ask and does not set: a mail account is the
    // one answer whose value is a long-lived password typed into a config file
    // that ends up in an image layer, a CI log or an `inspect` output. The
    // wizard therefore refuses to *add* mail unattended, and — symmetrically
    // with the public URL — will not *remove* it either. Mail is configured by
    // an attended re-run, which is the path §18.6 already designed for.
    let (smtp, imap) = if answers.unattended {
        if !config.scheduling.smtp.is_empty() {
            writeln!(
                output,
                "5+6. Mail left exactly as configured — an unattended run never reads or \
                 writes a mail password. Re-run this wizard without --unattended to change it."
            )?;
        }
        (
            config.scheduling.smtp.clone(),
            config.scheduling.imap.clone(),
        )
    } else {
        prompt_mail(
            input,
            output,
            &config.scheduling.smtp,
            &config.scheduling.imap,
            interactive,
        )?
    };
    config.scheduling.smtp = smtp;
    config.scheduling.imap = imap;
    config.scheduling.enabled = !config.scheduling.smtp.is_empty();

    // 7. Registration.
    let default_registration = RegistrationChoice::from_config(&config.registration);
    let registration = match preanswered(
        answers.registration.as_deref(),
        FLAG_REGISTRATION,
        answers.unattended,
        |answer| parse_registration(answer).map(|_| ()),
    )? {
        Some(answer) => parse_registration(&answer)?,
        None => prompt_choice(
            input,
            output,
            "7. Registration",
            RegistrationChoice::OPTIONS,
            default_registration,
            RegistrationChoice::key,
            RegistrationChoice::parse,
        )?,
    };
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
        &pool,
        &principal_store,
        interactive,
        min_password_length,
        answers,
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
        unattended: answers.unattended,
    };
    print_next_steps(output, &report)?;
    Ok(report)
}

/// Returns `(admin id, created?)`.
async fn ensure_administrator(
    input: &mut impl BufRead,
    output: &mut impl Write,
    pool: &SqlitePool,
    principal_store: &SqlitePrincipalStore,
    interactive: bool,
    min_password_length: usize,
    answers: &SetupAnswers,
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

    let admin = match preanswered(
        answers.admin_email.as_deref(),
        FLAG_ADMIN_EMAIL,
        answers.unattended,
        validate_email,
    )? {
        Some(answer) => answer,
        None => prompt_text(
            input,
            output,
            "8. Administrator email address",
            &default_admin,
            validate_email,
        )?,
    };

    if let Some(principal) = principal_store.get_principal(&admin).await? {
        writeln!(
            output,
            "Administrator {admin} already exists — left untouched. Change the password with\n\
                 `rustical principals edit {admin} --password`."
        )?;
        // A principal with no password can only sign in through OIDC. Offer
        // to set one, but never overwrite a password that is already set.
        if principal.password.is_none() {
            let password = new_password(
                input,
                output,
                &admin,
                interactive,
                min_password_length,
                answers,
            )?;
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

    let password = new_password(
        input,
        output,
        &admin,
        interactive,
        min_password_length,
        answers,
    )?;
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

    // …with the collections a client needs, because the next step this wizard
    // prints is "add a client from the calendar page". Same code registration
    // uses, so a wizard-created administrator and a self-registered one are
    // indistinguishable to a client — see `register::seed_collections`.
    let (send, _recv) = tokio::sync::mpsc::channel(1000);
    let cal_store = SqliteCalendarStore::new(pool.clone(), send.clone(), true);
    let addr_store = SqliteAddressbookStore::new(pool.clone(), send, true);
    seed_collections(&cal_store, &addr_store, &admin)
        .await
        .context("seeding the administrator's calendar and addressbook")?;
    writeln!(
        output,
        "Created the 'personal' calendar, the 'tasks' calendar and the 'personal' \
         addressbook for {admin}."
    )?;
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
    if report.unattended {
        // The one thing an unattended run could not do, said where the operator
        // is already looking, rather than in a manual nobody opens.
        writeln!(
            output,
            "  5. No mail account was configured — an unattended run never reads or writes a\n\
             \x20    mail password. Run `rustical setup` without --unattended to add SMTP/IMAP;\n\
             \x20    invitations stay off until you do."
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

// --- pre-answered questions (the unattended path) ---------------------------

/// The flag that answers each question, and the `OMNICAL_SETUP_*` variable
/// behind it, spelled out so every error message can name both.
///
/// The error message is the *product* here. An unattended run that fails must
/// say which variable to set and what it will accept; a bare "missing field" in
/// a `docker compose up` log is a support ticket, and the whole point of the
/// unattended path is that it is not one.
const FLAG_DATA_DIR: &str = "--data-dir (OMNICAL_SETUP_DATA_DIR)";
const FLAG_BIND: &str = "--bind (OMNICAL_SETUP_BIND)";
const FLAG_PUBLIC_URL: &str = "--public-url (OMNICAL_SETUP_PUBLIC_URL)";
const FLAG_TLS: &str = "--tls (OMNICAL_SETUP_TLS)";
const FLAG_REGISTRATION: &str = "--registration (OMNICAL_SETUP_REGISTRATION)";
const FLAG_ADMIN_EMAIL: &str = "--admin-email (OMNICAL_SETUP_ADMIN_EMAIL)";
const ENV_ADMIN_PASSWORD: &str = "OMNICAL_SETUP_ADMIN_PASSWORD";

/// A question that was answered ahead of time, or that still needs asking.
///
/// * `Some(answer)` — the caller got its value, validated with the *same*
///   predicate the prompt would have used, so a pre-answered value is not
///   subject to laxer rules than a typed one.
/// * `None` — ask the question.
///
/// Unattended and unanswered is an **error**, never a default. That is the
/// whole safety property of this mode: `read_line` returning `None` at end of
/// input already fails loudly (§18.6 burn scar 1), and this keeps that true
/// when the input is not stdin at all.
fn preanswered(
    answer: Option<&str>,
    flag: &str,
    unattended: bool,
    validate: impl Fn(&str) -> Result<()>,
) -> Result<Option<String>> {
    let Some(answer) = answer else {
        if unattended {
            bail!(
                "unattended setup needs an answer for this question: pass {flag}\n\
                 \x20   (run `rustical setup` without --unattended to be asked instead)"
            );
        }
        return Ok(None);
    };
    validate(answer).map_err(|reason| anyhow!("{flag}: {reason}"))?;
    Ok(Some(answer.trim().to_owned()))
}

fn validate_email(answer: &str) -> Result<()> {
    if answer.contains('@') && answer.len() > 3 {
        Ok(())
    } else {
        Err(anyhow!("that does not look like an email address"))
    }
}

fn validate_url(what: &str, answer: &str) -> Result<String> {
    url::Url::parse(answer)
        .map(|_| answer.to_owned())
        .map_err(|e| anyhow!("{what}: {e}"))
}

fn parse_tls(answer: &str) -> Result<TlsChoice> {
    TlsChoice::parse_word(answer)
        .ok_or_else(|| anyhow!("{FLAG_TLS} must be one of: proxy, dav-tls, none"))
}

fn parse_registration(answer: &str) -> Result<RegistrationChoice> {
    RegistrationChoice::parse_word(answer)
        .ok_or_else(|| anyhow!("{FLAG_REGISTRATION} must be one of: invite-only, open, closed"))
}

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

/// A password for a new administrator, from the environment or the prompt.
///
/// The supplied password is held to the **same** length floor as a typed one.
/// An unattended path that accepted a 4-character password because nobody was
/// watching would be the worst version of this feature.
fn new_password(
    input: &mut impl BufRead,
    output: &mut impl Write,
    admin: &str,
    interactive: bool,
    min_password_length: usize,
    answers: &SetupAnswers,
) -> Result<String> {
    let minimum = min_password_length.max(MIN_ADMIN_PASSWORD);
    if let Some(password) = answers.admin_password.as_deref() {
        if password.chars().count() < minimum {
            bail!("{ENV_ADMIN_PASSWORD} is too short — at least {minimum} characters");
        }
        return Ok(password.to_owned());
    }
    if answers.unattended {
        bail!(
            "unattended setup cannot ask for the administrator's password.\n\
             \x20   Set {ENV_ADMIN_PASSWORD} (environment only, never a flag: an argument \
             would be visible in `ps`).\n\
             \x20   It is read only when this account does not exist yet, so it can be \
             removed from the environment after the first run."
        );
    }
    prompt_new_password(input, output, admin, interactive, min_password_length)
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
    prompt_text(input, output, label, DEFAULT_ADMIN, validate_email)
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
        RegistrationChoice, SetupAnswers, TlsChoice, generate_rsvp_secret, preanswered,
        prompt_choice, prompt_text, prompt_yes_no,
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

    /// The `OMNICAL_SETUP_*` variables must do nothing at all unless
    /// `--unattended` was asked for.
    ///
    /// These flags are `env`-backed, so clap fills them in regardless — an
    /// `OMNICAL_SETUP_DATA_DIR` in the environment otherwise pre-answers
    /// question 1 of the *interactive* wizard, which shifts a piped answer
    /// script by one line and lets the next answer (a filesystem path) be
    /// accepted as the listen address. `install.sh` sets that variable, and the
    /// resulting config said `bind = "/var/lib/omnical"`. See
    /// `SetupAnswers::from_args`.
    #[test]
    fn test_environment_answers_are_inert_without_unattended() {
        let args = super::SetupArgs {
            unattended: false,
            data_dir: Some("/var/lib/omnical".to_owned()),
            bind: Some("127.0.0.1:4000".to_owned()),
            public_url: Some("https://cal.example.com".to_owned()),
            tls: Some("proxy".to_owned()),
            registration: Some("open".to_owned()),
            admin_email: Some("someone@example.com".to_owned()),
            admin_password: Some("a-long-enough-password".to_owned()),
        };
        let answers = super::SetupAnswers::from_args(&args);
        assert!(!answers.unattended);
        assert_eq!(answers.data_dir, None);
        assert_eq!(answers.bind, None);
        assert_eq!(answers.public_url, None);
        assert_eq!(answers.tls, None);
        assert_eq!(answers.registration, None);
        assert_eq!(answers.admin_email, None);
        assert_eq!(answers.admin_password, None);
    }

    /// …and with `--unattended` they are all live, including the password.
    #[test]
    fn test_environment_answers_are_used_with_unattended() {
        let args = super::SetupArgs {
            unattended: true,
            data_dir: Some("/var/lib/omnical".to_owned()),
            bind: Some("127.0.0.1:4000".to_owned()),
            public_url: Some("https://cal.example.com".to_owned()),
            tls: Some("proxy".to_owned()),
            registration: Some("open".to_owned()),
            admin_email: Some("someone@example.com".to_owned()),
            admin_password: Some("a-long-enough-password".to_owned()),
        };
        let answers = super::SetupAnswers::from_args(&args);
        assert!(answers.unattended);
        assert_eq!(answers.data_dir.as_deref(), Some("/var/lib/omnical"));
        assert_eq!(answers.bind.as_deref(), Some("127.0.0.1:4000"));
        assert_eq!(answers.tls.as_deref(), Some("proxy"));
        assert_eq!(
            answers.admin_password.as_deref(),
            Some("a-long-enough-password")
        );
    }

    // --- the unattended path ------------------------------------------------

    /// A pre-answered question is validated by the *same* predicate the prompt
    /// would have used. If these drifted, an unattended install would quietly
    /// accept a bind address the interactive one rejects.
    #[test]
    fn test_preanswered_runs_the_prompt_validator() {
        let validator = |answer: &str| {
            if answer.contains(':') {
                Ok(())
            } else {
                Err(anyhow!("not an address"))
            }
        };
        assert_eq!(
            preanswered(Some("0.0.0.0:4000"), "--bind", true, validator)
                .unwrap()
                .as_deref(),
            Some("0.0.0.0:4000")
        );
        // A single line carrying the flag *and* the reason, rather than an
        // `anyhow` context chain: `{}` formatting shows only the outermost error, so
        // a context here would put "not an address" nowhere a log reader ever sees
        // it — the message is the product in a `docker compose up` log.
        let error = preanswered(
            Some("nonsense"),
            "--bind (OMNICAL_SETUP_BIND)",
            true,
            validator,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("not an address"), "{error}");
        assert!(
            error.contains("--bind"),
            "the error must name the flag: {error}"
        );
    }

    /// The safety property of the whole mode: unattended + unanswered is an
    /// error, never a default. §18.6's burn scar was a wizard that took
    /// defaults when input ran dry; this is the same rule one level up.
    #[test]
    fn test_preanswered_never_defaults_when_unattended() {
        let error = preanswered(None, super::FLAG_DATA_DIR, true, |_: &str| Ok(()))
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("unattended setup needs an answer"),
            "{error}"
        );
        assert!(error.contains("OMNICAL_SETUP_DATA_DIR"), "{error}");
    }

    /// Without `--unattended` a missing answer still means "ask", which is what
    /// keeps the existing wizard and its 12 tests untouched.
    #[test]
    fn test_preanswered_asks_when_not_unattended() {
        assert!(
            preanswered(None, "--data-dir", false, |_| Ok(()))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn test_preanswered_trims() {
        assert_eq!(
            preanswered(
                Some("  /var/lib/omnical \n"),
                "--data-dir",
                true,
                |_| Ok(())
            )
            .unwrap(),
            Some("/var/lib/omnical".to_owned())
        );
    }

    /// The letters the interactive prompt offers and the words a `.env` file
    /// carries must accept the same set of choices. A new option added to
    /// `OPTIONS` without a word here would be reachable by hand and not by
    /// container — the exact silent gap §8.1's two channels must not have.
    #[test]
    fn test_parse_word_covers_every_letter_in_options() {
        for (letter, word) in [('c', "proxy"), ('d', "dav-tls"), ('n', "none")] {
            assert!(
                TlsChoice::OPTIONS.contains(letter),
                "{letter} missing from OPTIONS"
            );
            assert_eq!(TlsChoice::parse(letter), TlsChoice::parse_word(word));
            assert_eq!(
                TlsChoice::parse(letter),
                TlsChoice::parse_word(&letter.to_string())
            );
        }
        for (letter, word) in [('i', "invite-only"), ('o', "open"), ('c', "closed")] {
            assert!(
                RegistrationChoice::OPTIONS.contains(letter),
                "{letter} missing from OPTIONS"
            );
            assert_eq!(
                RegistrationChoice::parse(letter),
                RegistrationChoice::parse_word(word)
            );
        }
    }

    /// A `.env` value is written by humans: case, padding and the word form.
    #[test]
    fn test_parse_word_is_forgiving_about_spelling_and_case() {
        assert_eq!(TlsChoice::parse_word(" Proxy "), Some(TlsChoice::Proxy));
        assert_eq!(TlsChoice::parse_word("DAV-TLS"), Some(TlsChoice::DavTls));
        assert_eq!(TlsChoice::parse_word("None"), Some(TlsChoice::None));
        assert_eq!(TlsChoice::parse_word("tls-terminated"), None);
        assert_eq!(
            RegistrationChoice::parse_word("INVITE-ONLY"),
            Some(RegistrationChoice::InviteOnly)
        );
        assert_eq!(RegistrationChoice::parse_word("yes"), None);
    }

    /// An unattended password is held to the same floor as a typed one, and is
    /// never read when the account already exists.
    #[tokio::test]
    async fn test_unattended_password_obeys_the_length_floor() {
        let answers = SetupAnswers {
            unattended: true,
            admin_password: Some("short".to_owned()),
            ..SetupAnswers::default()
        };
        let error = super::new_password(
            &mut Cursor::new(Vec::new()),
            &mut Vec::new(),
            "admin@example.com",
            false,
            12,
            &answers,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("too short"), "{error}");
        assert!(error.contains("12"), "{error}");
    }

    #[tokio::test]
    async fn test_unattended_without_a_password_says_where_to_put_it() {
        let answers = SetupAnswers {
            unattended: true,
            ..SetupAnswers::default()
        };
        let error = super::new_password(
            &mut Cursor::new(Vec::new()),
            &mut Vec::new(),
            "admin@example.com",
            false,
            12,
            &answers,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("OMNICAL_SETUP_ADMIN_PASSWORD"), "{error}");
        // The `ps` warning is the reason it is an env var and not a flag, and it
        // is only useful if the message actually says so.
        assert!(error.contains("ps"), "{error}");
    }

    #[tokio::test]
    async fn test_unattended_password_is_taken_verbatim() {
        let answers = SetupAnswers {
            unattended: true,
            admin_password: Some("correct-horse-battery".to_owned()),
            ..SetupAnswers::default()
        };
        let password = super::new_password(
            &mut Cursor::new(Vec::new()),
            &mut Vec::new(),
            "admin@example.com",
            false,
            12,
            &answers,
        )
        .unwrap();
        assert_eq!(password, "correct-horse-battery");
    }
}
