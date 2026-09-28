//! `rustical setup` wizard tests (PLAN_DEPLOYMENTS.md §8.2, verification-matrix
//! row 44).
//!
//! Row 44 is the gate: **`rustical setup` twice, and the second run edits
//! rather than clobbers** — the existing database, the existing administrator
//! and the existing password all survive. That is the property that makes the
//! wizard safe to re-run on a live install, and it is the one a first-run-only
//! test cannot show, so the re-run is a first-class case here rather than an
//! afterthought.
//!
//! The wizard is driven entirely from a scripted stdin, in the same order a
//! real operator would answer. That ordering is part of the contract: the
//! administrator is asked *last*, after the wizard knows what the database
//! already holds, so a re-run cannot talk someone into creating a second
//! administrator.
use rustical::config::Config;
use rustical::{
    RegistrationChoice, SetupAnswers, SetupReport, TlsChoice, run_setup, run_setup_with,
};
use rustical_store::auth::AuthenticationProvider;
use rustical_store::{AddressbookReadStore, CalendarReadStore, CollectionOperation};
use rustical_store_sqlite::{
    SqliteAddressbookStore, SqliteCalendarStore, SqlitePrincipalStore, create_db_pool,
};
use std::io::Cursor;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

/// A first run: accept every default except a real data directory, a public
/// URL, the TLS answer and the administrator, and skip both mail steps.
fn first_run_answers(data_dir: &Path) -> Vec<String> {
    vec![
        data_dir.to_string_lossy().into_owned(), // 1. data directory
        String::new(),                           // 2. listen address (default)
        "https://cal.example.com".to_owned(),    // 3. public URL
        "c".to_owned(),                          // 4. reverse proxy
        "n".to_owned(),                          // 5. no SMTP
        "n".to_owned(),                          // 6. no IMAP
        "i".to_owned(),                          // 7. invite-only
        "owner@example.com".to_owned(),          // 8. administrator
        "correct-horse-battery".to_owned(),      //    password
        "correct-horse-battery".to_owned(),      //    confirm
    ]
}

/// A re-run: the same questions, the administrator left on its default (which
/// is now the account that exists), and **no password prompt at all** — there
/// is nothing to change.
fn rerun_answers(data_dir: &Path) -> Vec<String> {
    vec![
        data_dir.to_string_lossy().into_owned(),
        String::new(),
        String::new(),
        String::new(),
        String::new(),
        String::new(),
        String::new(),
        String::new(), // keep the existing administrator
    ]
}

async fn run(dir: &Path, answers: &[String]) -> (SetupReport, String) {
    let mut input = Cursor::new(format!("{}\n", answers.join("\n")).into_bytes());
    let mut output: Vec<u8> = Vec::new();
    let config_file = dir.join("config.toml");
    let report = run_setup(&mut input, &mut output, &config_file, false)
        .await
        .expect("the wizard must complete on a scripted stdin");
    (
        report,
        String::from_utf8(output).expect("the prompt text is utf-8"),
    )
}

async fn principals(db_path: &Path) -> Vec<String> {
    let pool = create_db_pool(&db_path.to_string_lossy(), false)
        .await
        .unwrap();
    let store = SqlitePrincipalStore::new(pool.clone());
    let mut ids: Vec<String> = store
        .get_principals()
        .await
        .unwrap()
        .into_iter()
        .map(|principal| principal.id)
        .collect();
    ids.sort();
    pool.close().await;
    ids
}

async fn password_hash(db_path: &Path, principal: &str) -> Option<String> {
    let pool = create_db_pool(&db_path.to_string_lossy(), false)
        .await
        .unwrap();
    let store = SqlitePrincipalStore::new(pool.clone());
    let hash = store
        .get_principal(principal)
        .await
        .unwrap()
        .and_then(|found| found.password.map(|secret| secret.into_inner()));
    pool.close().await;
    hash
}

/// The gate (row 44): a first run creates the install, a second run changes
/// nothing that matters.
#[tokio::test]
async fn test_setup_is_idempotent() {
    let dir = tempfile::tempdir().unwrap();
    let data_dir = dir.path().join("data");
    let (first, first_output) = run(dir.path(), &first_run_answers(&data_dir)).await;
    assert!(first.admin_created);
    assert_eq!(first.admin, "owner@example.com");
    assert!(first.rsvp_secret_generated);
    assert!(first_output.contains("Created administrator owner@example.com"));
    assert!(first.db_path.is_file(), "{}", first.db_path.display());
    let hash_after_first = password_hash(&first.db_path, "owner@example.com").await;
    assert!(hash_after_first.is_some());

    // The second run: the operator changes nothing at all.
    let (second, second_output) = run(dir.path(), &rerun_answers(&data_dir)).await;
    assert!(!second.admin_created, "a re-run must not create anything");
    assert_eq!(
        second.admin, "owner@example.com",
        "the default must be the account that already exists, not a new one"
    );
    assert!(
        !second.rsvp_secret_generated,
        "the RSVP secret must be kept, not rotated: rotating it invalidates \
         every invitation link already sent"
    );
    assert!(second_output.contains("already exists"));
    assert!(second_output.contains("left untouched"));

    // The database survived, with the same single principal...
    assert_eq!(principals(&second.db_path).await, ["owner@example.com"]);
    // ...and, the part that matters most, with the same password hash.
    assert_eq!(
        password_hash(&second.db_path, "owner@example.com").await,
        hash_after_first,
        "a re-run must never reset the administrator's password"
    );
    // The data directory was not re-created or emptied.
    assert_eq!(second.data_dir, first.data_dir);
}

/// The first run has to produce a config the production binary can load, with
/// no `deny_unknown_fields` error in either direction (§8.3's gate).
#[tokio::test]
async fn test_written_config_round_trips() {
    let dir = tempfile::tempdir().unwrap();
    let data_dir = dir.path().join("data");
    let (report, _) = run(dir.path(), &first_run_answers(&data_dir)).await;

    let text = std::fs::read_to_string(&report.config_file).unwrap();
    let parsed: Config = toml::from_str(&text).expect("the wizard wrote an unparseable config");
    assert_eq!(
        parsed.http.bind.as_deref(),
        Some("0.0.0.0:4000"),
        "a fresh install gets the documented default, not the upstream [::]:4000"
    );
    assert_eq!(
        parsed.subscriptions.public_url.as_deref(),
        Some("https://cal.example.com")
    );
    assert!(parsed.subscriptions.enabled);
    assert_eq!(parsed.sqlite_db_path(), Some(report.db_path.clone()));
    assert!(parsed.scheduling.rsvp_secret.is_some());
    assert_eq!(
        parsed.scheduling.rsvp_base_url.as_deref(),
        Some("https://cal.example.com")
    );
    assert!(parsed.registration.enabled);
    assert!(parsed.registration.invite_required);
    assert!(parsed.scheduling.smtp.is_empty());
    assert!(!parsed.scheduling.enabled);

    // And the other direction, which is the half of §8.3's gate that a
    // first-run test cannot show: a config the wizard did *not* write — the
    // one `gen-config` prints — must load, and the values the wizard does not
    // ask about must survive the round trip untouched.
    let dir = tempfile::tempdir().unwrap();
    let data_dir = dir.path().join("data");
    let config_file = dir.path().join("config.toml");
    std::fs::write(
        &config_file,
        toml::to_string_pretty(&Config::default_config()).unwrap(),
    )
    .unwrap();

    // The gen-config file points at /var/lib/rustical, so the wizard is given
    // a temp data directory and lands on an empty database: a first run, with
    // a password to set.
    let mut answers = first_run_answers(&data_dir);
    answers[1] = String::new(); // keep the bind the gen-config file had
    answers.extend([
        "a-long-enough-password".to_owned(),
        "a-long-enough-password".to_owned(),
    ]);
    let mut input = Cursor::new(format!("{}\n", answers.join("\n")).into_bytes());
    let mut output: Vec<u8> = Vec::new();
    run_setup(&mut input, &mut output, &config_file, false)
        .await
        .expect("a gen-config file must load in the wizard");
    let rewritten: Config =
        toml::from_str(&std::fs::read_to_string(&config_file).unwrap()).unwrap();
    assert_eq!(
        rewritten.http.payload_limit_mb,
        Config::default_config().http.payload_limit_mb,
        "a value the wizard never asks about must survive it"
    );
    assert_eq!(
        rewritten.registration.auto_app_tokens,
        Config::default_config().registration.auto_app_tokens
    );
    assert_eq!(rewritten.registration.min_password_length, 12);
    assert!(rewritten.frontend.enabled);
}

/// The config holds mail passwords in cleartext, so it must be 0600 — the same
/// protection class as the TLS key (§8.6).
#[tokio::test]
async fn test_written_config_is_private() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let data_dir = dir.path().join("data");
    let (report, _) = run(dir.path(), &first_run_answers(&data_dir)).await;

    let mode = std::fs::metadata(&report.config_file)
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600, "config mode was {mode:o}");
    let data_mode = std::fs::metadata(&data_dir).unwrap().permissions().mode() & 0o777;
    assert_eq!(data_mode, 0o700, "data directory mode was {data_mode:o}");

    // No temp file left behind by the atomic write.
    let strays: Vec<String> = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name.contains("setup-tmp"))
        .collect();
    assert!(strays.is_empty(), "{strays:?}");
}

/// No secret may reach stdout — not the typed password, not the generated RSVP
/// secret, not a mail password.
#[tokio::test]
async fn test_no_secret_reaches_stdout() {
    let dir = tempfile::tempdir().unwrap();
    let data_dir = dir.path().join("data");
    let (report, output) = run(dir.path(), &first_run_answers(&data_dir)).await;

    assert!(
        !output.contains("correct-horse-battery"),
        "the administrator password was printed:\n{output}"
    );
    let secret = toml::from_str::<Config>(&std::fs::read_to_string(&report.config_file).unwrap())
        .unwrap()
        .scheduling
        .rsvp_secret
        .unwrap();
    assert!(
        !output.contains(&secret),
        "the RSVP secret was printed:\n{output}"
    );
    assert!(
        !output.contains("smtp-password"),
        "a mail password was printed"
    );
}

/// A mail password typed at the wizard must reach the config (that is the only
/// place it can live) and nothing else.
#[tokio::test]
async fn test_smtp_password_reaches_the_config_only() {
    let dir = tempfile::tempdir().unwrap();
    let data_dir = dir.path().join("data");
    let mut answers = first_run_answers(&data_dir);
    answers[4] = "y".to_owned(); // 5. yes, configure SMTP
    // Splice the SMTP sub-prompts in after step 5's "y".
    let mut spliced = answers[..5].to_vec();
    spliced.extend(
        [
            "cal@example.com",  // from address
            "smtp.example.com", // host
            "587",              // port
            "cal@example.com",  // username
            "smtp-secret-pw",   // password
            "n",                // 6. no IMAP
        ]
        .map(str::to_owned),
    );
    spliced.extend(answers[5..].to_vec());
    answers = spliced;

    let (report, output) = run(dir.path(), &answers).await;
    let config: Config = toml::from_str(&std::fs::read_to_string(&report.config_file).unwrap())
        .expect("the config must parse");
    assert_eq!(config.scheduling.smtp.len(), 1);
    let account = &config.scheduling.smtp[0];
    assert_eq!(account.identity, "cal@example.com");
    assert_eq!(account.host, "smtp.example.com");
    assert_eq!(account.port, 587);
    assert_eq!(account.password, "smtp-secret-pw");
    assert!(
        config.scheduling.enabled,
        "an SMTP account implies scheduling"
    );
    assert!(!output.contains("smtp-secret-pw"), "{output}");
}

/// A re-run must not re-ask for a stored mail password, and keeping the
/// account must not rotate it.
#[tokio::test]
async fn test_rerun_keeps_the_smtp_account_without_asking_for_the_password() {
    let dir = tempfile::tempdir().unwrap();
    let data_dir = dir.path().join("data");

    let mut answers = first_run_answers(&data_dir);
    answers[4] = "y".to_owned();
    let mut spliced = answers[..5].to_vec();
    spliced.extend(
        [
            "cal@example.com",
            "smtp.example.com",
            "587",
            "cal@example.com",
            "smtp-secret-pw",
            "n",
        ]
        .map(str::to_owned),
    );
    spliced.extend(answers[5..].to_vec());
    let (first, _) = run(dir.path(), &spliced).await;

    // A re-run answers "keep the account" and "no, don't replace it" — two
    // extra questions, and deliberately *no* password. If the wizard asked for
    // one the scripted stdin would run dry and it would fail with "input
    // ended", which is the assertion.
    let mut rerun = rerun_answers(&data_dir);
    rerun.splice(4..4, ["".to_owned(), "n".to_owned()]);
    let (second, output) = run(dir.path(), &rerun).await;
    let config: Config =
        toml::from_str(&std::fs::read_to_string(&second.config_file).unwrap()).unwrap();
    assert_eq!(config.scheduling.smtp.len(), 1);
    assert_eq!(config.scheduling.smtp[0].password, "smtp-secret-pw");
    assert!(output.contains("Keep the 1 configured SMTP account"));
    assert_eq!(first.data_dir, second.data_dir);
}

/// An unusable answer is re-asked, and a truncated script fails loudly rather
/// than silently taking defaults.
#[tokio::test]
async fn test_bad_answers_are_re_asked_and_empty_input_fails() {
    let dir = tempfile::tempdir().unwrap();
    let data_dir = dir.path().join("data");
    let mut answers = first_run_answers(&data_dir);
    answers[0] = data_dir.to_string_lossy().into_owned();
    // An http URL with no port is exactly what `HttpBindConfig` rejects, so
    // the wizard must reject it too rather than write a config the server
    // cannot start from.
    answers[1] = "http://localhost".to_owned();
    answers.insert(2, "127.0.0.1:14001".to_owned());
    let (report, output) = run(dir.path(), &answers).await;
    assert!(
        output.contains("(1/5)"),
        "the bad address should have been rejected:\n{output}"
    );
    let config: Config =
        toml::from_str(&std::fs::read_to_string(&report.config_file).unwrap()).unwrap();
    assert_eq!(config.http.bind.as_deref(), Some("127.0.0.1:14001"));

    // A script that stops early is an error, not a config with defaults.
    let short = tempfile::tempdir().unwrap();
    let short_dir = short.path().join("data");
    let mut input = Cursor::new(b"/tmp/does-not-matter\n\n".to_vec());
    let mut output: Vec<u8> = Vec::new();
    let error = run_setup(
        &mut input,
        &mut output,
        &short.path().join("config.toml"),
        false,
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(error.contains("input ended"), "{error}");
    let _ = short_dir;
    assert!(!short.path().join("config.toml").exists());
}

/// A config file the wizard does not understand is never overwritten.
#[tokio::test]
async fn test_unparseable_existing_config_is_not_clobbered() {
    let dir = tempfile::tempdir().unwrap();
    let config_file = dir.path().join("config.toml");
    let original = "this is not a config\n";
    std::fs::write(&config_file, original).unwrap();

    let mut input = Cursor::new(Vec::new());
    let mut output: Vec<u8> = Vec::new();
    let error = run_setup(&mut input, &mut output, &config_file, false)
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("does not parse"), "{error}");
    assert_eq!(std::fs::read_to_string(&config_file).unwrap(), original);
}

/// The wizard never overwrites a password, and it offers to set one for a
/// passwordless (OIDC-only) principal rather than leaving it unusable.
#[tokio::test]
async fn test_passwordless_principal_is_offered_a_password() {
    let dir = tempfile::tempdir().unwrap();
    let data_dir = dir.path().join("data");
    let db_path = data_dir.join("db.sqlite3");

    // A database that already has an OIDC-only administrator.
    std::fs::create_dir_all(&data_dir).unwrap();
    let pool = create_db_pool(&db_path.to_string_lossy(), true)
        .await
        .unwrap();
    let store = SqlitePrincipalStore::new(pool.clone());
    store
        .insert_principal(
            rustical_store::auth::Principal {
                id: "oidc@example.com".to_owned(),
                displayname: None,
                memberships: vec![],
                password: None,
                principal_type: rustical_store::auth::PrincipalType::Individual,
                needs_password_change: false,
                privileges: Default::default(),
            },
            false,
        )
        .await
        .unwrap();
    pool.close().await;

    let mut answers = rerun_answers(&data_dir);
    answers.push("a-password-long-enough".to_owned());
    answers.push("a-password-long-enough".to_owned());
    let (report, output) = run(dir.path(), &answers).await;
    assert!(!report.admin_created);
    assert_eq!(report.admin, "oidc@example.com");
    assert!(output.contains("Password set for oidc@example.com"));
    assert!(password_hash(&db_path, "oidc@example.com").await.is_some());
}

/// The wizard reports what it decided, in a form a script can read.
#[tokio::test]
async fn test_report_and_next_steps() {
    let dir = tempfile::tempdir().unwrap();
    let data_dir = dir.path().join("data");
    let (report, output) = run(dir.path(), &first_run_answers(&data_dir)).await;

    assert_eq!(report.tls, TlsChoice::Proxy);
    assert_eq!(report.registration, RegistrationChoice::InviteOnly);
    assert_eq!(
        report.public_url.as_deref(),
        Some("https://cal.example.com")
    );
    assert_eq!(report.data_dir, data_dir);
    assert!(report.config_file.is_file());

    // The next steps have to be actionable, and must not claim a TLS setup the
    // operator did not ask for.
    assert!(output.contains("rustical --config-file"), "{output}");
    assert!(output.contains("reverse proxy"), "{output}");
    assert!(
        output.contains("https://cal.example.com/frontend"),
        "{output}"
    );
    assert!(output.contains("/.well-known/caldav"), "{output}");
    assert!(
        output.contains("will not reset"),
        "the re-run promise has to be printed, not just implemented:\n{output}"
    );
}

/// A different data directory means a different install, even over an existing
/// config — the wizard must not silently reuse the old database.
#[tokio::test]
async fn test_changing_the_data_directory_creates_a_new_install() {
    let dir = tempfile::tempdir().unwrap();
    let first_dir = dir.path().join("first");
    let second_dir = dir.path().join("second");
    let (first, _) = run(dir.path(), &first_run_answers(&first_dir)).await;
    assert!(first.db_path.is_file());

    let mut answers = rerun_answers(&first_dir);
    answers[0] = second_dir.to_string_lossy().into_owned();
    answers[7] = "second-owner@example.com".to_owned();
    answers.push("another-long-password".to_owned());
    answers.push("another-long-password".to_owned());
    let (second, _) = run(dir.path(), &answers).await;

    assert_eq!(second.data_dir, second_dir);
    assert!(second.db_path.is_file());
    assert_ne!(first.db_path, second.db_path);
    assert_eq!(
        principals(&second.db_path).await,
        ["second-owner@example.com"]
    );
    assert_eq!(
        principals(&first.db_path).await,
        ["owner@example.com"],
        "the old install must be untouched"
    );
}

/// `--config-file` is honoured, and a relative path works from any directory.
#[tokio::test]
async fn test_config_file_location_is_honoured() {
    let dir = tempfile::tempdir().unwrap();
    let data_dir = dir.path().join("data");
    let config_file = PathBuf::from(dir.path())
        .join("nested")
        .join("omnical.toml");

    let mut input =
        Cursor::new(format!("{}\n", first_run_answers(&data_dir).join("\n")).into_bytes());
    let mut output: Vec<u8> = Vec::new();
    let report = run_setup(&mut input, &mut output, &config_file, false)
        .await
        .unwrap();
    assert_eq!(report.config_file, config_file);
    assert!(config_file.is_file(), "{}", config_file.display());
}

// ── the unattended path (PLAN_DEPLOYMENTS.md §8.1, row 40) ───────────────────
//
// The Compose channel has to bring a server up with nobody at the keyboard.
// The image is `FROM scratch` (rustical/Dockerfile:44) so there is no shell to
// pipe a scripted stdin from, and `stdin_open` would leave the wizard blocked on
// a read that never ends. So the wizard itself takes the answers, and these
// tests are the gate that it does — on this host, with the real database, which
// is the part of row 40 that does not need Docker.

/// The complete unattended answer set, as `compose.omnical.yml` supplies it.
fn unattended_answers(data_dir: &Path) -> SetupAnswers {
    SetupAnswers {
        unattended: true,
        data_dir: Some(data_dir.to_string_lossy().into_owned()),
        bind: Some("0.0.0.0:4000".to_owned()),
        public_url: Some("https://cal.example.com".to_owned()),
        tls: Some("proxy".to_owned()),
        registration: Some("invite-only".to_owned()),
        admin_email: Some("owner@example.com".to_owned()),
        admin_password: Some("correct-horse-battery".to_owned()),
    }
}

/// The administrator the wizard creates must be able to sync *something*.
///
/// The wizard's third next step is "sign in as this administrator, then add a
/// client from the calendar page". Before `register::seed_collections` was
/// shared with the wizard, that promise was false: the account was created with
/// no collections at all, and the first thing a self-hoster's client did —
/// `PROPFIND /caldav/principal/<admin>/personal/` — was a 404, on an account
/// the installer had just created for them. Found by the §8.1 self-host gate
/// (`router-dav/scripts/selfhost-gate.sh`), which is why it is asserted here
/// too: the shell gate needs a release build and a server, this does not.
#[tokio::test]
async fn test_the_administrator_gets_collections() {
    let dir = tempfile::tempdir().unwrap();
    let data_dir = dir.path().join("data");
    let (report, output) = run(dir.path(), &first_run_answers(&data_dir)).await;
    assert!(report.admin_created);

    let pool = create_db_pool(&report.db_path.to_string_lossy(), false)
        .await
        .unwrap();
    let cal_store = SqliteCalendarStore::new(pool.clone(), send_channel(), true);
    let addr_store = SqliteAddressbookStore::new(pool.clone(), send_channel(), true);
    let admin = report.admin.as_str();

    for cal in ["personal", "tasks"] {
        // `get_calendars` rather than `get_calendar`: the latter returns a
        // `Calendar` and *errors* on a missing id, so "does it exist" would be
        // an `Err` to catch rather than an `Option` to read.
        let ids: Vec<String> = cal_store
            .get_calendars(admin)
            .await
            .unwrap()
            .into_iter()
            .map(|calendar| calendar.id)
            .collect();
        assert!(
            ids.contains(&cal.to_owned()),
            "the wizard created {admin} with no '{cal}' calendar (has {ids:?})"
        );
    }
    let book_ids: Vec<String> = addr_store
        .get_addressbooks(admin)
        .await
        .unwrap()
        .into_iter()
        .map(|book| book.id)
        .collect();
    assert!(
        book_ids.contains(&"personal".to_owned()),
        "the wizard created {admin} with no 'personal' addressbook (has {book_ids:?})"
    );

    // Not empty either: a first sync that returns nothing looks identical to a
    // broken server, and this is the first sync a self-hoster ever sees.
    let objects = cal_store.get_objects(admin, "personal").await.unwrap();
    assert!(
        !objects.is_empty(),
        "the seeded 'personal' calendar is empty"
    );
    assert!(
        objects
            .iter()
            .any(|(_id, object)| object.get_ics().contains("SUMMARY:Welcome")),
        "no welcome object among {}",
        objects.len()
    );
    pool.close().await;

    // …and it is said out loud, because "3. add a client" is only true if the
    // collections exist.
    assert!(
        output.contains("'personal' calendar"),
        "the wizard does not report the collections it created:\n{output}"
    );
}

fn send_channel() -> tokio::sync::mpsc::Sender<CollectionOperation> {
    let (send, _recv) = tokio::sync::mpsc::channel(1000);
    send
}

/// An unattended run on an **empty stdin**, which is the whole point: a
/// container's stdin is either closed or a socket nobody writes to.
#[tokio::test]
async fn test_unattended_needs_no_stdin_at_all() {
    let dir = tempfile::tempdir().unwrap();
    let data_dir = dir.path().join("data");
    let answers = unattended_answers(&data_dir);
    let mut input = Cursor::new(Vec::new());
    let mut output: Vec<u8> = Vec::new();
    let config_file = dir.path().join("config.toml");

    let report = run_setup_with(&mut input, &mut output, &config_file, false, &answers)
        .await
        .expect("an unattended run must complete with nothing on stdin");
    let printed = String::from_utf8(output).unwrap();

    assert!(report.unattended);
    assert!(report.admin_created);
    assert_eq!(report.admin, "owner@example.com");
    assert_eq!(report.tls, TlsChoice::Proxy);
    assert_eq!(report.registration, RegistrationChoice::InviteOnly);
    assert_eq!(report.data_dir, data_dir);
    assert!(report.db_path.is_file(), "{}", report.db_path.display());
    assert_eq!(principals(&report.db_path).await, ["owner@example.com"]);
    assert!(
        password_hash(&report.db_path, "owner@example.com")
            .await
            .is_some()
    );
    assert!(
        printed.contains("Unattended"),
        "a container log is the only place the operator can see how the config was \
         decided: {printed}"
    );

    // Same guarantees as the interactive path, or it is not the same command.
    assert_eq!(report.config_file, config_file);
    let mode = std::fs::metadata(&config_file)
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600, "the config holds secrets; mode was {mode:o}");
}

/// A missing answer is a **loud failure**, not a default. This is the test that
/// makes the unattended path safe to hand to a provisioning system: the failure
/// mode of a typo is a stopped container with a legible reason.
#[tokio::test]
async fn test_unattended_missing_answer_is_an_error_not_a_default() {
    let dir = tempfile::tempdir().unwrap();
    let mut answers = unattended_answers(&dir.path().join("data"));
    answers.tls = None;
    let mut input = Cursor::new(Vec::new());
    let mut output: Vec<u8> = Vec::new();

    let error = run_setup_with(
        &mut input,
        &mut output,
        &dir.path().join("config.toml"),
        false,
        &answers,
    )
    .await
    .unwrap_err()
    .to_string();

    assert!(
        error.contains("unattended setup needs an answer"),
        "{error}"
    );
    assert!(error.contains("OMNICAL_SETUP_TLS"), "{error}");
    assert!(
        !dir.path().join("config.toml").exists(),
        "a run that could not answer everything must not leave a half-written config"
    );
}

/// The unattended path is a re-run, not a first-run-only code path: it must
/// behave exactly like the interactive re-run against a live install.
#[tokio::test]
async fn test_unattended_rerun_preserves_everything() {
    let dir = tempfile::tempdir().unwrap();
    let data_dir = dir.path().join("data");
    let config_file = dir.path().join("config.toml");
    let answers = unattended_answers(&data_dir);

    let first = run_setup_with(
        &mut Cursor::new(Vec::new()),
        &mut Vec::new(),
        &config_file,
        false,
        &answers,
    )
    .await
    .unwrap();
    let hash_after_first = password_hash(&first.db_path, "owner@example.com").await;

    // The password is removed from the environment, exactly as the compose
    // comment tells an operator to do after the first run. A re-run that needed
    // it would make that instruction a lie.
    let rerun = SetupAnswers {
        admin_password: None,
        ..answers.clone()
    };
    let second = run_setup_with(
        &mut Cursor::new(Vec::new()),
        &mut Vec::new(),
        &config_file,
        false,
        &rerun,
    )
    .await
    .expect("a re-run must not need the administrator password");

    assert!(!second.admin_created, "a re-run must not create anything");
    assert!(
        !second.rsvp_secret_generated,
        "the RSVP secret must be kept"
    );
    assert_eq!(principals(&second.db_path).await, ["owner@example.com"]);
    assert_eq!(
        password_hash(&second.db_path, "owner@example.com").await,
        hash_after_first,
        "a re-run must never reset the administrator's password"
    );
}

/// An unattended run changes the answers it was given — a public URL, a bind, a
/// registration mode — and leaves the ones it was not given alone.
#[tokio::test]
async fn test_unattended_applies_its_answers_to_the_config() {
    let dir = tempfile::tempdir().unwrap();
    let data_dir = dir.path().join("data");
    let config_file = dir.path().join("config.toml");
    let answers = unattended_answers(&data_dir);
    let report = run_setup_with(
        &mut Cursor::new(Vec::new()),
        &mut Vec::new(),
        &config_file,
        false,
        &answers,
    )
    .await
    .unwrap();

    // Loading it back through the production config type is the real assertion:
    // it proves `deny_unknown_fields` is happy with what the wizard wrote
    // (§8.3's gate, row 45) and lets us read the values back.
    let text = std::fs::read_to_string(&report.config_file).unwrap();
    let config: Config = toml::from_str(&text).expect("the written config must load");

    assert_eq!(
        config.sqlite_db_path().as_deref(),
        Some(report.db_path.as_path()),
        "the config's db_url and the database the wizard actually opened must be \
         the same file — this is the one that silently creates two installs"
    );
    assert_eq!(config.http.bind.as_deref(), Some("0.0.0.0:4000"));
    assert!(
        config.subscriptions.enabled,
        "a public URL means the share feeds are worth mounting"
    );
    assert_eq!(
        config.subscriptions.public_url.as_deref(),
        Some("https://cal.example.com")
    );
    assert!(config.registration.enabled);
    assert!(config.registration.invite_required);
    assert!(!config.scheduling.enabled, "no mail was configured");
}

/// An unattended run is a *provisioning* surface, so the one answer it must
/// never take is a mail password: that value ends up in a config file which
/// ends up in a volume, a CI log or an `inspect` output.
#[tokio::test]
async fn test_unattended_never_configures_mail_but_keeps_it() {
    let dir = tempfile::tempdir().unwrap();
    let data_dir = dir.path().join("data");
    let config_file = dir.path().join("config.toml");
    let mut output: Vec<u8> = Vec::new();

    // First, an interactive run *with* SMTP, as today. The five SMTP answers
    // have to be spliced in at the point the wizard asks them — which is
    // immediately after the yes/no, and *before* the IMAP question (§18.6 burn
    // scar 1: the answer script is a contract).
    let mut smtp_answers = first_run_answers(&data_dir);
    smtp_answers.splice(
        5..5,
        [
            "owner@example.com", // from address
            "smtp.example.com",  // host
            "587",               // port
            "owner@example.com", // username
            "smtp-password",     // password
        ]
        .iter()
        .map(|s| (*s).to_owned()),
    );
    smtp_answers[4] = "y".to_owned(); // send invitations over SMTP?
    let interactive = run(dir.path(), &smtp_answers).await;
    assert!(interactive.0.config_file.is_file());

    // Now an unattended re-run over the same config, with no mail answers
    // offered at all. The account must survive untouched.
    let answers = unattended_answers(&data_dir);
    let report = run_setup_with(
        &mut Cursor::new(Vec::new()),
        &mut output,
        &config_file,
        false,
        &answers,
    )
    .await
    .expect("an unattended re-run must not be blocked by existing mail config");

    let text = std::fs::read_to_string(&report.config_file).unwrap();
    let config: Config = toml::from_str(&text).unwrap();
    assert_eq!(
        config.scheduling.smtp.len(),
        1,
        "an unattended run must not silently drop a configured mail account: \
         losing SMTP breaks every invitation with no visible cause"
    );
    assert_eq!(config.scheduling.smtp[0].host, "smtp.example.com");
    assert!(config.scheduling.enabled);

    let printed = String::from_utf8(output).unwrap();
    assert!(
        printed.contains("never reads or writes a mail password"),
        "and it must say so: {printed}"
    );
}

/// A fresh unattended install with no public URL is legitimate — the proxy is
/// not configured yet. The share feeds stay off, and the re-run does not clear
/// a public URL an earlier run had set.
#[tokio::test]
async fn test_unattended_public_url_sets_or_keeps_never_clears() {
    let dir = tempfile::tempdir().unwrap();
    let data_dir = dir.path().join("data");
    let config_file = dir.path().join("config.toml");

    // No public URL at all on the first run.
    let answers = SetupAnswers {
        public_url: None,
        ..unattended_answers(&data_dir)
    };
    let first = run_setup_with(
        &mut Cursor::new(Vec::new()),
        &mut Vec::new(),
        &config_file,
        false,
        &answers,
    )
    .await
    .unwrap();
    assert_eq!(first.public_url, None);
    let text = std::fs::read_to_string(&config_file).unwrap();
    let config: Config = toml::from_str(&text).unwrap();
    assert_eq!(config.subscriptions.public_url, None);
    assert!(!config.subscriptions.enabled);

    // Then the proxy exists and the operator sets it.
    let with_url = unattended_answers(&data_dir);
    run_setup_with(
        &mut Cursor::new(Vec::new()),
        &mut Vec::new(),
        &config_file,
        false,
        &with_url,
    )
    .await
    .unwrap();
    let text = std::fs::read_to_string(&config_file).unwrap();
    let config: Config = toml::from_str(&text).unwrap();
    assert_eq!(
        config.subscriptions.public_url.as_deref(),
        Some("https://cal.example.com")
    );

    // Then the variable is dropped from the environment — an operator tidying
    // up, or a compose file whose default changed. The public URL must survive,
    // because a provisioning run is the wrong place to lose a working hostname.
    let without_url = SetupAnswers {
        public_url: None,
        ..unattended_answers(&data_dir)
    };
    let third = run_setup_with(
        &mut Cursor::new(Vec::new()),
        &mut Vec::new(),
        &config_file,
        false,
        &without_url,
    )
    .await
    .unwrap();
    assert_eq!(
        third.public_url.as_deref(),
        Some("https://cal.example.com"),
        "an unattended run may set or keep the public URL, never clear it"
    );
}

/// A password supplied by a provisioning system is still a password: the same
/// floor, or the unattended path is a way to create a weak administrator.
#[tokio::test]
async fn test_unattended_password_still_obeys_the_floor() {
    let dir = tempfile::tempdir().unwrap();
    let answers = SetupAnswers {
        admin_password: Some("short".to_owned()),
        ..unattended_answers(&dir.path().join("data"))
    };
    let error = run_setup_with(
        &mut Cursor::new(Vec::new()),
        &mut Vec::new(),
        &dir.path().join("config.toml"),
        false,
        &answers,
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(error.contains("too short"), "{error}");

    // The unit test in setup.rs covers the branch directly; this one proves the
    // error escapes the whole wizard having already done real work. Note the
    // config *is* written by then — the wizard writes it before it touches the
    // database on purpose, so a re-run is the fix for a failed one. What must
    // not exist is the administrator.
    let db_path = dir.path().join("data").join("db.sqlite3");
    assert!(
        db_path.exists(),
        "the wizard got as far as the database before the password check"
    );
    assert!(
        principals(&db_path).await.is_empty(),
        "a rejected password must not leave an account behind"
    );
}
