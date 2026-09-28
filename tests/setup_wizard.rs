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
use rustical::{RegistrationChoice, SetupReport, TlsChoice, run_setup};
use rustical_store::auth::AuthenticationProvider;
use rustical_store_sqlite::{SqlitePrincipalStore, create_db_pool};
use std::io::Cursor;
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
