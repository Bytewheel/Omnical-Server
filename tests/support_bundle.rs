//! Row 50, which is the gate and also the feature.
//!
//! §9.4: *"`rustical` support bundle → `grep` for every SMTP password and the
//! RSVP secret → **no matches**."* And §9.4 calls this bundle "the single
//! highest-leverage support feature in this whole plan", so a gate that passes
//! vacuously would be worse than no gate: it would be read as the credential
//! risk being handled.
//!
//! So most of this file is adversarial. It plants a secret with a shape chosen
//! to defeat a naive implementation and then checks it is gone.

use std::path::PathBuf;

use rustical::commands::support_bundle::{
    REDACTED, build_bundle_text_for_test, cmd_support_bundle,
};

/// A config with one secret of every kind the gate names, plus several it does
/// not.
fn config_with_secrets() -> (rustical::config::Config, String) {
    let dir = std::env::temp_dir();
    let smtp_pw = "Smtp-Passw0rd!x9";
    let imap_pw = "Imap-Passw0rd!x9";
    let rsvp = "rsvp-hmac-4f2a9c1e7b";
    let config_file = dir.join(format!("omnical-sb-{}.toml", std::process::id()));
    let raw = format!(
        r#"[data_store]
[data_store.sqlite]
db_url = "file:/usr/local/share/rustical/db.sqlite3"

[http]
bind = "127.0.0.1:4000"

[scheduling]
enabled = true
rsvp_secret = "{rsvp}"

[[scheduling.smtp]]
identity = "alerts@customer.example"
host = "smtp.customer.example"
port = 587
username = "alerts@customer.example"
password = "{smtp_pw}"

[[scheduling.imap]]
identity = "alerts@customer.example"
host = "imap.customer.example"
port = 993
username = "alerts@customer.example"
password = "{imap_pw}"

"#
    );
    std::fs::write(&config_file, &raw).unwrap();
    let config: rustical::config::Config = toml::from_str(&raw).expect("the fixture parses");
    (config, config_file.display().to_string())
}

struct Cleanup(PathBuf);
impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// A `Config` for a fixture that may contain sections this build has never heard of.
///
/// The adversarial fixtures invent `[auth]`, `[some_future_section]` and similar,
/// and this build is `deny_unknown_fields` (§18.14: "a config key that is accepted
/// and does nothing is worse than a missing one"). So a whole-config parse
/// rejects them, which is correct and not what this file is about.
///
/// The fix is not to weaken `Config`. It is to keep the invented sections **out**
/// of the typed parse and let them reach the redaction through the raw-text
/// path, which is the path under test: the key-shape pass must redact a field
/// the typed config has never seen, and that is exactly what a lenient parse
/// would prevent us from checking.
fn bundle_for(raw: &str) -> String {
    let config = config_from_real_sections_only(raw);
    build_bundle_text_for_test(&config, raw, Some("fake health line")).expect("the bundle builds")
}

/// Parse only the sections this build knows, dropping invented ones.
///
/// Section state is tracked rather than filtered per line, so a known section
/// appearing *after* an invented one is still included — a naive "drop every
/// line under an unknown header" would silently discard a real `[http]` block
/// that happened to follow, and the bundle would quietly stop reporting the
/// bind address.
fn config_from_real_sections_only(raw: &str) -> rustical::config::Config {
    // `data_store` is a required field, so a fixture that is only a
    // `[scheduling]` fragment cannot parse on its own. Prepended only when the
    // fixture does not already have one — otherwise `[data_store.sqlite]` appears
    // twice and TOML reports a duplicate key, which is a fixture bug that looks
    // exactly like a redaction bug.
    let raw = if raw.contains("[data_store") {
        raw.to_owned()
    } else {
        format!("[data_store]\n[data_store.sqlite]\ndb_url = \"file:/tmp/x.sqlite3\"\n\n{raw}")
    };
    let raw = raw.as_str();
    let mut kept = String::new();
    let mut in_unknown = false;
    for line in raw.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with('[') {
            in_unknown = !is_real_section(trimmed);
        }
        if !in_unknown {
            kept.push_str(line);
            kept.push('\n');
        }
    }
    toml::from_str(&kept).unwrap_or_else(|e| {
        panic!("the known sections must parse as a config: {e}\n--- kept ---\n{kept}")
    })
}

/// Sections this build's `Config` actually has. Anything else in a fixture is
/// the redaction's problem, not the parser's.
fn is_real_section(line: &str) -> bool {
    const REAL: &[&str] = &[
        "[data_store]",
        "[data_store.sqlite]",
        "[http]",
        "[scheduling]",
        "[[scheduling.smtp]]",
        "[[scheduling.imap]]",
        "[registration]",
        "[subscriptions]",
        "[tenancy]",
        "[dav_push]",
        "[tracing]",
        "[oidc]",
    ];
    REAL.iter().any(|r| line.starts_with(r))
        // `[tenancy.foo]` and other sub-tables of a real section.
        || (line.starts_with('[')
            && !line.starts_with("[[")
            && REAL.iter().any(|r| line.starts_with(&r[..r.len() - 1])))
}

#[test]
fn no_smtp_password_survives() {
    let raw = r#"
[[scheduling.smtp]]
identity = "a@example.com"
host = "smtp.example.com"
port = 587
username = "a@example.com"
password = "Smtp-Secret-AAA111"
"#;
    let bundle = bundle_for(raw);
    assert!(
        !bundle.contains("Smtp-Secret-AAA111"),
        "the SMTP password is in the bundle:\n{bundle}"
    );
    assert!(
        bundle.contains(REDACTED),
        "nothing was redacted at all:\n{bundle}"
    );
}

#[test]
fn no_rsvp_secret_survives() {
    let raw = r#"
[scheduling]
rsvp_secret = "rsvp-Secret-BBB222"
"#;
    let bundle = bundle_for(raw);
    assert!(
        !bundle.contains("rsvp-Secret-BBB222"),
        "the RSVP secret is in the bundle:\n{bundle}"
    );
}

#[test]
fn no_imap_password_survives() {
    let raw = r#"
[[scheduling.imap]]
identity = "a@example.com"
host = "imap.example.com"
port = 993
username = "a@example.com"
password = "Imap-Secret-CCC333"
"#;
    let bundle = bundle_for(raw);
    assert!(!bundle.contains("Imap-Secret-CCC333"), "{bundle}");
}

#[test]
fn a_secret_this_build_does_not_know_about_is_still_redacted() {
    // The important one. The gate names two secret kinds; a config written by a
    // later version, or by hand, will have more. Key-shape redaction is what
    // makes row 50 keep meaning something after this release.
    let raw = r#"
[some_future_section]
api_token = "tok-Secret-DDD444"
client_secret = "sec-Secret-EEE555"
webhook_key = "key-Secret-FFF666"
"#;
    let bundle = bundle_for(raw);
    for secret in [
        "tok-Secret-DDD444",
        "sec-Secret-EEE555",
        "key-Secret-FFF666",
    ] {
        assert!(!bundle.contains(secret), "{secret} survived:\n{bundle}");
    }
}

#[test]
fn a_secret_that_appears_in_more_than_one_place_is_removed_from_all_of_them() {
    // Replacement, not just deletion of one line. The SMTP password also
    // appears in a comment and in a second account, and a bundle that redacts
    // only the first occurrence is a bundle with the password in it.
    let raw = r#"
# the old password was Smtp-Secret-GGG777 before the rotation
[[scheduling.smtp]]
identity = "a@example.com"
host = "smtp.example.com"
port = 587
username = "a@example.com"
password = "Smtp-Secret-GGG777"

[[scheduling.smtp]]
identity = "b@example.com"
host = "smtp2.example.com"
port = 587
username = "b@example.com"
password = "Smtp-Secret-GGG777"
"#;
    let bundle = bundle_for(raw);
    assert_eq!(
        bundle.matches("Smtp-Secret-GGG777").count(),
        0,
        "the password appears {} times in the bundle:\n{bundle}",
        bundle.matches("Smtp-Secret-GGG777").count()
    );
}

#[test]
fn a_one_character_secret_is_still_redacted() {
    // The degenerate case. A naive "only redact values longer than N" guard —
    // which is a real temptation, to avoid shredding the whole file on a short
    // match — would leave this one in.
    let raw = r#"
[auth]
token = "7"
"#;
    let bundle = bundle_for(raw);
    assert!(
        !bundle.contains("token = \"7\"") && !bundle.contains("\"7\""),
        "a one-character secret survived, which means a length guard exists:\n{bundle}"
    );
}

#[test]
fn a_secret_containing_another_secret_is_removed_whole() {
    // Longest-first replacement. Redacting the short one first would leave the
    // tail of the long one behind — which is enough to authenticate with, since
    // the tail is usually the part that varies.
    let raw = r#"
[auth]
secret = "hunter2"
api_token = "hunter2-extra-tail-9999"
"#;
    let bundle = bundle_for(raw);
    assert!(
        !bundle.contains("hunter2"),
        "the short secret survived:\n{bundle}"
    );
    assert!(
        !bundle.contains("hunter2-extra-tail-9999"),
        "the long secret survived:\n{bundle}"
    );
    assert!(
        !bundle.contains("extra-tail-9999"),
        "a tail survived:\n{bundle}"
    );
}

#[test]
fn paths_and_urls_are_not_mistaken_for_credentials() {
    // The other failure direction, and the one that would make the bundle
    // useless. `db_url`, `ca_file` and a `key = "/etc/ssl/private/x.pem"` are
    // exactly the lines a support engineer needs, and a redactor that cannot
    // tell a secret from a path produces a bundle that answers no questions.
    let raw = r#"
[some_other_store]
db_url = "file:/usr/local/share/rustical/db.sqlite3"
ca_file = "/etc/rustical/certs/imap.pem"
key_file = "/etc/rustical/tls/key.pem"
"#;
    let bundle = bundle_for(raw);
    assert!(
        bundle.contains("/usr/local/share/rustical/db.sqlite3"),
        "the database path was redacted, which makes the bundle useless:\n{bundle}"
    );
    assert!(bundle.contains("/etc/rustical/certs/imap.pem"), "{bundle}");
}

#[test]
fn every_occurrence_of_a_secret_is_removed_not_just_the_first() {
    // The single most common redaction bug, and the one `replace` gets right for
    // free — which is exactly why it needed a test: a mutation that replaced
    // only the first occurrence passed the whole suite, because the other
    // multi-occurrence fixture happened to have its repeats on lines the
    // key-shape pass had already rewritten.
    //
    // Pinned directly: a secret repeated on three lines, where only the middle
    // one is a credential-looking field, so the key-shape pass cannot be what
    // removes it.
    let raw = r#"
[[scheduling.smtp]]
identity = "a@example.com"
host = "smtp.example.com"
port = 587
username = "a@example.com"
password = "Repeat-Me-9999"

# a comment that repeats it: Repeat-Me-9999

[unrelated]
note = "and again: Repeat-Me-9999"
"#;
    let bundle = bundle_for(raw);
    assert_eq!(
        bundle.matches("Repeat-Me-9999").count(),
        0,
        "{} occurrence(s) survived:\n{bundle}",
        bundle.matches("Repeat-Me-9999").count()
    );
}

#[test]
fn a_path_is_not_redacted_even_though_its_key_looks_like_a_credential() {
    // The over-redaction direction, pinned at the *value* level rather than
    // through `contains`. A mutation that dropped the "looks like a reference"
    // guard passed the earlier version of this test, because the fixture's
    // fields were all named `db_url`/`ca_file` — and the key-shape pass skips
    // `ca_file` and `db_url` on key grounds alone, so the guard was never
    // exercised.
    //
    // `key` is a key shape the pass claims, and this value is a path. Without the
    // reference guard the whole line goes, and the bundle stops naming the
    // certificate — which is usually the thing being asked about.
    let raw = r#"
[tls]
key = "/etc/rustical/tls/privkey.pem"
cert = "/etc/rustical/tls/fullchain.pem"
key_password = "/etc/rustical/tls/notes.txt"
"#;
    let bundle = bundle_for(raw);
    assert!(
        bundle.contains("/etc/rustical/tls/privkey.pem"),
        "a key path was redacted, which makes the bundle useless:\n{bundle}"
    );
    assert!(
        bundle.contains("/etc/rustical/tls/fullchain.pem"),
        "{bundle}"
    );
    // …and a `key_password` whose value is a path is *also* left alone, because
    // the value is a reference. That is the same guard, stated twice, because
    // the two field names are the ones an operator actually writes.
    assert!(bundle.contains("/etc/rustical/tls/notes.txt"), "{bundle}");
}

#[test]
fn the_bundle_names_what_it_redacted_without_naming_the_values() {
    // §9.4's value is that a support engineer can see the *shape* of the
    // problem. But the reason list must not become a second copy of the
    // secrets.
    let raw = r#"
[[scheduling.smtp]]
identity = "a@example.com"
host = "smtp.example.com"
port = 587
username = "a@example.com"
password = "Smtp-Secret-HHH888"
"#;
    let bundle = bundle_for(raw);
    assert!(
        bundle.contains("SMTP password"),
        "no reason given:\n{bundle}"
    );
    assert!(!bundle.contains("Smtp-Secret-HHH888"));
}

#[tokio::test]
async fn redaction_fails_loudly_rather_than_writing_a_bundle_with_a_secret() {
    // The property that makes this a gate rather than a hope: if redaction ever
    // fails to remove a secret, the command must write **nothing**. A bundle
    // that exists and is then discovered to contain a password is already the
    // incident, and by then it has been attached to something.
    let config: rustical::config::Config = config_from_real_sections_only(
        r#"
[[scheduling.smtp]]
identity = "a@example.com"
host = "smtp.example.com"
port = 587
username = "a@example.com"
password = "Smtp-Secret-III999"
"#,
    );
    let out = std::env::temp_dir().join(format!("omnical-sb-fail-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&out);
    let result = cmd_support_bundle(
        config,
        std::path::Path::new("/nonexistent/config.toml"),
        rustical::commands::support_bundle::SupportBundleArgs {
            out_dir: Some(out.clone()),
            no_config: false,
            stdout: false,
        },
    )
    .await;
    assert!(
        result.is_err(),
        "a missing config must not produce a bundle"
    );
    let written: Vec<_> = std::fs::read_dir(&out)
        .map(|d| d.filter_map(Result::ok).collect())
        .unwrap_or_default();
    assert!(
        written.is_empty(),
        "the failed run wrote {:?}",
        written.iter().map(|e| e.path()).collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn a_real_config_produces_a_bundle_with_no_secret() {
    // End to end through the command, with the gate's own greps.
    let (config, path) = config_with_secrets();
    let _guard = Cleanup(PathBuf::from(&path));
    let dir = std::env::temp_dir().join(format!("omnical-sb-out-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);

    cmd_support_bundle(
        config,
        std::path::Path::new(&path),
        rustical::commands::support_bundle::SupportBundleArgs {
            out_dir: Some(dir.clone()),
            no_config: false,
            stdout: false,
        },
    )
    .await
    .expect("the bundle is written");

    let written: Vec<_> = std::fs::read_dir(&dir)
        .expect("the output directory")
        .filter_map(Result::ok)
        .collect();
    assert_eq!(written.len(), 1, "expected exactly one bundle file");
    let body = std::fs::read_to_string(written[0].path()).expect("the bundle is readable");

    for secret in [
        "Smtp-Passw0rd!x9",
        "Imap-Passw0rd!x9",
        "rsvp-hmac-4f2a9c1e7b",
    ] {
        assert!(
            !body.contains(secret),
            "row 50 violated: {secret} is in the bundle:\n{body}"
        );
    }
    // …and the non-secret parts are still there, or the bundle is useless.
    assert!(body.contains("smtp.customer.example"), "{body}");
    assert!(body.contains("127.0.0.1:4000"), "{body}");

    let _ = std::fs::remove_dir_all(&dir);
}
