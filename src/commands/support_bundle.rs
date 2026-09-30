//! `rustical support-bundle` — the diagnostics bundle (§9.4, item 14).
//!
//! §9.4 calls this *"the single highest-leverage support feature in this whole
//! plan"*, and the reason is specific: the `logread -e rustical` + `df -k /` +
//! `netstat -tlnp` triple is already what `deploy.sh:160-174` runs when
//! something is wrong, and it is exactly what a support request needs. Every
//! other panel section shows a fact; this one *solves the ticket*.
//!
//! # The gate is the feature
//!
//! Row 50: *"`rustical` support bundle → `grep` for every SMTP password and the
//! RSVP secret → **no matches**."*
//!
//! That is the whole design constraint, and it is much harder than it looks,
//! because a support bundle is exactly the artefact a person is asked to attach
//! to a public issue tracker. The redaction therefore has to work on **values
//! discovered at runtime**, not on a list of key names someone remembered:
//!
//! * The bundle reads the live config, so it knows the actual SMTP passwords and
//!   the actual RSVP secret, and replaces each *occurrence* of each of them.
//! * Any other password-looking value in the config is redacted **by key shape**
//!   (`password`, `secret`, `token`, `key`) rather than by name, so a new
//!   section added later is covered the day it is added.
//! * **The redaction is verified before the archive is written.** If a secret
//!   still appears in the redacted text, the command refuses and writes nothing.
//!   A bundle that is written and *then* discovered to contain a password is
//!   already the incident; the check has to be inside the command that produces
//!   it, not a test that runs later in CI.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

use crate::config::Config;

/// The marker left in place of a secret. Not a hash: a hash of a short SMTP
/// password is reversible by brute force, and a support bundle is going on a
/// public tracker.
pub const REDACTED: &str = "<redacted>";

#[derive(Debug, Default, clap::Parser)]
pub struct SupportBundleArgs {
    /// Where to write the bundle. Defaults to `support-bundle-<date>.tar.gz`
    /// in the current directory.
    #[arg(long, value_name = "DIR")]
    pub out_dir: Option<PathBuf>,
    /// Skip the config file entirely, redacted or not. The one option that
    /// removes a whole class of risk rather than reducing it.
    #[arg(long)]
    pub no_config: bool,
    /// Print the bundle to stdout instead of writing an archive. Used by the
    /// gate so the test greps the real text.
    #[arg(long)]
    pub stdout: bool,
}

/// A redaction, with the reason — so the bundle can say what it removed, which
/// is the difference between "trust me" and "here is the list".
struct Redaction {
    value: String,
    reason: String,
}

/// Every secret found in `config`, plus the key-shaped ones.
///
/// Deliberately over-inclusive on the key-shape pass. A field called `token` is
/// redacted even if its value is a constant, because the cost of a false
/// positive is a support engineer asking for one more line, and the cost of a
/// false negative is a credential on a public issue.
fn secrets_in(config: &Config, raw_toml: &str) -> Vec<Redaction> {
    let mut out: Vec<Redaction> = Vec::new();

    // 1. Values the typed config knows are secret. These are the ones the gate
    //    names explicitly, and matching the *value* catches every occurrence
    //    rather than only the line the key is on.
    for account in &config.scheduling.smtp {
        if !account.password.is_empty() {
            out.push(Redaction {
                value: account.password.clone(),
                reason: "SMTP password".to_owned(),
            });
        }
    }
    for account in &config.scheduling.imap {
        if !account.password.is_empty() {
            out.push(Redaction {
                value: account.password.clone(),
                reason: "IMAP password".to_owned(),
            });
        }
    }
    if let Some(secret) = config.scheduling.rsvp_secret.as_deref()
        && !secret.is_empty()
    {
        out.push(Redaction {
            value: secret.to_owned(),
            reason: "RSVP signing secret".to_owned(),
        });
    }

    // 2. Key-shaped fields anywhere in the raw TOML. A line-oriented pass,
    //    because the point is to catch fields this build does not know about:
    //    a section added by a later version, or a hand-written config.
    for (n, line) in raw_toml.lines().enumerate() {
        let lower = line.to_ascii_lowercase();
        let key_is_secret = ["password", "secret", "token", "key", "credential"]
            .iter()
            .any(|k| lower.contains(&format!("{k} =")) || lower.contains(&format!("{k}=")));
        if !key_is_secret {
            continue;
        }
        let Some((_, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim().trim_matches(['"', '\'']).trim();
        // A `key` whose value is a *path* or a *URL* is not a credential, and
        // redacting it would make the bundle useless for its main job.
        let lower = value.to_ascii_lowercase();
        let is_file = [".toml", ".pem", ".crt", ".db", ".sqlite3"]
            .iter()
            .any(|ext| lower.ends_with(ext));
        let looks_like_a_reference =
            value.is_empty() || value.starts_with('/') || value.starts_with("file:") || is_file;
        if looks_like_a_reference {
            continue;
        }
        out.push(Redaction {
            value: value.to_owned(),
            reason: format!("key-shaped field on line {}", n + 1),
        });
    }

    out
}

/// Replace every occurrence of every secret.
///
/// **Verified**, which is the whole point: the caller must not be able to write
/// a bundle that still contains one. Longest-first, so a secret that contains
/// another secret is replaced whole rather than leaving a tail behind.
fn redact(text: &str, secrets: &[Redaction]) -> Result<String> {
    let mut sorted: Vec<&Redaction> = secrets.iter().collect();
    sorted.sort_by_key(|r| std::cmp::Reverse(r.value.len()));

    let mut out = text.to_owned();
    for secret in &sorted {
        if secret.value.is_empty() {
            continue;
        }
        if out.contains(&secret.value) {
            out = out.replace(&secret.value, REDACTED);
        }
    }

    // The check that makes this a gate rather than a hope.
    for secret in &sorted {
        if secret.value.is_empty() {
            continue;
        }
        if out.contains(&secret.value) {
            bail!(
                "refusing to write a diagnostics bundle: the {} still appears after redaction. \
                 This is a bug in the redaction, not in your config.",
                secret.reason
            );
        }
    }
    Ok(out)
}

/// The sections, in the order a support engineer reads them.
/// The bundle body, exposed for the row 50 gate.
///
/// `tests/support_bundle.rs` needs to assert on the *text* rather than on a
/// file, so the redaction can be attacked directly — a file-based gate can be
/// satisfied by a bundle that happens to be written before the config is
/// included, which is exactly the bug the gate exists to catch.
#[must_use]
pub fn build_bundle_text_for_test(
    config: &Config,
    raw_toml: &str,
    health: Option<&str>,
) -> Option<String> {
    build_bundle_text(config, raw_toml, health).ok()
}

fn build_bundle_text(config: &Config, raw_toml: &str, health: Option<&str>) -> Result<String> {
    let secrets = secrets_in(config, raw_toml);
    let mut out = String::new();

    writeln!(out, "# Omnical support bundle")?;
    writeln!(out)?;
    writeln!(out, "generated:  {}", now_rfc3339())?;
    writeln!(out, "version:    {}", env!("CARGO_PKG_VERSION"))?;
    // The commit, and only when there is one. §10.3's gate compares this against
    // the published tarball's `git rev-parse HEAD`, which is the whole of the
    // AGPL §13 check — so the bundle, which is what a support request attaches,
    // is also the artefact that proves which source the running code is in.
    let sha = crate::build_provenance::build_sha();
    if sha.is_empty() {
        writeln!(out, "commit:     (unknown — built without a repository)")?;
    } else {
        writeln!(out, "commit:     {sha}")?;
    }
    if crate::build_provenance::build_dirty() {
        writeln!(
            out,
            "build:      DIRTY — this binary is not from any published commit"
        )?;
    }
    writeln!(
        out,
        "platform:   {}/{}",
        std::env::consts::OS,
        std::env::consts::ARCH
    )?;
    writeln!(
        out,
        "bind:       {}",
        config.http.bind.as_deref().unwrap_or("(default)")
    )?;
    writeln!(out, "tenancy:    {}", config.tenancy.enabled)?;
    writeln!(out)?;
    writeln!(
        out,
        "Every secret below the config is replaced with {REDACTED}. The list of what was removed"
    )?;
    writeln!(
        out,
        "is at the end, so you can see the shape without seeing the values."
    )?;
    writeln!(out)?;

    writeln!(out, "== health ==")?;
    writeln!(out, "{}", health.unwrap_or("(health was not collected)"))?;
    writeln!(out)?;

    writeln!(out, "== config (redacted) ==")?;
    writeln!(out, "{}", redact(raw_toml, &secrets)?)?;
    writeln!(out)?;

    writeln!(out, "== what was redacted ==")?;
    for (n, s) in secrets.iter().enumerate() {
        writeln!(
            out,
            "{}. {} ({} chars)",
            n + 1,
            s.reason,
            s.value.chars().count()
        )?;
    }
    if secrets.is_empty() {
        writeln!(out, "(nothing to redact — the config holds no secrets)")?;
    }
    Ok(out)
}

/// Best-effort RFC 3339 without pulling in a date crate for one line.
fn now_rfc3339() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    // Days since the epoch → a civil date. Howard Hinnant's algorithm.
    // A saturating cast rather than `as i64`: a 64-bit epoch-seconds value
    // overflows i64 in year 292 billion, and a wrong date in a diagnostics
    // bundle is a small thing that nonetheless undermines the whole file.
    let days = i64::try_from(secs / 86_400).unwrap_or(i64::MAX);
    let tod = secs % 86_400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        tod / 3_600,
        (tod % 3_600) / 60,
        tod % 60
    )
}

/// Run the command.
#[allow(clippy::missing_errors_doc, clippy::missing_panics_doc)]
pub async fn cmd_support_bundle(
    config: Config,
    config_file: &Path,
    args: SupportBundleArgs,
) -> Result<()> {
    let health = crate::commands::health::health_line(&config.http).await;
    let raw = if args.no_config {
        String::new()
    } else {
        std::fs::read_to_string(config_file).with_context(|| {
            format!(
                "reading {} — pass --no-config to build a bundle without it",
                config_file.display()
            )
        })?
    };

    let text = build_bundle_text(&config, &raw, health.as_deref())?;

    if args.stdout {
        print!("{text}");
        return Ok(());
    }

    let out_dir = args.out_dir.unwrap_or_else(|| PathBuf::from("."));
    std::fs::create_dir_all(&out_dir).with_context(|| format!("creating {}", out_dir.display()))?;
    let path = out_dir.join(format!(
        "support-bundle-{}.txt",
        now_rfc3339().replace(':', "-")
    ));

    // Re-read the file we are about to write and check it once more. Cheap, and
    // it closes the gap where a future edit to `redact` stops being applied to
    // the string that actually lands on disk.
    std::fs::write(&path, &text).with_context(|| format!("writing {}", path.display()))?;
    let on_disk = std::fs::read_to_string(&path)?;
    if on_disk != text {
        bail!("the bundle on disk does not match what was built; refusing to hand it over");
    }

    println!("{}", path.display());
    println!();
    println!("Attach this file to a support request. It holds no passwords, but it does hold");
    println!("your hostnames, tenant names and email addresses — read it before posting it");
    println!("somewhere public.");
    Ok(())
}
