// Shared by `build.rs` and `src/build_provenance.rs`.
//
// `build.rs` cannot include a file from `src/`, and the constants it emits are
// only visible to the crate, so the git logic lives here and both sides
// `include!` it. That is why the two files exist at all: one implementation, two
// include sites. An `include!`d file cannot carry inner doc comments, hence the
// `//` rather than `//!` above.
//
// Build-time provenance, for the AGPL §13 source offer (§10.1, item 19).

use std::process::Command;

// Only `build.rs` calls these; the `src/` include site only reads the constants
// the build emitted. Hence the allow, and hence this file.
#[allow(dead_code, reason = "used by build.rs, which includes this file")]
fn git_sha() -> Option<String> {
    let out = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let sha = String::from_utf8(out.stdout).ok()?.trim().to_owned();
    if sha.len() == 40 && sha.chars().all(|c| c.is_ascii_hexdigit()) {
        Some(sha)
    } else {
        None
    }
}

/// Whether the working tree is dirty at build time.
///
/// A binary built from a dirty tree has no corresponding source **anywhere**,
/// which is an AGPL §13 problem and not just a reproducibility one. The page
/// says so rather than presenting a SHA that does not describe the code.
#[allow(dead_code, reason = "used by build.rs, which includes this file")]
fn is_dirty() -> bool {
    Command::new("git")
        .args(["status", "--porcelain"])
        .output()
        .is_ok_and(|o| o.status.success() && !o.stdout.is_empty())
}
