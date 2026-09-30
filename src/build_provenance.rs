//! Build-time provenance, for the AGPL §13 source offer (§10.1, item 19).
//!
//! The git logic lives in `build_provenance.rs` at the crate root, because
//! `build.rs` cannot include a file from `src/`. This is the read side: the
//! constants the build script emitted, read by the page that has to publish them.

include!("../build_provenance.rs");

/// The commit this binary was built from, or `""` when the build had no
/// repository.
///
/// Empty rather than a guess. A distro package, a `cargo install` and a source
/// tarball all build without a `.git`, and §10.1's requirement is satisfiable
/// only by naming the commit the running code is in — so "unknown" is the honest
/// answer, and a page printing a plausible-looking SHA nobody can verify is
/// worse than one admitting it does not know.
#[must_use]
pub const fn build_sha() -> &'static str {
    env!("OMNICAL_BUILD_SHA")
}

/// Was the working tree dirty when this was built?
///
/// A binary built from a dirty tree has no corresponding source **anywhere**,
/// which is an AGPL §13 problem and not only a reproducibility one. The page
/// says so rather than presenting a SHA that does not describe the code.
#[must_use]
pub fn build_dirty() -> bool {
    matches!(env!("OMNICAL_BUILD_DIRTY"), "true" | "1")
}

/// The `dav-tls` commit, or `""` when the build was not told one.
///
/// §10.1 requires both SHAs and the appliance ships both binaries. This one
/// cannot be discovered from here — `dav-tls` is a separate crate in the
/// packaging repository — so the release job passes it in as
/// `OMNICAL_BUILD_DAV_TLS_SHA`, and the page says "unknown" when it is absent.
/// Guessing it equal to the server's would be precisely the failure the page
/// exists to avoid.
#[must_use]
pub const fn dav_tls_sha() -> &'static str {
    env!("OMNICAL_BUILD_DAV_TLS_SHA")
}

/// Is the commit known at all?
#[must_use]
pub const fn has_build_sha() -> bool {
    !build_sha().is_empty()
}
