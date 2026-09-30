//! The build script: capture the commit this binary was built from.
//!
//! §10.1 (item 19) requires the AGPL source offer to name *"both commit SHAs"*.
//! The SHA cannot be found at runtime — there is no `.git` next to a deployed
//! binary, and on the appliance the whole point is that it is a sysupgrade image
//! with no repository on the device. So it is captured here and baked in.
//!
//! The build is therefore the only place a SHA can be wrong, which is what
//! §10.3's gate needs: the page prints this value, CI compares it against the
//! tarball's `git rev-parse HEAD`, and a build made from an unpublished tree
//! fails instead of shipping a page that points at source the running code is
//! not in.

include!("build_provenance.rs");

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=build_provenance.rs");
    println!("cargo:rerun-if-env-changed=OMNICAL_BUILD_SHA");
    // §10.1 names *both* commit SHAs. `dav-tls` is a separate crate in the
    // packaging repo, and a binary built here cannot see its history — so the
    // release job passes it in, and without it the page says "unknown" rather
    // than guessing. See `SourceOffer::current`.
    println!("cargo:rerun-if-env-changed=OMNICAL_BUILD_DAV_TLS_SHA");

    // An explicit override wins, so a release build can stamp the tag's commit
    // even from a shallow checkout, and so CI can assert the value it expects.
    let sha = std::env::var("OMNICAL_BUILD_SHA")
        .ok()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .or_else(git_sha);

    match sha {
        Some(sha) => println!("cargo:rustc-env=OMNICAL_BUILD_SHA={sha}"),
        // Empty rather than absent: `env!` needs the variable to exist, and a
        // page that prints "unknown" is better than one that prints a guess.
        None => println!("cargo:rustc-env=OMNICAL_BUILD_SHA="),
    }
    println!("cargo:rustc-env=OMNICAL_BUILD_DIRTY={}", is_dirty());

    // §10.1's second SHA. Empty is a legitimate answer — a server-only build
    // genuinely has no `dav-tls` — and the page renders "unknown" for it.
    println!(
        "cargo:rustc-env=OMNICAL_BUILD_DAV_TLS_SHA={}",
        std::env::var("OMNICAL_BUILD_DAV_TLS_SHA").unwrap_or_default()
    );
}
