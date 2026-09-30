//! §10's gate (item 19): *"on a running hosted instance, an anonymous client can
//! reach `/frontend/source`, download a tarball whose `git rev-parse HEAD` matches
//! the running binary's build, and the tarball builds."*
//!
//! Two of those three are checkable in a unit test and the third is not, and the
//! split matters. What is tested here is that the page **refuses to lie**: it
//! publishes a commit only when the build had one, and it withholds the tarball
//! link when the commit is unknown or the tree was dirty. A page that always
//! prints a link passes "can an anonymous client download a tarball" and fails
//! AGPL §13, which is the opposite of what the gate is for.
//!
//! The tarball-vs-`git rev-parse HEAD` half is `scripts/source-offer-gate.sh`
//! and runs in CI against a real release build, because it needs a real tarball.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use rustical::build_provenance::{build_dirty, build_sha, dav_tls_sha, has_build_sha};
use rustical::host_dispatch::SOURCE_PATH;
use rustical::source_offer::{SourceOffer, source_offer};

fn block_on<F: std::future::Future>(f: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime")
        .block_on(f)
}

fn body_of(response: axum::response::Response) -> String {
    String::from_utf8_lossy(
        &block_on(axum::body::to_bytes(response.into_body(), usize::MAX)).expect("a body"),
    )
    .into_owned()
}

fn offer(server_sha: Option<&str>, dav_tls_sha: Option<&str>, dirty: bool) -> SourceOffer {
    SourceOffer {
        version: "0.16.1".to_owned(),
        server_sha: server_sha.map(ToOwned::to_owned),
        dav_tls_sha: dav_tls_sha.map(ToOwned::to_owned),
        repository: "https://example.invalid/Omnical-Server".to_owned(),
        tarball: None,
        dirty_build: dirty,
    }
}

// ── the page answers, unauthenticated ───────────────────────────────────────

#[test]
fn the_source_offer_is_reachable_without_an_account() {
    let request = Request::builder()
        .uri(SOURCE_PATH)
        .body(Body::empty())
        .unwrap();
    // No cookies, no Authorization header. §10.1's obligation is to every user
    // interacting over a network.
    let response = block_on(
        axum::Router::new()
            .route(SOURCE_PATH, axum::routing::get(source_offer))
            .oneshot(request),
    )
    .expect("infallible");
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_of(response);
    assert!(body.contains("corresponding source"), "{body}");
    assert!(body.contains("GNU Affero"), "{body}");
}

#[test]
fn the_path_is_the_one_the_plan_names() {
    // §10.1 says `/frontend/source`, and §10.3's gate curls exactly that. A
    // renamed path is a compliance obligation at a URL nobody visits.
    assert_eq!(SOURCE_PATH, "/frontend/source");
}

// ── it names the commit, or admits it cannot ───────────────────────────────

#[test]
fn a_known_commit_is_published_with_a_matching_tarball() {
    let sha = "a".repeat(40);
    let o = offer(Some(&sha), Some(&"b".repeat(40)), false);
    assert!(o.is_verifiable());
    let body = o.render();
    assert!(
        body.contains(&sha),
        "the commit is not on the page:\n{body}"
    );
    assert!(
        body.contains(&"b".repeat(40)),
        "dav-tls's commit is missing:\n{body}"
    );
    assert!(
        body.contains(&o.tarball_for(&sha)),
        "no tarball link:\n{body}"
    );
}

#[test]
fn an_unknown_commit_withholds_the_tarball_link() {
    // The heart of it. A tarball link with no commit is the offer without the
    // offer: it satisfies the letter of §10.3 and none of its purpose, so the
    // page refuses rather than shipping an unverifiable link.
    let o = offer(None, None, false);
    assert!(!o.is_verifiable());
    let body = o.render();
    assert!(
        !body.contains(".tar.gz"),
        "an unverifiable tarball was linked:\n{body}"
    );
    assert!(
        body.contains("unknown"),
        "the page does not admit ignorance:\n{body}"
    );
    assert!(
        body.contains("compliance failure") || body.contains("AGPL &sect;13"),
        "the page must say this is not acceptable, not merely absent:\n{body}"
    );
}

#[test]
fn a_dirty_build_withholds_the_tarball_link() {
    // A binary built from a modified tree has **no corresponding source
    // anywhere**. Linking a tarball of the published commit would be offering
    // source that is not the code running.
    let sha = "c".repeat(40);
    let o = offer(Some(&sha), Some(&sha), true);
    assert!(!o.is_verifiable());
    let body = o.render();
    assert!(!body.contains(".tar.gz"), "{body}");
    assert!(body.contains("modified working tree"), "{body}");
    // The commit is still printed — it is true information — but the archive is
    // withheld.
    assert!(body.contains(&sha), "{body}");
}

#[test]
fn a_dirty_build_is_reported_rather_than_hidden() {
    // The same fact, in a form the release process can check rather than one
    // somebody has to read.
    let o = offer(Some(&"d".repeat(40)), None, true);
    let serialised = serde_json::to_string(&o).expect("it serialises");
    assert!(serialised.contains("\"dirty_build\":true"), "{serialised}");
    let clean = offer(Some(&"d".repeat(40)), None, false);
    assert!(
        serde_json::to_string(&clean)
            .expect("it serialises")
            .contains("\"dirty_build\":false")
    );
}

// ── the running binary agrees with itself ───────────────────────────────────

#[test]
fn the_page_and_the_build_constants_cannot_disagree() {
    // `SourceOffer::current()` reads `build_sha()`; a change that made the page
    // use anything else would let it print a commit that is not this binary's.
    let current = SourceOffer::current();
    let expected = (!build_sha().is_empty()).then_some(build_sha());
    assert_eq!(current.server_sha.as_deref(), expected);
    assert_eq!(current.dirty_build, build_dirty());
    assert_eq!(current.version, env!("CARGO_PKG_VERSION"));
}

#[test]
fn this_build_can_or_cannot_name_its_commit_and_says_so() {
    // Informational, and deliberately not an assertion about the value: CI
    // builds from a checkout (known) and a distro package does not (unknown).
    // What is asserted is that the two states are distinguishable.
    if has_build_sha() {
        assert_eq!(build_sha().len(), 40, "a SHA is 40 hex characters");
        assert!(build_sha().chars().all(|c| c.is_ascii_hexdigit()));
        assert!(SourceOffer::current().is_verifiable() || build_dirty());
    } else {
        assert!(!SourceOffer::current().is_verifiable());
    }
}

// ── what must never appear ──────────────────────────────────────────────────

#[test]
fn the_page_publishes_no_secret() {
    // It is unauthenticated and public. A config value reaching this page would
    // be the worst leak in the project, so the shape of the type is the defence:
    // `SourceOffer` has six fields and none of them is tenant data.
    let o = SourceOffer::current();
    let serialised = serde_json::to_string(&o).expect("it serialises");
    for forbidden in ["password", "secret", "token", "smtp", "db_url"] {
        assert!(
            !serialised.to_lowercase().contains(forbidden),
            "the offer's serialised form mentions {forbidden}: {serialised}"
        );
    }
}

#[test]
fn dav_tls_is_never_guessed() {
    // §10.1 asks for "both commit SHAs". This binary cannot see `dav-tls`'s
    // commit — it is a separate crate in the packaging repository — so the
    // release job passes it in, and the page says "unknown" when it did not.
    // Inventing a second SHA equal to the server's would be the exact failure
    // the page exists to avoid.
    let current = SourceOffer::current();
    let expected = (!dav_tls_sha().is_empty()).then(|| dav_tls_sha().to_owned());
    assert_eq!(
        current.dav_tls_sha, expected,
        "the dav-tls commit must come from the build, never from a guess"
    );
    if current.dav_tls_sha.is_none() {
        let body = current.render();
        assert!(body.contains("unknown"), "{body}");
        // …and it must not fall back to the server's SHA, which would render a
        // page that looks complete and is wrong.
        if let Some(server) = &current.server_sha {
            let dav_row = body
                .split("dav-tls commit")
                .nth(1)
                .unwrap_or_default()
                .split("</tr>")
                .next()
                .unwrap_or_default()
                .to_owned();
            assert!(
                !dav_row.contains(server.as_str()),
                "the dav-tls row shows the server's commit:\n{dav_row}"
            );
        }
    }
    // The field exists so the release job can fill it; a server-only build is a
    // legitimate "unknown".
    let filled = offer(Some(&"e".repeat(40)), Some(&"f".repeat(40)), false);
    assert!(filled.render().contains(&"f".repeat(40)));
}
