//! `/frontend/source` — the AGPL §13 source offer (§10, item 19).
//!
//! §10.1: AGPL §13 requires that every user interacting with a modified version
//! **over a network** be offered the *complete corresponding source* of that
//! version. Concretely, the page has to name:
//!
//! | | |
//! |---|---|
//! | the running version | [`crate::build_provenance::build_sha`] and the package version |
//! | **both** commit SHAs | the server's, and `dav-tls`'s — the appliance ships both |
//! | a link to the tarball | version-matched, from the same release |
//! | the AGPL notice | and the licence link |
//!
//! # Why this is a feature and not a formality
//!
//! §10.2's second consequence is the reason the gate has teeth: because the repo
//! must be genuinely public, §5's live private key and 15 live app tokens become
//! a **licence- and security-blocking** issue, not just hygiene. A compliance
//! failure here is not a support ticket.
//!
//! # What this page will not do
//!
//! **It will not guess.** When the build had no repository — a distro package, a
//! `cargo install`, a source tarball — the SHA is unknown and the page says so
//! and refuses to link a tarball, because a page that prints a plausible-looking
//! commit nobody can verify is *worse* than one admitting ignorance: it looks
//! like compliance. §10.3's CI check turns an unverifiable page into a red build.
//!
//! **It will not hide a dirty build.** A binary built from a dirty tree has no
//! corresponding source anywhere. The page says the build is not from a
//! published tree rather than presenting a SHA that does not describe the code.
//!
//! # Authentication
//!
//! **Unauthenticated**, and deliberately mounted ahead of `HostDispatch` like
//! §6.6's panel. A compliance obligation that a prospective customer cannot read
//! without an account is not met by existing. It serves *no* tenant data: it is a
//! static page over build-time constants.

use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Serialize;

use crate::build_provenance::{build_dirty, build_sha};

/// Where the source lives. Overridable so a self-hoster can point at their own
/// mirror — which §10.2.1 makes the *only* option for a customer-specific change
/// anyway, since no closed fork is permitted.
const DEFAULT_REPO_URL: &str = "https://github.com/Bytewheel/Omnical-Server";

/// What the page publishes, as a serialisable value.
///
/// A struct rather than a formatted string so §10.3's gate can assert on
/// *fields* — a test that greps HTML for a SHA passes just as happily when the
/// SHA is in a comment, and this is the value the release process has to match.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SourceOffer {
    /// The running server's version.
    pub version: String,
    /// The commit, or `None` when the build had no repository.
    pub server_sha: Option<String>,
    /// The `dav-tls` commit. Separate because the appliance ships both binaries
    /// and §10.1 says "the `dav-tls` crate source — same repo, same tag"; a
    /// single SHA for two crates is a claim this build cannot verify.
    pub dav_tls_sha: Option<String>,
    pub repository: String,
    /// The tarball URL, present only when the offer is *verifiable* — see
    /// [`Self::is_verifiable`].
    pub tarball: Option<String>,
    /// True when the build came from a dirty tree, so no corresponding source
    /// exists for it.
    pub dirty_build: bool,
}

impl SourceOffer {
    /// The offer for the running binary.
    #[must_use]
    pub fn current() -> Self {
        let sha = build_sha();
        let dav_tls = crate::build_provenance::dav_tls_sha();
        Self {
            version: env!("CARGO_PKG_VERSION").to_owned(),
            server_sha: (!sha.is_empty()).then(|| sha.to_owned()),
            // Filled in by the release job (`OMNICAL_BUILD_DAV_TLS_SHA`), which
            // is the only place that can know it. Empty is legitimate — a
            // server-only build has no `dav-tls` — and renders as "unknown".
            dav_tls_sha: (!dav_tls.is_empty()).then(|| dav_tls.to_owned()),
            repository: std::env::var("OMNICAL_SOURCE_REPO")
                .unwrap_or_else(|_| DEFAULT_REPO_URL.to_owned()),
            tarball: None,
            dirty_build: build_dirty(),
        }
    }

    /// Can a reader actually get the source this describes?
    ///
    /// **No** without a commit. A tarball link with no SHA is the offer without
    /// the offer: it satisfies the letter and none of the purpose, so the page
    /// withholds it rather than shipping a link that cannot be checked.
    #[must_use]
    pub const fn is_verifiable(&self) -> bool {
        self.server_sha.is_some() && !self.dirty_build
    }

    /// The tarball URL for a given commit.
    #[must_use]
    pub fn tarball_for(&self, sha: &str) -> String {
        format!("{}/archive/{sha}.tar.gz", self.repository)
    }

    /// The page body.
    ///
    /// `clippy::format_push_string` is allowed deliberately. `write!` into the
    /// same `String` is the lint's suggestion; converting these call sites to it
    /// produced a collision-prone edit that had to be reverted once, and two
    /// `push_str(&format!(..))` calls building a static page is not a performance
    /// problem worth a fragile rewrite.
    #[allow(
        clippy::format_push_string,
        reason = "a static page; the write! rewrite was reverted once already"
    )]
    #[must_use]
    pub fn render(&self) -> String {
        let mut html = String::new();

        html.push_str(
            "<!doctype html><html><head><meta charset=utf-8>\
             <meta name=viewport content='width=device-width,initial-scale=1'>\
             <title>Source offer &mdash; Omnical</title>\
             <style>body{font:16px/1.6 system-ui,sans-serif;max-width:44rem;margin:3rem auto;\
             padding:0 1rem}table{border-collapse:collapse;margin:1rem 0}\
             th,td{text-align:left;padding:.35rem .9rem .35rem 0;vertical-align:top}\
             th{white-space:nowrap;color:#555}code{background:#f4f4f4;padding:.1rem .3rem;\
             border-radius:3px}.warn{background:#fff4e5;border-left:3px solid #e90;\
             padding:.7rem .9rem;margin:1rem 0}footer{margin-top:2.5rem;font-size:.85rem;\
             color:#666}</style></head><body>",
        );
        html.push_str("<h1>Complete corresponding source</h1>");
        html.push_str(
            "<p>This server is a modified version of Omnical, offered under the GNU Affero \
             General Public License v3. The complete corresponding source for the version you \
             are talking to is the one identified below.</p>",
        );

        html.push_str("<table><tbody>");
        html.push_str(&format!(
            "<tr><th>Running version</th><td><code>{}</code></td></tr>",
            escape(&self.version)
        ));
        html.push_str(&sha_row("Server commit", self.server_sha.as_deref()));
        html.push_str(&sha_row("dav-tls commit", self.dav_tls_sha.as_deref()));
        html.push_str(&format!(
            "<tr><th>Repository</th><td><a href=\"{}\">{}</a></td></tr>",
            escape(&self.repository),
            escape(&self.repository)
        ));
        html.push_str("</tbody></table>");

        if self.is_verifiable() {
            let tarball = self.tarball.clone().unwrap_or_else(|| {
                self.tarball_for(self.server_sha.as_deref().unwrap_or_default())
            });
            html.push_str(&format!(
                "<p><a href=\"{tarball}\">Download the complete corresponding source \
                 ({tarball})</a></p>\
                 <p>The tarball is the tree at the commit above. If it does not match, that is a \
                 compliance failure and we want to know: please report it.</p>"
            ));
        } else {
            html.push_str(
                "<div class=warn><strong>This build cannot offer a matching source archive.</strong>\
                 <ul>",
            );
            if self.server_sha.is_none() {
                html.push_str(
                    "<li>The binary was built without a repository, so no commit can be named. \
                     This happens with distribution packages and <code>cargo install</code>.</li>",
                );
            }
            if self.dirty_build {
                html.push_str(
                    "<li>The binary was built from a <strong>modified working tree</strong>, so \
                     the code that is running is not the code in any published commit.</li>",
                );
            }
            html.push_str(
                "</ul><p>Neither is acceptable under AGPL &sect;13. If you are running this build, \
                 please contact support: you should be given a matching source tree, and if we \
                 cannot produce one that is a problem we need to fix rather than a page we need \
                 to reword.</p></div>",
            );
        }

        html.push_str(
            "<p>You may copy, modify and redistribute this program under the terms of the GNU \
             Affero General Public License version 3. <strong>If you modify this program and let \
             other people interact with it remotely through a computer network</strong> &mdash; \
             which is exactly what using this server over CalDAV, CardDAV or the web interface \
             is &mdash; you must give those users the source of <em>your</em> modified version.</p>\
             <p>Third-party dependency licences are listed on the About page.</p>",
        );
        html.push_str(
            "<footer>AGPL-3.0 &mdash; source offer rendered by Omnical itself, at \
             <code>/frontend/source</code>.</footer></body></html>",
        );
        html
    }
}

/// One row of the commit table, or the row that admits the commit is unknown.
fn sha_row(label: &str, value: Option<&str>) -> String {
    value.map_or_else(
        || {
            format!(
                "<tr><th>{label}</th><td><em>unknown</em> &mdash; this build had no repository, \
                 so no commit can be named. See the notice below.</td></tr>"
            )
        },
        |sha| {
            format!(
                "<tr><th>{label}</th><td><code>{}</code></td></tr>",
                escape(sha)
            )
        },
    )
}

/// `GET /frontend/source` — 200, unauthenticated.
pub async fn source_offer() -> Response {
    let offer = SourceOffer::current();
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        offer.render(),
    )
        .into_response()
}

fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
