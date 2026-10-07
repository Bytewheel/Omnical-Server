use axum::{
    Extension,
    body::Body,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use headers::{CacheControl, ETag, HeaderMapExt};
use rustical_store::auth::Principal;
use sha2::{Digest, Sha256};
use std::{path::PathBuf, str::FromStr};

/// The `HawkBook` Android package this deployment serves at
/// `/frontend/download/hawkbook.apk`. Read + hashed **once, at startup**,
/// never per request: the route's `ETag`, the sha256 printed on the profile
/// intro and the file it can actually serve all derive from that single
/// read, so a stale or truncated file on disk is detected at boot (warned
/// about, route stays off) rather than served as a working-looking link
/// next to a checksum it does not match.
#[derive(Clone)]
pub struct HawkBookApk {
    path: PathBuf,
    sha256: String,
}

impl HawkBookApk {
    pub fn sha256_hex(&self) -> String {
        self.sha256.clone()
    }

    /// Configured path → served state, or `None` (warned) when the file is
    /// unreadable: the intro then omits the download sentence and the route
    /// 404s, so the page never links at something it cannot serve.
    pub fn from_config(path: Option<&PathBuf>) -> Option<Self> {
        let path = path?;
        match std::fs::read(path) {
            Ok(bytes) => Some(Self {
                sha256: hex::encode(Sha256::digest(&bytes)),
                path: path.clone(),
            }),
            Err(e) => {
                tracing::warn!(
                    "configured [frontend] hawkbook_apk {path:?} is unreadable ({e}) — \
                     the download route stays off until it is deployed"
                );
                None
            }
        }
    }
}

/// `GET /download/hawkbook.apk` — the download. Behind the portal session
/// (`Principal`) on purpose: an 18 MB file on a home-router uplink must not
/// be anonymously leechable, and every user who needs it (the intro links
/// it) is signed in by construction — the invite→register→intro flow lands
/// them authenticated before the link can ever render for them.
pub async fn route_download_hawkbook(
    Extension(apk): Extension<Option<HawkBookApk>>,
    headers: HeaderMap,
    _user: Principal,
) -> Response {
    let Some(apk) = apk else {
        return StatusCode::NOT_FOUND.into_response();
    };
    // Same validator discipline as the embedded assets: the ETag is the
    // startup sha256, and `no-cache` means "always revalidate". Revalidation
    // itself is answered HERE (the embedded assets never need to: a stale
    // CSS re-sends kilobytes; a stale APK re-sends 18 MB over a home-router
    // uplink) — a matching `If-None-Match` is a 304 before the file is even
    // read, so a phone re-checking costs one round trip, not a re-download.
    // `*` matches too (RFC 9110 §13.1.2: "any current representation").
    let etag = format!("\"{}\"", apk.sha256);
    if headers
        .get(header::IF_NONE_MATCH)
        .is_some_and(|inm| inm.as_bytes() == etag.as_bytes() || inm.as_bytes() == b"*")
    {
        let mut response = Response::builder().status(StatusCode::NOT_MODIFIED);
        let hdrs = response.headers_mut().unwrap();
        hdrs.typed_insert(ETag::from_str(&etag).unwrap());
        hdrs.typed_insert(CacheControl::new().with_no_cache());
        return response.body(Body::empty()).unwrap();
    }
    match tokio::fs::read(&apk.path).await {
        Ok(bytes) => {
            let mut response = Response::builder().status(StatusCode::OK);
            let hdrs = response.headers_mut().unwrap();
            hdrs.insert(
                header::CONTENT_TYPE,
                header::HeaderValue::from_static("application/vnd.android.package-archive"),
            );
            hdrs.typed_insert(ETag::from_str(&etag).unwrap());
            hdrs.typed_insert(CacheControl::new().with_no_cache());
            response.body(Body::from(bytes)).unwrap()
        }
        // The file disappeared between startup and this request (deployed
        // away, not replaced). Not a 500: for the client this is
        // indistinguishable from a deployment that never had it, and the
        // 404 keeps the same contract the un-configured route has.
        Err(e) => {
            tracing::warn!("hawkbook_apk {:?} vanished since startup ({e})", apk.path);
            StatusCode::NOT_FOUND.into_response()
        }
    }
}
