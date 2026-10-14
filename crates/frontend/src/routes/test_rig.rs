//! `cfg(test)`-only: a shared `frontend_router` test rig — the
//! `password_reset.rs` `TestRig` pattern lifted to a module so the
//! mirror (§18.42) and contacts-import (§18.43) suites can use it
//! without each carrying a private copy.
//!
//! One in-memory SQLite pool; every store over it (the house rule the
//! production bundle follows); `frontend_router` over the stores with
//! a `SessionManagerLayer`; a `user` principal whose app token
//! (`pass`) authenticates via HTTP basic — the `Principal` extractor's
//! production path, exercised end to end.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use axum::body::Body as AxBody;
use axum::response::Response;
use headers::Authorization;
use headers::HeaderMapExt;
use http::{Method, Request, StatusCode};
use rustical_ical::CalendarObject;
use rustical_store::auth::{AuthenticationProvider, Principal, PrincipalType};
use rustical_store::{Calendar, CalendarWriteStore};
use rustical_store_sqlite::{
    SqliteAddressbookStore, SqliteCalendarSourceStore, SqliteCalendarStore,
    SqliteCollectionShareStore, SqliteInviteStore, SqliteMirrorStore, SqlitePasswordResetStore,
    SqlitePrincipalStore, SqlitePrintStore, SqliteSubscriptionStore, create_db_pool,
};
use tower::ServiceExt;
use tower_sessions::{MemoryStore, SessionManagerLayer};

use crate::routes::mirror::MirrorUiContext;
use crate::{FrontendConfig, frontend_router};

/// The rig: the router plus the handles the tests poke at (the pool,
/// for seeding and asserting rows; the stores, for re-building the
/// router with a mirror context).
pub struct Rig {
    pub router: axum::Router,
    pub db: sqlx::SqlitePool,
    pub cal_store: Arc<SqliteCalendarStore>,
    pub principal_store: Arc<SqlitePrincipalStore>,
    pub addr_store: Arc<SqliteAddressbookStore>,
}

impl Rig {
    /// One `user` principal with the app token `pass`, no calendars —
    /// each test seeds what it needs.
    pub async fn new() -> Self {
        let db = create_db_pool(":memory:", true).await.unwrap();
        let (send_addr, _recv) = tokio::sync::mpsc::channel(1000);
        let (send_cal, _recv) = tokio::sync::mpsc::channel(1000);
        let addr_store = Arc::new(SqliteAddressbookStore::new(db.clone(), send_addr, false));
        let cal_store = Arc::new(SqliteCalendarStore::new(db.clone(), send_cal, false));
        let principal_store = Arc::new(SqlitePrincipalStore::new(db.clone()));
        principal_store
            .insert_principal(
                Principal {
                    id: "user".to_owned(),
                    displayname: None,
                    principal_type: PrincipalType::Individual,
                    password: None,
                    memberships: vec![],
                    needs_password_change: false,
                    timezone: String::new(),
                    privileges: std::collections::BTreeMap::new(),
                },
                false,
            )
            .await
            .unwrap();
        principal_store
            .add_app_token("user", "test".to_owned(), "pass".to_owned())
            .await
            .unwrap();
        let addr_store = addr_store.clone();
        Self::router_over(db, addr_store, cal_store, principal_store, None).await
    }

    /// The same stores, a fresh router, with a mirror context — the
    /// §18.42 tests configure targets and re-mount.
    pub async fn router_with(&self, mirror: Option<Arc<MirrorUiContext>>) -> axum::Router {
        let (send_addr, _recv) = tokio::sync::mpsc::channel(1000);
        let addr_store = Arc::new(SqliteAddressbookStore::new(
            self.db.clone(),
            send_addr,
            false,
        ));
        let (send_cal, _recv) = tokio::sync::mpsc::channel(1000);
        let cal_store = Arc::new(SqliteCalendarStore::new(self.db.clone(), send_cal, false));
        Self::router_over(
            self.db.clone(),
            addr_store,
            cal_store,
            self.principal_store.clone(),
            mirror,
        )
        .await
        .router
    }

    /// A mirror store over this rig's pool (the state/run tables).
    pub fn mirror_store(&self) -> Arc<SqliteMirrorStore> {
        let (send, _recv) = tokio::sync::mpsc::channel(1000);
        Arc::new(SqliteMirrorStore::new(SqliteCalendarStore::new(
            self.db.clone(),
            send,
            false,
        )))
    }

    // Both of `unused_async`'s spellings fire here (the fn builds a
    // value, it awaits nothing) — the async stays so `Rig::new` and
    // `router_with` keep the one builder shape.
    #[allow(clippy::unused_async, clippy::unused_async_trait_impl)]
    pub async fn router_over(
        db: sqlx::SqlitePool,
        addr_store: Arc<SqliteAddressbookStore>,
        cal_store: Arc<SqliteCalendarStore>,
        principal_store: Arc<SqlitePrincipalStore>,
        mirror: Option<Arc<MirrorUiContext>>,
    ) -> Self {
        let _ = &db;
        let source_store: Arc<dyn rustical_store::CalendarSourceStore> =
            Arc::new(SqliteCalendarSourceStore::new((*cal_store).clone()));
        let sub_store: Arc<dyn rustical_store::SubscriptionStore> =
            Arc::new(SqliteSubscriptionStore::new((*cal_store).clone()));
        let invite_store: Arc<dyn rustical_store::InviteStore> =
            Arc::new(SqliteInviteStore::new((*cal_store).clone()));
        let share_store: Arc<dyn rustical_store::CollectionShareStore> =
            Arc::new(SqliteCollectionShareStore::new((*cal_store).clone()));
        let password_reset_store: Arc<dyn rustical_store::PasswordResetStore> =
            Arc::new(SqlitePasswordResetStore::new((*cal_store).clone()));
        let print_store: Arc<dyn rustical_store::PrintStore> =
            Arc::new(SqlitePrintStore::new((*cal_store).clone()));
        let router = frontend_router(
            "/frontend",
            principal_store.clone(),
            cal_store.clone(),
            addr_store.clone(),
            FrontendConfig::default(),
            None,
            Some(sub_store),
            source_store,
            "https://cal.example.com:8443".to_owned(),
            invite_store,
            share_store,
            password_reset_store,
            print_store,
            mirror,
            Vec::new(),
        )
        .layer(
            SessionManagerLayer::new(MemoryStore::default())
                .with_name("rustical_session")
                .with_secure(true),
        );
        Self {
            router,
            db,
            cal_store,
            principal_store,
            addr_store,
        }
    }

    /// A second user (for the cross-user gates), token `pass`.
    pub async fn insert_user(&self, id: &str) {
        self.principal_store
            .insert_principal(
                Principal {
                    id: id.to_owned(),
                    displayname: None,
                    principal_type: PrincipalType::Individual,
                    password: None,
                    memberships: vec![],
                    needs_password_change: false,
                    timezone: String::new(),
                    privileges: std::collections::BTreeMap::new(),
                },
                false,
            )
            .await
            .unwrap();
        self.principal_store
            .add_app_token(id, "test".to_owned(), "pass".to_owned())
            .await
            .unwrap();
    }

    /// One calendar owned by `principal`, with a one-shot event (a
    /// non-recurring object the phone-feed and master paths both carry).
    /// The UID is unique per calendar: the store enforces UID
    /// uniqueness across the whole account, so two calendars cannot
    /// both carry an object named `TESTUID1`.
    pub async fn insert_calendar_with_object(&self, principal: &str, id: &str) {
        self.cal_store
            .insert_calendar(Calendar {
                principal: principal.to_owned(),
                id: id.to_owned(),
                // `push_topic` is UNIQUE in the schema and `Default` is
                // the empty string — two default calendars would collide.
                push_topic: uuid::Uuid::new_v4().to_string(),
                ..Default::default()
            })
            .await
            .unwrap();
        let uid = format!("TESTUID-{id}");
        let object = CalendarObject::from_ics(
            "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//omnical//test//EN\r\nBEGIN:VEVENT\r\nUID:TESTUID1\r\n\
             DTSTAMP:20261012T195155Z\r\nDTSTART:20261012T190000Z\r\nSUMMARY:test\r\n\
             END:VEVENT\r\nEND:VCALENDAR\r\n"
                .replace("TESTUID1", &uid),
        )
        .expect("the test ics parses");
        self.cal_store
            .put_object(principal, id, &uid, object, false)
            .await
            .unwrap();
    }

    #[allow(dead_code)] // GET paths of future tests; the mirror suite currently rides `router_with`
    async fn request(&self, method: Method, path: &str, body: AxBody) -> (StatusCode, String) {
        let mut req = Request::builder()
            .method(method)
            .uri(path)
            .body(body)
            .unwrap();
        req.headers_mut()
            .typed_insert(Authorization::basic("user", "pass"));
        let resp = self.router.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        (status, String::from_utf8(bytes.to_vec()).unwrap())
    }

    /// An authenticated GET as `user`.
    #[allow(dead_code)] // same: kept for the suites that follow
    pub async fn get(&self, path: &str) -> (StatusCode, String) {
        self.request(Method::GET, path, AxBody::empty()).await
    }

    /// An authenticated urlencoded form POST as `user`.
    #[allow(dead_code)] // same
    pub async fn post_form(&self, path: &str, fields: &[(&str, &str)]) -> (StatusCode, String) {
        let body = fields
            .iter()
            .map(|(k, v)| format!("{k}={}", urlencode(v)))
            .collect::<Vec<_>>()
            .join("&");
        let mut req = Request::builder()
            .method(Method::POST)
            .uri(path)
            .header("content-type", "application/x-www-form-urlencoded")
            .header("host", "127.0.0.1:4000")
            .body(AxBody::from(body))
            .unwrap();
        req.headers_mut()
            .typed_insert(Authorization::basic("user", "pass"));
        let resp = self.router.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        (status, String::from_utf8(bytes.to_vec()).unwrap())
    }

    /// An authenticated raw-body POST as `user` (the contacts-import
    /// fetch-the-File shape).
    pub async fn post_body(&self, path: &str, body: &str) -> (StatusCode, String) {
        let mut req = Request::builder()
            .method(Method::POST)
            .uri(path)
            .header("content-type", "text/vcard")
            .body(AxBody::from(body.to_owned()))
            .unwrap();
        req.headers_mut()
            .typed_insert(Authorization::basic("user", "pass"));
        let resp = self.router.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        (status, String::from_utf8(bytes.to_vec()).unwrap())
    }
}

pub fn urlencode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(char::from(b));
            }
            b' ' => out.push('+'),
            _ => {
                use std::fmt::Write as _;
                write!(out, "%{b:02X}").unwrap();
            }
        }
    }
    out
}

/// The one answer of the stub below: the state machine the mirror
/// engine drives, as a plain fn both mounted paths share.
///
/// `PROPFIND` lists the map's own keys — one href per stored object
/// (basename == key == the filename the engine PUTs, so the engine's
/// unchanged-check sees a real listed remote; a static list would name
/// an href the engine never wrote and every sync would re-PUT
/// forever). `PUT` stores the body under the path, `DELETE` removes
/// it, anything else is a 405.
fn stub_caldav_answer(
    method: &Method,
    path: &str,
    state: &Arc<Mutex<HashMap<String, String>>>,
    body: &[u8],
) -> Response {
    match method.as_str() {
        "PROPFIND" => {
            use std::fmt::Write as _;
            let hrefs: String = state
                .lock()
                .unwrap()
                .keys()
                .fold(String::new(), |mut out, key| {
                    let _ = write!(out, "<D:response><D:href>/{key}</D:href></D:response>");
                    out
                });
            Response::builder()
                .status(207)
                .header("content-type", "application/xml")
                .body(AxBody::from(format!(
                    "<?xml version=\"1.0\"?><D:multistatus xmlns:D=\"DAV:\">{hrefs}</D:multistatus>"
                )))
                .unwrap()
        }
        "PUT" => {
            state
                .lock()
                .unwrap()
                .insert(path.to_owned(), String::from_utf8_lossy(body).to_string());
            Response::builder()
                .status(201)
                .body(AxBody::empty())
                .unwrap()
        }
        "DELETE" => {
            state.lock().unwrap().remove(path);
            Response::builder()
                .status(204)
                .body(AxBody::empty())
                .unwrap()
        }
        _ => Response::builder()
            .status(StatusCode::METHOD_NOT_ALLOWED)
            .body(AxBody::empty())
            .unwrap(),
    }
}

/// A local stub `CalDAV` server: answers the three verbs the mirror
/// engine speaks, at the paths it speaks them on — `PROPFIND` hits the
/// collection root (`/`), which `/{*path}` alone does NOT match in
/// axum, so the root gets its own route to the same answer; `PUT` and
/// `DELETE` hit `/{*path}` with the object filename.
pub async fn stub_caldav_server() -> (String, Arc<Mutex<HashMap<String, String>>>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let remote: Arc<Mutex<HashMap<String, String>>> = Arc::new(Mutex::new(HashMap::new()));
    let state = remote.clone();
    let state_for_root = state.clone();
    let app = axum::Router::new()
        .route(
            "/",
            axum::routing::any(move |method: Method, body: axum::body::Bytes| {
                let state = state_for_root.clone();
                async move { stub_caldav_answer(&method, "", &state, &body) }
            }),
        )
        .route(
            "/{*path}",
            axum::routing::any(
                move |method: Method,
                      axum::extract::Path(path): axum::extract::Path<String>,
                      body: axum::body::Bytes| {
                    let state = state.clone();
                    async move { stub_caldav_answer(&method, &path, &state, &body) }
                },
            ),
        );
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{addr}"), remote)
}

/// A configured target for the tests: `name`, `principal`/`calendar`,
/// at `url`, canonical (not a phone feed) — the §18.41 default shape.
pub fn target_config(
    name: &str,
    principal: &str,
    calendar: &str,
    url: &str,
) -> rustical_caldav::mirror::MirrorTargetConfig {
    rustical_caldav::mirror::MirrorTargetConfig {
        name: name.to_owned(),
        principal: principal.to_owned(),
        calendar: calendar.to_owned(),
        url: url.to_owned(),
        username: "stub".to_owned(),
        password: "stub".to_owned(),
        organizer: String::new(),
        phone_instances: false,
        phone_feed_only: false,
        horizon_days: 90,
        interval_secs: 1800,
    }
}

/// The shared mirror context over the rig's pool.
pub fn mirror_context(
    store: Arc<SqliteMirrorStore>,
    targets: Vec<rustical_caldav::mirror::MirrorTargetConfig>,
    deployment_timezone: &str,
) -> Arc<MirrorUiContext> {
    Arc::new(MirrorUiContext {
        store,
        targets,
        deployment_timezone: deployment_timezone.to_owned(),
        in_flight: Mutex::new(HashSet::new()),
    })
}
