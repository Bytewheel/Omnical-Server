// This integration test checks whether the HTTP server works by actually running rustical in a new
// thread.
use common::{rustical_process, rustical_process_with};
use http::{Method, StatusCode};
use reqwest::redirect::Policy;
use rustical::{
    PrincipalsArgs, cmd_health, cmd_invites, cmd_principals, cmd_subscriptions,
    config::{Config, DataStoreConfig, HttpConfig, SqliteDataStoreConfig, SubscriptionsConfig},
    invites::{CreateArgs as InviteCreateArgs, InvitesArgs, InvitesCommand},
    membership::{AssignArgs, MembershipArgs, MembershipCommand},
    principals::{CreateArgs, EditArgs, PrincipalsCommand},
    subscriptions::{AddArgs, KindArg, RemoveArgs, SubscriptionsArgs, SubscriptionsCommand},
};
use rustical_ical::CalendarObjectType;
use rustical_store::auth::{AuthenticationProvider, PrincipalType};
use rustical_store::{
    AddressbookReadStore, Calendar, CalendarMetadata, CalendarReadStore, CalendarWriteStore,
    InviteStore, SubscriptionKind, SubscriptionStore,
};
use rustical_store_sqlite::{
    SqliteAddressbookStore, SqliteCalendarStore, SqliteInviteStore, SqlitePrincipalStore,
    SqliteSubscriptionStore, create_db_pool,
};
use std::{collections::HashMap, time::Duration};

mod common;

pub async fn test_runner<O, F>(db_path: Option<String>, inner: F)
where
    O: IntoFuture<Output = ()>,
    // <O as IntoFuture>::IntoFuture: UnwindSafe,
    F: FnOnce(u16) -> O,
{
    // Start RustiCal process
    let (token, port, main_process, start_notify) = rustical_process(db_path);

    // Wait for RustiCal server to listen
    tokio::time::timeout(Duration::new(2, 0), start_notify.notified())
        .await
        .unwrap();

    // We use catch_unwind to make sure we'll always correctly stop RustiCal
    // Otherwise, our process would just run indefinitely
    inner(port).into_future().await;

    // Signal RustiCal to stop
    token.cancel();
    main_process.join().unwrap();
}

pub async fn test_runner_with<O, F, C>(db_path: Option<String>, customize: C, inner: F)
where
    O: IntoFuture<Output = ()>,
    F: FnOnce(u16) -> O,
    C: FnOnce(&mut Config) + Send + 'static,
{
    // Start RustiCal process
    let (token, port, main_process, start_notify) = rustical_process_with(db_path, customize);

    // Wait for RustiCal server to listen
    tokio::time::timeout(Duration::new(2, 0), start_notify.notified())
        .await
        .unwrap();

    // We use catch_unwind to make sure we'll always correctly stop RustiCal
    // Otherwise, our process would just run indefinitely
    inner(port).into_future().await;

    // Signal RustiCal to stop
    token.cancel();
    main_process.join().unwrap();
}

#[tokio::test]
async fn test_ping() {
    test_runner(None, async |port| {
        let origin = format!("http://localhost:{port}");
        let resp = reqwest::get(origin.clone() + "/ping").await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Ensure that path normalisation works as intended
        let resp = reqwest::get(origin + "/ping/").await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        cmd_health(
            HttpConfig {
                bind: Some(format!("127.0.0.1:{port}")),
                ..Default::default()
            },
            Default::default(),
        )
        .await
        .unwrap();
    })
    .await
}

// When setting a use password from the CLI we effectively have two processes accessing the same
// database: The server and the CLI.
// This test ensures that the server correctly picks up the changes made by the CLI.
#[tokio::test]
async fn test_initial_setup() {
    let db_tempfile = tempfile::NamedTempFile::with_suffix(".rustical-test.sqlite3").unwrap();
    let db_path = db_tempfile.path().to_string_lossy().into_owned();

    test_runner(Some(db_path.clone()), async |port| {
        let origin = format!("http://localhost:{port}");
        // Create principal
        cmd_principals(
            PrincipalsArgs {
                command: PrincipalsCommand::Create(CreateArgs {
                    id: "user".to_owned(),
                    name: Some("Test User".to_owned()),
                    password: false,
                    for_testing_password_from_arg: None,
                    principal_type: Some(PrincipalType::Individual),
                    overwrite: true,
                }),
            },
            Config {
                data_store: DataStoreConfig::Sqlite(SqliteDataStoreConfig {
                    db_url: db_path.clone(),
                    run_repairs: true,
                    skip_broken: false,
                }),
                http: Default::default(),
                frontend: Default::default(),
                oidc: None,
                tracing: Default::default(),
                dav_push: Default::default(),
                nextcloud_login: Default::default(),
                caldav: Default::default(),
                scheduling: Default::default(),
                subscriptions: Default::default(),
                registration: Default::default(),
                maintenance: Default::default(),
            },
        )
        .await
        .unwrap();
        // Set principal password
        cmd_principals(
            PrincipalsArgs {
                command: PrincipalsCommand::Edit(EditArgs {
                    id: "user".to_owned(),
                    name: None,
                    password: false,
                    remove_password: false,
                    for_testing_password_from_arg: Some("pass".to_owned()),
                    principal_type: Some(PrincipalType::Individual),
                }),
            },
            Config {
                data_store: DataStoreConfig::Sqlite(SqliteDataStoreConfig {
                    db_url: db_path.clone(),
                    run_repairs: true,
                    skip_broken: false,
                }),
                http: Default::default(),
                frontend: Default::default(),
                oidc: None,
                tracing: Default::default(),
                dav_push: Default::default(),
                nextcloud_login: Default::default(),
                caldav: Default::default(),
                scheduling: Default::default(),
                subscriptions: Default::default(),
                registration: Default::default(),
                maintenance: Default::default(),
            },
        )
        .await
        .unwrap();

        let client = reqwest::Client::builder()
            .redirect(Policy::none())
            .cookie_store(true)
            .build()
            .unwrap();
        {
            // Log in to the frontend
            let url = origin.clone() + "/frontend/login";
            let mut form = HashMap::new();
            form.insert("username", "user");
            form.insert("password", "pass");
            let resp = client
                .request(Method::POST, &url)
                .form(&form)
                .send()
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::SEE_OTHER);
            let location = resp.headers().get("Location").unwrap().to_str().unwrap();
            assert_eq!(location, "/frontend/user");
        }

        {
            let url = origin.clone() + "/frontend/user";
            let resp = client.request(Method::GET, &url).send().await.unwrap();
            assert_eq!(resp.status(), StatusCode::SEE_OTHER);
            let location = resp.headers().get("Location").unwrap().to_str().unwrap();
            assert_eq!(location, "/frontend/user/user");
        }

        {
            let url = origin.clone() + "/frontend/user/user";
            let resp = client.request(Method::GET, &url).send().await.unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
        }

        let app_token = {
            let url = origin.clone() + "/frontend/user/user/app_token";
            let mut form = HashMap::new();
            form.insert("name", "Test Token");
            let resp = client
                .request(Method::POST, &url)
                .form(&form)
                .send()
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);

            resp.text().await.unwrap()
        };

        let url = origin.clone() + "/caldav/principal/user";
        let resp = reqwest::Client::new()
            .request(Method::from_bytes(b"PROPFIND").unwrap(), &url)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let resp = reqwest::Client::new()
            .request(Method::from_bytes(b"PROPFIND").unwrap(), &url)
            .basic_auth("user", Some(&app_token))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::MULTI_STATUS);

        let db = create_db_pool(&db_path, false).await.unwrap();
        let principal_store = SqlitePrincipalStore::new(db);
        principal_store.remove_principal("user").await.unwrap();

        let resp = reqwest::Client::new()
            .request(Method::from_bytes(b"PROPFIND").unwrap(), &url)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    })
    .await;
}

#[tokio::test]
async fn test_principal_impersonation() {
    let db_tempfile = tempfile::NamedTempFile::with_suffix(".rustical-test.sqlite3").unwrap();
    let db_path = db_tempfile.path().to_string_lossy().into_owned();

    test_runner(Some(db_path.clone()), async |port| {
        let origin = format!("http://localhost:{port}");
        let config = Config {
            data_store: DataStoreConfig::Sqlite(SqliteDataStoreConfig {
                db_url: db_path.clone(),
                run_repairs: true,
                skip_broken: false,
            }),
            http: Default::default(),
            frontend: Default::default(),
            oidc: None,
            tracing: Default::default(),
            dav_push: Default::default(),
            nextcloud_login: Default::default(),
            caldav: Default::default(),
            scheduling: Default::default(),
            subscriptions: Default::default(),
            registration: Default::default(),
            maintenance: Default::default(),
        };

        // Create principal
        cmd_principals(
            PrincipalsArgs {
                command: PrincipalsCommand::Create(CreateArgs {
                    id: "user".to_owned(),
                    name: Some("Test User".to_owned()),
                    password: false,
                    for_testing_password_from_arg: None,
                    principal_type: Some(PrincipalType::Individual),
                    overwrite: true,
                }),
            },
            config.clone(),
        )
        .await
        .unwrap();
        // Set principal password
        cmd_principals(
            PrincipalsArgs {
                command: PrincipalsCommand::Edit(EditArgs {
                    id: "user".to_owned(),
                    name: None,
                    password: false,
                    remove_password: false,
                    for_testing_password_from_arg: Some("pass".to_owned()),
                    principal_type: Some(PrincipalType::Individual),
                }),
            },
            config.clone(),
        )
        .await
        .unwrap();

        // Add groups
        cmd_principals(
            PrincipalsArgs {
                command: PrincipalsCommand::Create(CreateArgs {
                    id: "group.allowed".to_owned(),
                    name: Some("User is member of this group".to_owned()),
                    password: false,
                    for_testing_password_from_arg: None,
                    principal_type: Some(PrincipalType::Group),
                    overwrite: true,
                }),
            },
            config.clone(),
        )
        .await
        .unwrap();
        cmd_principals(
            PrincipalsArgs {
                command: PrincipalsCommand::Create(CreateArgs {
                    id: "group.forbidden".to_owned(),
                    name: Some("User is not member of this group".to_owned()),
                    password: false,
                    for_testing_password_from_arg: None,
                    principal_type: Some(PrincipalType::Group),
                    overwrite: true,
                }),
            },
            config.clone(),
        )
        .await
        .unwrap();

        cmd_principals(
            PrincipalsArgs {
                command: PrincipalsCommand::Membership(MembershipArgs {
                    command: MembershipCommand::Assign(AssignArgs {
                        id: "user".to_owned(),
                        to: "group.allowed".to_owned(),
                    }),
                }),
            },
            config.clone(),
        )
        .await
        .unwrap();

        let client = reqwest::Client::builder()
            .redirect(Policy::none())
            .cookie_store(true)
            .build()
            .unwrap();
        {
            // Log in to the frontend
            let url = origin.clone() + "/frontend/login";
            let mut form = HashMap::new();
            form.insert("username", "user");
            form.insert("password", "pass");
            let resp = client
                .request(Method::POST, &url)
                .form(&form)
                .send()
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::SEE_OTHER);
            let location = resp.headers().get("Location").unwrap().to_str().unwrap();
            assert_eq!(location, "/frontend/user");
        }

        {
            // First-ever membership (the CLI assign above) forces a password
            // change on the user's next portal login (Omnical sharing), so
            // the portal redirects everything to the change form first.
            let url = origin.clone() + "/frontend/user";
            let resp = client.request(Method::GET, &url).send().await.unwrap();
            assert_eq!(resp.status(), StatusCode::SEE_OTHER);
            let location = resp.headers().get("Location").unwrap().to_str().unwrap();
            assert_eq!(location, "/frontend/user/user/password");
        }

        {
            // The change form requires the current password, then applies the
            // new hash and lifts the gate.
            let url = origin.clone() + "/frontend/user/user/password";
            let resp = client.request(Method::GET, &url).send().await.unwrap();
            assert_eq!(resp.status(), StatusCode::OK);

            let mut form = HashMap::new();
            form.insert("current_password", "pass");
            form.insert("new_password", "super-secret-new-pass");
            form.insert("new_password_confirm", "super-secret-new-pass");
            let resp = client
                .request(Method::POST, &url)
                .form(&form)
                .send()
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::SEE_OTHER);
            let location = resp.headers().get("Location").unwrap().to_str().unwrap();
            assert_eq!(location, "/frontend/user/user");
        }

        {
            let url = origin.clone() + "/frontend/user/user";
            let resp = client.request(Method::GET, &url).send().await.unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
        }

        let app_token = {
            let url = origin.clone() + "/frontend/user/user/app_token";
            let mut form = HashMap::new();
            form.insert("name", "Test Token");
            let resp = client
                .request(Method::POST, &url)
                .form(&form)
                .send()
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);

            resp.text().await.unwrap()
        };

        let url = origin.clone() + "/caldav-compat";
        let resp = reqwest::Client::new()
            .request(Method::from_bytes(b"PROPFIND").unwrap(), &url)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let resp = reqwest::Client::new()
            .request(Method::from_bytes(b"PROPFIND").unwrap(), &url)
            .basic_auth("user", Some(&app_token))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::MULTI_STATUS);

        let resp = reqwest::Client::new()
            .request(Method::from_bytes(b"PROPFIND").unwrap(), &url)
            .basic_auth("user$group.allowed", Some(&app_token))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::MULTI_STATUS);

        let resp = reqwest::Client::new()
            .request(Method::from_bytes(b"PROPFIND").unwrap(), &url)
            .basic_auth("user$group.forbidden", Some(&app_token))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    })
    .await;
}

// Omnical share-links extension (PLAN.md §17.7): enabled-path coverage of the
// src wiring — spawns a real `cmd_serve` with `[subscriptions] enabled` and
// exercises the whole CLI → DB → route chain: the `subscriptions` CLI (with
// the real token generator), an unauthenticated GET of the export URL, the
// kind/extension mismatch 404, and instant revocation via `remove`.
#[tokio::test]
async fn test_subscriptions_export() {
    let db_tempfile = tempfile::NamedTempFile::with_suffix(".rustical-test.sqlite3").unwrap();
    let db_path = db_tempfile.path().to_string_lossy().into_owned();

    test_runner_with(
        Some(db_path.clone()),
        |config| {
            config.subscriptions.enabled = true;
        },
        async |port| {
            let origin = format!("http://localhost:{port}");
            let config = Config {
                data_store: DataStoreConfig::Sqlite(SqliteDataStoreConfig {
                    db_url: db_path.clone(),
                    run_repairs: true,
                    skip_broken: false,
                }),
                http: HttpConfig {
                    bind: Some(format!("127.0.0.1:{port}")),
                    ..Default::default()
                },
                frontend: Default::default(),
                oidc: None,
                tracing: Default::default(),
                dav_push: Default::default(),
                nextcloud_login: Default::default(),
                caldav: Default::default(),
                scheduling: Default::default(),
                subscriptions: SubscriptionsConfig {
                    enabled: true,
                    public_url: Some(origin.clone()),
                },
                registration: Default::default(),
                maintenance: Default::default(),
            };

            // Create the principal (CLI), seed a calendar through the stores
            cmd_principals(
                PrincipalsArgs {
                    command: PrincipalsCommand::Create(CreateArgs {
                        id: "user".to_owned(),
                        name: Some("Test User".to_owned()),
                        password: false,
                        for_testing_password_from_arg: None,
                        principal_type: Some(PrincipalType::Individual),
                        overwrite: true,
                    }),
                },
                config.clone(),
            )
            .await
            .unwrap();

            let db = create_db_pool(&db_path, false).await.unwrap();
            let (send, _recv) = tokio::sync::mpsc::channel(1);
            SqliteCalendarStore::new(db, send, false)
                .insert_calendar(Calendar {
                    id: "personal".to_owned(),
                    principal: "user".to_owned(),
                    meta: CalendarMetadata {
                        displayname: Some("Personal".to_owned()),
                        order: 0,
                        description: None,
                        color: None,
                    },
                    timezone_id: None,
                    deleted_at: None,
                    synctoken: 0,
                    subscription_url: None,
                    push_topic: "personal-push-topic".to_owned(),
                    components: vec![CalendarObjectType::Event],
                })
                .await
                .unwrap();

            // CLI: create the subscription (real token generator)
            cmd_subscriptions(
                SubscriptionsArgs {
                    command: SubscriptionsCommand::Add(AddArgs {
                        principal: "user".to_owned(),
                        collection_id: "personal".to_owned(),
                        kind: KindArg::Calendar,
                    }),
                },
                config.clone(),
            )
            .await
            .unwrap();

            // The CLI prints the URL to stdout, which an in-process test
            // cannot capture — read the subscription back through the store.
            let db = create_db_pool(&db_path, false).await.unwrap();
            let (send, _recv) = tokio::sync::mpsc::channel(1);
            let sub_store = SqliteSubscriptionStore::new(SqliteCalendarStore::new(db, send, false));
            let subscriptions = sub_store.get_subscriptions("user").await.unwrap();
            assert_eq!(subscriptions.len(), 1);
            let (id, token) = {
                let subscription = &subscriptions[0];
                assert_eq!(subscription.token.len(), 64);
                (subscription.id.clone(), subscription.token.clone())
            };

            // Unauthenticated GET: the token in the URL is the only credential
            let resp = reqwest::get(format!("{origin}/export/{token}.ics"))
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
            assert!(
                resp.headers()
                    .get("content-type")
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .starts_with("text/calendar")
            );
            let body = resp.text().await.unwrap();
            assert!(body.starts_with("BEGIN:VCALENDAR"));

            // Kind/extension mismatch: a calendar token must not serve .vcf
            let resp = reqwest::get(format!("{origin}/export/{token}.vcf"))
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::NOT_FOUND);

            // CLI remove revokes the URL instantly
            cmd_subscriptions(
                SubscriptionsArgs {
                    command: SubscriptionsCommand::Remove(RemoveArgs {
                        principal: "user".to_owned(),
                        id,
                    }),
                },
                config.clone(),
            )
            .await
            .unwrap();
            let resp = reqwest::get(format!("{origin}/export/{token}.ics"))
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        },
    )
    .await;
}

#[tokio::test]
async fn test_register_disabled_unmounted() {
    test_runner(None, async |port| {
        let resp = reqwest::get(format!("http://localhost:{port}/register"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    })
    .await;
}

fn csrf_from(html: &str) -> String {
    html.split(r#"name="csrf" value=""#)
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .unwrap_or_default()
        .to_owned()
}

fn alert_from(html: &str) -> String {
    html.split("role=\"alert\">")
        .nth(1)
        .and_then(|rest| rest.split("</p>").next())
        .unwrap_or_default()
        .to_owned()
}

#[tokio::test]
async fn test_register_enabled_provisions() {
    let db_tempfile = tempfile::NamedTempFile::with_suffix(".rustical-test.sqlite3").unwrap();
    let db_path = db_tempfile.path().to_string_lossy().into_owned();

    test_runner_with(
        Some(db_path.clone()),
        |config| {
            config.registration.enabled = true;
            config.subscriptions.enabled = true;
            let bind = config.http.bind.clone().unwrap();
            config.subscriptions.public_url = Some(format!("http://{bind}"));
        },
        async |port| {
            let origin = format!("http://localhost:{port}");
            let config = Config {
                data_store: DataStoreConfig::Sqlite(SqliteDataStoreConfig {
                    db_url: db_path.clone(),
                    run_repairs: true,
                    skip_broken: false,
                }),
                http: HttpConfig {
                    bind: Some(format!("127.0.0.1:{port}")),
                    ..Default::default()
                },
                frontend: Default::default(),
                oidc: None,
                tracing: Default::default(),
                dav_push: Default::default(),
                nextcloud_login: Default::default(),
                caldav: Default::default(),
                scheduling: Default::default(),
                subscriptions: SubscriptionsConfig {
                    enabled: true,
                    public_url: Some(origin.clone()),
                },
                registration: Default::default(),
                maintenance: Default::default(),
            };

            cmd_invites(
                InvitesArgs {
                    command: InvitesCommand::Create(InviteCreateArgs {
                        email: Some("new@example.com".to_owned()),
                        group: None,
                        expires: None,
                        created_by: "test".to_owned(),
                    }),
                },
                config.clone(),
            )
            .await
            .unwrap();

            let db = create_db_pool(&db_path, false).await.unwrap();
            let (send, _recv) = tokio::sync::mpsc::channel(1);
            let invite_store = SqliteInviteStore::new(SqliteCalendarStore::new(db, send, false));
            let invites = invite_store.list_invites(false).await.unwrap();
            assert_eq!(invites.len(), 1);
            let code = invites[0].code.clone();

            let client = reqwest::Client::builder()
                .redirect(Policy::none())
                .cookie_store(true)
                .build()
                .unwrap();

            let form_html = client
                .get(format!("{origin}/register"))
                .send()
                .await
                .unwrap()
                .text()
                .await
                .unwrap();
            let csrf = csrf_from(&form_html);
            assert!(!csrf.is_empty(), "{form_html}");

            let mut form = HashMap::new();
            form.insert("email", "new@example.com");
            form.insert("displayname", "New User");
            form.insert("password", "correct horse battery staple");
            form.insert("password_confirm", "correct horse battery staple");
            form.insert("invite", code.as_str());
            form.insert("csrf", csrf.as_str());
            let resp = client
                .post(format!("{origin}/register"))
                .form(&form)
                .send()
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
            let body = resp.text().await.unwrap();
            assert!(body.contains("new@example.com"), "{body}");
            assert!(body.contains("/export/"), "{body}");
            assert!(body.contains(".ics"), "{body}");
            assert!(body.contains(".vcf"), "{body}");

            let db = create_db_pool(&db_path, false).await.unwrap();
            let principal_store = SqlitePrincipalStore::new(db.clone());
            let principal = principal_store
                .get_principal("new@example.com")
                .await
                .unwrap()
                .unwrap();
            assert!(principal.password.is_some());
            assert_eq!(
                principal_store
                    .get_app_tokens(&principal.id)
                    .await
                    .unwrap()
                    .len(),
                5
            );

            let (send, _recv) = tokio::sync::mpsc::channel(1);
            let cal_store = SqliteCalendarStore::new(db.clone(), send, false);
            cal_store
                .get_calendar(&principal.id, "personal", false)
                .await
                .unwrap();
            cal_store
                .get_calendar(&principal.id, "tasks", false)
                .await
                .unwrap();
            let (send, _recv) = tokio::sync::mpsc::channel(1);
            SqliteAddressbookStore::new(db.clone(), send, false)
                .get_addressbook(&principal.id, "personal", false)
                .await
                .unwrap();
            let (send, _recv) = tokio::sync::mpsc::channel(1);
            let subs =
                SqliteSubscriptionStore::new(SqliteCalendarStore::new(db.clone(), send, false))
                    .get_subscriptions(&principal.id)
                    .await
                    .unwrap();
            assert_eq!(subs.len(), 2);
            for sub in &subs {
                let ext = match sub.kind {
                    SubscriptionKind::Calendar => "ics",
                    SubscriptionKind::Addressbook => "vcf",
                };
                let resp = reqwest::get(format!("{origin}/export/{}.{ext}", sub.token))
                    .await
                    .unwrap();
                assert_eq!(resp.status(), StatusCode::OK, "{}.{ext}", sub.token);
            }

            let resp = client
                .get(format!("{origin}/register"))
                .send()
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::SEE_OTHER);

            // Single-use: a fresh session with the same code matches the unknown-code body.
            let client2 = reqwest::Client::builder()
                .redirect(Policy::none())
                .cookie_store(true)
                .build()
                .unwrap();
            let form_html = client2
                .get(format!("{origin}/register"))
                .send()
                .await
                .unwrap()
                .text()
                .await
                .unwrap();
            let csrf = csrf_from(&form_html);
            let mut reuse = HashMap::new();
            reuse.insert("email", "other@example.com");
            reuse.insert("password", "correct horse battery staple");
            reuse.insert("password_confirm", "correct horse battery staple");
            reuse.insert("invite", code.as_str());
            reuse.insert("csrf", csrf.as_str());
            let used = client2
                .post(format!("{origin}/register"))
                .form(&reuse)
                .send()
                .await
                .unwrap();
            assert_eq!(used.status(), StatusCode::BAD_REQUEST);
            let used_body = used.text().await.unwrap();

            let form_html = client2
                .get(format!("{origin}/register"))
                .send()
                .await
                .unwrap()
                .text()
                .await
                .unwrap();
            let csrf = csrf_from(&form_html);
            let mut unknown = HashMap::new();
            unknown.insert("email", "third@example.com");
            unknown.insert("password", "correct horse battery staple");
            unknown.insert("password_confirm", "correct horse battery staple");
            unknown.insert("invite", "no-such-code");
            unknown.insert("csrf", csrf.as_str());
            let unknown_resp = client2
                .post(format!("{origin}/register"))
                .form(&unknown)
                .send()
                .await
                .unwrap();
            assert_eq!(unknown_resp.status(), StatusCode::BAD_REQUEST);
            let unknown_body = unknown_resp.text().await.unwrap();
            assert_eq!(alert_from(&used_body), alert_from(&unknown_body));
            assert_eq!(
                alert_from(&used_body),
                "Invalid or expired invitation code."
            );
        },
    )
    .await;
}
