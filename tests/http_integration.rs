// This integration test checks whether the HTTP server works by actually running rustical in a new
// thread.
use common::{rustical_process, rustical_process_with};
use http::{Method, StatusCode};
use reqwest::redirect::Policy;
use rustical::{
    PrincipalsArgs, cmd_health, cmd_invites, cmd_principals, cmd_subscriptions,
    config::{
        Config, DataStoreConfig, HttpConfig, MirrorConfig, SqliteDataStoreConfig,
        SubscriptionsConfig, TenancyConfig,
    },
    invites::{CreateArgs as InviteCreateArgs, InvitesArgs, InvitesCommand},
    membership::{AssignArgs, MembershipArgs, MembershipCommand},
    principals::{CreateArgs, EditArgs, PrincipalsCommand},
    subscriptions::{AddArgs, KindArg, RemoveArgs, SubscriptionsArgs, SubscriptionsCommand},
};
use rustical_ical::{AddressObject, CalendarObject, CalendarObjectType};
use rustical_store::auth::{AuthenticationProvider, PrincipalType};
use rustical_store::{
    Addressbook, AddressbookReadStore, AddressbookWriteStore, Calendar, CalendarMetadata,
    CalendarReadStore, CalendarSourceStore, CalendarWriteStore, InviteStore, SubscriptionKind,
    SubscriptionStore,
};
use rustical_store_sqlite::{
    SqliteAddressbookStore, SqliteCalendarSourceStore, SqliteCalendarStore, SqliteInviteStore,
    SqlitePrincipalStore, SqliteSubscriptionStore, create_db_pool,
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

    // Wait for RustiCal server to listen. The budget is generous on purpose:
    // under tarpaulin's ptrace instrumentation (the CI coverage job) every
    // syscall of the spawned server is intercepted, several servers start in
    // parallel, and a 2s budget failed the coverage run — a wait that only
    // ever costs time when the server is genuinely not coming up (which
    // fails the test either way).
    tokio::time::timeout(Duration::from_secs(30), start_notify.notified())
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

    // Wait for RustiCal server to listen — same generous budget as
    // `test_runner` (see there for why 2s failed the CI coverage run).
    tokio::time::timeout(Duration::from_secs(30), start_notify.notified())
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
                tenancy: TenancyConfig::default(),
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
                mirror: Default::default(),
                registration: Default::default(),
                maintenance: Default::default(),
                appliance: Default::default(),
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
                tenancy: TenancyConfig::default(),
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
                mirror: Default::default(),
                registration: Default::default(),
                maintenance: Default::default(),
                appliance: Default::default(),
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
            tenancy: TenancyConfig::default(),
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
            mirror: Default::default(),
            registration: Default::default(),
            maintenance: Default::default(),
            appliance: Default::default(),
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
                tenancy: TenancyConfig::default(),
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
                mirror: MirrorConfig::default(),
                registration: Default::default(),
                maintenance: Default::default(),
                appliance: Default::default(),
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
                tenancy: TenancyConfig::default(),
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
                mirror: MirrorConfig::default(),
                registration: Default::default(),
                maintenance: Default::default(),
                appliance: Default::default(),
            };

            cmd_invites(
                InvitesArgs {
                    command: InvitesCommand::Create(InviteCreateArgs {
                        email: Some("new@example.com".to_owned()),
                        group: None,
                        expires: None,
                        created_by: "test".to_owned(),
                        send: false,
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
            // No app tokens at registration — the user mints them from the
            // profile page when connecting a device.
            assert!(
                principal_store
                    .get_app_tokens(&principal.id)
                    .await
                    .unwrap()
                    .is_empty()
            );

            let (send, _recv) = tokio::sync::mpsc::channel(1);
            let cal_store = SqliteCalendarStore::new(db.clone(), send, false);
            // Seeded displaynames must be NULL: calendar/addressbook
            // displaynames are globally unique, so a hard-coded "Personal"/
            // "Tasks" would 500 the next registration (see the second
            // registration below, which regression-locks this).
            let personal_cal = cal_store
                .get_calendar(&principal.id, "personal", false)
                .await
                .unwrap();
            let tasks_cal = cal_store
                .get_calendar(&principal.id, "tasks", false)
                .await
                .unwrap();
            assert_eq!(personal_cal.meta.displayname, None);
            assert_eq!(tasks_cal.meta.displayname, None);
            let (send, _recv) = tokio::sync::mpsc::channel(1);
            let personal_book = SqliteAddressbookStore::new(db.clone(), send, false)
                .get_addressbook(&principal.id, "personal", false)
                .await
                .unwrap();
            assert_eq!(personal_book.displayname, None);
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

            // Second registration against the same DB: regression-locks the
            // globally-unique displayname collision (before the fix, seeding
            // "Personal"/"Tasks" for a second user collided with the first
            // user's rows and every registration after the first would 500).
            cmd_invites(
                InvitesArgs {
                    command: InvitesCommand::Create(InviteCreateArgs {
                        email: Some("second@example.com".to_owned()),
                        group: None,
                        expires: None,
                        created_by: "test".to_owned(),
                        send: false,
                    }),
                },
                config.clone(),
            )
            .await
            .unwrap();
            let db = create_db_pool(&db_path, false).await.unwrap();
            let (send, _recv) = tokio::sync::mpsc::channel(1);
            let invite_store = SqliteInviteStore::new(SqliteCalendarStore::new(db, send, false));
            let second_code = invite_store
                .list_invites(false)
                .await
                .unwrap()
                .into_iter()
                .find(|invite| invite.code.as_str() != code.as_str())
                .expect("second invite (the first is hidden as used)")
                .code;

            let client3 = reqwest::Client::builder()
                .redirect(Policy::none())
                .cookie_store(true)
                .build()
                .unwrap();
            let form_html = client3
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
            form.insert("email", "second@example.com");
            form.insert("displayname", "Second User");
            form.insert("password", "correct horse battery staple");
            form.insert("password_confirm", "correct horse battery staple");
            form.insert("invite", second_code.as_str());
            form.insert("csrf", csrf.as_str());
            let resp = client3
                .post(format!("{origin}/register"))
                .form(&form)
                .send()
                .await
                .unwrap();
            let status = resp.status();
            let body = resp.text().await.unwrap();
            assert_eq!(status, StatusCode::OK, "{body}");
            assert!(body.contains("second@example.com"), "{body}");

            let db = create_db_pool(&db_path, false).await.unwrap();
            let principal_store = SqlitePrincipalStore::new(db.clone());
            let second_principal = principal_store
                .get_principal("second@example.com")
                .await
                .unwrap()
                .unwrap();
            assert!(second_principal.password.is_some());
            assert!(
                principal_store
                    .get_app_tokens(&second_principal.id)
                    .await
                    .unwrap()
                    .is_empty()
            );
            let (send, _recv) = tokio::sync::mpsc::channel(1);
            let cal_store = SqliteCalendarStore::new(db, send, false);
            let second_personal = cal_store
                .get_calendar(&second_principal.id, "personal", false)
                .await
                .unwrap();
            let second_tasks = cal_store
                .get_calendar(&second_principal.id, "tasks", false)
                .await
                .unwrap();
            assert_eq!(second_personal.meta.displayname, None);
            assert_eq!(second_tasks.meta.displayname, None);

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

/// The unified profile page: every former top-level tab (Calendars,
/// Addressbooks, Groups, Linked platforms) is a collapsed `<details>` section
/// on /frontend/user/{user}, the legacy tab URLs deep-link into the same page
/// with their section expanded, and the aggregate Contacts page behaves like
/// the Tasks one (list + picker form + create-redirect).
#[tokio::test]
async fn test_portal_profile_sections_and_contacts() {
    let db_tempfile = tempfile::NamedTempFile::with_suffix(".rustical-test.sqlite3").unwrap();
    let db_path = db_tempfile.path().to_string_lossy().into_owned();

    test_runner_with(
        Some(db_path.clone()),
        |_| {},
        async |port| {
            let origin = format!("http://localhost:{port}");
            let config = Config {
                tenancy: TenancyConfig::default(),
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
                subscriptions: Default::default(),
                mirror: Default::default(),
                registration: Default::default(),
                maintenance: Default::default(),
                appliance: Default::default(),
            };

            // Create the principal (CLI), then set its password.
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
            cmd_principals(
                PrincipalsArgs {
                    command: PrincipalsCommand::Edit(EditArgs {
                        id: "user".to_owned(),
                        name: None,
                        password: false,
                        remove_password: false,
                        for_testing_password_from_arg: Some("pass".to_owned()),
                        principal_type: None,
                    }),
                },
                config.clone(),
            )
            .await
            .unwrap();

            // Seed one addressbook for the Contacts page.
            let db = create_db_pool(&db_path, false).await.unwrap();
            let (send, _recv) = tokio::sync::mpsc::channel(1);
            SqliteAddressbookStore::new(db, send, false)
                .insert_addressbook(Addressbook {
                    id: "people".to_owned(),
                    principal: "user".to_owned(),
                    displayname: Some("People".to_owned()),
                    description: None,
                    deleted_at: None,
                    synctoken: 0,
                    push_topic: "people-push-topic".to_owned(),
                })
                .await
                .unwrap();

            let client = reqwest::Client::builder()
                .redirect(Policy::none())
                .cookie_store(true)
                .build()
                .unwrap();
            let url = origin.clone() + "/frontend/login";
            let resp = client
                .request(Method::POST, &url)
                .form(&[("username", "user"), ("password", "pass")])
                .send()
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::SEE_OTHER);

            {
                // The unified profile page: every former tab is a collapsed
                // section.
                let url = origin.clone() + "/frontend/user/user";
                let resp = client.request(Method::GET, &url).send().await.unwrap();
                assert_eq!(resp.status(), StatusCode::OK);
                let body = resp.text().await.unwrap();
                for id in [
                    "app-tokens-section",
                    "calendars-section",
                    "addressbooks-section",
                    "groups-section",
                    "linked-platforms-section",
                ] {
                    let collapsed = format!(r#"<details class="profile-section" id="{id}">"#);
                    assert!(
                        body.contains(&collapsed),
                        "{id} renders as a collapsed profile section: {body}"
                    );
                }
                // The seeded addressbook is embedded in the Addressbooks
                // section.
                assert!(body.contains("People"), "addressbook listed: {body}");
                // The nav keeps the aggregate frontends …
                assert!(body.contains(r#"href="/frontend/user/user/tasks""#));
                assert!(body.contains(r#"href="/frontend/user/user/contacts""#));
                // … and the former tab entries are gone from the nav.
                // (Scoped to the <nav> itself: §18.43's intro
                // deep-links the Addressbooks section, so a page-wide
                // substring would misfire on the intro, not the nav.)
                let nav_start = body
                    .find(r#"<nav class="header-center">"#)
                    .expect("the nav renders");
                let nav_end = nav_start + body[nav_start..].find("</nav>").expect("the nav closes");
                let nav = &body[nav_start..nav_end];
                assert!(!nav.contains(">Addressbooks</a>"), "nav: {body}");
                assert!(!nav.contains(">Groups</a>"), "nav: {body}");
                assert!(!nav.contains(">Linked platforms</a>"), "nav: {body}");
            }

            {
                // A legacy tab URL renders the same page with its section
                // expanded (deep-link behaviour).
                let url = origin.clone() + "/frontend/user/user/calendar";
                let resp = client.request(Method::GET, &url).send().await.unwrap();
                assert_eq!(resp.status(), StatusCode::OK);
                let body = resp.text().await.unwrap();
                assert!(
                    body.contains(
                        r#"<details class="profile-section" id="calendars-section" open>"#
                    ),
                    "calendars expanded on its deep link: {body}"
                );
                assert!(
                    body.contains(r#"<details class="profile-section" id="addressbooks-section">"#),
                    "addressbooks still collapsed: {body}"
                );
            }

            {
                // The aggregate Contacts page: empty state + create button.
                let url = origin.clone() + "/frontend/user/user/contacts";
                let resp = client.request(Method::GET, &url).send().await.unwrap();
                assert_eq!(resp.status(), StatusCode::OK);
                let body = resp.text().await.unwrap();
                assert!(body.contains("Contacts"), "heading: {body}");
                assert!(body.contains("No contacts yet"), "empty state: {body}");
                assert!(body.contains("New contact"), "create button: {body}");
            }

            {
                // The aggregate form offers the addressbook picker.
                let url = origin.clone() + "/frontend/user/user/contacts/new";
                let resp = client.request(Method::GET, &url).send().await.unwrap();
                assert_eq!(resp.status(), StatusCode::OK);
                let body = resp.text().await.unwrap();
                assert!(body.contains(r#"name="addressbook""#), "picker: {body}");
                assert!(body.contains(r#"value="user|people""#), "offered: {body}");
            }

            {
                // A contact created through the aggregate form lands on the
                // aggregate list, and the per-addressbook list agrees.
                let url = origin.clone() + "/frontend/user/user/contacts";
                let resp = client
                    .request(Method::POST, &url)
                    .form(&[
                        ("addressbook", "user|people"),
                        ("name", "Jane Doe"),
                        ("email", "jane@example.com"),
                    ])
                    .send()
                    .await
                    .unwrap();
                assert_eq!(resp.status(), StatusCode::SEE_OTHER);
                assert_eq!(
                    resp.headers().get("Location").unwrap().to_str().unwrap(),
                    "/frontend/user/user/contacts"
                );

                let resp = client.request(Method::GET, &url).send().await.unwrap();
                let body = resp.text().await.unwrap();
                assert!(body.contains("Jane Doe"), "created contact listed: {body}");
                assert!(body.contains("jane@example.com"), "email rendered: {body}");
                assert!(body.contains("People"), "addressbook label: {body}");

                let url = origin.clone() + "/frontend/user/user/addressbook/people/contacts";
                let resp = client.request(Method::GET, &url).send().await.unwrap();
                assert_eq!(resp.status(), StatusCode::OK);
                let body = resp.text().await.unwrap();
                assert!(body.contains("Jane Doe"), "per-addressbook list: {body}");
            }
        },
    )
    .await;
}

#[tokio::test]
async fn test_portal_holidays() {
    let db_tempfile = tempfile::NamedTempFile::with_suffix(".rustical-test.sqlite3").unwrap();
    let db_path = db_tempfile.path().to_string_lossy().into_owned();
    let holidays_dir = tempfile::tempdir().unwrap();

    // Fixture catalog: two groups, two sets — a multi-select import merges
    // both into one calendar.
    std::fs::write(
        holidays_dir.path().join("holidays.toml"),
        "[[groups]]\n\
         id = \"countries\"\n\
         label = \"Countries\"\n\n\
         [[groups.sets]]\n\
         id = \"us\"\n\
         label = \"United States (federal)\"\n\
         file = \"us.ics\"\n\n\
         [[groups]]\n\
         id = \"judaism\"\n\
         label = \"Judaism\"\n\n\
         [[groups.sets]]\n\
         id = \"judaism\"\n\
         label = \"Jewish holidays\"\n\
         file = \"judaism.ics\"\n",
    )
    .unwrap();
    let us_ics = "BEGIN:VCALENDAR\r\n\
                  PRODID:-//omnical//holidays//EN\r\n\
                  VERSION:2.0\r\n\
                  BEGIN:VEVENT\r\n\
                  UID:hol-us-20260101@omnical\r\n\
                  DTSTAMP:20260101T000000Z\r\n\
                  DTSTART;VALUE=DATE:20260101\r\n\
                  SUMMARY:New Year's Day\r\n\
                  END:VEVENT\r\n\
                  BEGIN:VEVENT\r\n\
                  UID:hol-us-20260704@omnical\r\n\
                  DTSTAMP:20260101T000000Z\r\n\
                  DTSTART;VALUE=DATE:20260704\r\n\
                  SUMMARY:Independence Day\r\n\
                  END:VEVENT\r\n\
                  END:VCALENDAR\r\n";
    std::fs::write(holidays_dir.path().join("us.ics"), us_ics).unwrap();
    std::fs::write(
        holidays_dir.path().join("judaism.ics"),
        "BEGIN:VCALENDAR\r\n\
         PRODID:-//omnical//holidays//EN\r\n\
         VERSION:2.0\r\n\
         BEGIN:VEVENT\r\n\
         UID:hol-judaism-20260912@omnical\r\n\
         DTSTAMP:20260101T000000Z\r\n\
         DTSTART;VALUE=DATE:20260912\r\n\
         SUMMARY:Rosh Hashanah\r\n\
         END:VEVENT\r\n\
         END:VCALENDAR\r\n",
    )
    .unwrap();

    let dir_for_server = holidays_dir.path().to_path_buf();
    test_runner_with(
        Some(db_path.clone()),
        move |config| {
            config.frontend.holidays_dir = Some(dir_for_server);
        },
        async |port| {
            let origin = format!("http://localhost:{port}");
            let config = Config {
                tenancy: TenancyConfig::default(),
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
                subscriptions: Default::default(),
                mirror: Default::default(),
                registration: Default::default(),
                maintenance: Default::default(),
                appliance: Default::default(),
            };

            // Create the principal (CLI), then set its password.
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
            cmd_principals(
                PrincipalsArgs {
                    command: PrincipalsCommand::Edit(EditArgs {
                        id: "user".to_owned(),
                        name: None,
                        password: false,
                        remove_password: false,
                        for_testing_password_from_arg: Some("pass".to_owned()),
                        principal_type: None,
                    }),
                },
                config.clone(),
            )
            .await
            .unwrap();

            // Seed one calendar to import into (the modal creates it with
            // MKCOL; the store seed skips the XML dance).
            let db = create_db_pool(&db_path, false).await.unwrap();
            let (send, _recv) = tokio::sync::mpsc::channel(1);
            SqliteCalendarStore::new(db, send, false)
                .insert_calendar(Calendar {
                    id: "hols".to_owned(),
                    principal: "user".to_owned(),
                    meta: CalendarMetadata {
                        displayname: Some("Holidays".to_owned()),
                        order: 0,
                        description: None,
                        color: None,
                    },
                    timezone_id: None,
                    deleted_at: None,
                    synctoken: 0,
                    subscription_url: None,
                    push_topic: "hols-push-topic".to_owned(),
                    components: vec![CalendarObjectType::Event],
                })
                .await
                .unwrap();

            // The list endpoint is public metadata: names of sets, no
            // credentials needed (same trust class as the timezone list).
            let plain = reqwest::Client::builder().build().unwrap();
            let resp = plain
                .get(origin.clone() + "/frontend/_holidays.json")
                .send()
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
            let body = resp.text().await.unwrap();
            assert!(body.contains("countries"), "list groups: {body}");
            assert!(
                body.contains("United States (federal)"),
                "list sets: {body}"
            );
            assert!(body.contains("Jewish holidays"), "list sets: {body}");

            // Login session for the portal writes.
            let client = reqwest::Client::builder()
                .redirect(Policy::none())
                .cookie_store(true)
                .build()
                .unwrap();
            let resp = client
                .request(Method::POST, origin.clone() + "/frontend/login")
                .form(&[("username", "user"), ("password", "pass")])
                .send()
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::SEE_OTHER);

            // Import two sets in one go — merged into the one calendar.
            let url = origin.clone() + "/frontend/user/user/calendar/hols/holidays";
            let resp = client
                .request(Method::POST, &url)
                .form(&[("principal", "user"), ("sets", "us,judaism")])
                .send()
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK, "import: {url}");
            let body = resp.text().await.unwrap();
            assert!(body.contains("\"imported\":2"), "import count: {body}");

            // Both sets' events materialized as one calendar's objects.
            let db = create_db_pool(&db_path, false).await.unwrap();
            let (send, _recv) = tokio::sync::mpsc::channel(1);
            let cal_store = SqliteCalendarStore::new(db, send, false);
            let objects = cal_store.get_objects("user", "hols").await.unwrap();
            let uids: std::collections::HashSet<_> =
                objects.iter().map(|(id, _)| id.as_str()).collect();
            assert_eq!(objects.len(), 3, "3 events from 2 sets: {uids:?}");
            for uid in [
                "hol-us-20260101@omnical",
                "hol-us-20260704@omnical",
                "hol-judaism-20260912@omnical",
            ] {
                assert!(uids.contains(uid), "merged UID {uid}: {uids:?}");
            }

            // Re-import is idempotent: same UIDs overwrite, never duplicate.
            let resp = client
                .request(Method::POST, &url)
                .form(&[("principal", "user"), ("sets", "us,judaism")])
                .send()
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
            let objects = cal_store.get_objects("user", "hols").await.unwrap();
            assert_eq!(objects.len(), 3, "no duplicates: {objects:?}");

            // The sources recorded per set show with their manifest labels
            // on the unified profile page.
            let resp = client
                .get(origin.clone() + "/frontend/user/user")
                .send()
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
            let body = resp.text().await.unwrap();
            assert!(
                body.contains("Holidays · United States (federal)"),
                "source label: {body}"
            );
            assert!(body.contains("Holidays · Jewish holidays"), "label: {body}");

            // Refresh: mutate the set on disk, refresh the holidays://us
            // source via the linked-platforms flow, the new event arrives
            // by the same by-UID diff as any other source.
            std::fs::write(
                holidays_dir.path().join("us.ics"),
                "BEGIN:VCALENDAR\r\n\
                 PRODID:-//omnical//holidays//EN\r\n\
                 VERSION:2.0\r\n\
                 BEGIN:VEVENT\r\n\
                 UID:hol-us-20260101@omnical\r\n\
                 DTSTAMP:20260101T000000Z\r\n\
                 DTSTART;VALUE=DATE:20260101\r\n\
                 SUMMARY:New Year's Day\r\n\
                 END:VEVENT\r\n\
                 BEGIN:VEVENT\r\n\
                 UID:hol-us-20260704@omnical\r\n\
                 DTSTAMP:20260101T000000Z\r\n\
                 DTSTART;VALUE=DATE:20260704\r\n\
                 SUMMARY:Independence Day\r\n\
                 END:VEVENT\r\n\
                 BEGIN:VEVENT\r\n\
                 UID:hol-us-20261126@omnical\r\n\
                 DTSTAMP:20260101T000000Z\r\n\
                 DTSTART;VALUE=DATE:20261126\r\n\
                 SUMMARY:Thanksgiving\r\n\
                 END:VEVENT\r\n\
                 END:VCALENDAR\r\n",
            )
            .unwrap();
            let source_store = SqliteCalendarSourceStore::new(SqliteCalendarStore::new(
                create_db_pool(&db_path, false).await.unwrap(),
                tokio::sync::mpsc::channel(1).0,
                false,
            ));
            let sources = source_store.get_calendar_sources("user").await.unwrap();
            let us_source = sources
                .iter()
                .find(|s| s.source_url == "holidays://us")
                .expect("the holidays://us source row");
            let refresh_url = format!(
                "{origin}/frontend/user/user/linked-platforms/{}/refresh",
                us_source.id
            );
            let resp = client.post(&refresh_url).send().await.unwrap();
            assert_eq!(
                resp.status(),
                StatusCode::SEE_OTHER,
                "refresh: {}",
                resp.text().await.unwrap()
            );
            let objects = cal_store.get_objects("user", "hols").await.unwrap();
            let uids: std::collections::HashSet<_> =
                objects.iter().map(|(id, _)| id.as_str()).collect();
            assert!(
                uids.contains("hol-us-20261126@omnical"),
                "refresh: {uids:?}"
            );
            assert_eq!(objects.len(), 4, "one added, none lost: {uids:?}");

            // Unknown set ids are refused before any row is written.
            let resp = client
                .request(Method::POST, &url)
                .form(&[("principal", "user"), ("sets", "us,nope")])
                .send()
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
            let body = resp.text().await.unwrap();
            assert!(body.contains("nope"), "names the bad set: {body}");

            // Unauthenticated imports do nothing.
            let resp = plain
                .request(Method::POST, &url)
                .form(&[("principal", "user"), ("sets", "us")])
                .send()
                .await
                .unwrap();
            assert_ne!(resp.status(), StatusCode::OK, "unauthenticated: {resp:?}");
            let objects = cal_store.get_objects("user", "hols").await.unwrap();
            assert_eq!(objects.len(), 4, "untouched: {objects:?}");
        },
    )
    .await;
}

// ---------------------------------------------------------------------------
// Print pages (PLAN_NEXT_AGENT_PRINTING.md §5): sticker sheets + letter
// lists for events/tasks/contacts, with print-state tracking (new vs all).
// ---------------------------------------------------------------------------

/// The full `Config` literal every portal test in this file builds — the
/// spawned server's arguments (see `test_portal_profile_sections_and_contacts`
/// for the shape's origin).
fn print_test_config(db_path: &str, port: u16) -> Config {
    Config {
        tenancy: TenancyConfig::default(),
        data_store: DataStoreConfig::Sqlite(SqliteDataStoreConfig {
            db_url: db_path.to_owned(),
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
        subscriptions: Default::default(),
        mirror: Default::default(),
        registration: Default::default(),
        maintenance: Default::default(),
        appliance: Default::default(),
    }
}

/// Create a principal with a password, the way the portal tests do.
async fn print_test_principal(config: &Config, id: &str, password: &str) {
    cmd_principals(
        PrincipalsArgs {
            command: PrincipalsCommand::Create(CreateArgs {
                id: id.to_owned(),
                name: Some(id.to_owned()),
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
    cmd_principals(
        PrincipalsArgs {
            command: PrincipalsCommand::Edit(EditArgs {
                id: id.to_owned(),
                name: None,
                password: false,
                remove_password: false,
                for_testing_password_from_arg: Some(password.to_owned()),
                principal_type: None,
            }),
        },
        config.clone(),
    )
    .await
    .unwrap();
}

/// A logged-in cookie client.
async fn print_test_client(origin: &str, username: &str, password: &str) -> reqwest::Client {
    let client = reqwest::Client::builder()
        .redirect(Policy::none())
        .cookie_store(true)
        .build()
        .unwrap();
    let resp = client
        .post(format!("{origin}/frontend/login"))
        .form(&[("username", username), ("password", password)])
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    client
}

/// The hidden mark inputs the print page renders (`name="markN"
/// value="…"`): indexed names, one per rendered sticker.
fn print_test_marks(body: &str) -> Vec<String> {
    body.split("name=\"mark")
        .skip(1)
        .filter_map(|rest| {
            let value = rest.split("value=\"").nth(1)?;
            Some(value.split('"').next().unwrap_or_default().to_owned())
        })
        .collect()
}

#[tokio::test]
async fn test_print_events_stickers_new_then_all() {
    let db_tempfile = tempfile::NamedTempFile::with_suffix(".rustical-test.sqlite3").unwrap();
    let db_path = db_tempfile.path().to_string_lossy().into_owned();

    test_runner_with(
        Some(db_path.clone()),
        |_| {},
        async |port| {
            let origin = format!("http://localhost:{port}");
            let config = print_test_config(&db_path, port);
            print_test_principal(&config, "user", "pass").await;

            // One calendar; a dated event and a weekly series inside October.
            let db = create_db_pool(&db_path, false).await.unwrap();
            let (send, _recv) = tokio::sync::mpsc::channel(1);
            let cal_store = SqliteCalendarStore::new(db, send, false);
            cal_store
                .insert_calendar(Calendar {
                    id: "personal".to_owned(),
                    principal: "user".to_owned(),
                    meta: CalendarMetadata {
                        displayname: Some("Personal".to_owned()),
                        order: 0,
                        description: None,
                        color: Some("#3a87ad".to_owned()),
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
            cal_store
                .put_object(
                    "user",
                    "personal",
                    "obj-dentist",
                    CalendarObject::from_ics(
                        "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//omnical//test//EN\r\n\
                         BEGIN:VEVENT\r\nUID:dentist@omnical\r\nSUMMARY:Dentist\r\nDTSTAMP:20260925T103702Z\r\n\
                         DTSTART:20261014T180000Z\r\nDTEND:20261014T183000Z\r\n\
                         END:VEVENT\r\nEND:VCALENDAR\r\n"
                            .to_owned(),
                    )
                    .unwrap(),
                    false,
                )
                .await
                .unwrap();
            cal_store
                .put_object(
                    "user",
                    "personal",
                    "obj-trash",
                    CalendarObject::from_ics(
                        "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//omnical//test//EN\r\n\
                         BEGIN:VEVENT\r\nUID:trash-day@omnical\r\nSUMMARY:Trash day\r\nDTSTAMP:20260925T103702Z\r\n\
                         DTSTART:20261005T190000Z\r\nDTEND:20261005T200000Z\r\n\
                         RRULE:FREQ=WEEKLY\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"
                            .to_owned(),
                    )
                    .unwrap(),
                    false,
                )
                .await
                .unwrap();

            let client = print_test_client(&origin, "user", "pass").await;
            let per_calendar = format!(
                "{origin}/frontend/user/user/calendar/personal/events/print\
                 ?scope=new&format=stickers&date=2026-10"
            );

            // Stickers for the month: the dated event plus one sticker per
            // concrete recurrence instance (Mondays 5, 12, 19, 26 October).
            let resp = client.get(&per_calendar).send().await.unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
            let body = resp.text().await.unwrap();
            assert!(body.contains("sticker-sheet"), "sticker layout: {body}");
            assert!(body.contains("Dentist"), "dated event: {body}");
            let trash_positions: Vec<usize> =
                body.match_indices("Trash day").map(|(i, _)| i).collect();
            assert_eq!(trash_positions.len(), 4, "weekly instances: {body}");
            let dentist_pos = body.find("Dentist").expect("the dated event");
            assert!(
                trash_positions[1] < dentist_pos && dentist_pos < trash_positions[2],
                "chronological: {body}"
            );
            let marks = print_test_marks(&body);
            assert_eq!(marks.len(), 5, "one mark per rendered sticker: {body}");

            // The aggregate Calendar tab prints the same data set.
            let aggregate = format!(
                "{origin}/frontend/user/user/events/print?scope=new&format=stickers&date=2026-10"
            );
            let resp = client.get(&aggregate).send().await.unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
            let aggregate_body = resp.text().await.unwrap();
            assert!(
                aggregate_body.contains("Dentist"),
                "aggregate: {aggregate_body}"
            );
            assert!(
                aggregate_body.match_indices("Trash day").count() == 4,
                "aggregate weekly instances: {aggregate_body}"
            );

            // Paper format: same data, letter list.
            let paper = format!(
                "{origin}/frontend/user/user/calendar/personal/events/print\
                 ?scope=new&format=paper&date=2026-10"
            );
            let resp = client.get(&paper).send().await.unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
            let paper_body = resp.text().await.unwrap();
            assert!(
                paper_body.contains("paper-list"),
                "paper layout: {paper_body}"
            );
            assert!(
                !paper_body.contains("sticker-sheet"),
                "no stickers: {paper_body}"
            );

            // Marking printed is an explicit POST, then the "new" scope is
            // empty and "all" still shows everything.
            let mut form: Vec<(String, String)> = marks
                .iter()
                .enumerate()
                .map(|(index, mark)| (format!("mark{index}"), mark.clone()))
                .collect();
            form.push(("format".to_owned(), "stickers".to_owned()));
            form.push(("date".to_owned(), "2026-10".to_owned()));
            let resp = client.post(&per_calendar).form(&form).send().await.unwrap();
            assert_eq!(resp.status(), StatusCode::SEE_OTHER);
            let location = resp
                .headers()
                .get("Location")
                .unwrap()
                .to_str()
                .unwrap()
                .to_owned();

            let resp = client
                .get(format!("{origin}{location}"))
                .send()
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
            let body = resp.text().await.unwrap();
            assert!(body.contains("Marked 5 as printed"), "banner: {body}");
            assert!(
                body.contains("Nothing new to print"),
                "new scope drained: {body}"
            );
            assert!(
                !body.contains("Dentist"),
                "marked events gone from new: {body}"
            );

            let resp = client.get(&per_calendar).send().await.unwrap();
            let body = resp.text().await.unwrap();
            assert!(
                !body.contains("Dentist"),
                "still gone on a fresh GET: {body}"
            );
            assert_eq!(print_test_marks(&body).len(), 0, "no marks left: {body}");

            let all = format!(
                "{origin}/frontend/user/user/calendar/personal/events/print\
                 ?scope=all&format=stickers&date=2026-10"
            );
            let resp = client.get(&all).send().await.unwrap();
            let body = resp.text().await.unwrap();
            assert!(body.contains("Dentist"), "all scope keeps them: {body}");
            assert_eq!(print_test_marks(&body).len(), 5, "all-scope marks: {body}");
        },
    )
    .await;
}

#[tokio::test]
async fn test_print_events_next_month_instances_are_new() {
    let db_tempfile = tempfile::NamedTempFile::with_suffix(".rustical-test.sqlite3").unwrap();
    let db_path = db_tempfile.path().to_string_lossy().into_owned();

    test_runner_with(
        Some(db_path.clone()),
        |_| {},
        async |port| {
            let origin = format!("http://localhost:{port}");
            let config = print_test_config(&db_path, port);
            print_test_principal(&config, "user", "pass").await;

            let db = create_db_pool(&db_path, false).await.unwrap();
            let (send, _recv) = tokio::sync::mpsc::channel(1);
            let cal_store = SqliteCalendarStore::new(db, send, false);
            cal_store
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
            cal_store
                .put_object(
                    "user",
                    "personal",
                    "obj-trash",
                    CalendarObject::from_ics(
                        "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//omnical//test//EN\r\n\
                         BEGIN:VEVENT\r\nUID:trash-day@omnical\r\nSUMMARY:Trash day\r\nDTSTAMP:20260925T103702Z\r\n\
                         DTSTART:20261005T190000Z\r\nDTEND:20261005T200000Z\r\n\
                         RRULE:FREQ=WEEKLY\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"
                            .to_owned(),
                    )
                    .unwrap(),
                    false,
                )
                .await
                .unwrap();

            let client = print_test_client(&origin, "user", "pass").await;
            let october = format!(
                "{origin}/frontend/user/user/calendar/personal/events/print\
                 ?scope=new&format=stickers&date=2026-10"
            );

            // Mark October's four instances printed.
            let resp = client.get(&october).send().await.unwrap();
            let body = resp.text().await.unwrap();
            let mut form: Vec<(String, String)> = print_test_marks(&body)
                .into_iter()
                .enumerate()
                .map(|(index, mark)| (format!("mark{index}"), mark))
                .collect();
            form.push(("format".to_owned(), "stickers".to_owned()));
            form.push(("date".to_owned(), "2026-10".to_owned()));
            let resp = client.post(&october).form(&form).send().await.unwrap();
            assert_eq!(resp.status(), StatusCode::SEE_OTHER);

            // November: the same series, but next month's instances were never
            // printed — they are new stickers again (plan D4: per-instance
            // keys, not per-master marks).
            let november = format!(
                "{origin}/frontend/user/user/calendar/personal/events/print\
                 ?scope=new&format=stickers&date=2026-11"
            );
            let resp = client.get(&november).send().await.unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
            let body = resp.text().await.unwrap();
            assert!(
                !body.contains("Nothing new to print"),
                "next month has new instances: {body}"
            );
            assert_eq!(
                body.match_indices("Trash day").count(),
                5,
                "the five November Mondays: {body}"
            );
            let marks = print_test_marks(&body);
            assert_eq!(marks.len(), 5, "one per November instance: {body}");
            assert!(
                marks.iter().all(|mark| mark.contains("202611")),
                "instance keys are November starts: {marks:?}"
            );
        },
    )
    .await;
}

#[tokio::test]
async fn test_print_tasks_and_contacts() {
    let db_tempfile = tempfile::NamedTempFile::with_suffix(".rustical-test.sqlite3").unwrap();
    let db_path = db_tempfile.path().to_string_lossy().into_owned();

    test_runner_with(
        Some(db_path.clone()),
        |_| {},
        async |port| {
            let origin = format!("http://localhost:{port}");
            let config = print_test_config(&db_path, port);
            print_test_principal(&config, "user", "pass").await;

            let db = create_db_pool(&db_path, false).await.unwrap();
            let (send, _recv) = tokio::sync::mpsc::channel(1);
            let cal_store = SqliteCalendarStore::new(db.clone(), send.clone(), false);
            cal_store
                .insert_calendar(Calendar {
                    id: "chores".to_owned(),
                    principal: "user".to_owned(),
                    meta: CalendarMetadata {
                        displayname: Some("Chores".to_owned()),
                        order: 0,
                        description: None,
                        color: None,
                    },
                    timezone_id: None,
                    deleted_at: None,
                    synctoken: 0,
                    subscription_url: None,
                    push_topic: "chores-push-topic".to_owned(),
                    components: vec![CalendarObjectType::Todo],
                })
                .await
                .unwrap();
            cal_store
                .put_object(
                    "user",
                    "chores",
                    "obj-milk",
                    CalendarObject::from_ics(
                        "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//omnical//test//EN\r\n\
                         BEGIN:VTODO\r\nUID:buy-milk@omnical\r\nSUMMARY:Buy milk\r\nDTSTAMP:20260925T103702Z\r\n\
                         DUE:20261020T120000Z\r\nSTATUS:NEEDS-ACTION\r\n\
                         END:VTODO\r\nEND:VCALENDAR\r\n"
                            .to_owned(),
                    )
                    .unwrap(),
                    false,
                )
                .await
                .unwrap();

            let addr_store = SqliteAddressbookStore::new(db, send, false);
            addr_store
                .insert_addressbook(Addressbook {
                    id: "people".to_owned(),
                    principal: "user".to_owned(),
                    displayname: Some("People".to_owned()),
                    description: None,
                    deleted_at: None,
                    synctoken: 0,
                    push_topic: "people-push-topic".to_owned(),
                })
                .await
                .unwrap();
            AddressbookWriteStore::put_object(
                &addr_store,
                "user",
                "people",
                "obj-ada",
                AddressObject::from_vcf(
                    "BEGIN:VCARD\r\nVERSION:4.0\r\nFN:Ada Example\r\n\
                         N:Example;Ada;;;\r\nTEL:+15550100\r\nEMAIL:ada@example.com\r\n\
                         END:VCARD\r\n"
                        .to_owned(),
                )
                .unwrap(),
                false,
            )
            .await
            .unwrap();

            let client = print_test_client(&origin, "user", "pass").await;

            // Tasks: sticker and paper, aggregate and per-tab hrefs.
            let tasks_print = format!("{origin}/frontend/user/user/tasks/print");
            let resp = client
                .get(format!("{tasks_print}?scope=new&format=stickers"))
                .send()
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
            let body = resp.text().await.unwrap();
            assert!(body.contains("Buy milk"), "task sticker: {body}");
            assert!(body.contains("NEEDS-ACTION"), "task status: {body}");
            assert!(body.contains("due 12:00"), "task due time: {body}");
            let marks = print_test_marks(&body);
            assert_eq!(marks.len(), 1, "whole-object mark: {body}");

            let resp = client
                .get(format!("{tasks_print}?scope=new&format=paper"))
                .send()
                .await
                .unwrap();
            let body = resp.text().await.unwrap();
            assert!(body.contains("paper-list"), "paper layout: {body}");
            assert!(body.contains("Buy milk"), "paper keeps the task: {body}");

            // Mark the task printed, then it is gone from "new".
            let resp = client
                .post(&tasks_print)
                .form(&[("mark0", marks[0].clone()), ("format", "paper".to_owned())])
                .send()
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::SEE_OTHER);
            let resp = client
                .get(format!("{tasks_print}?scope=new"))
                .send()
                .await
                .unwrap();
            let body = resp.text().await.unwrap();
            assert!(
                !body.contains("Buy milk"),
                "marked task drained from new: {body}"
            );
            let resp = client
                .get(format!("{tasks_print}?scope=all"))
                .send()
                .await
                .unwrap();
            let body = resp.text().await.unwrap();
            assert!(body.contains("Buy milk"), "all keeps it: {body}");

            // Contacts: aggregate and per-addressbook.
            let resp = client
                .get(format!(
                    "{origin}/frontend/user/user/contacts/print?scope=new&format=stickers"
                ))
                .send()
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
            let body = resp.text().await.unwrap();
            assert!(body.contains("Ada Example"), "contact sticker: {body}");
            assert!(body.contains("ada@example.com"), "contact email: {body}");
            assert!(body.contains("+15550100"), "contact phone: {body}");

            let resp = client
                .get(format!(
                    "{origin}/frontend/user/user/addressbook/people/contacts/print\
                     ?scope=new&format=stickers"
                ))
                .send()
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
            let body = resp.text().await.unwrap();
            assert!(body.contains("Ada Example"), "per-addressbook: {body}");
            let marks = print_test_marks(&body);
            assert_eq!(marks.len(), 1, "one contact mark: {body}");

            // Mark the contact printed, then it is gone from "new".
            let resp = client
                .post(format!(
                    "{origin}/frontend/user/user/addressbook/people/contacts/print"
                ))
                .form(&[
                    ("mark0", marks[0].clone()),
                    ("format", "stickers".to_owned()),
                ])
                .send()
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::SEE_OTHER);
            let resp = client
                .get(format!(
                    "{origin}/frontend/user/user/contacts/print?scope=new"
                ))
                .send()
                .await
                .unwrap();
            let body = resp.text().await.unwrap();
            assert!(
                !body.contains("Ada Example"),
                "marked contact drained from new: {body}"
            );
        },
    )
    .await;
}

#[tokio::test]
async fn test_print_gates() {
    let db_tempfile = tempfile::NamedTempFile::with_suffix(".rustical-test.sqlite3").unwrap();
    let db_path = db_tempfile.path().to_string_lossy().into_owned();

    test_runner_with(
        Some(db_path.clone()),
        |_| {},
        async |port| {
            let origin = format!("http://localhost:{port}");
            let config = print_test_config(&db_path, port);
            print_test_principal(&config, "user", "pass").await;
            print_test_principal(&config, "other", "pass").await;

            let db = create_db_pool(&db_path, false).await.unwrap();
            let (send, _recv) = tokio::sync::mpsc::channel(1);
            let cal_store = SqliteCalendarStore::new(db.clone(), send.clone(), false);
            cal_store
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
            let addr_store = SqliteAddressbookStore::new(db, send, false);
            addr_store
                .insert_addressbook(Addressbook {
                    id: "people".to_owned(),
                    principal: "user".to_owned(),
                    displayname: Some("People".to_owned()),
                    description: None,
                    deleted_at: None,
                    synctoken: 0,
                    push_topic: "people-push-topic".to_owned(),
                })
                .await
                .unwrap();

            // The non-member cannot print another principal's calendar …
            let other = print_test_client(&origin, "other", "pass").await;
            for url in [
                format!("{origin}/frontend/user/user/calendar/personal/events/print"),
                format!("{origin}/frontend/user/user/events/print"),
                format!("{origin}/frontend/user/user/tasks/print"),
                format!("{origin}/frontend/user/user/contacts/print"),
                format!("{origin}/frontend/user/user/addressbook/people/contacts/print"),
            ] {
                let resp = other.get(&url).send().await.unwrap();
                assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "{url}");
            }
            // … and cannot mark printed on it either (the GET renders the
            // form, the POST must refuse just as hard).
            let resp = other
                .post(format!(
                    "{origin}/frontend/user/user/calendar/personal/events/print"
                ))
                .form(&[(
                    "mark0",
                    "user\u{1f}personal\u{1f}obj-stolen\u{1f}".to_owned(),
                )])
                .send()
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

            // The owner's own pages still answer.
            let user = print_test_client(&origin, "user", "pass").await;
            let resp = user
                .get(format!("{origin}/frontend/user/user/events/print"))
                .send()
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
            // `other`'s own aggregate page answers too (its own calendars,
            // of which it has none — an empty, bannered page, not an error).
            let resp = other
                .get(format!("{origin}/frontend/user/other/events/print"))
                .send()
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
        },
    )
    .await;
}
