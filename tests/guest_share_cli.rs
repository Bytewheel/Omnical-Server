//! CLI round-trip test for the guest-share extension (PLAN.md §17.10.8):
//! `guest-share add` → `guest-share list` → `guest-share revoke`, asserted
//! against the database after every step.
use rustical::config::{Config, DataStoreConfig, SqliteDataStoreConfig, TenancyConfig};
use rustical::guest_shares::{AddArgs, GuestShareCommand, ListArgs, PrivilegeArg, RevokeArgs};
use rustical::{GuestSharesArgs, cmd_guest_shares};
use rustical_store::auth::{AuthenticationProvider, Principal, PrincipalType, Privilege};
use rustical_store::{
    Calendar, CalendarMetadata, CalendarWriteStore, CollectionShare, CollectionShareStore,
};
use rustical_store_sqlite::{
    SqliteCalendarStore, SqliteCollectionShareStore, SqlitePrincipalStore, create_db_pool,
};

fn test_config(db_url: String) -> Config {
    Config {
        tenancy: TenancyConfig::default(),
        data_store: DataStoreConfig::Sqlite(SqliteDataStoreConfig {
            db_url,
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
    }
}

#[tokio::test]
async fn test_guest_share_cli_roundtrip() {
    let db_tempfile = tempfile::NamedTempFile::with_suffix(".rustical-test.sqlite3").unwrap();
    let db_url = db_tempfile.path().to_string_lossy().into_owned();

    let pool = create_db_pool(&db_url, true).await.unwrap();
    let (send_cal, _recv) = tokio::sync::mpsc::channel(1);
    let principal_store = SqlitePrincipalStore::new(pool.clone());
    let cal_store = SqliteCalendarStore::new(pool.clone(), send_cal, false);

    // Owner + a calendar to invite a guest into.
    principal_store
        .insert_principal(
            Principal {
                id: "user".to_owned(),
                displayname: None,
                memberships: vec![],
                password: None,
                principal_type: PrincipalType::Individual,
                needs_password_change: false,
                privileges: Default::default(),
            },
            false,
        )
        .await
        .unwrap();
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
            push_topic: "cli-guest-test".to_owned(),
            components: vec![rustical_ical::CalendarObjectType::Event],
        })
        .await
        .unwrap();

    // `add` mints the guest principal, app token and share row.
    cmd_guest_shares(
        GuestSharesArgs {
            command: GuestShareCommand::Add(AddArgs {
                owner: "user".to_owned(),
                collection_id: "personal".to_owned(),
                privilege: PrivilegeArg::Edit,
                email: Some("guest@example.com".to_owned()),
            }),
        },
        test_config(db_url.clone()),
    )
    .await
    .unwrap();

    let share_store = SqliteCollectionShareStore::new(cal_store.clone());
    let shares: Vec<CollectionShare> = share_store.list_guest_shares("user").await.unwrap();
    assert_eq!(shares.len(), 1, "add must create exactly one share");
    let share = &shares[0];
    assert_eq!(share.collection_id, "personal");
    assert_eq!(share.privilege, Privilege::Edit);
    assert_eq!(share.kind, "calendar");
    assert_eq!(share.target_email.as_deref(), Some("guest@example.com"));
    assert!(
        share.guest_principal.starts_with("guest-"),
        "guest principal must be guest-*: {}",
        share.guest_principal
    );

    // The guest is a real, login-free individual principal with an app token.
    assert!(
        principal_store
            .get_principal(&share.guest_principal)
            .await
            .unwrap()
            .is_some(),
        "guest principal must exist so DAV basic auth works"
    );

    // `list` runs fine while the share is active.
    cmd_guest_shares(
        GuestSharesArgs {
            command: GuestShareCommand::List(ListArgs {
                owner: "user".to_owned(),
            }),
        },
        test_config(db_url.clone()),
    )
    .await
    .unwrap();

    // `revoke` removes access; the share row stays for audit but is inactive.
    let share_id = share.id.clone();
    cmd_guest_shares(
        GuestSharesArgs {
            command: GuestShareCommand::Revoke(RevokeArgs { share_id }),
        },
        test_config(db_url.clone()),
    )
    .await
    .unwrap();

    assert!(
        share_store
            .list_guest_shares("user")
            .await
            .unwrap()
            .is_empty(),
        "revoke must deactivate the share"
    );
}
