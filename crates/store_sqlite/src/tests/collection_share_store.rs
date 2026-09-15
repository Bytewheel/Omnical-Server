#[cfg(test)]
mod tests {
    use crate::SqliteCollectionShareStore;
    use crate::tests::{TestStoreContext, test_store_context};
    use rstest::rstest;
    use rustical_store::CollectionShareStore;
    use rustical_store::auth::{AuthenticationProvider, Principal, PrincipalType, Privilege};

    async fn insert_guest(context: &TestStoreContext, id: &str) -> rustical_store::auth::Principal {
        let principal = Principal {
            id: id.to_owned(),
            displayname: None,
            memberships: vec![],
            password: None,
            principal_type: PrincipalType::Individual,
            needs_password_change: false,
            privileges: Default::default(),
        };
        context
            .principal_store
            .insert_principal(principal.clone(), false)
            .await
            .unwrap();
        principal
    }

    #[rstest]
    #[tokio::test]
    async fn test_share_lifecycle(
        #[future]
        #[from(test_store_context)]
        context: TestStoreContext,
    ) {
        let context = context.await;
        let store = SqliteCollectionShareStore::new(context.cal_store.clone());
        insert_guest(&context, "guest-1").await;

        // Unknown guest -> get_share_by_guest is Ok(None)
        assert!(
            store
                .get_share_by_guest("guest-none")
                .await
                .unwrap()
                .is_none()
        );

        // Create
        let id = store
            .add_share(
                "user",
                "work",
                "calendar",
                Privilege::Edit,
                "guest-1",
                &Some("guest@example.com".to_owned()),
                "user",
            )
            .await
            .unwrap();

        let share = store.get_share_by_guest("guest-1").await.unwrap().unwrap();
        assert_eq!(share.id, id);
        assert_eq!(share.owner_principal, "user");
        assert_eq!(share.collection_id, "work");
        assert_eq!(share.kind, "calendar");
        assert_eq!(share.privilege, Privilege::Edit);
        assert_eq!(share.guest_principal, "guest-1");
        assert_eq!(share.target_email.as_deref(), Some("guest@example.com"));
        assert_eq!(share.created_by, "user");
        assert!(share.revoked_at.is_none());
        assert!(
            share.created_at.is_some(),
            "created_at is set by the database"
        );

        // List active shares per collection / per owner
        let mut shares = store
            .get_shares_for_collection("user", "work")
            .await
            .unwrap();
        assert_eq!(shares.len(), 1);
        assert_eq!(shares.remove(0).id, id);
        assert!(
            store
                .list_guest_shares("user")
                .await
                .unwrap()
                .iter()
                .any(|s| s.id == id)
        );
        assert!(store.list_guest_shares("other").await.unwrap().is_empty());

        // Revoke: rows_affected guards against double-revoke / unknown id
        assert!(
            matches!(
                store.revoke_share("unknown-share").await,
                Err(rustical_store::Error::NotFound)
            ),
            "revoking an unknown share must return NotFound"
        );
        store.revoke_share(&id).await.unwrap();
        assert!(
            matches!(
                store.revoke_share(&id).await,
                Err(rustical_store::Error::NotFound)
            ),
            "revoking an already-revoked share must return NotFound"
        );

        // Revoked share no longer resolves via any listing
        assert!(store.get_share_by_guest("guest-1").await.unwrap().is_none());
        assert!(
            store
                .get_shares_for_collection("user", "work")
                .await
                .unwrap()
                .is_empty()
        );
        assert!(store.list_guest_shares("user").await.unwrap().is_empty());
    }

    #[rstest]
    #[tokio::test]
    async fn test_share_one_share_per_guest(
        #[future]
        #[from(test_store_context)]
        context: TestStoreContext,
    ) {
        let context = context.await;
        let store = SqliteCollectionShareStore::new(context.cal_store.clone());
        insert_guest(&context, "guest-1").await;

        store
            .add_share(
                "user",
                "work",
                "calendar",
                Privilege::View,
                "guest-1",
                &None,
                "user",
            )
            .await
            .unwrap();
        assert!(
            matches!(
                store
                    .add_share(
                        "user",
                        "personal",
                        "calendar",
                        Privilege::Edit,
                        "guest-1",
                        &None,
                        "user",
                    )
                    .await,
                Err(rustical_store::Error::AlreadyExists)
            ),
            "a guest principal can only hold one share (V1)"
        );
    }
}
