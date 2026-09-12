#[cfg(test)]
mod tests {
    use crate::SqliteInviteStore;
    use crate::tests::{TestStoreContext, test_store_context};
    use rstest::rstest;
    use rustical_store::{Invite, InviteStore};

    const NOW: &str = "2026-09-07T12:00:00Z";

    #[rstest]
    #[tokio::test]
    async fn test_invite_lifecycle(
        #[future]
        #[from(test_store_context)]
        context: TestStoreContext,
    ) {
        let store = SqliteInviteStore::new(context.await.cal_store);

        // Unknown code -> get_invite is Ok(None), redeem is NotFound
        assert!(store.get_invite("unknown-code").await.unwrap().is_none());
        assert!(
            matches!(
                store.redeem_invite("unknown-code", "user", NOW).await,
                Err(rustical_store::Error::NotFound)
            ),
            "redeeming an unknown code must return NotFound"
        );

        // Create (unbound, no expiry)
        let id = store
            .add_invite("test-code-1", &None, "admin", &None)
            .await
            .unwrap();

        let invite = store.get_invite("test-code-1").await.unwrap().unwrap();
        assert_eq!(invite.id, id);
        assert_eq!(invite.code, "test-code-1");
        assert_eq!(invite.created_by, "admin");
        assert!(invite.target_email.is_none());
        assert!(invite.expires_at.is_none());
        assert!(invite.used_by.is_none());
        assert!(
            invite.created_at.is_some(),
            "created_at is set by the database"
        );

        // List (unredeemed only)
        let mut invites = store.list_invites(false).await.unwrap();
        assert_eq!(invites.len(), 1);
        assert_eq!(invites.remove(0).id, id);
        assert_eq!(store.list_invites(true).await.unwrap().len(), 1);

        // Redeem once, then the code is dead
        store
            .redeem_invite("test-code-1", "user", NOW)
            .await
            .unwrap();
        let invite = store.get_invite("test-code-1").await.unwrap().unwrap();
        assert_eq!(invite.used_by.as_deref(), Some("user"));
        assert!(
            matches!(
                store.redeem_invite("test-code-1", "user2", NOW).await,
                Err(rustical_store::Error::NotFound)
            ),
            "a redeemed code must refuse a second redemption (single-use)"
        );
        assert!(
            store
                .list_invites(false)
                .await
                .unwrap()
                .iter()
                .all(|i: &Invite| i.used_by.is_none()),
            "the default list must hide redeemed invites"
        );
        assert_eq!(store.list_invites(true).await.unwrap().len(), 1);

        // Revoke
        assert!(
            matches!(
                store.delete_invite("unknown-code").await,
                Err(rustical_store::Error::NotFound)
            ),
            "deleting an unknown code must return NotFound"
        );
        store.delete_invite("test-code-1").await.unwrap();
        assert!(store.get_invite("test-code-1").await.unwrap().is_none());
    }

    #[rstest]
    #[tokio::test]
    async fn test_invite_duplicate_code(
        #[future]
        #[from(test_store_context)]
        context: TestStoreContext,
    ) {
        let store = SqliteInviteStore::new(context.await.cal_store);

        store
            .add_invite("dup-code", &None, "admin", &None)
            .await
            .unwrap();
        assert!(
            matches!(
                store.add_invite("dup-code", &None, "admin", &None).await,
                Err(rustical_store::Error::AlreadyExists)
            ),
            "a duplicated code must be rejected"
        );
    }

    #[rstest]
    #[tokio::test]
    async fn test_invite_expiry(
        #[future]
        #[from(test_store_context)]
        context: TestStoreContext,
    ) {
        let store = SqliteInviteStore::new(context.await.cal_store);

        // Expires in the past: pre-check reveals it, redeem refuses it.
        let past = "2026-09-01T00:00:00Z";
        store
            .add_invite("expired", &None, "admin", &Some(past.to_owned()))
            .await
            .unwrap();
        let invite = store.get_invite("expired").await.unwrap().unwrap();
        assert_eq!(invite.expires_at.as_deref(), Some(past));
        assert!(
            matches!(
                store.redeem_invite("expired", "user", NOW).await,
                Err(rustical_store::Error::NotFound)
            ),
            "an expired invite must not be redeemable"
        );

        // Expires in the future: redeemable normally.
        let future = "2026-12-31T23:59:59Z";
        store
            .add_invite("fresh", &None, "admin", &Some(future.to_owned()))
            .await
            .unwrap();
        store.redeem_invite("fresh", "user", NOW).await.unwrap();
        assert!(
            matches!(
                store.redeem_invite("fresh", "user2", NOW).await,
                Err(rustical_store::Error::NotFound)
            ),
            "a future-expiry invite is still single-use"
        );
    }

    #[rstest]
    #[tokio::test]
    async fn test_invite_email_binding(
        #[future]
        #[from(test_store_context)]
        context: TestStoreContext,
    ) {
        let store = SqliteInviteStore::new(context.await.cal_store);

        store
            .add_invite(
                "bound-code",
                &Some("target@example.com".to_owned()),
                "admin",
                &None,
            )
            .await
            .unwrap();
        let invite = store.get_invite("bound-code").await.unwrap().unwrap();
        assert_eq!(invite.target_email.as_deref(), Some("target@example.com"));
        // Binding is enforced by the caller (registration endpoint); the store
        // just records it. Any caller may redeem, but the registrations
        // surface checks target_email before calling redeem.
        store
            .redeem_invite("bound-code", "target@example.com", NOW)
            .await
            .unwrap();
    }
}
