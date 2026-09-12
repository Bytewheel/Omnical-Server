#[cfg(test)]
mod tests {
    use crate::SqliteSubscriptionStore;
    use crate::tests::{TestStoreContext, test_store_context};
    use rstest::rstest;
    use rustical_store::{SubscriptionKind, SubscriptionStore};

    #[rstest]
    #[tokio::test]
    async fn test_subscription_lifecycle(
        #[future]
        #[from(test_store_context)]
        context: TestStoreContext,
    ) {
        let store = SqliteSubscriptionStore::new(context.await.cal_store.clone());

        // Unknown token -> NotFound (this is the export URL's 404 path)
        assert!(
            matches!(
                store.get_subscription_by_token("unknown-token").await,
                Err(rustical_store::Error::NotFound)
            ),
            "looking up an unknown token must return NotFound"
        );

        // Create
        let id = store
            .add_subscription(
                "user",
                SubscriptionKind::Calendar,
                "personal",
                "share-token-1",
            )
            .await
            .unwrap();

        // Lookup by token
        let subscription = store
            .get_subscription_by_token("share-token-1")
            .await
            .unwrap();
        assert_eq!(subscription.id, id);
        assert_eq!(subscription.principal, "user");
        assert_eq!(subscription.kind, SubscriptionKind::Calendar);
        assert_eq!(subscription.collection_id, "personal");
        assert_eq!(subscription.token, "share-token-1");
        assert!(
            subscription.created_at.is_some(),
            "created_at is set by the database"
        );

        // List
        let mut subscriptions = store.get_subscriptions("user").await.unwrap();
        assert_eq!(subscriptions.len(), 1);
        assert_eq!(subscriptions.remove(0).id, id);
        assert!(
            store.get_subscriptions("other").await.unwrap().is_empty(),
            "list must be scoped to the principal"
        );

        // Revoke: deleting under another principal must not touch it
        assert!(
            matches!(
                store.delete_subscription("other", &id).await,
                Err(rustical_store::Error::NotFound)
            ),
            "deleting under a foreign principal must return NotFound"
        );
        store
            .get_subscription_by_token("share-token-1")
            .await
            .unwrap();
        store.delete_subscription("user", &id).await.unwrap();
        assert!(
            matches!(
                store.get_subscription_by_token("share-token-1").await,
                Err(rustical_store::Error::NotFound)
            ),
            "a revoked token must stop working immediately"
        );
        assert!(
            matches!(
                store.delete_subscription("user", &id).await,
                Err(rustical_store::Error::NotFound)
            ),
            "deleting an already-revoked subscription must return NotFound"
        );
        assert!(store.get_subscriptions("user").await.unwrap().is_empty());
    }

    #[rstest]
    #[tokio::test]
    async fn test_subscription_duplicate_token(
        #[future]
        #[from(test_store_context)]
        context: TestStoreContext,
    ) {
        let store = SqliteSubscriptionStore::new(context.await.cal_store.clone());

        store
            .add_subscription(
                "user",
                SubscriptionKind::Addressbook,
                "personal",
                "dup-token",
            )
            .await
            .unwrap();

        // Same token again -> AlreadyExists (tokens are globally unique)
        assert!(
            matches!(
                store
                    .add_subscription(
                        "user",
                        SubscriptionKind::Addressbook,
                        "personal",
                        "dup-token"
                    )
                    .await,
                Err(rustical_store::Error::AlreadyExists)
            ),
            "a duplicated token must be rejected"
        );

        // A different kind/collection does not change the uniqueness of the token
        assert!(
            matches!(
                store
                    .add_subscription("user", SubscriptionKind::Calendar, "family", "dup-token")
                    .await,
                Err(rustical_store::Error::AlreadyExists)
            ),
            "token uniqueness is global, not per collection"
        );

        // Addressbooks round-trip their kind too
        let subscription = store.get_subscription_by_token("dup-token").await.unwrap();
        assert_eq!(subscription.kind, SubscriptionKind::Addressbook);
        assert_eq!(subscription.collection_id, "personal");
    }
}
