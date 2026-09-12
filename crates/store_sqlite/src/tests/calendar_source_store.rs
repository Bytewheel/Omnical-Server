#[cfg(test)]
mod tests {
    use crate::SqliteCalendarSourceStore;
    use crate::tests::{TestStoreContext, test_store_context};
    use rstest::rstest;
    use rustical_store::CalendarSourceStore;

    #[rstest]
    #[tokio::test]
    async fn test_calendar_source_lifecycle(
        #[future]
        #[from(test_store_context)]
        context: TestStoreContext,
    ) {
        let store = SqliteCalendarSourceStore::new(context.await.cal_store);

        // Unknown id -> NotFound (this is the portal's refresh/remove path)
        assert!(
            matches!(
                store.get_calendar_source("user", "unknown-id").await,
                Err(rustical_store::Error::NotFound)
            ),
            "looking up an unknown source must return NotFound"
        );

        // Create
        let id = store
            .add_calendar_source(
                "user",
                "personal",
                "https://calendar.example.com/personal.ics",
                "calendar.example.com",
            )
            .await
            .unwrap();

        // Fetch by id (scoped to the owner)
        let source = store.get_calendar_source("user", &id).await.unwrap();
        assert_eq!(source.principal, "user");
        assert_eq!(source.calendar_id, "personal");
        assert_eq!(
            source.source_url,
            "https://calendar.example.com/personal.ics"
        );
        assert_eq!(source.provider_host, "calendar.example.com");
        assert!(!source.last_fetch_success);
        assert!(source.last_fetch_at.is_none());
        assert!(
            source.created_at.is_some(),
            "created_at is set by the database"
        );
        assert!(
            matches!(
                store.get_calendar_source("other", &id).await,
                Err(rustical_store::Error::NotFound)
            ),
            "a source must not be visible to a foreign principal"
        );

        // List
        assert_eq!(store.get_calendar_sources("user").await.unwrap().len(), 1);
        assert!(
            store
                .get_calendar_sources("other")
                .await
                .unwrap()
                .is_empty(),
            "list must be scoped to the principal"
        );

        // Record a refresh outcome
        store
            .update_calendar_source_fetch("user", &id, "2026-09-07T12:00:00Z", true)
            .await
            .unwrap();
        let source = store.get_calendar_source("user", &id).await.unwrap();
        assert!(source.last_fetch_success);
        assert_eq!(
            source.last_fetch_at.as_deref(),
            Some("2026-09-07T12:00:00Z")
        );
        assert!(
            matches!(
                store
                    .update_calendar_source_fetch("other", &id, "2026-09-07T12:00:00Z", true)
                    .await,
                Err(rustical_store::Error::NotFound)
            ),
            "recording a refresh under a foreign principal must return NotFound"
        );

        // Remove: deletes the mapping, scoped to the owner
        store.delete_calendar_source("user", &id).await.unwrap();
        assert!(store.get_calendar_sources("user").await.unwrap().is_empty());
        assert!(
            matches!(
                store.delete_calendar_source("user", &id).await,
                Err(rustical_store::Error::NotFound)
            ),
            "deleting an already-removed source must return NotFound"
        );
    }

    #[rstest]
    #[tokio::test]
    async fn test_calendar_source_duplicate_url(
        #[future]
        #[from(test_store_context)]
        context: TestStoreContext,
    ) {
        let store = SqliteCalendarSourceStore::new(context.await.cal_store);

        store
            .add_calendar_source(
                "user",
                "personal",
                "https://calendar.example.com/personal.ics",
                "calendar.example.com",
            )
            .await
            .unwrap();

        // Same (principal, calendar_id, source_url) triple -> AlreadyExists
        assert!(
            matches!(
                store
                    .add_calendar_source(
                        "user",
                        "personal",
                        "https://calendar.example.com/personal.ics",
                        "calendar.example.com",
                    )
                    .await,
                Err(rustical_store::Error::AlreadyExists)
            ),
            "a duplicated source triple must be rejected"
        );

        // A different target calendar of the same user is a fresh mapping
        store
            .add_calendar_source(
                "user",
                "work",
                "https://calendar.example.com/personal.ics",
                "calendar.example.com",
            )
            .await
            .unwrap();
        assert_eq!(store.get_calendar_sources("user").await.unwrap().len(), 2);
    }
}
