#[cfg(test)]
mod tests {
    use crate::SqliteMirrorStore;
    use crate::tests::{TestStoreContext, test_store_context};
    use rstest::rstest;
    use rustical_store::{MirrorObject, MirrorStore};

    /// §18.41: the state rows are a wholesale replace, so the lifecycle that
    /// matters is "empty → two objects → replace with one → the first run's
    /// delete diff sees exactly the replaced one" plus per-mirror isolation.
    #[rstest]
    #[tokio::test]
    async fn test_mirror_state_replace_lifecycle(
        #[future]
        #[from(test_store_context)]
        context: TestStoreContext,
    ) {
        let context = context.await;
        let store = SqliteMirrorStore::new(context.cal_store.clone());

        // Empty, not an error — a mirror's first run starts from nothing.
        assert!(
            store
                .get_mirror_objects("personal-to-default")
                .await
                .unwrap()
                .is_empty(),
            "a fresh mirror has no recorded objects"
        );

        let first = vec![
            MirrorObject {
                uid: "RGKW68NDCGRYYVVHH55NLH5PU8Z6QH1IDKBU".to_owned(),
                href: "RGKW68NDCGRYYVVHH55NLH5PU8Z6QH1IDKBU.ics".to_owned(),
                hash: "hash-1".to_owned(),
            },
            MirrorObject {
                uid: "RGKW68NDCGRYYVVHH55NLH5PU8Z6QH1IDKBU-20261012T230000Z".to_owned(),
                href: "RGKW68NDCGRYYVVHH55NLH5PU8Z6QH1IDKBU-20261012T230000Z.ics".to_owned(),
                hash: "hash-2".to_owned(),
            },
        ];
        store
            .replace_mirror_objects("personal-to-default", &first)
            .await
            .unwrap();
        assert_eq!(
            store
                .get_mirror_objects("personal-to-default")
                .await
                .unwrap(),
            first,
            "the written state round-trips"
        );

        // A second mirror's state is fully isolated by name.
        store
            .replace_mirror_objects("liturgical-to-omnical", &[])
            .await
            .unwrap();
        assert_eq!(
            store
                .get_mirror_objects("liturgical-to-omnical")
                .await
                .unwrap()
                .len(),
            0,
            "another mirror's replace must not touch this one"
        );
        assert_eq!(
            store
                .get_mirror_objects("personal-to-default")
                .await
                .unwrap()
                .len(),
            2,
            "and the first mirror's rows survive it"
        );

        // Replace is wholesale: the vanished instance UID is gone on the
        // next read, which is exactly what the delete diff consumes.
        let second = vec![MirrorObject {
            uid: "RGKW68NDCGRYYVVHH55NLH5PU8Z6QH1IDKBU".to_owned(),
            href: "RGKW68NDCGRYYVVHH55NLH5PU8Z6QH1IDKBU.ics".to_owned(),
            hash: "hash-3".to_owned(),
        }];
        store
            .replace_mirror_objects("personal-to-default", &second)
            .await
            .unwrap();
        assert_eq!(
            store
                .get_mirror_objects("personal-to-default")
                .await
                .unwrap(),
            second,
            "the replace dropped the stale instance row and moved the hash"
        );
    }

    use rustical_store::MirrorRun;

    /// §18.42: one row per recorded run, `last_mirror_run` reads the newest,
    /// and the prune keeps the history at `KEEP_RUNS_PER_TARGET` — the
    /// whole point of a bounded history is the bound.
    #[rstest]
    #[tokio::test]
    async fn test_mirror_runs_record_last_and_prune(
        #[future]
        #[from(test_store_context)]
        context: TestStoreContext,
    ) {
        let context = context.await;
        let store = SqliteMirrorStore::new(context.cal_store.clone());

        // Never run is Ok(None), not an error.
        assert!(
            store
                .last_mirror_run("personal-to-default")
                .await
                .unwrap()
                .is_none(),
            "a target that never ran has no newest run"
        );

        // Record three runs with distinct timestamps; the newest wins.
        for (put, deleted, unchanged, error) in [(1, 0, 5, None), (0, 1, 6, None), (0, 0, 7, None)]
        {
            store
                .record_mirror_run(
                    "personal-to-default",
                    &MirrorRun {
                        ran_at: format!("2026-10-13T1{unchanged}:00:00Z"),
                        put,
                        deleted,
                        unchanged,
                        error,
                    },
                )
                .await
                .unwrap();
        }
        let last = store
            .last_mirror_run("personal-to-default")
            .await
            .unwrap()
            .expect("three recorded runs");
        assert_eq!(last.ran_at, "2026-10-13T17:00:00Z");
        assert_eq!((last.put, last.deleted, last.unchanged), (0, 0, 7));
        assert!(last.error.is_none(), "a successful run carries no error");

        // A failed run records its error string verbatim.
        store
            .record_mirror_run(
                "personal-to-default",
                &MirrorRun {
                    ran_at: "2026-10-13T18:00:00Z".to_owned(),
                    put: 0,
                    deleted: 0,
                    unchanged: 0,
                    error: Some("PROPFIND http://… returned 401".to_owned()),
                },
            )
            .await
            .unwrap();
        let last = store
            .last_mirror_run("personal-to-default")
            .await
            .unwrap()
            .expect("the failed run is recorded");
        assert_eq!(
            last.error.as_deref(),
            Some("PROPFIND http://… returned 401")
        );
        assert_eq!(last.ran_at, "2026-10-13T18:00:00Z");

        // Prune: recording 25 runs for one target keeps only the newest 20
        // (the bound), per-target — the other target's rows are untouched.
        for i in 0..25 {
            store
                .record_mirror_run(
                    "liturgical-to-omnical",
                    &MirrorRun {
                        ran_at: format!("2026-10-13T19:{:02}:00Z", 25 - i),
                        put: i,
                        deleted: 0,
                        unchanged: 0,
                        error: None,
                    },
                )
                .await
                .unwrap();
        }
        let kept: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM mirror_runs WHERE mirror = 'liturgical-to-omnical'",
        )
        .fetch_one(&context.db)
        .await
        .unwrap();
        assert_eq!(kept, 20, "the history is bounded at 20 per target");
        let oldest_kept: String = sqlx::query_scalar(
            "SELECT MIN(ran_at) FROM mirror_runs WHERE mirror = 'liturgical-to-omnical'",
        )
        .fetch_one(&context.db)
        .await
        .unwrap();
        assert_eq!(
            oldest_kept, "2026-10-13T19:06:00Z",
            "the newest 20 survive the prune"
        );
        let personal: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM mirror_runs WHERE mirror = 'personal-to-default'",
        )
        .fetch_one(&context.db)
        .await
        .unwrap();
        assert_eq!(
            personal, 4,
            "one target's prune must not touch another's rows"
        );
    }
}
