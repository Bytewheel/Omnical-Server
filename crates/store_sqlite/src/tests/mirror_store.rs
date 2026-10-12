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
        let store = SqliteMirrorStore::new(context.await.cal_store);

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
}
