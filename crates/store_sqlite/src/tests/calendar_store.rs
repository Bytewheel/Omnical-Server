#[cfg(test)]
mod tests {
    use crate::tests::{TestStoreContext, test_store_context};
    use rstest::rstest;
    use rustical_ical::CalendarObject;
    use rustical_store::{
        Calendar, CalendarMetadata, CalendarReadStore, CalendarStorePruneDeleted,
        CalendarWriteStore,
    };

    const CALENDAR_OBJECT_ICS: &str = r"
BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//iCalendar Event//EN
CALSCALE:GREGORIAN
BEGIN:VEVENT
UID:20260628T153000Z-123456@domain.com
DTSTAMP:20260628T153000Z
DTSTART:20260715T100000Z
DTEND:20260715T110000Z
SUMMARY:iCal Event
DESCRIPTION:Basic calendar event.
LOCATION:Meeting Room A
END:VEVENT
END:VCALENDAR";

    #[rstest]
    #[tokio::test]
    async fn test_calendar_store(
        #[future]
        #[from(test_store_context)]
        context: TestStoreContext,
    ) {
        let TestStoreContext { cal_store, .. } = context.await;

        let cal_store = cal_store;

        let cal = Calendar {
            principal: "fake-user".to_string(),
            timezone_id: None,
            deleted_at: None,
            meta: CalendarMetadata::default(),
            id: "cal".to_string(),
            synctoken: 0,
            subscription_url: None,
            push_topic: "alskdj".to_string(),
            components: vec![],
        };

        assert!(
            cal_store.insert_calendar(cal).await.is_err(),
            "This should fail due to the user not existing "
        );

        let cal = Calendar {
            principal: "user".to_string(),
            timezone_id: None,
            deleted_at: None,
            meta: CalendarMetadata::default(),
            id: "cal".to_string(),
            synctoken: 0,
            subscription_url: None,
            push_topic: "alskdj".to_string(),
            components: vec![],
        };

        cal_store.insert_calendar(cal.clone()).await.unwrap();

        assert_eq!(
            cal_store.get_calendar("user", "cal", false).await.unwrap(),
            cal
        );

        let object_id = "test-object";
        let object =
            CalendarObject::from_ics(CALENDAR_OBJECT_ICS.to_owned()).expect("to parse ics");

        cal_store
            .put_object(&cal.principal, &cal.id, object_id, object.clone(), false)
            .await
            .expect("to insert object");
        cal_store
            .delete_calendar("user", "cal", true)
            .await
            .unwrap();

        let Err(err) = cal_store.get_calendar("user", "cal", false).await else {
            panic!()
        };
        assert!(err.is_not_found());

        let fetched_object = cal_store
            .get_object(&cal.principal, &cal.id, object_id, false)
            .await
            .expect("object remains");
        assert_eq!(fetched_object.get_uid(), object.get_uid());

        cal_store.get_calendar("user", "cal", true).await.unwrap();

        cal_store.restore_calendar("user", "cal").await.unwrap();

        cal_store
            .delete_calendar("user", "cal", false)
            .await
            .unwrap();

        let Err(err) = cal_store.get_calendar("user", "cal", true).await else {
            panic!()
        };
        assert!(err.is_not_found());

        match cal_store
            .get_object(&cal.principal, &cal.id, object_id, false)
            .await
        {
            Ok(_object) => panic!("Calendar deletion should cascade to relevant objects deletion"),
            Err(error) => assert!(error.is_not_found()),
        }
    }

    #[rstest]
    #[tokio::test]
    async fn should_deleted_trashed_calendar_andobjects_by_date_limit(
        #[future]
        #[from(test_store_context)]
        context: TestStoreContext,
    ) {
        let TestStoreContext { cal_store, .. } = context.await;

        let cal_store = cal_store;

        let cal = Calendar {
            principal: "user".to_string(),
            timezone_id: None,
            deleted_at: None,
            meta: CalendarMetadata::default(),
            id: "trashed-cal".to_string(),
            synctoken: 0,
            subscription_url: None,
            push_topic: "trashed".to_string(),
            components: vec![],
        };

        cal_store.insert_calendar(cal.clone()).await.unwrap();

        let object_id = "test-trash-object";
        let object =
            CalendarObject::from_ics(CALENDAR_OBJECT_ICS.to_owned()).expect("to parse ics");

        cal_store
            .put_object(&cal.principal, &cal.id, object_id, object.clone(), false)
            .await
            .expect("to insert object");

        let now = chrono::Utc::now().date_naive();
        //Delete object and calendar
        cal_store
            .delete_object(&cal.principal, &cal.id, object_id, true)
            .await
            .expect("to delete");
        cal_store
            .delete_calendar(&cal.principal, &cal.id, true)
            .await
            .unwrap();

        //Verify we delete only BEFORE timestamp
        cal_store.prune_deleted_objects(now).await.expect("success");
        cal_store
            .get_object(&cal.principal, &cal.id, object_id, true)
            .await
            .expect("Nothing deleted yet");
        cal_store
            .prune_deleted_calendars(now)
            .await
            .expect("success");
        cal_store
            .get_calendar(&cal.principal, &cal.id, true)
            .await
            .expect("Nothing deleted yet");

        //delete everything that was marked for deletion before tomorrow
        cal_store
            .prune_deleted_objects(now + chrono::Duration::days(1))
            .await
            .expect("success");
        let error = cal_store
            .get_object(&cal.principal, &cal.id, object_id, true)
            .await
            .expect_err("object should be deleted");
        assert!(error.is_not_found());
        cal_store
            .prune_deleted_calendars(now + chrono::Duration::days(1))
            .await
            .expect("success");
        let error = cal_store
            .get_calendar(&cal.principal, &cal.id, true)
            .await
            .expect_err("calendar should be deleted");
        assert!(error.is_not_found());
    }

    // --- Omnical §17.10: calendar-level guest shares -----------------------

    use crate::SqliteCollectionShareStore;
    use rustical_store::CollectionShareStore;
    use rustical_store::auth::{AuthenticationProvider, Principal, PrincipalType, Privilege};

    /// Create a calendar (with one object) owned by `owner`, plus the guest
    /// principals needed for share resolution tests.
    async fn setup_shared_calendar(
        context: &TestStoreContext,
        owner: &str,
        cal_id: &str,
    ) -> (Calendar, String) {
        let cal = Calendar {
            principal: owner.to_string(),
            timezone_id: None,
            deleted_at: None,
            meta: CalendarMetadata::default(),
            id: cal_id.to_string(),
            synctoken: 0,
            subscription_url: None,
            push_topic: format!("{owner}-{cal_id}-topic"),
            components: vec![],
        };
        context
            .cal_store
            .insert_calendar(cal.clone())
            .await
            .unwrap();
        let object_id = "shared-object";
        let object =
            CalendarObject::from_ics(CALENDAR_OBJECT_ICS.to_owned()).expect("to parse ics");
        context
            .cal_store
            .put_object(owner, cal_id, object_id, object, false)
            .await
            .unwrap();
        (cal, object_id.to_string())
    }

    async fn insert_guest(context: &TestStoreContext, id: &str) {
        context
            .principal_store
            .insert_principal(
                Principal {
                    id: id.to_owned(),
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
    }

    async fn add_calendar_share(
        context: &TestStoreContext,
        owner: &str,
        cal_id: &str,
        guest: &str,
        privilege: Privilege,
    ) {
        let store = SqliteCollectionShareStore::new(context.cal_store.clone());
        insert_guest(context, guest).await;
        store
            .add_share(owner, cal_id, "calendar", privilege, guest, &None, owner)
            .await
            .unwrap();
    }

    #[rstest]
    #[tokio::test]
    async fn test_guest_resolves_shared_calendar(
        #[future]
        #[from(test_store_context)]
        context: TestStoreContext,
    ) {
        let context = context.await;
        setup_shared_calendar(&context, "user", "work").await;
        add_calendar_share(&context, "user", "work", "guest-1", Privilege::Edit).await;

        // The guest resolves the shared calendar, with principal = guest id.
        let cal = context
            .cal_store
            .get_calendar("guest-1", "work", false)
            .await
            .unwrap();
        assert_eq!(cal.principal, "guest-1");
        assert_eq!(cal.id, "work");

        // Objects resolve through the share too.
        let objects = context
            .cal_store
            .get_objects("guest-1", "work")
            .await
            .unwrap();
        assert_eq!(objects.len(), 1);
        let object = context
            .cal_store
            .get_object("guest-1", "work", "shared-object", false)
            .await
            .unwrap();
        assert_eq!(object.get_uid(), "20260628T153000Z-123456@domain.com");

        // A write lands in the owner's namespace (visible through the
        // guest's share-aware sync).
        let edited =
            CalendarObject::from_ics(CALENDAR_OBJECT_ICS.to_owned()).expect("to parse ics");
        context
            .cal_store
            .put_object("guest-1", "work", "shared-object", edited.clone(), true)
            .await
            .unwrap();
        let (updated, deleted, _token) = context
            .cal_store
            .sync_changes("guest-1", "work", 0)
            .await
            .unwrap();
        assert!(updated.iter().any(|(id, _o)| id == "shared-object"));
        assert!(deleted.is_empty());

        // Meanwhile the owner's own view is unchanged.
        assert_eq!(
            context
                .cal_store
                .get_calendar("user", "work", false)
                .await
                .unwrap()
                .principal,
            "user"
        );
    }

    #[rstest]
    #[tokio::test]
    async fn test_guest_sees_only_shared_calendars(
        #[future]
        #[from(test_store_context)]
        context: TestStoreContext,
    ) {
        let context = context.await;
        setup_shared_calendar(&context, "user", "shared-cal").await;
        setup_shared_calendar(&context, "user", "private-cal").await;
        add_calendar_share(&context, "user", "shared-cal", "guest-1", Privilege::View).await;

        let calendars = context.cal_store.get_calendars("guest-1").await.unwrap();
        assert_eq!(calendars.len(), 1, "guest sees exactly the shared calendar");
        assert_eq!(calendars[0].id, "shared-cal");
        assert_eq!(calendars[0].principal, "guest-1");

        // The unshared calendar stays invisible to the guest.
        assert!(
            context
                .cal_store
                .get_calendar("guest-1", "private-cal", false)
                .await
                .unwrap_err()
                .is_not_found()
        );
    }

    #[rstest]
    #[tokio::test]
    async fn test_non_share_principal_unaffected(
        #[future]
        #[from(test_store_context)]
        context: TestStoreContext,
    ) {
        let context = context.await;
        setup_shared_calendar(&context, "user", "work").await;
        insert_guest(&context, "stranger").await;

        // A principal with no share cannot see or touch the calendar, read or
        // write.
        assert!(
            context
                .cal_store
                .get_calendar("stranger", "work", false)
                .await
                .unwrap_err()
                .is_not_found()
        );
        assert!(
            context
                .cal_store
                .get_calendars("stranger")
                .await
                .unwrap()
                .is_empty()
        );
        assert!(
            context
                .cal_store
                .get_object("stranger", "work", "shared-object", false)
                .await
                .unwrap_err()
                .is_not_found()
        );
        let object =
            CalendarObject::from_ics(CALENDAR_OBJECT_ICS.to_owned()).expect("to parse ics");
        assert!(
            context
                .cal_store
                .put_object("stranger", "work", "shared-object", object, false)
                .await
                .unwrap_err()
                .is_not_found()
        );

        // Revoking the share removes guest access while the owner is intact.
        add_calendar_share(&context, "user", "work", "guest-r", Privilege::View).await;
        let share = SqliteCollectionShareStore::new(context.cal_store.clone())
            .get_share_by_guest("guest-r")
            .await
            .unwrap()
            .unwrap();
        SqliteCollectionShareStore::new(context.cal_store.clone())
            .revoke_share(&share.id)
            .await
            .unwrap();
        assert!(
            context
                .cal_store
                .get_calendar("guest-r", "work", false)
                .await
                .unwrap_err()
                .is_not_found(),
            "revoked share must no longer resolve"
        );
    }
}
