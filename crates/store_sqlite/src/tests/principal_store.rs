#[cfg(test)]
mod tests {
    use crate::tests::{TestStoreContext, test_store_context};
    use argon2::password_hash::{PasswordHasher, SaltString};
    use rstest::rstest;
    use rustical_store::Secret;
    use rustical_store::auth::{AuthenticationProvider, Principal, PrincipalType};

    /// Deterministic argon2 password hash (Omnical sharing: password-change
    /// nudge fixtures).
    fn hash_password(password: &str) -> String {
        let salt = SaltString::encode_b64(b"0123456789abcdef").unwrap();
        argon2::Argon2::default()
            .hash_password(password.as_bytes(), &salt)
            .unwrap()
            .to_string()
    }

    /// `memberships` keeps a foreign key on `member_of`, so the target group
    /// must exist as a principal first.
    async fn insert_group(context: &TestStoreContext, id: &str) {
        context
            .principal_store
            .insert_principal(
                Principal {
                    id: id.to_owned(),
                    displayname: None,
                    principal_type: PrincipalType::Group,
                    password: None,
                    memberships: vec![],
                    needs_password_change: false,
                    privileges: Default::default(),
                },
                false,
            )
            .await
            .unwrap();
    }

    /// Insert a real (password-carrying) user and return its principal id.
    async fn insert_user_with_password(context: &TestStoreContext, id: &str, password: &str) {
        context
            .principal_store
            .insert_principal(
                Principal {
                    id: id.to_owned(),
                    displayname: None,
                    principal_type: PrincipalType::Individual,
                    password: Some(Secret::from(hash_password(password))),
                    memberships: vec![],
                    needs_password_change: false,
                    privileges: Default::default(),
                },
                false,
            )
            .await
            .unwrap();
    }

    #[rstest]
    #[tokio::test]
    async fn first_join_sets_needs_password_change(
        #[from(test_store_context)]
        #[future]
        context: TestStoreContext,
    ) {
        let context = context.await;
        let principal_store = context.principal_store.clone();
        let id = "firstjoin@example.com";
        insert_user_with_password(&context, id, "testpassword").await;

        assert!(!principal_store.get_needs_password_change(id).await.unwrap());

        insert_group(&context, "group").await;
        principal_store.add_membership(id, "group").await.unwrap();

        // First-ever join ⇒ one forced password change on next portal login.
        assert!(principal_store.get_needs_password_change(id).await.unwrap());
        let principal = principal_store.get_principal(id).await.unwrap().unwrap();
        assert!(principal.needs_password_change);
        assert_eq!(principal.memberships, vec!["group"]);
    }

    #[rstest]
    #[tokio::test]
    async fn later_joins_do_not_retrigger_the_nudge(
        #[from(test_store_context)]
        #[future]
        context: TestStoreContext,
    ) {
        let context = context.await;
        let principal_store = context.principal_store.clone();
        let id = "later@example.com";
        insert_user_with_password(&context, id, "testpassword").await;

        // First join sets the flag; the user changes their password (flag
        // cleared), then joins a second group — no new nudge.
        insert_group(&context, "group").await;
        insert_group(&context, "group2").await;
        principal_store.add_membership(id, "group").await.unwrap();
        principal_store
            .set_needs_password_change(id, false)
            .await
            .unwrap();
        principal_store.add_membership(id, "group2").await.unwrap();

        assert!(!principal_store.get_needs_password_change(id).await.unwrap());
    }

    #[rstest]
    #[tokio::test]
    async fn passwordless_principal_is_never_flagged(
        #[from(test_store_context)]
        #[future]
        context: TestStoreContext,
    ) {
        let context = context.await;
        let principal_store = context.principal_store.clone();
        // A group (or a user without any stored password — e.g. OIDC-only)
        // joining a group must never be forced to change a password.
        let id = "member@example.com";
        principal_store
            .insert_principal(
                Principal {
                    id: id.to_owned(),
                    displayname: None,
                    principal_type: PrincipalType::Individual,
                    password: None,
                    memberships: vec![],
                    needs_password_change: false,
                    privileges: Default::default(),
                },
                false,
            )
            .await
            .unwrap();

        insert_group(&context, "group").await;
        principal_store.add_membership(id, "group").await.unwrap();
        assert!(!principal_store.get_needs_password_change(id).await.unwrap());
    }

    #[rstest]
    #[tokio::test]
    async fn set_and_clear_needs_password_change_roundtrip(
        #[from(test_store_context)]
        #[future]
        context: TestStoreContext,
    ) {
        let context = context.await;
        let principal_store = context.principal_store;

        principal_store
            .set_needs_password_change("user", true)
            .await
            .unwrap();
        assert!(
            principal_store
                .get_needs_password_change("user")
                .await
                .unwrap()
        );
        let principal = principal_store
            .get_principal("user")
            .await
            .unwrap()
            .unwrap();
        assert!(principal.needs_password_change);

        principal_store
            .set_needs_password_change("user", false)
            .await
            .unwrap();
        assert!(
            !principal_store
                .get_needs_password_change("user")
                .await
                .unwrap()
        );
        let principal = principal_store
            .get_principal("user")
            .await
            .unwrap()
            .unwrap();
        assert!(!principal.needs_password_change);
    }

    #[rstest]
    #[tokio::test]
    async fn update_password_rotates_hash_and_clears_the_nudge(
        #[from(test_store_context)]
        #[future]
        context: TestStoreContext,
    ) {
        let context = context.await;
        let principal_store = context.principal_store.clone();
        let id = "rotate@example.com";
        insert_user_with_password(&context, id, "testpassword").await;
        insert_group(&context, "group").await;
        principal_store.add_membership(id, "group").await.unwrap();
        assert!(principal_store.get_needs_password_change(id).await.unwrap());

        principal_store
            .update_password(id, &hash_password("newpassword"))
            .await
            .unwrap();

        assert!(!principal_store.get_needs_password_change(id).await.unwrap());
        assert!(
            principal_store
                .validate_password(id, "testpassword")
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            principal_store
                .validate_password(id, "newpassword")
                .await
                .unwrap()
                .is_some()
        );
    }

    // --- Omnical §17.10: guest share privilege stamping ---------------------

    use crate::SqliteCollectionShareStore;
    use rustical_store::CollectionShareStore;

    /// Insert a guest principal and grant it a share over `owner/collection`.
    async fn insert_guest_with_share(
        context: &TestStoreContext,
        guest: &str,
        privilege: rustical_store::auth::Privilege,
    ) {
        context
            .principal_store
            .insert_principal(
                Principal {
                    id: guest.to_owned(),
                    displayname: None,
                    principal_type: PrincipalType::Individual,
                    password: None,
                    memberships: vec![],
                    needs_password_change: false,
                    privileges: Default::default(),
                },
                false,
            )
            .await
            .unwrap();
        let shares = SqliteCollectionShareStore::new(context.cal_store.clone());
        shares
            .add_share("user", "work", "calendar", privilege, guest, &None, "user")
            .await
            .unwrap();
    }

    #[rstest]
    #[tokio::test]
    async fn guest_privilege_is_stamped(
        #[from(test_store_context)]
        #[future]
        context: TestStoreContext,
    ) {
        let context = context.await;
        let principal_store = context.principal_store.clone();

        insert_guest_with_share(
            &context,
            "guest-view",
            rustical_store::auth::Privilege::View,
        )
        .await;
        let guest = principal_store
            .get_principal("guest-view")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            guest.privilege_for("guest-view"),
            rustical_store::auth::Privilege::View,
            "a view guest is stamped read-only instead of the self-default Admin"
        );
        assert!(!guest.can_write("guest-view"));

        insert_guest_with_share(
            &context,
            "guest-edit",
            rustical_store::auth::Privilege::Edit,
        )
        .await;
        let guest = principal_store
            .get_principal("guest-edit")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            guest.privilege_for("guest-edit"),
            rustical_store::auth::Privilege::Edit
        );
        assert!(guest.can_write("guest-edit"));

        // `validate_app_token` (the DAV auth path) returns the same stamped
        // principal.
        let token_value = "s3cret-token-value";
        let token_id = principal_store
            .add_app_token(
                "guest-edit",
                "test-token".to_string(),
                token_value.to_string(),
            )
            .await
            .unwrap();
        let principal = principal_store
            .validate_app_token("guest-edit", &format!("{token_id}_{token_value}"))
            .await
            .unwrap()
            .expect("valid app token authenticates the guest");
        assert_eq!(
            principal.privilege_for("guest-edit"),
            rustical_store::auth::Privilege::Edit
        );
        assert!(principal.can_write("guest-edit"));

        // And the bulk listing agrees.
        let listed = principal_store.get_principals().await.unwrap();
        let listed = listed
            .iter()
            .find(|p| p.id == "guest-edit")
            .expect("guest listed");
        assert_eq!(
            listed.privilege_for("guest-edit"),
            rustical_store::auth::Privilege::Edit
        );
    }

    #[rstest]
    #[tokio::test]
    async fn non_guest_is_not_stamped(
        #[from(test_store_context)]
        #[future]
        context: TestStoreContext,
    ) {
        let context = context.await;
        let principal_store = context.principal_store.clone();

        // The fixture's `user` has no share → no own-id privilege row, so the
        // self-default stays Admin.
        let user = principal_store
            .get_principal("user")
            .await
            .unwrap()
            .unwrap();
        assert!(
            !user.privileges.contains_key("user"),
            "a regular principal must not be stamped as a guest"
        );
        assert_eq!(
            user.privilege_for("user"),
            rustical_store::auth::Privilege::Admin
        );
        assert!(user.can_write("user"));

        // A revoked share must not stamp the guest anymore.
        insert_guest_with_share(
            &context,
            "guest-revoked",
            rustical_store::auth::Privilege::View,
        )
        .await;
        let share = SqliteCollectionShareStore::new(context.cal_store.clone())
            .get_share_by_guest("guest-revoked")
            .await
            .unwrap()
            .unwrap();
        SqliteCollectionShareStore::new(context.cal_store.clone())
            .revoke_share(&share.id)
            .await
            .unwrap();
        let guest = principal_store
            .get_principal("guest-revoked")
            .await
            .unwrap()
            .unwrap();
        assert!(
            !guest.privileges.contains_key("guest-revoked"),
            "revoked shares must not stamp a privilege"
        );
    }
}
