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
}
