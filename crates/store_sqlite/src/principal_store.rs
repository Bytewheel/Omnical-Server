use async_trait::async_trait;
use derive_more::Constructor;
use password_hash::{CustomizedPasswordHasher, phc::Salt};
use pbkdf2::Params;
use rand::rngs::SysRng;
use rustical_store::{
    Error, Secret,
    auth::{AppToken, AuthenticationProvider, Principal},
};
use sqlx::{Row, SqlitePool, types::Json};
use tracing::instrument;

#[derive(Debug, Clone, Constructor)]
pub struct SqlitePrincipalStore {
    db: SqlitePool,
}

/// Map a `principals` row (with its JSON-aggregated memberships) into a
/// [`Principal`]. Runtime `Row::get` decodes the nullable memberships JSON
/// the same way the old `query_as!` row did (`Json<Vec<Option<String>>>`).
fn principal_from_row(row: &sqlx::sqlite::SqliteRow) -> Result<Principal, Error> {
    Ok(Principal {
        id: row.get("id"),
        displayname: row.get("displayname"),
        password: row
            .get::<Option<String>, _>("password_hash")
            .map(Secret::from),
        principal_type: row.get::<String, _>("principal_type").as_str().try_into()?,
        memberships: row
            .get::<Option<Json<Vec<Option<String>>>>, _>("memberships")
            .map(|val| val.0)
            .unwrap_or_default()
            .into_iter()
            .flatten()
            .collect(),
        needs_password_change: row.get("needs_password_change"),
    })
}

#[async_trait]
impl AuthenticationProvider for SqlitePrincipalStore {
    #[instrument]
    async fn get_principals(&self) -> Result<Vec<Principal>, Error> {
        // Runtime query (not `query_as!`) so the planner-selected rows can
        // carry the `needs_password_change` column without regenerating the
        // committed `.sqlx/` offline metadata for the old statement shape.
        let rows = sqlx::query(
            r#"
            SELECT p.id, p.displayname, p.principal_type, p.password_hash,
                   p.needs_password_change,
                   json_group_array(m.member_of) AS memberships
            FROM principals p
            LEFT JOIN memberships m ON p.id == m.principal
            GROUP BY p.id
        "#,
        )
        .fetch_all(&self.db)
        .await
        .map_err(crate::Error::from)?;
        Ok(rows
            .into_iter()
            .map(|row| principal_from_row(&row))
            .collect::<Result<Vec<_>, _>>()?)
    }

    #[instrument]
    async fn get_principal(&self, id: &str) -> Result<Option<Principal>, Error> {
        let row = sqlx::query(
            r#"
            SELECT p.id, p.displayname, p.principal_type, p.password_hash,
                   p.needs_password_change,
                   json_group_array(m.member_of) AS memberships
            FROM (SELECT * FROM principals WHERE id = ?) AS p
            LEFT JOIN memberships m ON p.id == m.principal
            GROUP BY p.id
        "#,
        )
        .bind(id)
        .fetch_optional(&self.db)
        .await
        .map_err(crate::Error::from)?;
        Ok(row.map(|row| principal_from_row(&row)).transpose()?)
    }

    #[instrument]
    async fn remove_principal(&self, id: &str) -> Result<(), Error> {
        sqlx::query!(r#"DELETE FROM principals WHERE id = ?"#, id)
            .execute(&self.db)
            .await
            .map_err(crate::Error::from)?;
        Ok(())
    }

    #[instrument]
    async fn insert_principal(
        &self,
        user: Principal,
        overwrite: bool,
    ) -> Result<(), rustical_store::Error> {
        if user.id.contains(':') || user.id.contains('$') {
            return Err(rustical_store::Error::InvalidPrincipalId);
        }

        // Would be cleaner to put this into a transaction but for now it will be fine
        if !overwrite && self.get_principal(&user.id).await?.is_some() {
            return Err(Error::AlreadyExists);
        }
        let principal_type = user.principal_type.as_str();
        let password = user.password.map(Secret::into_inner);
        sqlx::query!(
            r#"
            INSERT INTO principals
            (id, displayname, principal_type, password_hash) VALUES (?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                (displayname, principal_type, password_hash)
                = (excluded.displayname, excluded.principal_type, excluded.password_hash)
        "#,
            user.id,
            user.displayname,
            principal_type,
            password
        )
        .execute(&self.db)
        .await
        .map_err(crate::Error::from)?;
        Ok(())
    }

    #[instrument]
    async fn get_app_tokens(&self, principal: &str) -> Result<Vec<AppToken>, Error> {
        Ok(sqlx::query_as!(
            AppToken,
            r#"SELECT id, displayname AS name, token, created_at AS "created_at: _" FROM app_tokens WHERE principal = ?"#,
            principal
        )
        .fetch_all(&self.db)
        .await
        .map_err(crate::Error::from)?)
    }

    #[instrument]
    async fn remove_app_token(&self, user_id: &str, token_id: &str) -> Result<(), Error> {
        sqlx::query!(
            r#"DELETE FROM app_tokens WHERE (principal, id) = (?, ?)"#,
            user_id,
            token_id
        )
        .execute(&self.db)
        .await
        .map_err(crate::Error::from)?;
        Ok(())
    }

    #[instrument(skip(token))]
    async fn add_app_token(
        &self,
        user_id: &str,
        name: String,
        token: String,
    ) -> Result<String, Error> {
        let id = uuid::Uuid::new_v4().to_string();
        let salt = Salt::try_from_rng(&mut SysRng).map_err(|err| Error::Other(err.into()))?;
        let token_hash = pbkdf2::Pbkdf2::SHA512
            .hash_password_with_params(
                token.as_bytes(),
                &salt,
                // The app token has a high entropy so we are quite safe from quessing attacks
                // Also if an attacker got access to the hashes they'd have already gotten
                // access to the whole database.
                Params::new(1000).expect("1000 rounds are valid"),
            )
            .map_err(|_| Error::PasswordHash)?
            .to_string();
        sqlx::query!(
            r#"
            INSERT INTO app_tokens
                (id, principal, token, displayname)
            VALUES (?, ?, ?, ?)
        "#,
            id,
            user_id,
            token_hash,
            name
        )
        .execute(&self.db)
        .await
        .map_err(crate::Error::from)?;
        Ok(id)
    }

    #[instrument]
    async fn add_membership(&self, principal: &str, member_of: &str) -> Result<(), Error> {
        let mut tx = self.db.begin().await.map_err(crate::Error::from)?;
        // Whether this is the principal's FIRST membership, and whether they
        // are a real user (have a stored password) — group principals never
        // get the forced password-change nudge.
        let info = sqlx::query(
            r#"
            SELECT
                (SELECT COUNT(*) FROM memberships WHERE principal = ?) AS membership_count,
                (SELECT password_hash FROM principals WHERE id = ?) AS password_hash
            "#,
        )
        .bind(principal)
        .bind(principal)
        .fetch_one(&mut *tx)
        .await
        .map_err(crate::Error::from)?;
        let membership_count: i64 = info.get("membership_count");
        let has_password: bool = info.get::<Option<String>, _>("password_hash").is_some();

        let result = sqlx::query!(
            r#"REPLACE INTO memberships (principal, member_of) VALUES (?, ?)"#,
            principal,
            member_of
        )
        .execute(&mut *tx)
        .await
        .map_err(crate::Error::from)?;

        // First-ever join of a real user ⇒ one-time password-change nudge on
        // the user's next portal login.
        if membership_count == 0 && has_password && result.rows_affected() == 1 {
            sqlx::query("UPDATE principals SET needs_password_change = 1 WHERE id = ?")
                .bind(principal)
                .execute(&mut *tx)
                .await
                .map_err(crate::Error::from)?;
        }

        tx.commit().await.map_err(crate::Error::from)?;
        Ok(())
    }

    #[instrument]
    async fn get_needs_password_change(&self, principal: &str) -> Result<bool, Error> {
        Ok(
            sqlx::query("SELECT needs_password_change FROM principals WHERE id = ?")
                .bind(principal)
                .fetch_optional(&self.db)
                .await
                .map_err(crate::Error::from)?
                .is_some_and(|row| row.get("needs_password_change")),
        )
    }

    #[instrument]
    async fn set_needs_password_change(&self, principal: &str, value: bool) -> Result<(), Error> {
        sqlx::query("UPDATE principals SET needs_password_change = ? WHERE id = ?")
            .bind(value)
            .bind(principal)
            .execute(&self.db)
            .await
            .map_err(crate::Error::from)?;
        Ok(())
    }

    #[instrument]
    async fn update_password(&self, principal: &str, password_hash: &str) -> Result<(), Error> {
        // Rotating the password also clears the forced-change nudge.
        sqlx::query(
            "UPDATE principals SET password_hash = ?, needs_password_change = 0 WHERE id = ?",
        )
        .bind(password_hash)
        .bind(principal)
        .execute(&self.db)
        .await
        .map_err(crate::Error::from)?;
        Ok(())
    }

    #[instrument]
    async fn remove_membership(&self, principal: &str, member_of: &str) -> Result<(), Error> {
        sqlx::query!(
            r#"DELETE FROM memberships WHERE (principal, member_of) = (?, ?)"#,
            principal,
            member_of
        )
        .execute(&self.db)
        .await
        .map_err(crate::Error::from)?;
        Ok(())
    }

    #[instrument]
    async fn list_members(&self, principal: &str) -> Result<Vec<String>, Error> {
        Ok(sqlx::query!(
            r#"SELECT principal FROM memberships WHERE member_of = ?"#,
            principal
        )
        .fetch_all(&self.db)
        .await
        .map_err(crate::Error::from)?
        .into_iter()
        .map(|record| record.principal)
        .collect())
    }

    #[instrument]
    async fn list_groups_for_user(&self, user_id: &str) -> Result<Vec<(String, String)>, Error> {
        Ok(sqlx::query(
            r#"
            SELECT memberships.member_of AS id, principals.displayname
            FROM memberships
            JOIN principals ON memberships.member_of = principals.id
            WHERE memberships.principal = ? AND principals.principal_type = 'GROUP'
            "#,
        )
        .bind(user_id)
        .fetch_all(&self.db)
        .await
        .map_err(crate::Error::from)?
        .into_iter()
        .map(|row| {
            (
                row.get("id"),
                row.get::<Option<String>, _>("displayname")
                    .unwrap_or_default(),
            )
        })
        .collect())
    }

    #[instrument]
    async fn get_group_owner(&self, group_id: &str) -> Result<Option<String>, Error> {
        Ok(
            sqlx::query(r#"SELECT owner_id FROM group_owners WHERE group_id = ?"#)
                .bind(group_id)
                .fetch_optional(&self.db)
                .await
                .map_err(crate::Error::from)?
                .map(|row| row.get("owner_id")),
        )
    }

    #[instrument]
    async fn set_group_owner(&self, group_id: &str, owner_id: &str) -> Result<(), Error> {
        sqlx::query(r#"INSERT INTO group_owners (group_id, owner_id) VALUES (?, ?)"#)
            .bind(group_id)
            .bind(owner_id)
            .execute(&self.db)
            .await
            .map_err(crate::Error::from)?;
        Ok(())
    }

    #[instrument]
    async fn search_users(&self, query: &str) -> Result<Vec<(String, String)>, Error> {
        let pattern = format!("%{query}%");
        Ok(sqlx::query(
            r#"
            SELECT id, displayname
            FROM principals
            WHERE principal_type = 'INDIVIDUAL' AND (id LIKE ? OR displayname LIKE ?)
            LIMIT 20
            "#,
        )
        .bind(&pattern)
        .bind(&pattern)
        .fetch_all(&self.db)
        .await
        .map_err(crate::Error::from)?
        .into_iter()
        .map(|row| {
            (
                row.get("id"),
                row.get::<Option<String>, _>("displayname")
                    .unwrap_or_default(),
            )
        })
        .collect())
    }
}
