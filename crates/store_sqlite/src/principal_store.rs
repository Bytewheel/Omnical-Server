use async_trait::async_trait;
use derive_more::Constructor;
use password_hash::{CustomizedPasswordHasher, phc::Salt};
use pbkdf2::Params;
use rand::rngs::SysRng;
use rustical_store::{
    Error, Secret,
    auth::{AppToken, AuthenticationProvider, Principal, Privilege},
};
use sqlx::{Row, SqlitePool, types::Json};
use std::collections::BTreeMap;
use tracing::instrument;

#[derive(Debug, Clone, Constructor)]
pub struct SqlitePrincipalStore {
    db: SqlitePool,
}

/// pbkdf2-hash an app-token secret for storage (add + regenerate share it).
fn hash_app_token(token: &str) -> Result<String, Error> {
    let salt = Salt::try_from_rng(&mut SysRng).map_err(|err| Error::Other(err.into()))?;
    pbkdf2::Pbkdf2::SHA512
        .hash_password_with_params(
            token.as_bytes(),
            &salt,
            // The app token has a high entropy so we are quite safe from quessing attacks
            // Also if an attacker got access to the hashes they'd have already gotten
            // access to the whole database.
            Params::new(1000).expect("1000 rounds are valid"),
        )
        .map_err(|_| Error::PasswordHash)
        .map(|hash| hash.to_string())
}

impl SqlitePrincipalStore {
    // Omnical §17.10: stamp a guest's share privilege into the principal's
    // own-id privilege slot. `privilege_for(self)` would otherwise default to
    // `Privilege::Admin`; the stamped value makes `can_write(self)` respect
    // the share (`view` → read-only, `edit`/`admin` → write). Stamping here —
    // rather than in the auth middleware — means every load path (DAV app-token
    // auth via `validate_app_token` → `get_principal`, discovery, portal)
    // carries the same privilege, requiring no plumbing through
    // `AuthenticationLayer`/`caldav_router`/`carddav_router`.
    #[instrument(skip(self))]
    async fn stamp_guest_share(&self, principal: &mut Principal) -> Result<(), Error> {
        let row = sqlx::query(
            "SELECT privilege FROM collection_shares \
             WHERE guest_principal = ? AND revoked_at IS NULL",
        )
        .bind(&principal.id)
        .fetch_optional(&self.db)
        .await
        .map_err(crate::Error::from)?;
        if let Some(row) = row {
            let privilege: String = row.get("privilege");
            if let Ok(privilege) = privilege.parse() {
                principal.privileges.insert(principal.id.clone(), privilege);
            }
        }
        Ok(())
    }
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
        privileges: BTreeMap::new(),
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

        // Omnical §17.9.2: attach each principal's group privileges (one
        // bulk query; merging into the memberships JSON would need a second
        // aggregate join and can silently drop rows).
        let privilege_rows =
            sqlx::query("SELECT group_id, member_id, privilege FROM group_members")
                .fetch_all(&self.db)
                .await
                .map_err(crate::Error::from)?;
        let mut privileges_by_member: BTreeMap<String, BTreeMap<String, Privilege>> =
            BTreeMap::new();
        for row in privilege_rows {
            let member_id: String = row.get("member_id");
            let group_id: String = row.get("group_id");
            let privilege: String = row.get("privilege");
            if let Ok(privilege) = privilege.parse() {
                privileges_by_member
                    .entry(member_id)
                    .or_default()
                    .insert(group_id, privilege);
            }
        }

        let mut principals = rows
            .into_iter()
            .map(|row| principal_from_row(&row))
            .collect::<Result<Vec<_>, _>>()?;
        for principal in &mut principals {
            principal.privileges = privileges_by_member
                .remove(&principal.id)
                .unwrap_or_default();
        }

        // Omnical §17.10: stamp guest share privileges (bulk, like the group
        // privileges above).
        let share_rows = sqlx::query(
            "SELECT guest_principal, privilege FROM collection_shares WHERE revoked_at IS NULL",
        )
        .fetch_all(&self.db)
        .await
        .map_err(crate::Error::from)?;
        let mut shares_by_guest: BTreeMap<String, Privilege> = BTreeMap::new();
        for row in share_rows {
            let guest_id: String = row.get("guest_principal");
            let privilege: String = row.get("privilege");
            if let Ok(privilege) = privilege.parse() {
                shares_by_guest.insert(guest_id, privilege);
            }
        }
        for principal in &mut principals {
            if let Some(privilege) = shares_by_guest.get(&principal.id).copied() {
                principal.privileges.insert(principal.id.clone(), privilege);
            }
        }
        Ok(principals)
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
        let Some(row) = row else {
            return Ok(None);
        };
        let mut principal = principal_from_row(&row)?;

        let privilege_rows =
            sqlx::query("SELECT group_id, privilege FROM group_members WHERE member_id = ?")
                .bind(id)
                .fetch_all(&self.db)
                .await
                .map_err(crate::Error::from)?;
        for privilege_row in privilege_rows {
            let group_id: String = privilege_row.get("group_id");
            let privilege: String = privilege_row.get("privilege");
            if let Ok(privilege) = privilege.parse() {
                principal.privileges.insert(group_id, privilege);
            }
        }
        self.stamp_guest_share(&mut principal).await?;
        Ok(Some(principal))
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
        let token_hash = hash_app_token(&token)?;
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

    #[instrument(skip(token))]
    async fn update_app_token(
        &self,
        user_id: &str,
        token_id: &str,
        token: String,
    ) -> Result<(), Error> {
        let token_hash = hash_app_token(&token)?;
        // Runtime query (not the query! macro) so no sqlx prepare-cache
        // entry is needed — same pattern as stamp_guest_share.
        let result = sqlx::query("UPDATE app_tokens SET token = ? WHERE (principal, id) = (?, ?)")
            .bind(token_hash)
            .bind(user_id)
            .bind(token_id)
            .execute(&self.db)
            .await
            .map_err(crate::Error::from)?;
        if result.rows_affected() == 0 {
            return Err(Error::NotFound);
        }
        Ok(())
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

        // Omnical §17.9.2: seed the default `edit` privilege row for group
        // memberships (an existing row — e.g. the owner's `admin` row seeded
        // by `set_group_owner` — is left untouched).
        sqlx::query(
            r#"
            INSERT INTO group_members (group_id, member_id, privilege)
            SELECT ?, ?, 'edit'
            FROM principals
            WHERE id = ? AND principal_type = 'GROUP'
            ON CONFLICT(group_id, member_id) DO NOTHING
            "#,
        )
        .bind(member_of)
        .bind(principal)
        .bind(member_of)
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
        let mut tx = self.db.begin().await.map_err(crate::Error::from)?;

        // Omnical §17.9.2 invariant: the last admin of a group cannot be
        // removed.
        let info = sqlx::query(
            r#"
            SELECT
                (SELECT privilege FROM group_members
                 WHERE group_id = ? AND member_id = ?) AS privilege,
                (SELECT COUNT(*) FROM group_members
                 WHERE group_id = ? AND member_id != ? AND privilege = 'admin')
                 AS other_admins
            "#,
        )
        .bind(member_of)
        .bind(principal)
        .bind(member_of)
        .bind(principal)
        .fetch_one(&mut *tx)
        .await
        .map_err(crate::Error::from)?;
        let privilege: Option<String> = info.get("privilege");
        let other_admins: i64 = info.get("other_admins");
        if privilege.as_deref() == Some("admin") && other_admins == 0 {
            return Err(Error::LastAdmin);
        }

        sqlx::query!(
            r#"DELETE FROM memberships WHERE (principal, member_of) = (?, ?)"#,
            principal,
            member_of
        )
        .execute(&mut *tx)
        .await
        .map_err(crate::Error::from)?;

        // Runtime query (not `query!`) so this recent statement does not need
        // `.sqlx/` offline metadata regeneration.
        sqlx::query("DELETE FROM group_members WHERE (group_id, member_id) = (?, ?)")
            .bind(member_of)
            .bind(principal)
            .execute(&mut *tx)
            .await
            .map_err(crate::Error::from)?;

        tx.commit().await.map_err(crate::Error::from)?;
        Ok(())
    }

    #[instrument]
    async fn get_privilege(&self, member_id: &str, group_id: &str) -> Result<Privilege, Error> {
        let row =
            sqlx::query("SELECT privilege FROM group_members WHERE group_id = ? AND member_id = ?")
                .bind(group_id)
                .bind(member_id)
                .fetch_optional(&self.db)
                .await
                .map_err(crate::Error::from)?;
        let privilege = row
            .map(|row| row.get::<String, _>("privilege"))
            .unwrap_or_else(|| Privilege::Edit.as_str().to_owned());
        privilege
            .parse()
            .map_err(|e| Error::Other(anyhow::Error::msg(e)))
    }

    #[instrument]
    async fn set_privilege(
        &self,
        member_id: &str,
        group_id: &str,
        privilege: Privilege,
    ) -> Result<(), Error> {
        let mut tx = self.db.begin().await.map_err(crate::Error::from)?;

        // Omnical §17.9.2 invariants: the owner is an implicit admin that can
        // never be demoted; the last remaining admin cannot be demoted.
        let owner: Option<String> =
            sqlx::query("SELECT owner_id FROM group_owners WHERE group_id = ?")
                .bind(group_id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(crate::Error::from)?
                .map(|row| row.get("owner_id"));
        if privilege != Privilege::Admin && owner.as_deref() == Some(member_id) {
            return Err(Error::OwnerNotDemotable);
        }
        let current: Option<String> =
            sqlx::query("SELECT privilege FROM group_members WHERE group_id = ? AND member_id = ?")
                .bind(group_id)
                .bind(member_id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(crate::Error::from)?
                .map(|row| row.get("privilege"));
        if privilege != Privilege::Admin && current.as_deref() == Some("admin") {
            let other_admins: i64 = sqlx::query(
                "SELECT COUNT(*) FROM group_members WHERE group_id = ? AND member_id != ? AND privilege = 'admin'",
            )
            .bind(group_id)
            .bind(member_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(crate::Error::from)?
            .get("COUNT(*)");
            if other_admins == 0 {
                return Err(Error::LastAdmin);
            }
        }

        sqlx::query(
            r#"
            INSERT INTO group_members (group_id, member_id, privilege)
            VALUES (?, ?, ?)
            ON CONFLICT(group_id, member_id)
            DO UPDATE SET privilege = excluded.privilege
            "#,
        )
        .bind(group_id)
        .bind(member_id)
        .bind(privilege.as_str())
        .execute(&mut *tx)
        .await
        .map_err(crate::Error::from)?;

        tx.commit().await.map_err(crate::Error::from)?;
        Ok(())
    }

    #[instrument]
    async fn list_members_with_privileges(
        &self,
        group_id: &str,
    ) -> Result<Vec<(String, Privilege)>, Error> {
        let rows = sqlx::query(
            r#"
            SELECT m.principal AS member_id,
                   COALESCE(gm.privilege, 'edit') AS privilege,
                   o.owner_id IS NOT NULL AS is_owner
            FROM memberships m
            LEFT JOIN group_members gm
                ON gm.group_id = m.member_of AND gm.member_id = m.principal
            LEFT JOIN group_owners o
                ON o.group_id = m.member_of AND o.owner_id = m.principal
            WHERE m.member_of = ?
            ORDER BY m.principal
            "#,
        )
        .bind(group_id)
        .fetch_all(&self.db)
        .await
        .map_err(crate::Error::from)?;

        let mut members = Vec::with_capacity(rows.len());
        for row in rows {
            let member_id: String = row.get("member_id");
            let is_owner: bool = row.get("is_owner");
            let privilege: String = row.get("privilege");
            let privilege = if is_owner {
                Privilege::Admin
            } else {
                privilege
                    .parse()
                    .map_err(|e| Error::Other(anyhow::Error::msg(e)))?
            };
            members.push((member_id, privilege));
        }
        Ok(members)
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
        let mut tx = self.db.begin().await.map_err(crate::Error::from)?;
        sqlx::query(r#"INSERT INTO group_owners (group_id, owner_id) VALUES (?, ?)"#)
            .bind(group_id)
            .bind(owner_id)
            .execute(&mut *tx)
            .await
            .map_err(crate::Error::from)?;
        // Omnical §17.9.2: the owner is an implicit admin (upsert so the row
        // wins even when the membership — and its default `edit` row — was
        // created first).
        sqlx::query(
            r#"
            INSERT INTO group_members (group_id, member_id, privilege)
            VALUES (?, ?, 'admin')
            ON CONFLICT(group_id, member_id) DO UPDATE SET privilege = 'admin'
            "#,
        )
        .bind(group_id)
        .bind(owner_id)
        .execute(&mut *tx)
        .await
        .map_err(crate::Error::from)?;
        tx.commit().await.map_err(crate::Error::from)?;
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
