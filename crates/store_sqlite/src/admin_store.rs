//! Platform-admin credentials in the control plane — `PLAN_DEPLOYMENTS.md`
//! §6.6.3, §6.6.5.
//!
//! ## Why this is on `SqliteTenantStore` and not its own struct
//!
//! Because it is **the same database**. `SqliteTenantStore` owns the control
//! plane's pool, and the whole argument for that pool being separate
//! (`tenant_store.rs`'s module doc) is that a tenant's backup cannot reach the
//! cross-tenant index. A second struct over the same file would be a second
//! pool — and that module doc already explains why the control plane pool is
//! deliberately capped at two connections.
//!
//! The struct's name is a little narrow for it, which is the cost of not
//! renaming something item 8, 11 and 12 all reference in their tests. Its own
//! module doc calling it the control plane is the tie-breaker.
//!
//! ## The invariant this file cannot enforce
//!
//! **Config is authoritative.** Nothing here checks `platform_admins`, and
//! that is correct rather than an oversight: this file cannot see the config.
//! Every caller must check a name against the allowlist *before* asking for its
//! credential, and the phase-3 login form is where that check lives. What this
//! file contributes is [`AdminCredentialStore::allowlist_gaps`], which is how an
//! operator *sees* a name sitting in the wrong half.
//!
//! ## Error types
//!
//! Internals speak this crate's [`Error`] (which maps a unique violation to
//! `AlreadyExists`); the trait methods return `rustical_store::Error` and
//! convert at the boundary, exactly as `tenant_store.rs` does. None of the
//! statements here can raise a unique violation — `set_admin_credential` is an
//! `ON CONFLICT` upsert — so that mapping is not load-bearing here; it is
//! inherited by using the same type rather than by being needed.

use rustical_store::admin_store::{
    ADMIN_LOCKOUT_SECS, ADMIN_MAX_FAILED_ATTEMPTS, AdminCredential, AdminCredentialStore,
    AdminStanding,
};
use sqlx::{AssertSqlSafe, Row};

use crate::error::Error;
use crate::{SqliteTenantStore, now_iso};

/// The columns every admin read selects, in one place — same reasoning as
/// `TENANT_COLUMNS` in `tenant_store.rs`: a `SELECT *` would silently widen the
/// struct the next time a column is added.
const ADMIN_COLUMNS: &str =
    "name, password_hash, created_at, last_login_at, failed_attempts, locked_until";

/// A row that does not satisfy its own schema.
///
/// Same treatment as `tenant_store.rs`'s `decode_error`: a corrupt control
/// plane belongs in the 500 path, not in a default that would silently
/// authenticate somebody or silently lock them out.
fn decode_error(message: impl Into<String>) -> Error {
    Error::SqlxError(sqlx::Error::Decode(Box::new(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        format!("control_admin_credential: {}", message.into()),
    ))))
}

fn row_to_admin(row: &sqlx::sqlite::SqliteRow) -> Result<AdminCredential, Error> {
    let failed_attempts: i64 = row
        .try_get("failed_attempts")
        .map_err(|e| decode_error(format!("failed_attempts is not an integer: {e}")))?;
    Ok(AdminCredential {
        name: row.try_get("name").map_err(Error::from)?,
        password_hash: row.try_get("password_hash").map_err(Error::from)?,
        created_at: row.try_get("created_at").map_err(Error::from)?,
        last_login_at: row.try_get("last_login_at").map_err(Error::from)?,
        failed_attempts,
        locked_until: row.try_get("locked_until").map_err(Error::from)?,
    })
}

#[async_trait::async_trait]
impl AdminCredentialStore for SqliteTenantStore {
    async fn set_admin_credential(
        &self,
        name: &str,
        password_hash: &str,
        now: &str,
    ) -> Result<(), rustical_store::Error> {
        // `ON CONFLICT DO UPDATE`, and the update **resets the lockout state**.
        // That is the intended reading of a re-`add`: a credential reset, after
        // which "five wrong passwords" starts again. It is also the only
        // supported way to un-stick a locked-out admin, and refusing it would
        // leave the operator with no recovery at all.
        //
        // `created_at` is deliberately **not** overwritten: it is when this
        // credential was first issued, which stays true across a rotation.
        sqlx::query(
            "INSERT INTO platform_admins (name, password_hash, created_at, failed_attempts) \
             VALUES (?, ?, ?, 0) \
             ON CONFLICT(name) DO UPDATE SET password_hash = excluded.password_hash, \
             failed_attempts = 0, locked_until = NULL",
        )
        .bind(name)
        .bind(password_hash)
        .bind(now)
        .execute(self.pool())
        .await
        .map_err(Error::from)?;
        Ok(())
    }

    async fn get_admin_credential(
        &self,
        name: &str,
    ) -> Result<Option<AdminCredential>, rustical_store::Error> {
        // Exact and case-sensitive, matching how `platform_admins` is written
        // in config and passed to `--actor`. A case-insensitive match here
        // would make "Ops" and "ops" two rows in one table while the allowlist
        // treats them as one name.
        // `AssertSqlSafe` for the same reason and on the same terms as
        // `tenant_store.rs`'s: the only interpolated part is `ADMIN_COLUMNS`, a
        // `const` with no user input in it, and the *value* is still a bound
        // parameter. sqlx cannot see that through `format!`.
        let query = format!("SELECT {ADMIN_COLUMNS} FROM platform_admins WHERE name = ?");
        let row = sqlx::query(AssertSqlSafe(query.as_str()))
            .bind(name)
            .fetch_optional(self.pool())
            .await
            .map_err(Error::from)?;
        row.as_ref()
            .map(row_to_admin)
            .transpose()
            .map_err(Into::into)
    }

    async fn list_admin_credentials(&self) -> Result<Vec<AdminCredential>, rustical_store::Error> {
        let query = format!("SELECT {ADMIN_COLUMNS} FROM platform_admins ORDER BY name");
        let rows = sqlx::query(AssertSqlSafe(query.as_str()))
            .fetch_all(self.pool())
            .await
            .map_err(Error::from)?;
        rows.iter()
            .map(row_to_admin)
            .collect::<Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    async fn remove_admin_credential(&self, name: &str) -> Result<bool, rustical_store::Error> {
        let result = sqlx::query("DELETE FROM platform_admins WHERE name = ?")
            .bind(name)
            .execute(self.pool())
            .await
            .map_err(Error::from)?;
        Ok(result.rows_affected() > 0)
    }

    async fn record_login_failure(
        &self,
        name: &str,
        _now: &str,
        lockout_until: &str,
    ) -> Result<(), rustical_store::Error> {
        // One statement, not a read-modify-write. Under a concurrent flood of
        // wrong passwords a read-modify-write loses updates, and the lockout
        // would then be *weaker* under exactly the load that is trying to beat
        // it — the failure mode a lockout exists to prevent.
        //
        // `MAX(COALESCE(locked_until, ?), ?)` on the threshold attempt: a name
        // that is already locked keeps its existing, later value, so failing
        // repeatedly can neither shorten a lockout nor clear one. `MAX` of NULL
        // and a string is the string, which is what makes the "already locked"
        // case a no-op rather than an overwrite.
        sqlx::query(
            "UPDATE platform_admins \
             SET failed_attempts = failed_attempts + 1, \
                 locked_until = CASE \
                     WHEN failed_attempts + 1 >= ? THEN MAX(COALESCE(locked_until, ?), ?) \
                     ELSE locked_until \
                 END \
             WHERE name = ?",
        )
        .bind(ADMIN_MAX_FAILED_ATTEMPTS)
        .bind(lockout_until)
        .bind(lockout_until)
        .bind(name)
        .execute(self.pool())
        .await
        .map_err(Error::from)?;
        Ok(())
    }

    async fn record_login_success(
        &self,
        name: &str,
        now: &str,
    ) -> Result<(), rustical_store::Error> {
        sqlx::query(
            "UPDATE platform_admins \
             SET failed_attempts = 0, locked_until = NULL, last_login_at = ? \
             WHERE name = ?",
        )
        .bind(now)
        .bind(name)
        .execute(self.pool())
        .await
        .map_err(Error::from)?;
        Ok(())
    }

    async fn allowlist_gaps(
        &self,
        allowlist: &[String],
    ) -> Result<Vec<(String, AdminStanding)>, rustical_store::Error> {
        let credentials = self.list_admin_credentials().await?;
        let mut out: Vec<(String, AdminStanding)> = credentials
            .iter()
            .map(|c| {
                let standing = if allowlist.iter().any(|n| n == &c.name) {
                    AdminStanding::Ready {
                        credential: c.clone(),
                    }
                } else {
                    AdminStanding::NotAllowlisted {
                        credential: c.clone(),
                    }
                };
                (c.name.clone(), standing)
            })
            .collect();
        for name in allowlist {
            if !out.iter().any(|(n, _)| n == name) {
                out.push((name.clone(), AdminStanding::NoCredential));
            }
        }
        out.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(out)
    }
}

/// The current time, in the format the credential columns are written in.
///
/// Public because the CLI writes `created_at`/`last_login_at` from outside the
/// crate, and a caller that formatted the timestamp itself would eventually
/// disagree with `is_locked`'s string comparison by one character.
#[must_use]
pub fn admin_now() -> String {
    now_iso()
}

/// The lockout deadline for a failure recorded at `now`.
///
/// Exposed so the login handler computes the **same** string it would have
/// stored, rather than depending on the SQL `CASE` alone: a test asserting
/// "still locked one second before the deadline, free after it" needs the
/// deadline without reaching into a row, and phase 3's login handler needs it
/// to decide whether to even run the password comparison.
///
/// Never fails. An unparseable `now` falls back to the real clock, because a
/// malformed timestamp should not be a panic on a login path, and the real
/// clock is the only timestamp in reach that is certainly valid.
#[must_use]
pub fn admin_lockout_until(now: &str) -> String {
    let deadline = chrono::DateTime::parse_from_rfc3339(now)
        .unwrap_or_else(|_| chrono::Utc::now().fixed_offset())
        + chrono::Duration::seconds(ADMIN_LOCKOUT_SECS);
    deadline.format("%Y-%m-%dT%H:%M:%SZ").to_string()
}
