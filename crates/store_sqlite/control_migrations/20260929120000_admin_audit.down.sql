-- Reverses 20260929120000_admin_audit.up.sql.
--
-- `platform_admins` first: it holds credential hashes, and the indexes belong to
-- the audit table. The audit table goes last, and on purpose — a migration that
-- dropped it would leave no record that it had ever existed.

DROP INDEX IF EXISTS idx_control_admin_audit_tenant;
DROP INDEX IF EXISTS idx_control_admin_audit_at;
DROP TABLE IF EXISTS platform_admins;
DROP TABLE IF EXISTS control_admin_audit;
