-- Reverses 20260928120000_control_plane.up.sql.
--
-- `tenant_hosts` is dropped first even though `ON DELETE CASCADE` would clear
-- its rows anyway: it holds a foreign key *into* `tenants`, so the referencing
-- table has to go first. Dropping `tenants` and letting the cascade do it
-- works today and is the kind of thing that breaks the day this file is edited.

DROP INDEX IF EXISTS idx_tenant_hosts_tenant;
DROP INDEX IF EXISTS idx_tenants_status_created;
DROP TABLE IF EXISTS tenant_hosts;
DROP TABLE IF EXISTS tenants;
