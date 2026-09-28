-- Omnical §3.4 — the hosted-tenancy control plane.
--
-- THIS IS A SEPARATE DATABASE from every tenant store, and this migration
-- lives in a separate directory (`control_migrations/`) from the tenant store
-- migrations for exactly that reason. Running `sqlx::migrate!("./migrations")`
-- against the control plane would create 13 tables of calendar, addressbook and
-- credential schema inside the one database that must not hold any of it. The
-- split is structural, not a convention: a control plane with a calendar table
-- in it is a per-tenant backup that can take out every other tenant.
--
-- It is the cross-tenant index (§3.2's stated cost: "no cross-tenant SQL
-- query"), so a tenant list or a status change is answerable here and nowhere
-- else. It holds no calendar, contact or credential data.
--
-- `slug` rather than `id` is the public identity because the slug is what
-- appears in a hostname ({slug}.{base_domain}, §3.3) and in a directory under
-- `data_root`. `id` stays the primary key so that a future slug rename (a
-- customer rebrands) does not rewrite every path that ever referenced them.
--
-- The CHECK on `status` is not decoration: `TenantStatus` parses from exactly
-- these two strings, and a third value written by hand would surface as a parse
-- error at request time, on the dispatch path, rather than at the moment of the
-- mistake.

CREATE TABLE tenants (
    id            TEXT PRIMARY KEY,          -- ulid/short random id
    slug          TEXT NOT NULL UNIQUE,      -- [a-z0-9-]{1,63}, DNS-safe
    display_name  TEXT NOT NULL,
    status        TEXT NOT NULL CHECK (status IN ('active','suspended')),
    plan          TEXT NOT NULL DEFAULT 'free',
    -- Per-tenant overrides for the GLOBAL-only config sections (§3.6):
    -- scheduling.smtp / scheduling.imap / subscriptions.public_url /
    -- registration.* / rsvp_secret. Absent key = inherit the global value.
    config_json   TEXT NOT NULL DEFAULT '{}',
    -- NULL = unlimited, which is why these are nullable and not 0. A 0 here
    -- would be indistinguishable from "deny everything".
    quota_principals   INTEGER,
    quota_calendars    INTEGER,
    quota_megabytes    INTEGER,
    created_at    TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    suspended_at  TEXT
);

-- `host` is the PRIMARY KEY, not an index on a (host, tenant) pair: one host
-- must resolve to exactly one tenant, and that is a constraint rather than a
-- convention. The alternative — allowing two rows for one host and letting the
-- application pick — makes "which tenant does this Host header belong to"
-- depend on row order, which is how a customer ends up served another
-- customer's calendar.
CREATE TABLE tenant_hosts (
    host    TEXT PRIMARY KEY,
    tenant  TEXT NOT NULL REFERENCES tenants (id) ON DELETE CASCADE
);

-- Listing filters on status and orders by creation time; without this the admin
-- view is a full scan of a table that is the one thing every request consults.
CREATE INDEX idx_tenants_status_created ON tenants (status, created_at DESC);

-- Resolving a host is the single hottest query in the system (every request,
-- §3.3). `tenant_hosts` is keyed by host, so the lookup is already an index
-- probe; this index covers the joining side.
CREATE INDEX idx_tenant_hosts_tenant ON tenant_hosts (tenant);
