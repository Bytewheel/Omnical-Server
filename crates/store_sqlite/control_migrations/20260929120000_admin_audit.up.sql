-- Omnical §6.6 — the admin audit trail and the platform-admin credential store.
--
-- These two tables live in the CONTROL PLANE, which is already the most
-- sensitive file in the system: it holds every tenant's `scheduling.smtp`
-- password in `tenants.config_json` (§3.6). Adding the platform admin's hash here
-- is what §18.20 records as the item's security consequence — the file that was
-- made 0600 for SMTP passwords now also protects the one credential that crosses
-- every tenant boundary. It is created 0600 by `create_control_plane_pool`
-- before SQLx opens it, so there is no window in which either is world-readable.

-- ── The audit trail ──────────────────────────────────────────────────────────
--
-- Append-only, and the append happens **in the same transaction as the mutation
-- it records** (§6.6.7). That is the whole point of the table: an audit row
-- that could be written after the fact, or lost when a process dies between two
-- statements, is not a control. `TenantStore`'s mutating methods own the
-- transaction, so no caller — panel or CLI — can bypass it by choosing a
-- different tool.
--
-- There is deliberately no UPDATE or DELETE path for this table anywhere in the
-- fork, and no `ON DELETE CASCADE` from `tenants`: an audit row must outlive the
-- tenant it describes, or deleting a tenant would erase the record of who
-- deleted it.
CREATE TABLE control_admin_audit (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    actor     TEXT NOT NULL,          -- an admin name, or the CLI's --actor
    action    TEXT NOT NULL,          -- create_tenant, update_tenant_status, …
    tenant    TEXT,                   -- the tenant id; NULL for create
    at        TEXT NOT NULL,          -- ISO-8601 UTC, written by Rust
    detail    TEXT                    -- optional JSON; never a credential
);

-- The admin list reads newest-last, and an incident reads one tenant's history
-- in time order. Without these it is a full scan of the only table whose growth
-- is unbounded.
CREATE INDEX idx_control_admin_audit_at ON control_admin_audit (at);
CREATE INDEX idx_control_admin_audit_tenant ON control_admin_audit (tenant, at);

-- ── Platform admins ──────────────────────────────────────────────────────────
--
-- The credential half of an identity whose *names* live in `[tenancy]
-- platform_admins` (config, reviewable in version control, no secret in it).
-- The split is the security property, not a convenience: **config is
-- authoritative**, so a name absent from `platform_admins` cannot authenticate
-- even with a valid hash here. That is what stops anyone who can write this file
-- — the file holding every tenant's SMTP password — from promoting themselves.
--
-- `failed_attempts`/`locked_until` are the lockout state (§6.6.5). They are here
-- rather than in memory because a lockout that resets on restart is not a
-- lockout, and an admin brute-force must not be able to wait out a restart.
CREATE TABLE platform_admins (
    name           TEXT PRIMARY KEY,   -- must also appear in platform_admins
    password_hash  TEXT NOT NULL,      -- argon2, the same primitive `principals` uses
    created_at     TEXT NOT NULL,
    last_login_at  TEXT,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until   TEXT
);
