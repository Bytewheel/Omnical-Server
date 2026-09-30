-- NOTE ON THE VERSION NUMBER. This is `...130000`, not `...120000`:
-- `20260929120000_admin_audit` already took 120000, and sqlx keys
-- `_sqlx_migrations` by the version string alone. A duplicate is not a
-- "skipped migration" warning — it is `UNIQUE constraint failed:
-- _sqlx_migrations.version` on the *second* `migrate!()` of the process, which
-- makes every control plane fail to open. The first version of this file was
-- numbered 120000 and the collision showed up as five unrelated-looking test
-- failures. Checked with `ls | sort` before trusting it.
-- Tenant usage snapshots (§7.5 item 20a, PLAN_DEPLOYMENTS.md §3.4).
--
-- A **snapshot**, not a live view. Deliberately: the alternative is the admin
-- panel reading each tenant's SQLite file, which is the one thing §6.6.6 says it
-- must never do ("the panel never opens a tenant's database"). A snapshot keeps
-- that boundary — the *job* crosses it, on a schedule, and the panel reads one
-- row from the control plane it already holds open.
--
-- `NULL` on a dimension means "not measured", which is a different fact from
-- zero. A usage figure that has never been collected rendered as `0` would tell
-- a customer they are at their limit when nothing is known about them, and a
-- missing snapshot rendering as `0` is the single most damaging thing this table
-- could do wrong. The panel's job is to render "not measured" — see
-- `tests/tenant_usage.rs`.
--
-- One row per tenant per run, replaced rather than appended, so the table's size
-- is bounded by the tenant count and not by how long the server has been up.
-- History, if it is ever wanted, belongs in a metrics exporter, not in a table
-- somebody queries from a request path.

CREATE TABLE control_tenant_usage (
    tenant_id        TEXT    PRIMARY KEY
                     REFERENCES tenants(id) ON DELETE CASCADE,

    -- When the snapshot was taken. NOT `DEFAULT now` on purpose: the value is
    -- written by the job so that a clock skew between the job and the database
    -- shows up as a wrong timestamp rather than as a plausible one.
    measured_at     TEXT    NOT NULL,

    -- Who ran the job. §6.6.7's rule: the audit table records an actor, and a
    -- usage number with no provenance is a number nobody can act on.
    actor           TEXT    NOT NULL,

    principals      INTEGER,
    calendars       INTEGER,
    addressbooks    INTEGER,
    -- Bytes, from the file itself, not from summing rows. A `SUM(length(...))`
    -- over every object is a full table scan of the customer's data on a
    -- schedule, which is the job turning into a load generator.
    bytes_on_disk   INTEGER,

    -- The count of the measurement, so a stale figure is visible as a fact
    -- rather than inferred from `measured_at` alone.
    object_count    INTEGER
);

-- `measured_at` is what an operator queries ("who has not reported?"), and
-- `tenant_id` alone does not answer it.
CREATE INDEX control_tenant_usage_measured_at ON control_tenant_usage(measured_at);
