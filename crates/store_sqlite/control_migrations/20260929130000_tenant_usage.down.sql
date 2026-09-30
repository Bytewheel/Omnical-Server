-- §18.21's rule applies here too: a down that drops a table is destructive, and
-- that is worth knowing rather than discovering. `control_tenant_usage` holds no
-- customer data — it is derived, and `rustical tenant usage` regenerates it — so
-- dropping it costs one measurement, not a customer's calendar.
DROP INDEX IF EXISTS control_tenant_usage_measured_at;
DROP TABLE IF EXISTS control_tenant_usage;
