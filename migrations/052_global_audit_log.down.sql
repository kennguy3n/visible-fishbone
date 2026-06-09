-- 052_global_audit_log (down)
--
-- Restore strict per-tenant audit_log isolation. The global
-- (NULL-tenant) rows must be removed before the NOT NULL constraint
-- can be re-applied. The migration runner is a superuser and so
-- bypasses FORCE ROW LEVEL SECURITY (see 002_role_bootstrap.up.sql).
--
-- audit_log_global_idx is owned by migration 055 (created CONCURRENTLY
-- there) and its 055 down step drops it. We also DROP IF EXISTS it here
-- so a database that applied the pre-split 052 — which created the
-- index inline — is still cleaned up if it rolls 052 back without
-- having migrated through 055. A plain DROP INDEX takes a brief
-- ACCESS EXCLUSIVE lock and is not a table rewrite, so it is lock-safe.

DROP INDEX IF EXISTS audit_log_global_idx;

DELETE FROM audit_log WHERE tenant_id IS NULL;

DROP POLICY audit_log_tenant_isolation ON audit_log;
CREATE POLICY audit_log_tenant_isolation ON audit_log
    USING (tenant_id = NULLIF(current_setting('sng.tenant_id', true), '')::uuid);

ALTER TABLE audit_log ALTER COLUMN tenant_id SET NOT NULL;
