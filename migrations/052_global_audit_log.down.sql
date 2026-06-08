-- 052_global_audit_log (down)
--
-- Restore strict per-tenant audit_log isolation. The global
-- (NULL-tenant) rows must be removed before the NOT NULL constraint
-- can be re-applied. The migration runner is a superuser and so
-- bypasses FORCE ROW LEVEL SECURITY (see 002_role_bootstrap.up.sql).

DROP INDEX IF EXISTS audit_log_global_idx;

DELETE FROM audit_log WHERE tenant_id IS NULL;

DROP POLICY audit_log_tenant_isolation ON audit_log;
CREATE POLICY audit_log_tenant_isolation ON audit_log
    USING (tenant_id = NULLIF(current_setting('sng.tenant_id', true), '')::uuid);

ALTER TABLE audit_log ALTER COLUMN tenant_id SET NOT NULL;
