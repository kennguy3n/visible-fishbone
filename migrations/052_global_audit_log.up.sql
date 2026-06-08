-- 052_global_audit_log
--
-- Permit platform-scoped (tenant-less) audit rows so GLOBAL
-- app_registry catalog mutations and vendor syncs leave a forensic
-- record.
--
-- Before this migration, those events were emitted with
-- tenant_id = uuid.Nil (see internal/service/appdb/service.go) and
-- rejected by the audit_log NOT NULL constraint, so the audit trail
-- for global mutations was silently dropped — the control plane
-- logged a recurring "appdb: audit append failed" warning on every
-- app-registry sync. The app_registry catalog is global (not
-- tenant-scoped), so its mutations have no owning tenant; NULL is the
-- correct representation.

-- Allow the global rows. The FK to tenants(id) is unaffected: a NULL
-- value is never checked against the referenced table.
ALTER TABLE audit_log ALTER COLUMN tenant_id DROP NOT NULL;

-- Replace the strict tenant-isolation policy with the standard
-- tenant + system-role form already used by tenant_usage,
-- integrations, webhooks, metering, etc. Tenant sessions still see
-- ONLY their own rows: a NULL-tenant row never satisfies
-- `tenant_id = <tenant GUC>`, and tenant sessions never carry
-- sng.system_role. Only system-role sessions (sng.system_role='true',
-- set exclusively via Store.withSystem) can read or write the global
-- rows.
DROP POLICY audit_log_tenant_isolation ON audit_log;
CREATE POLICY audit_log_tenant_isolation ON audit_log
    USING (
        tenant_id = NULLIF(current_setting('sng.tenant_id', true), '')::uuid
        OR NULLIF(current_setting('sng.system_role', true), '') = 'true'
    )
    WITH CHECK (
        tenant_id = NULLIF(current_setting('sng.tenant_id', true), '')::uuid
        OR NULLIF(current_setting('sng.system_role', true), '') = 'true'
    );

-- A partial index keeps the global-audit read path (system-role
-- sessions filtering tenant_id IS NULL) from scanning the full
-- per-tenant history.
CREATE INDEX audit_log_global_idx ON audit_log (created_at DESC) WHERE tenant_id IS NULL;
