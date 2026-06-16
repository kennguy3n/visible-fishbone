-- Migration 085: Continuous compliance evidence — collection runs (WP6).
--
-- The `complianceauto` service (internal/service/complianceauto) maps
-- real platform state to SOC 2 / ISO 27001 controls on a bounded,
-- leader-gated schedule. Each time it evaluates a tenant it records a
-- run row here: the wall-clock window of the evaluation and the
-- per-status control tallies. The run is the parent audit record the
-- control-status and evidence rows reference by run_id (a plain UUID
-- column, not an FK — keeping the tenant-scoped RLS tables independent
-- so a sweep never has to coordinate cross-table insert ordering under
-- row-level security).
--
-- Tenant-scoped: every row belongs to exactly one tenant and is
-- protected by RLS, mirroring compliance_reports (migration 023) and
-- idp_configs (migration 034). The leader-only collector runs under the
-- system role (sng.system_role='true') so it can sweep every tenant.

CREATE TABLE compliance_auto_runs (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID        NOT NULL REFERENCES tenants(id),
    started_at      TIMESTAMPTZ NOT NULL,
    finished_at     TIMESTAMPTZ NOT NULL,
    controls_total  INTEGER     NOT NULL DEFAULT 0,
    controls_pass   INTEGER     NOT NULL DEFAULT 0,
    controls_fail   INTEGER     NOT NULL DEFAULT 0,
    controls_na     INTEGER     NOT NULL DEFAULT 0,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE compliance_auto_runs ENABLE ROW LEVEL SECURITY;

-- Tenant-scoped policy: a request bound to sng.tenant_id sees only its
-- own runs. Mirrors every other tenant-scoped table.
CREATE POLICY compliance_auto_runs_tenant ON compliance_auto_runs
    USING (tenant_id::text = current_setting('sng.tenant_id', true))
    WITH CHECK (tenant_id::text = current_setting('sng.tenant_id', true));

-- System policy: the leader-only collector (sng.system_role='true')
-- may read/write across tenants to drive the scheduled sweep.
CREATE POLICY compliance_auto_runs_system ON compliance_auto_runs
    USING (current_setting('sng.system_role', true) = 'true')
    WITH CHECK (current_setting('sng.system_role', true) = 'true');

-- The posture/export read paths fetch the most recent run for a tenant;
-- index the (tenant, recency) sort key.
CREATE INDEX idx_compliance_auto_runs_tenant_started
    ON compliance_auto_runs (tenant_id, started_at DESC);
