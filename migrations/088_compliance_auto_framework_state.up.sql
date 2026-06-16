-- Migration 088: Continuous compliance evidence — per-framework rollup (WP6).
--
-- One row per (tenant, framework): a cheap, pre-aggregated posture
-- summary the collector upserts at the end of each sweep. It exists so
-- the "compliance posture" surface can render a tenant's per-framework
-- score (pass / total) and last-evaluated timestamp without scanning the
-- full control-status set — important at 5,000 SME tenants where the
-- dashboard and MSP roll-up read this frequently while the control rows
-- are written once per cycle.
--
-- Tenant-scoped + RLS, same posture as the other WP6 tables.

CREATE TABLE compliance_auto_framework_state (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID        NOT NULL REFERENCES tenants(id),
    framework       TEXT        NOT NULL,
    controls_total  INTEGER     NOT NULL DEFAULT 0,
    controls_pass   INTEGER     NOT NULL DEFAULT 0,
    controls_fail   INTEGER     NOT NULL DEFAULT 0,
    controls_na     INTEGER     NOT NULL DEFAULT 0,
    last_run_id     UUID        NOT NULL,
    evaluated_at    TIMESTAMPTZ NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE compliance_auto_framework_state ENABLE ROW LEVEL SECURITY;

CREATE POLICY compliance_auto_framework_state_tenant ON compliance_auto_framework_state
    USING (tenant_id::text = current_setting('sng.tenant_id', true))
    WITH CHECK (tenant_id::text = current_setting('sng.tenant_id', true));

CREATE POLICY compliance_auto_framework_state_system ON compliance_auto_framework_state
    USING (current_setting('sng.system_role', true) = 'true')
    WITH CHECK (current_setting('sng.system_role', true) = 'true');

-- The upsert target: exactly one rollup row per framework per tenant.
CREATE UNIQUE INDEX uq_compliance_auto_framework_state_tenant_fw
    ON compliance_auto_framework_state (tenant_id, framework);
