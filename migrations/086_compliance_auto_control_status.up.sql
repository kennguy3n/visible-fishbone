-- Migration 086: Continuous compliance evidence — latest control status (WP6).
--
-- One row per (tenant, framework, control): the most recent evaluation
-- of a single SOC 2 / ISO 27001 control for a tenant. The collector
-- upserts this row every sweep so the posture read path is a single
-- cheap indexed scan rather than an aggregation over the evidence
-- history. `details` carries the structured evidence reference (what was
-- observed, the source, and any collector-specific facts) as JSONB.
--
-- status is constrained to the pass/fail/not_applicable vocabulary the
-- engine computes. collector_id records which evidence collector
-- produced the observation, and run_id ties the row back to the
-- compliance_auto_runs record for the sweep that wrote it.
--
-- Tenant-scoped + RLS, same posture as compliance_auto_runs (085).

CREATE TABLE compliance_auto_control_status (
    id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id    UUID        NOT NULL REFERENCES tenants(id),
    framework    TEXT        NOT NULL,
    control_id   TEXT        NOT NULL,
    status       TEXT        NOT NULL
        CONSTRAINT compliance_auto_control_status_status_chk
            CHECK (status IN ('pass', 'fail', 'not_applicable')),
    collector_id TEXT        NOT NULL,
    summary      TEXT        NOT NULL DEFAULT '',
    source       TEXT        NOT NULL DEFAULT '',
    details      JSONB       NOT NULL DEFAULT '{}',
    observed_at  TIMESTAMPTZ NOT NULL,
    run_id       UUID        NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE compliance_auto_control_status ENABLE ROW LEVEL SECURITY;

CREATE POLICY compliance_auto_control_status_tenant ON compliance_auto_control_status
    USING (tenant_id::text = current_setting('sng.tenant_id', true))
    WITH CHECK (tenant_id::text = current_setting('sng.tenant_id', true));

CREATE POLICY compliance_auto_control_status_system ON compliance_auto_control_status
    USING (current_setting('sng.system_role', true) = 'true')
    WITH CHECK (current_setting('sng.system_role', true) = 'true');

-- The upsert target: exactly one current status row per control per
-- framework per tenant. The collector's ON CONFLICT clause keys off
-- this index.
CREATE UNIQUE INDEX uq_compliance_auto_control_status_tenant_fw_ctrl
    ON compliance_auto_control_status (tenant_id, framework, control_id);

-- The posture endpoint filters by (tenant, framework); index it.
CREATE INDEX idx_compliance_auto_control_status_tenant_fw
    ON compliance_auto_control_status (tenant_id, framework);
