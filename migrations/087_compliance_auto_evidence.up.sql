-- Migration 087: Continuous compliance evidence — evidence history (WP6).
--
-- Append-only log of every evidence observation the collector produces.
-- Where compliance_auto_control_status (086) holds only the *latest*
-- status per control, this table retains the full time series: one row
-- per (control, sweep) so an auditor can see how a control's posture
-- evolved and when a failing control was remediated. Evidence packs are
-- generated on demand from these rows plus the latest-status table.
--
-- This is distinct from the platform-level `compliance_evidence` table
-- (migration 039), which indexes signed SOC 2 bundles archived to S3 and
-- is NOT tenant-scoped. This table is per-tenant continuous-collection
-- evidence and IS RLS-scoped.

CREATE TABLE compliance_auto_evidence (
    id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id    UUID        NOT NULL REFERENCES tenants(id),
    run_id       UUID        NOT NULL,
    framework    TEXT        NOT NULL,
    control_id   TEXT        NOT NULL,
    collector_id TEXT        NOT NULL,
    status       TEXT        NOT NULL
        CONSTRAINT compliance_auto_evidence_status_chk
            CHECK (status IN ('pass', 'fail', 'not_applicable')),
    summary      TEXT        NOT NULL DEFAULT '',
    source       TEXT        NOT NULL DEFAULT '',
    details      JSONB       NOT NULL DEFAULT '{}',
    observed_at  TIMESTAMPTZ NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE compliance_auto_evidence ENABLE ROW LEVEL SECURITY;

CREATE POLICY compliance_auto_evidence_tenant ON compliance_auto_evidence
    USING (tenant_id::text = current_setting('sng.tenant_id', true))
    WITH CHECK (tenant_id::text = current_setting('sng.tenant_id', true));

CREATE POLICY compliance_auto_evidence_system ON compliance_auto_evidence
    USING (current_setting('sng.system_role', true) = 'true')
    WITH CHECK (current_setting('sng.system_role', true) = 'true');

-- Evidence-pack export and the per-control history view both read
-- newest-first, optionally filtered by control; index both access
-- patterns.
CREATE INDEX idx_compliance_auto_evidence_tenant_observed
    ON compliance_auto_evidence (tenant_id, observed_at DESC);

CREATE INDEX idx_compliance_auto_evidence_tenant_ctrl_observed
    ON compliance_auto_evidence (tenant_id, control_id, observed_at DESC);
