-- 022_compliance — Compliance reports table.
--
-- Stores generated compliance assessment reports per tenant/framework.
-- Each report captures a point-in-time compliance score, control
-- statuses, and an evidence pack in JSONB.

CREATE TABLE IF NOT EXISTS compliance_reports (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    framework       TEXT NOT NULL CHECK (framework IN ('PCI_DSS', 'HIPAA', 'SOC2', 'ISO_27001')),
    score           DOUBLE PRECISION NOT NULL DEFAULT 0,
    max_score       DOUBLE PRECISION NOT NULL DEFAULT 0,
    controls        JSONB NOT NULL DEFAULT '[]'::jsonb,
    evidence_pack   JSONB NOT NULL DEFAULT '{}'::jsonb,
    generated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_compliance_reports_tenant ON compliance_reports(tenant_id);
CREATE INDEX idx_compliance_reports_tenant_framework ON compliance_reports(tenant_id, framework);

ALTER TABLE compliance_reports ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON compliance_reports
    USING (tenant_id = current_setting('sng.tenant_id')::uuid);
