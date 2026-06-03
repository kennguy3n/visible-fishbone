-- Migration 029: AI alert correlations table.
-- Stores incident clusters produced by the AI correlation engine.

CREATE TABLE ai_alert_correlations (
    id         UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id  UUID        NOT NULL REFERENCES tenants(id),
    alert_ids  UUID[]      NOT NULL,
    summary    TEXT        NOT NULL DEFAULT '',
    severity   TEXT        NOT NULL,
    status     TEXT        NOT NULL DEFAULT 'open'
                           CHECK (status IN ('open', 'acknowledged', 'resolved')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- RLS policy on tenant_id.
ALTER TABLE ai_alert_correlations ENABLE ROW LEVEL SECURITY;
CREATE POLICY ai_alert_correlations_tenant ON ai_alert_correlations
    USING (tenant_id::text = current_setting('sng.tenant_id', true))
    WITH CHECK (tenant_id::text = current_setting('sng.tenant_id', true));

CREATE POLICY ai_alert_correlations_system ON ai_alert_correlations
    USING (current_setting('sng.system_role', true) = 'true')
    WITH CHECK (current_setting('sng.system_role', true) = 'true');

CREATE INDEX idx_ai_alert_correlations_tenant_created
    ON ai_alert_correlations (tenant_id, created_at DESC);
