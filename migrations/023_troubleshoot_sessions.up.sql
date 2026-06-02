-- Migration 028: Troubleshoot sessions for the autonomous troubleshooting assistant.

CREATE TABLE troubleshoot_sessions (
    id                 UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id          UUID        NOT NULL REFERENCES tenants(id),
    operator_id        UUID        NOT NULL,
    issue              TEXT        NOT NULL,
    status             TEXT        NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'resolved', 'escalated')),
    messages           JSONB       NOT NULL DEFAULT '[]',
    diagnostic_results JSONB       NOT NULL DEFAULT '[]',
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE troubleshoot_sessions ENABLE ROW LEVEL SECURITY;

CREATE POLICY troubleshoot_sessions_tenant ON troubleshoot_sessions
    USING (tenant_id::text = current_setting('sng.tenant_id', true))
    WITH CHECK (tenant_id::text = current_setting('sng.tenant_id', true));

CREATE POLICY troubleshoot_sessions_system ON troubleshoot_sessions
    USING (current_setting('sng.system_role', true) = 'true')
    WITH CHECK (current_setting('sng.system_role', true) = 'true');

CREATE INDEX idx_troubleshoot_sessions_tenant ON troubleshoot_sessions (tenant_id, created_at DESC);
