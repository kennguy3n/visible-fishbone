-- Migration 031: Operational health snapshot tables.
-- Stores periodic per-tenant health scores and component breakdowns.

CREATE TABLE ops_health_snapshots (
    id               UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id        UUID        NOT NULL REFERENCES tenants(id),
    health_score     INT         NOT NULL CHECK (health_score >= 0 AND health_score <= 100),
    component_scores JSONB       NOT NULL DEFAULT '{}',
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- RLS policy on tenant_id.
ALTER TABLE ops_health_snapshots ENABLE ROW LEVEL SECURITY;
CREATE POLICY ops_health_snapshots_tenant ON ops_health_snapshots
    USING (tenant_id::text = current_setting('sng.tenant_id', true))
    WITH CHECK (tenant_id::text = current_setting('sng.tenant_id', true));

CREATE POLICY ops_health_snapshots_system ON ops_health_snapshots
    USING (current_setting('sng.system_role', true) = 'true')
    WITH CHECK (current_setting('sng.system_role', true) = 'true');

-- Index on (tenant_id, created_at DESC) for efficient history queries.
CREATE INDEX idx_ops_health_snapshots_tenant_time
    ON ops_health_snapshots (tenant_id, created_at DESC);
