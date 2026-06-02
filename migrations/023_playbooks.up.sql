-- 023_playbooks — Playbook definitions table.
--
-- Each playbook defines a trigger condition and an ordered set of
-- response steps. Steps are stored as JSONB array so the schema
-- is flexible across step types.

CREATE TABLE IF NOT EXISTS playbooks (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id         UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name              TEXT NOT NULL,
    description       TEXT NOT NULL DEFAULT '',
    trigger_condition TEXT NOT NULL DEFAULT '',
    steps             JSONB NOT NULL DEFAULT '[]'::jsonb,
    enabled           BOOLEAN NOT NULL DEFAULT true,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT playbooks_name_tenant_unique UNIQUE (tenant_id, name)
);

CREATE INDEX idx_playbooks_tenant ON playbooks(tenant_id);
CREATE INDEX idx_playbooks_tenant_enabled ON playbooks(tenant_id, enabled);

ALTER TABLE playbooks ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON playbooks
    USING (tenant_id = current_setting('sng.tenant_id')::uuid);
