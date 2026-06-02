-- Migration 032: Knowledge base entries for the troubleshooting assistant.
-- Supports global (tenant_id IS NULL) and per-tenant custom entries.

CREATE TABLE kb_entries (
    id         UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id  UUID        REFERENCES tenants(id),
    category   TEXT        NOT NULL CHECK (category IN ('connectivity', 'policy', 'identity', 'performance', 'integration')),
    title      TEXT        NOT NULL,
    content    TEXT        NOT NULL,
    tags       TEXT[]      NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- RLS: tenants can read global + own entries, but only mutate their own.
ALTER TABLE kb_entries ENABLE ROW LEVEL SECURITY;

CREATE POLICY kb_entries_tenant_read ON kb_entries
    FOR SELECT
    USING (
        tenant_id IS NULL
        OR tenant_id::text = current_setting('sng.tenant_id', true)
    );

CREATE POLICY kb_entries_tenant_insert ON kb_entries
    FOR INSERT
    WITH CHECK (tenant_id::text = current_setting('sng.tenant_id', true));

CREATE POLICY kb_entries_tenant_update ON kb_entries
    FOR UPDATE
    USING (tenant_id::text = current_setting('sng.tenant_id', true))
    WITH CHECK (tenant_id::text = current_setting('sng.tenant_id', true));

CREATE POLICY kb_entries_tenant_delete ON kb_entries
    FOR DELETE
    USING (tenant_id::text = current_setting('sng.tenant_id', true));

CREATE POLICY kb_entries_system ON kb_entries
    USING (current_setting('sng.system_role', true) = 'true')
    WITH CHECK (current_setting('sng.system_role', true) = 'true');

CREATE INDEX idx_kb_entries_tenant_category ON kb_entries (tenant_id, category);
CREATE INDEX idx_kb_entries_tags ON kb_entries USING GIN (tags);
