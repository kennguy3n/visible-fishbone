-- ShieldNet Gateway (SNG) — browser protection policies migration.
--
-- Phase 4, Task 43: Browser Protection Service.
--
-- Adds the browser_policies table for managing browser-level
-- enforcement: download/upload restriction, clipboard control,
-- print control, screenshot prevention, and URL category blocking.
--
-- RLS: tenant-scoped via sng.tenant_id, same contract as sites.

CREATE TABLE IF NOT EXISTS browser_policies (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id   UUID NOT NULL REFERENCES tenants(id),
    name        TEXT NOT NULL,
    -- Rules is a JSONB array of {type, condition, action} objects.
    rules       JSONB NOT NULL DEFAULT '[]'::jsonb,
    action      TEXT NOT NULL DEFAULT 'block'
                CHECK (action IN ('block', 'allow', 'warn', 'log')),
    scope       TEXT NOT NULL DEFAULT 'user'
                CHECK (scope IN ('user', 'group', 'site')),
    enabled     BOOLEAN NOT NULL DEFAULT true,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Per-tenant name uniqueness.
CREATE UNIQUE INDEX IF NOT EXISTS browser_policies_tenant_name_uniq
    ON browser_policies (tenant_id, name);

-- Tenant lookup index for List queries.
CREATE INDEX IF NOT EXISTS browser_policies_tenant_id_idx
    ON browser_policies (tenant_id);

-- RLS policy: same pattern as sites.
ALTER TABLE browser_policies ENABLE ROW LEVEL SECURITY;

CREATE POLICY browser_policies_tenant_isolation ON browser_policies
    USING (tenant_id = current_setting('sng.tenant_id', true)::uuid);
