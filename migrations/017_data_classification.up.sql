-- ShieldNet Gateway (SNG) — data classification taxonomy migration.
--
-- Phase 4, Task 46: Data Classification Taxonomy.
--
-- Adds the data_classifications table for hierarchical data
-- classification: Public, Internal, Confidential, Restricted,
-- Top Secret. Per-tenant customization of labels and handling
-- rules. DLP policy matches map to classification levels.

CREATE TABLE IF NOT EXISTS data_classifications (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id),
    label           TEXT NOT NULL,
    level           TEXT NOT NULL
                    CHECK (level IN ('public', 'internal', 'confidential', 'restricted', 'top_secret')),
    description     TEXT NOT NULL DEFAULT '',
    handling_rules  JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Per-tenant level uniqueness (one entry per level per tenant).
CREATE UNIQUE INDEX IF NOT EXISTS data_classifications_tenant_level_uniq
    ON data_classifications (tenant_id, level);

-- Tenant lookup index.
CREATE INDEX IF NOT EXISTS data_classifications_tenant_id_idx
    ON data_classifications (tenant_id);

-- RLS policy.
ALTER TABLE data_classifications ENABLE ROW LEVEL SECURITY;

CREATE POLICY data_classifications_tenant_isolation ON data_classifications
    USING (tenant_id = current_setting('sng.tenant_id', true)::uuid);
