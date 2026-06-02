-- ShieldNet Gateway (SNG) — DLP (Data Loss Prevention) migration.
--
-- Phase 4: web + SaaS DLP — regex, MIP labels, document fingerprints.
--
-- Tables introduced:
--   - dlp_policies      : tenant-scoped DLP policy definitions with
--                         JSONB-encoded rules, action, and enable flag.
--   - dlp_fingerprints  : registered document fingerprints for
--                         near-duplicate detection via SimHash.
--   - dlp_matches       : audit trail recording every time a DLP
--                         policy fires against inspected content.
--
-- All three tables are RLS-protected via the existing
-- `sng.tenant_id` GUC pattern. Indexes are designed for the hot
-- path: "list all enabled policies for a tenant" and "list all
-- fingerprints for a tenant".

-- dlp_policies ----------------------------------------------------------

CREATE TABLE IF NOT EXISTS dlp_policies (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id   UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    rules       JSONB NOT NULL DEFAULT '[]'::jsonb,
    action      TEXT NOT NULL DEFAULT 'log'
                CHECK (action IN ('log', 'block', 'encrypt', 'redact')),
    enabled     BOOLEAN NOT NULL DEFAULT true,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS dlp_policies_tenant_idx
    ON dlp_policies (tenant_id);
CREATE INDEX IF NOT EXISTS dlp_policies_tenant_enabled_idx
    ON dlp_policies (tenant_id) WHERE enabled = true;

CREATE TRIGGER dlp_policies_set_updated_at
    BEFORE UPDATE ON dlp_policies
    FOR EACH ROW EXECUTE FUNCTION sng_set_updated_at();

ALTER TABLE dlp_policies ENABLE ROW LEVEL SECURITY;

CREATE POLICY dlp_policies_tenant_isolation ON dlp_policies
    USING (
        tenant_id = NULLIF(current_setting('sng.tenant_id', true), '')::uuid
    );

-- dlp_fingerprints ------------------------------------------------------

CREATE TABLE IF NOT EXISTS dlp_fingerprints (
    id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name          TEXT NOT NULL,
    hash          BYTEA NOT NULL,
    content_type  TEXT NOT NULL DEFAULT '',
    registered_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS dlp_fingerprints_tenant_idx
    ON dlp_fingerprints (tenant_id);

ALTER TABLE dlp_fingerprints ENABLE ROW LEVEL SECURITY;

CREATE POLICY dlp_fingerprints_tenant_isolation ON dlp_fingerprints
    USING (
        tenant_id = NULLIF(current_setting('sng.tenant_id', true), '')::uuid
    );

-- dlp_matches (audit trail) --------------------------------------------

CREATE TABLE IF NOT EXISTS dlp_matches (
    id         UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id  UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    policy_id  UUID NOT NULL REFERENCES dlp_policies(id) ON DELETE CASCADE,
    source     TEXT NOT NULL DEFAULT '',
    matched_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    details    JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS dlp_matches_tenant_idx
    ON dlp_matches (tenant_id);
CREATE INDEX IF NOT EXISTS dlp_matches_policy_idx
    ON dlp_matches (policy_id);
CREATE INDEX IF NOT EXISTS dlp_matches_matched_at_idx
    ON dlp_matches (tenant_id, matched_at DESC);

ALTER TABLE dlp_matches ENABLE ROW LEVEL SECURITY;

CREATE POLICY dlp_matches_tenant_isolation ON dlp_matches
    USING (
        tenant_id = NULLIF(current_setting('sng.tenant_id', true), '')::uuid
    );
