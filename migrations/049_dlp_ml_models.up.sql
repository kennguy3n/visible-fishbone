-- ShieldNet Gateway (SNG) — DLP ML model registry migration.
--
-- Workstream 4: on-device ML NER. The endpoint DLP engine (sng-dlp)
-- can run a lightweight ONNX NER classifier instead of literal
-- patterns. The model binary itself lives in object storage (S3,
-- like cold archives) and is delivered to devices through the
-- Ed25519-signed policy-bundle pipeline; these tables hold only the
-- metadata plus the trust-chain material the signing pipeline and the
-- agent's `ModelVerifier` verify against.
--
-- Tables introduced:
--   - dlp_ml_models           : tenant-scoped versioned model
--                               artifacts (object key, sha256,
--                               Ed25519 signature, declared entity
--                               classes, lifecycle status).
--   - dlp_ml_model_assignments: the single active model version per
--                               tenant; compiled into the tenant's
--                               endpoint bundle when it has an
--                               `ml_ner` rule.
--
-- Both tables are RLS-protected via the existing `sng.tenant_id` GUC
-- pattern, matching every other tenant-scoped DLP table (migration
-- 017).
--
-- Lock safety: CREATE TABLE on brand-new (empty) tables takes no
-- table-rewrite lock. No standalone secondary index is created — the
-- runner wraps each migration in a transaction (migration 041) inside
-- which CREATE INDEX CONCURRENTLY cannot run, and a plain CREATE INDEX
-- is exactly the table-rewrite-lock pattern the migration-lint
-- validator rejects. The UNIQUE constraints below create their backing
-- indexes as part of CREATE TABLE (not a separate statement), and the
-- hot reads ("the assigned model for a tenant", "models for a tenant")
-- are tenant-scoped under RLS, so no extra index is needed — mirroring
-- the deliberate no-secondary-index decision of migration 048.

-- dlp_ml_models ---------------------------------------------------------

CREATE TABLE IF NOT EXISTS dlp_ml_models (
    id             UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id      UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    -- Logical model name; successive versions share a name.
    name           TEXT NOT NULL,
    -- Monotonic version within (tenant_id, name).
    version        INTEGER NOT NULL CHECK (version > 0),
    status         TEXT NOT NULL DEFAULT 'draft'
                   CHECK (status IN ('draft', 'validated', 'retired')),
    -- Entity-class wire names this model emits (sng-dlp EntityClass).
    entity_classes JSONB NOT NULL DEFAULT '[]'::jsonb,
    -- Storage key of the ONNX artifact in object storage (S3).
    object_key     TEXT NOT NULL,
    -- ONNX artifact size in bytes.
    size_bytes     BIGINT NOT NULL DEFAULT 0 CHECK (size_bytes >= 0),
    -- Lowercase-hex SHA-256 of the ONNX bytes.
    sha256         TEXT NOT NULL DEFAULT '',
    -- Hex-encoded Ed25519 signature over the ONNX bytes; empty until
    -- the version is validated by the signing pipeline.
    signature      TEXT NOT NULL DEFAULT '',
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- One row per (tenant, name, version).
    UNIQUE (tenant_id, name, version)
);

CREATE TRIGGER dlp_ml_models_set_updated_at
    BEFORE UPDATE ON dlp_ml_models
    FOR EACH ROW EXECUTE FUNCTION sng_set_updated_at();

ALTER TABLE dlp_ml_models ENABLE ROW LEVEL SECURITY;
ALTER TABLE dlp_ml_models FORCE ROW LEVEL SECURITY;

CREATE POLICY dlp_ml_models_tenant_isolation ON dlp_ml_models
    USING (tenant_id = NULLIF(current_setting('sng.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('sng.tenant_id', true), '')::uuid);

-- dlp_ml_model_assignments ----------------------------------------------

CREATE TABLE IF NOT EXISTS dlp_ml_model_assignments (
    -- One active model per tenant: tenant_id is the primary key.
    tenant_id   UUID PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    model_id    UUID NOT NULL REFERENCES dlp_ml_models(id) ON DELETE CASCADE,
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE dlp_ml_model_assignments ENABLE ROW LEVEL SECURITY;
ALTER TABLE dlp_ml_model_assignments FORCE ROW LEVEL SECURITY;

CREATE POLICY dlp_ml_model_assignments_tenant_isolation ON dlp_ml_model_assignments
    USING (tenant_id = NULLIF(current_setting('sng.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('sng.tenant_id', true), '')::uuid);
