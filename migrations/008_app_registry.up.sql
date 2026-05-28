-- 008_app_registry — Traffic Classification & Steering Framework.
--
-- The traffic classification engine maps every flow into one of six
-- `traffic_class` values (see docs/TRAFFIC_CLASSIFICATION.md). The
-- mapping is sourced from two tables:
--
--   * app_registry            — global curated database of well-known
--                               apps (Microsoft 365, Google Workspace,
--                               …). NOT tenant-scoped; one row per
--                               app, identical content for every
--                               tenant.
--   * app_registry_overrides  — per-tenant promotions / demotions.
--                               RLS-isolated by `sng.tenant_id`.
--
-- The two-table layout mirrors the sn360 "global catalog + tenant
-- override" pattern: the global table is curated by operators and
-- refreshed by the vendor-endpoint sync job; the override table is
-- where each tenant expresses local intent.

-- ---------------------------------------------------------------------
-- app_registry
--
-- Curated global database. NOT tenant-scoped (no RLS). Application
-- code asserts admin-role on writes; reads are unrestricted because
-- the data is the same for every tenant.
-- ---------------------------------------------------------------------
CREATE TABLE app_registry (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name            TEXT NOT NULL,
    vendor          TEXT,
    traffic_class   TEXT NOT NULL CHECK (traffic_class IN (
        'trusted_direct',
        'trusted_media_bypass',
        'inspect_lite',
        'inspect_full',
        'tunnel_private',
        'block'
    )),
    scope           TEXT NOT NULL CHECK (scope IN ('global', 'regional')),
    -- regions is NULL for global apps; non-empty array of ISO/region
    -- codes for regional ones (e.g. {"APAC","JP"}).
    regions         TEXT[],
    -- domain patterns — wildcards allowed (e.g. "*.office.com").
    -- Stored as TEXT[] (not LTREE / regex) so the edge / agent can
    -- match them with a simple suffix walk.
    domains         TEXT[] NOT NULL,
    -- expected IP ranges for the domain-to-IP binding safety check.
    ip_ranges       CIDR[],
    -- expected certificate chain hashes (SHA256 hex) for the cert
    -- pin check.
    cert_pins       TEXT[],
    -- vendor-published URL the sync job pulls to refresh
    -- domains / ip_ranges (e.g. Microsoft's M365 endpoints JSON).
    metadata_url    TEXT,
    category        TEXT,
    -- is_system distinguishes baseline curated rows from
    -- operator-added ones. The sync job will not touch is_system=false.
    is_system       BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- name is unique for the global catalog so operators can
    -- reference apps by a stable handle.
    UNIQUE (name),
    CHECK (cardinality(domains) > 0),
    CHECK (
        scope = 'global'
        OR (scope = 'regional' AND regions IS NOT NULL AND cardinality(regions) > 0)
    )
);

CREATE INDEX app_registry_traffic_class_idx ON app_registry (traffic_class);
CREATE INDEX app_registry_scope_idx         ON app_registry (scope);
CREATE INDEX app_registry_category_idx      ON app_registry (category);
-- GIN index on domains enables efficient `?` (array contains) lookups
-- for the "which app does this domain belong to" path; falls back to
-- in-process suffix matching for wildcards.
CREATE INDEX app_registry_domains_idx       ON app_registry USING GIN (domains);

CREATE TRIGGER app_registry_set_updated_at
    BEFORE UPDATE ON app_registry
    FOR EACH ROW EXECUTE FUNCTION sng_set_updated_at();

-- ---------------------------------------------------------------------
-- app_registry_overrides
--
-- Per-tenant promotions / demotions of app classifications. Two
-- shapes are supported:
--
--   1. app_id IS NOT NULL  — override the classification of a
--                            global registry entry.
--   2. app_id IS NULL      — define a tenant-local app via
--                            `custom_domains` for entries that
--                            don't exist in the global catalog.
--
-- RLS-isolated via `sng.tenant_id` — same pattern as every other
-- tenant-scoped table (see docs/deploy.md).
-- ---------------------------------------------------------------------
CREATE TABLE app_registry_overrides (
    id                       UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id                UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    app_id                   UUID REFERENCES app_registry(id) ON DELETE CASCADE,
    -- custom_domains is populated only when app_id IS NULL (tenant
    -- defines a brand-new app). When app_id is set, this column is
    -- NULL and the global registry's domains list is used.
    custom_domains           TEXT[],
    traffic_class_override   TEXT NOT NULL CHECK (traffic_class_override IN (
        'trusted_direct',
        'trusted_media_bypass',
        'inspect_lite',
        'inspect_full',
        'tunnel_private',
        'block'
    )),
    -- expires_at supports auto-expiring demotions emitted by the
    -- demotion engine on transient signals (cert-pin mismatch, IP
    -- range mismatch, …). NULL = permanent override.
    expires_at               TIMESTAMPTZ,
    reason                   TEXT,
    created_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- Either reference a global app, or define a custom one — never
    -- both, never neither.
    CHECK (
        (app_id IS NOT NULL AND custom_domains IS NULL)
        OR (app_id IS NULL AND custom_domains IS NOT NULL AND cardinality(custom_domains) > 0)
    )
);

CREATE INDEX app_registry_overrides_tenant_idx ON app_registry_overrides (tenant_id);
CREATE INDEX app_registry_overrides_app_idx    ON app_registry_overrides (app_id);
CREATE INDEX app_registry_overrides_expires_idx ON app_registry_overrides (expires_at)
    WHERE expires_at IS NOT NULL;
CREATE INDEX app_registry_overrides_custom_domains_idx
    ON app_registry_overrides USING GIN (custom_domains)
    WHERE custom_domains IS NOT NULL;

-- A tenant can only have one active override per (app_id) OR per
-- (canonical custom_domains) pair. We rely on application-level
-- enforcement for the custom_domains case because Postgres lacks
-- a stable unique-on-array-content operator. For app_id-based
-- overrides we add a partial unique index.
CREATE UNIQUE INDEX app_registry_overrides_tenant_app_uniq
    ON app_registry_overrides (tenant_id, app_id)
    WHERE app_id IS NOT NULL;

CREATE TRIGGER app_registry_overrides_set_updated_at
    BEFORE UPDATE ON app_registry_overrides
    FOR EACH ROW EXECUTE FUNCTION sng_set_updated_at();

ALTER TABLE app_registry_overrides ENABLE ROW LEVEL SECURITY;
ALTER TABLE app_registry_overrides FORCE ROW LEVEL SECURITY;
CREATE POLICY app_registry_overrides_tenant_isolation ON app_registry_overrides
    USING (tenant_id = NULLIF(current_setting('sng.tenant_id', true), '')::uuid);
