-- 062_policy_templates — Smart-default security baselines for SMEs.
--
-- An SME onboarding to ShieldNet should not have to hand-author a
-- Policy-Graph. Instead it picks an INDUSTRY (healthcare, finance,
-- retail, professional-services, …) and a COUNTRY (which maps to a
-- privacy/compliance regime: EU GDPR, UK DPA, AU Privacy, CA PIPEDA, a
-- US baseline, …) and receives a working baseline: safe-browsing
-- category filtering, DLP detectors weighted by the PII that matters
-- in that jurisdiction, and a baseline firewall posture.
--
-- This migration persists two things:
--
--   1. policy_templates — the global, fleet-wide catalog of template
--      definitions (baseline + per-industry + per-regime). It is
--      authored in code (internal/service/policytemplates) and seeded
--      into this table for queryability and audit. NOT tenant-scoped:
--      the catalog is identical for every tenant, mirroring the global
--      app_registry / threat_intel_iocs tables (no RLS). Writes happen
--      in a system-role transaction.
--
--   2. tenant_policy_templates — per-tenant applied state: which
--      (industry, country) a tenant selected, the resolved regime, the
--      catalog templates that composed the result, and the rendered,
--      canonical Policy-Graph intent plus its content hash. Exactly one
--      active baseline per tenant, so tenant_id is the primary key and
--      Apply is an idempotent upsert keyed on it. Tenant-scoped under
--      the standard `sng.tenant_id` RLS pattern (mirrors
--      policy_rollouts / policy_graphs).
--
-- Lock safety: both are brand-new (empty) tables, so CREATE TABLE takes
-- no table-rewrite lock. No standalone secondary index is created — the
-- runner wraps each migration in a transaction (migration 041) inside
-- which CREATE INDEX CONCURRENTLY cannot run, and a plain CREATE INDEX
-- is the table-rewrite-lock pattern the migration-lint validator
-- rejects. Every access pattern here is primary-key-served (a
-- whole-catalog list, and a by-tenant_id lookup/upsert), so no
-- secondary index is needed.

-- ---------------------------------------------------------------------
-- Global template catalog (fleet-wide, no RLS).
-- ---------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS policy_templates (
    -- Stable catalog id, e.g. 'baseline', 'industry.healthcare',
    -- 'compliance.eu-gdpr'. Authored in code; the natural primary key.
    id           TEXT PRIMARY KEY,
    -- Template kind: 'baseline' (applied to everyone), 'industry'
    -- (selected by industry), or 'compliance' (selected by the regime
    -- the tenant's country maps to).
    kind         TEXT NOT NULL
                 CHECK (kind IN ('baseline', 'industry', 'compliance')),
    -- Industry token (e.g. 'healthcare'); empty unless kind='industry'.
    industry     TEXT NOT NULL DEFAULT '',
    -- Compliance regime token (e.g. 'eu-gdpr'); empty unless
    -- kind='compliance'.
    regime       TEXT NOT NULL DEFAULT '',
    -- Human-facing label and blurb for the catalog UI.
    name         TEXT NOT NULL,
    description  TEXT NOT NULL DEFAULT '',
    -- The declarative intent this template contributes: the JSON
    -- encoding of policytemplates.Spec (categories, detectors,
    -- firewall posture).
    spec         JSONB NOT NULL,
    -- SHA-256 of the canonical Spec encoding. Lets the seeder skip a
    -- write when a template's content is unchanged.
    content_hash TEXT NOT NULL,
    -- Renderer schema version stamped at seed time.
    version      INTEGER NOT NULL DEFAULT 1,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- A row is either an industry template or a compliance template or
    -- neither (the single baseline) — never both. Keeps the catalog's
    -- shape honest at the storage layer.
    CONSTRAINT policy_templates_kind_fields_check CHECK (
        (kind = 'industry'   AND industry <> '' AND regime = '') OR
        (kind = 'compliance' AND regime   <> '' AND industry = '') OR
        (kind = 'baseline'   AND industry = ''   AND regime = '')
    )
);

COMMENT ON TABLE policy_templates IS
    'Global, fleet-wide catalog of smart-default policy templates (baseline + per-industry + per-compliance-regime), authored in internal/service/policytemplates and seeded here for queryability/audit. Not tenant-scoped (no RLS); written in a system-role transaction.';

-- ---------------------------------------------------------------------
-- Per-tenant applied baseline (tenant-scoped, RLS).
-- ---------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS tenant_policy_templates (
    -- One active baseline per tenant: tenant_id is the primary key, so
    -- Apply is an idempotent upsert. ON DELETE CASCADE drops the
    -- applied state when the tenant is removed.
    tenant_id    UUID PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    -- The SME's selection.
    industry     TEXT NOT NULL,
    country      TEXT NOT NULL,
    -- Compliance regime the country resolved to at apply time.
    regime       TEXT NOT NULL,
    -- Catalog template ids that composed the rendered graph, ordered
    -- [baseline, industry, compliance].
    template_ids TEXT[] NOT NULL,
    -- SHA-256 of the canonical rendered graph; the idempotency key the
    -- service compares against to decide whether a re-apply is a no-op.
    graph_hash   TEXT NOT NULL,
    -- The rendered, canonical Policy-Graph intent (policy.Graph JSON).
    graph        JSONB NOT NULL,
    -- Renderer schema version stamped at apply time.
    version      INTEGER NOT NULL DEFAULT 1,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE tenant_policy_templates IS
    'Per-tenant applied policy-template baseline: the (industry, country) selection, resolved regime, composing template ids, and the rendered canonical Policy-Graph intent + content hash. One row per tenant (tenant_id PK); Apply upserts idempotently. Tenant-isolated via the sng.tenant_id RLS GUC.';

-- Row-level security — tenant isolation via `sng.tenant_id` GUC,
-- mirroring policy_rollouts / policy_graphs. FORCE so the table owner
-- and the service role are both subject to the policy. With no
-- explicit WITH CHECK, Postgres applies the USING expression to
-- INSERT/UPDATE as well, so a tenant can neither read nor write
-- another tenant's row.
ALTER TABLE tenant_policy_templates ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_policy_templates FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_policy_templates_tenant_isolation ON tenant_policy_templates
    USING (tenant_id = NULLIF(current_setting('sng.tenant_id', true), '')::uuid);
