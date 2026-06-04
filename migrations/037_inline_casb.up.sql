-- ShieldNet Gateway (SNG) — Inline CASB migration.
--
-- Upgrades API-mode CASB (migration 016) to inline, real-time
-- inspection in the SWG ext-authz path. This table holds the
-- per-tenant inline-CASB rules the control plane manages
-- (internal/service/casb/inline.go) and compiles into the SWG
-- slice of the signed policy bundle; the edge / cloud data plane
-- (crates/sng-swg/src/casb.rs) decodes that slice and enforces it
-- on live SaaS traffic (M365, Google Workspace, Slack, Salesforce).
--
-- Adds one table:
--   - inline_casb_rules : per-tenant inline-CASB rules.
--
-- RLS-scoped to `sng.tenant_id`, matching every other
-- tenant-scoped table.

CREATE TABLE IF NOT EXISTS inline_casb_rules (
    id          UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id   UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    -- SaaS app id the rule applies to: one of the inspector's
    -- detected apps ('m365', 'google_workspace', 'slack',
    -- 'salesforce') or '*' for any app. Kept as free TEXT rather
    -- than a CHECK so new apps in the data-plane catalog do not
    -- require a schema migration; the service layer validates the
    -- value against the known-app set.
    app_id      TEXT        NOT NULL,
    action      TEXT        NOT NULL
                CHECK (action IN ('upload', 'download', 'share', 'delete')),
    verdict     TEXT        NOT NULL DEFAULT 'log'
                CHECK (verdict IN ('allow', 'block', 'log')),
    -- Match conditions: {file_type, size_threshold, label_match}.
    -- Shape mirrors the Rust CasbConditions; an empty object means
    -- "match every request for this (app_id, action)".
    conditions  JSONB       NOT NULL DEFAULT '{}'::jsonb,
    enabled     BOOLEAN     NOT NULL DEFAULT TRUE,
    -- Higher priority wins when several rules match a request.
    priority    INTEGER     NOT NULL DEFAULT 0,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Hot-path index: "list all enabled rules for a tenant" (the
-- compile path reads only enabled rules), highest priority first.
CREATE INDEX IF NOT EXISTS idx_inline_casb_rules_tenant_enabled
    ON inline_casb_rules (tenant_id, priority DESC) WHERE enabled = TRUE;
CREATE INDEX IF NOT EXISTS idx_inline_casb_rules_tenant
    ON inline_casb_rules (tenant_id);
CREATE INDEX IF NOT EXISTS idx_inline_casb_rules_tenant_app_action
    ON inline_casb_rules (tenant_id, app_id, action);

CREATE TRIGGER inline_casb_rules_set_updated_at
    BEFORE UPDATE ON inline_casb_rules
    FOR EACH ROW EXECUTE FUNCTION sng_set_updated_at();

ALTER TABLE inline_casb_rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE inline_casb_rules FORCE ROW LEVEL SECURITY;

CREATE POLICY inline_casb_rules_tenant_isolation ON inline_casb_rules
    USING (tenant_id = NULLIF(current_setting('sng.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('sng.tenant_id', true), '')::uuid);
