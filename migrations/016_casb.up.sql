-- ShieldNet Gateway (SNG) — CASB discovery migration.
--
-- Phase 4 (PROPOSAL.md §10): API-mode CASB discovery + top SaaS
-- API connectors (M365, Google Workspace, Slack, Salesforce).
--
-- Adds three tables:
--   - casb_connectors       : per-tenant SaaS API connectors.
--   - casb_discovered_apps  : SaaS apps found by connectors.
--   - casb_posture_checks   : config posture assessment results.
--
-- All tables are RLS-scoped to `sng.tenant_id`.

CREATE TABLE IF NOT EXISTS casb_connectors (
    id            UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id     UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    type          TEXT        NOT NULL
                  CHECK (type IN ('m365', 'google', 'slack', 'salesforce')),
    name          TEXT        NOT NULL,
    status        TEXT        NOT NULL DEFAULT 'configuring'
                  CHECK (status IN ('active', 'disabled', 'error', 'configuring')),
    config        JSONB       NOT NULL DEFAULT '{}'::jsonb,
    secret        BYTEA       NOT NULL DEFAULT '\x'::bytea,
    last_sync_at  TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, name)
);

CREATE INDEX IF NOT EXISTS idx_casb_connectors_tenant
    ON casb_connectors (tenant_id);
CREATE INDEX IF NOT EXISTS idx_casb_connectors_tenant_status
    ON casb_connectors (tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_casb_connectors_tenant_type
    ON casb_connectors (tenant_id, type);

CREATE TRIGGER casb_connectors_set_updated_at
    BEFORE UPDATE ON casb_connectors
    FOR EACH ROW EXECUTE FUNCTION sng_set_updated_at();

ALTER TABLE casb_connectors ENABLE ROW LEVEL SECURITY;
ALTER TABLE casb_connectors FORCE ROW LEVEL SECURITY;

CREATE POLICY casb_connectors_tenant_isolation ON casb_connectors
    USING (tenant_id = NULLIF(current_setting('sng.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('sng.tenant_id', true), '')::uuid);

CREATE TABLE IF NOT EXISTS casb_discovered_apps (
    id            UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id     UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name          TEXT        NOT NULL,
    vendor        TEXT        NOT NULL DEFAULT '',
    category      TEXT        NOT NULL DEFAULT '',
    risk_score    INTEGER     NOT NULL DEFAULT 0,
    users_count   INTEGER     NOT NULL DEFAULT 0,
    first_seen    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, name)
);

CREATE INDEX IF NOT EXISTS idx_casb_discovered_apps_tenant
    ON casb_discovered_apps (tenant_id);

ALTER TABLE casb_discovered_apps ENABLE ROW LEVEL SECURITY;
ALTER TABLE casb_discovered_apps FORCE ROW LEVEL SECURITY;

CREATE POLICY casb_discovered_apps_tenant_isolation ON casb_discovered_apps
    USING (tenant_id = NULLIF(current_setting('sng.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('sng.tenant_id', true), '')::uuid);

CREATE TABLE IF NOT EXISTS casb_posture_checks (
    id            UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id     UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    app_id        UUID        NOT NULL REFERENCES casb_discovered_apps(id) ON DELETE CASCADE,
    check_name    TEXT        NOT NULL,
    status        TEXT        NOT NULL DEFAULT 'warn'
                  CHECK (status IN ('pass', 'fail', 'warn')),
    details       TEXT        NOT NULL DEFAULT '',
    assessed_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_casb_posture_checks_tenant
    ON casb_posture_checks (tenant_id);
CREATE INDEX IF NOT EXISTS idx_casb_posture_checks_app
    ON casb_posture_checks (app_id);

ALTER TABLE casb_posture_checks ENABLE ROW LEVEL SECURITY;
ALTER TABLE casb_posture_checks FORCE ROW LEVEL SECURITY;

CREATE POLICY casb_posture_checks_tenant_isolation ON casb_posture_checks
    USING (tenant_id = NULLIF(current_setting('sng.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('sng.tenant_id', true), '')::uuid);
