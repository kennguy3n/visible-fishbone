-- ShieldNet Gateway (SNG) — CASB NoOps app handling migration.
--
-- Makes shadow-IT app handling NoOps per tenant. The shadow-IT
-- discoverer (internal/service/casb/shadow_it.go) already turns SWG
-- telemetry into a per-tenant casb_discovered_apps inventory. This
-- migration adds the state the NoOps pipeline needs on top of it:
--
--   - casb_app_classifications  : the deterministic (optionally
--       AI-refined) verdict per (tenant, app): category, risk score,
--       sanction recommendation, confidence and provenance.
--   - casb_app_action_policies  : the per-tenant smart-default policy
--       that gates automatic enforcement (master switch + risk /
--       confidence bars). Absent row => engine uses DefaultActionPolicy.
--   - casb_app_actions          : the immutable, append-only audit
--       trail of every action the engine emitted (auto-applied or
--       recommended) so NoOps stays transparent.
--   - casb_app_digest_state     : the per-tenant digest cursor so each
--       periodic digest only summarises actions since the previous one.
--
-- Privacy: like the inventory it extends, every table is RLS-scoped to
-- sng.tenant_id and stores ONLY aggregates — app-level classifications
-- and actions, never device IDs, hostnames or user identities. 5000 SME
-- tenants share the pipeline, so isolation is enforced in the database
-- (FORCE ROW LEVEL SECURITY) rather than trusted to the application.

-- --------------------------------------------------------------------
-- Per-(tenant, app) classification.
-- --------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS casb_app_classifications (
    tenant_id     UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    app_name      TEXT        NOT NULL,
    category      TEXT        NOT NULL DEFAULT '',
    risk_score    INTEGER     NOT NULL DEFAULT 0
                  CHECK (risk_score BETWEEN 0 AND 100),
    sanction      TEXT        NOT NULL DEFAULT 'tolerated'
                  CHECK (sanction IN ('sanctioned', 'tolerated', 'unsanctioned')),
    confidence    INTEGER     NOT NULL DEFAULT 0
                  CHECK (confidence BETWEEN 0 AND 100),
    source        TEXT        NOT NULL DEFAULT 'heuristic'
                  CHECK (source IN ('heuristic', 'ai_refined')),
    rationale     TEXT        NOT NULL DEFAULT '',
    classified_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, app_name)
);

ALTER TABLE casb_app_classifications ENABLE ROW LEVEL SECURITY;
ALTER TABLE casb_app_classifications FORCE ROW LEVEL SECURITY;

CREATE POLICY casb_app_classifications_tenant_isolation ON casb_app_classifications
    USING (tenant_id = NULLIF(current_setting('sng.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('sng.tenant_id', true), '')::uuid);

-- --------------------------------------------------------------------
-- Per-tenant action policy (smart-default gate for auto-enforcement).
-- --------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS casb_app_action_policies (
    tenant_id            UUID        PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    auto_enforce_enabled BOOLEAN     NOT NULL DEFAULT TRUE,
    min_risk             INTEGER     NOT NULL DEFAULT 60
                         CHECK (min_risk BETWEEN 0 AND 100),
    min_confidence       INTEGER     NOT NULL DEFAULT 80
                         CHECK (min_confidence BETWEEN 0 AND 100),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE casb_app_action_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE casb_app_action_policies FORCE ROW LEVEL SECURITY;

CREATE POLICY casb_app_action_policies_tenant_isolation ON casb_app_action_policies
    USING (tenant_id = NULLIF(current_setting('sng.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('sng.tenant_id', true), '')::uuid);

-- --------------------------------------------------------------------
-- Immutable, append-only NoOps audit trail.
-- --------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS casb_app_actions (
    id            UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id     UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    app_name      TEXT        NOT NULL,
    category      TEXT        NOT NULL DEFAULT '',
    enforcement   TEXT        NOT NULL
                  CHECK (enforcement IN ('none', 'throttle', 'protect', 'route', 'enforce')),
    traffic_class TEXT        NOT NULL
                  CHECK (traffic_class IN ('trusted_direct', 'trusted_media_bypass',
                                           'inspect_lite', 'inspect_full',
                                           'tunnel_private', 'block')),
    mode          TEXT        NOT NULL
                  CHECK (mode IN ('auto', 'recommend')),
    risk_score    INTEGER     NOT NULL DEFAULT 0
                  CHECK (risk_score BETWEEN 0 AND 100),
    confidence    INTEGER     NOT NULL DEFAULT 0
                  CHECK (confidence BETWEEN 0 AND 100),
    sanction      TEXT        NOT NULL DEFAULT 'tolerated'
                  CHECK (sanction IN ('sanctioned', 'tolerated', 'unsanctioned')),
    applied       BOOLEAN     NOT NULL DEFAULT FALSE,
    reason        TEXT        NOT NULL DEFAULT '',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- The digest builder reads actions by (tenant, created_at); the console
-- reads the most recent per tenant. Both are served by this index.
CREATE INDEX IF NOT EXISTS idx_casb_app_actions_tenant_created
    ON casb_app_actions (tenant_id, created_at);

ALTER TABLE casb_app_actions ENABLE ROW LEVEL SECURITY;
ALTER TABLE casb_app_actions FORCE ROW LEVEL SECURITY;

CREATE POLICY casb_app_actions_tenant_isolation ON casb_app_actions
    USING (tenant_id = NULLIF(current_setting('sng.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('sng.tenant_id', true), '')::uuid);

-- --------------------------------------------------------------------
-- Per-tenant digest cursor.
-- --------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS casb_app_digest_state (
    tenant_id       UUID        PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    last_digest_at  TIMESTAMPTZ NOT NULL DEFAULT 'epoch',
    last_actions_at TIMESTAMPTZ NOT NULL DEFAULT 'epoch'
);

ALTER TABLE casb_app_digest_state ENABLE ROW LEVEL SECURITY;
ALTER TABLE casb_app_digest_state FORCE ROW LEVEL SECURITY;

CREATE POLICY casb_app_digest_state_tenant_isolation ON casb_app_digest_state
    USING (tenant_id = NULLIF(current_setting('sng.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('sng.tenant_id', true), '')::uuid);
