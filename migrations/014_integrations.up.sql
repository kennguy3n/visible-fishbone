-- ShieldNet Gateway (SNG) — integration connectors migration.
--
-- Adds two tables:
--   - integration_connectors : per-tenant external destinations (syslog,
--                              siem_webhook, jira, servicenow). Config + Secret
--                              are typed JSONB blobs owned by the connector
--                              plugin; the migration only pins the lifecycle
--                              fields (status, type, last-test-state).
--   - integration_deliveries : append-only delivery attempts per
--                              (connector, event) pair. Worker drains via
--                              FOR UPDATE SKIP LOCKED on the pending index.
--
-- Both tables are RLS-scoped to `sng.tenant_id`. The shape mirrors
-- webhook_endpoints / webhook_deliveries deliberately: a future
-- maintainer comparing the two pipes recognises the lifecycle
-- and the operational tooling is the same.
--
-- Secret encryption-at-rest is delegated to disk encryption / TDE in
-- the same way as webhook_endpoints.signing_secret. Per-row envelope
-- encryption is a known follow-up for the FedRAMP-track deployment.

CREATE TABLE IF NOT EXISTS integration_connectors (
    id                UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id         UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    type              TEXT        NOT NULL
                      CHECK (type IN ('syslog', 'siem_webhook', 'jira', 'servicenow')),
    name              TEXT        NOT NULL,
    description       TEXT        NOT NULL DEFAULT '',
    event_types       TEXT[]      NOT NULL DEFAULT ARRAY[]::TEXT[],
    config            JSONB       NOT NULL DEFAULT '{}'::jsonb,
    secret            BYTEA       NOT NULL DEFAULT '\x'::bytea,
    status            TEXT        NOT NULL DEFAULT 'active'
                      CHECK (status IN ('active', 'disabled')),
    last_test_result  TEXT        NOT NULL DEFAULT 'never'
                      CHECK (last_test_result IN ('never', 'success', 'failure')),
    last_test_at      TIMESTAMPTZ,
    last_test_error   TEXT        NOT NULL DEFAULT '',
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, name)
);

CREATE INDEX IF NOT EXISTS idx_integration_connectors_tenant
    ON integration_connectors (tenant_id);
CREATE INDEX IF NOT EXISTS idx_integration_connectors_tenant_status
    ON integration_connectors (tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_integration_connectors_tenant_type
    ON integration_connectors (tenant_id, type);

CREATE TRIGGER integration_connectors_set_updated_at
    BEFORE UPDATE ON integration_connectors
    FOR EACH ROW EXECUTE FUNCTION sng_set_updated_at();

ALTER TABLE integration_connectors ENABLE ROW LEVEL SECURITY;
ALTER TABLE integration_connectors FORCE ROW LEVEL SECURITY;

CREATE POLICY integration_connectors_tenant_isolation ON integration_connectors
    USING (tenant_id = NULLIF(current_setting('sng.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('sng.tenant_id', true), '')::uuid);

CREATE TABLE IF NOT EXISTS integration_deliveries (
    id                 UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id          UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    connector_id       UUID        NOT NULL REFERENCES integration_connectors(id) ON DELETE CASCADE,
    event_type         TEXT        NOT NULL,
    payload            JSONB       NOT NULL,
    status             TEXT        NOT NULL DEFAULT 'pending'
                       CHECK (status IN ('pending', 'processing', 'delivered', 'failed', 'exhausted')),
    attempts           INTEGER     NOT NULL DEFAULT 0,
    last_attempt_at    TIMESTAMPTZ,
    last_error         TEXT        NOT NULL DEFAULT '',
    next_retry_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    response_status    INTEGER     NOT NULL DEFAULT 0,
    -- ExternalReference: e.g. Jira issue key "SEC-1234", ServiceNow sys_id
    -- "abc123...". Empty until the connector returns it on first
    -- successful Deliver; immutable thereafter so retry / update
    -- targets are stable.
    external_reference TEXT        NOT NULL DEFAULT '',
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_integration_deliveries_tenant
    ON integration_deliveries (tenant_id);
CREATE INDEX IF NOT EXISTS idx_integration_deliveries_pending_next
    ON integration_deliveries (status, next_retry_at)
    WHERE status IN ('pending', 'processing');
CREATE INDEX IF NOT EXISTS idx_integration_deliveries_connector
    ON integration_deliveries (connector_id);

ALTER TABLE integration_deliveries ENABLE ROW LEVEL SECURITY;
ALTER TABLE integration_deliveries FORCE ROW LEVEL SECURITY;

CREATE POLICY integration_deliveries_tenant_isolation ON integration_deliveries
    USING (
        tenant_id = NULLIF(current_setting('sng.tenant_id', true), '')::uuid
        OR NULLIF(current_setting('sng.system_role', true), '') = 'true'
    )
    WITH CHECK (
        tenant_id = NULLIF(current_setting('sng.tenant_id', true), '')::uuid
        OR NULLIF(current_setting('sng.system_role', true), '') = 'true'
    );
