-- ShieldNet Gateway (SNG) — webhooks migration.
--
-- Adds two tables:
--   - webhook_endpoints  : per-tenant subscriptions (URL + event filter + signing secret).
--   - webhook_deliveries : append-only delivery attempts (status + retry metadata).
--
-- Both tables are RLS-scoped to `sng.tenant_id`. webhook_deliveries
-- joins to webhook_endpoints for tenant lookup so the RLS policy
-- can be written without a redundant `tenant_id` column.
-- However, we still carry a denormalised tenant_id on deliveries to
-- keep the policy simple and avoid recursive policy evaluation
-- (Postgres RLS recursion is allowed but expensive). The
-- denormalised column is enforced consistent by a trigger.

-- signing_secret stores the plaintext HMAC-SHA256 signing key
-- required by the delivery worker at request-signing time. The
-- receiver verifies signatures with the same plaintext, which is
-- emitted exactly once on POST /webhooks (Create). At-rest
-- protection is an ops concern handled by disk encryption / DB
-- TDE; future iterations can layer pgcrypto sym_encrypt with a
-- KEK without changing the column shape.
CREATE TABLE IF NOT EXISTS webhook_endpoints (
    id              UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id       UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    url             TEXT        NOT NULL,
    events          TEXT[]      NOT NULL,
    signing_secret  BYTEA       NOT NULL,
    status          TEXT        NOT NULL DEFAULT 'active'
                    CHECK (status IN ('active', 'disabled')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_webhook_endpoints_tenant
    ON webhook_endpoints (tenant_id);
CREATE INDEX IF NOT EXISTS idx_webhook_endpoints_tenant_status
    ON webhook_endpoints (tenant_id, status);

CREATE TRIGGER webhook_endpoints_set_updated_at
    BEFORE UPDATE ON webhook_endpoints
    FOR EACH ROW EXECUTE FUNCTION sng_set_updated_at();

ALTER TABLE webhook_endpoints ENABLE ROW LEVEL SECURITY;
ALTER TABLE webhook_endpoints FORCE ROW LEVEL SECURITY;

CREATE POLICY webhook_endpoints_tenant_isolation ON webhook_endpoints
    USING (tenant_id = NULLIF(current_setting('sng.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('sng.tenant_id', true), '')::uuid);

CREATE TABLE IF NOT EXISTS webhook_deliveries (
    id              UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id       UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    endpoint_id     UUID        NOT NULL REFERENCES webhook_endpoints(id) ON DELETE CASCADE,
    event_type      TEXT        NOT NULL,
    payload         JSONB       NOT NULL,
    status          TEXT        NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending', 'delivered', 'failed', 'exhausted')),
    attempts        INTEGER     NOT NULL DEFAULT 0,
    last_attempt_at TIMESTAMPTZ,
    last_error      TEXT,
    next_retry_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    response_status INTEGER,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_tenant
    ON webhook_deliveries (tenant_id);
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_pending_next
    ON webhook_deliveries (status, next_retry_at)
    WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_endpoint
    ON webhook_deliveries (endpoint_id);

ALTER TABLE webhook_deliveries ENABLE ROW LEVEL SECURITY;
ALTER TABLE webhook_deliveries FORCE ROW LEVEL SECURITY;

-- Tenant-scoped per-request access, plus a system-role bypass so
-- the cross-tenant delivery worker can drain pending rows via
-- `sng.system_role='true'`. The system role can only be set by the
-- application (it's a GUC, not a DB role grant) — RLS still
-- enforces per-tenant isolation for normal handlers.
CREATE POLICY webhook_deliveries_tenant_isolation ON webhook_deliveries
    USING (
        tenant_id = NULLIF(current_setting('sng.tenant_id', true), '')::uuid
        OR NULLIF(current_setting('sng.system_role', true), '') = 'true'
    )
    WITH CHECK (
        tenant_id = NULLIF(current_setting('sng.tenant_id', true), '')::uuid
        OR NULLIF(current_setting('sng.system_role', true), '') = 'true'
    );
