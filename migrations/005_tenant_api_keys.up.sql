-- ShieldNet Gateway (SNG) — production tenant API key store.
--
-- API keys are how machine-to-machine clients (CI bots, integrations,
-- third-party SaaS) authenticate to the control plane. Each row is a
-- single API key minted for a tenant:
--
--   * `hash` is the SHA-256 of the secret. The plaintext is shown to
--     the operator exactly once at creation time and never stored.
--     Lookups are by hash equality, so the column is a deterministic
--     digest, NOT a slow KDF — we trade KDF-style brute-force
--     resistance for O(1) lookup, justified because the underlying
--     secret is 256 random bits (32 base64url chars after the `sng_`
--     prefix). A 256-bit search space is comfortably outside the
--     reach of any offline cracker even with SHA-256.
--   * `subject` is a human-readable identity (e.g. "ci-bot",
--     "datadog-integration") audit logs use for the actor field. It
--     is NOT used for permission checks.
--   * `status` flips to 'revoked' on Revoke and never flips back —
--     a revoked key cannot be reactivated (operators mint a new
--     key instead). This matches the webhook endpoint convention.
--   * `expires_at` is optional. When set, the middleware compares
--     against `now()` and rejects expired keys without a status
--     change so a future automated job can sweep expired rows
--     into 'revoked' without racing the auth path.
--
-- The middleware looks up a presented key by hashing it once with
-- SHA-256 and querying `tenant_api_keys` by `hash`. The lookup has
-- to be cross-tenant (the request hasn't identified the tenant
-- yet — the API key IS the identification), so we expose a
-- `sng.system_role='true'` bypass on the RLS policy. The application
-- is the only thing that can set this GUC (it's a GUC, not a DB
-- role grant), and the middleware is the only call site that uses
-- the bypass.

CREATE TABLE tenant_api_keys (
    id             UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id      UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name           TEXT NOT NULL,
    subject        TEXT NOT NULL,
    hash           BYTEA NOT NULL,
    status         TEXT NOT NULL CHECK (status IN ('active', 'revoked')),
    expires_at     TIMESTAMPTZ,
    last_used_at   TIMESTAMPTZ,
    created_by     UUID,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at     TIMESTAMPTZ
);

-- Global uniqueness on `hash`. Two tenants minting the same SHA-256
-- digest is functionally a SHA-256 collision — impossibly rare in
-- practice, but the unique constraint makes the impossibility a
-- schema invariant: a hash maps to at most one (tenant, key) pair,
-- so the cross-tenant lookup path in the middleware cannot return
-- two ambiguous rows.
CREATE UNIQUE INDEX tenant_api_keys_hash_idx ON tenant_api_keys (hash);

-- Per-tenant list ordering. Created-desc covers the only list query
-- the handler exposes (`GET /tenants/{tid}/api-keys`). Including
-- `status` in the index lets the planner skip the heap probe for
-- the common active-keys-only list filter.
CREATE INDEX tenant_api_keys_tenant_created_idx
    ON tenant_api_keys (tenant_id, status, created_at DESC, id);

ALTER TABLE tenant_api_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_api_keys FORCE ROW LEVEL SECURITY;

-- Per-tenant CRUD goes through `sng.tenant_id`. The auth middleware
-- bypass uses `sng.system_role='true'` for the cross-tenant hash
-- lookup; same pattern as webhook_deliveries.
CREATE POLICY tenant_api_keys_tenant_isolation ON tenant_api_keys
    USING (
        tenant_id = NULLIF(current_setting('sng.tenant_id', true), '')::uuid
        OR NULLIF(current_setting('sng.system_role', true), '') = 'true'
    )
    WITH CHECK (
        tenant_id = NULLIF(current_setting('sng.tenant_id', true), '')::uuid
        OR NULLIF(current_setting('sng.system_role', true), '') = 'true'
    );
