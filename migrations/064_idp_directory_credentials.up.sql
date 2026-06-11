-- 064_idp_directory_credentials
--
-- Per-tenant directory-API credentials for the IdP SyncService
-- (internal/service/identity/idp_sync.go). The sync runner pulls each
-- tenant's provider directory (Okta SSWS, Microsoft Graph, Google
-- Workspace) to provision / off-board users and refresh group
-- memberships. Calling those APIs needs a bearer credential that the
-- token-validation config in idp_configs deliberately does NOT hold
-- (migration 034 persists only issuer / client_id / allowed_domains /
-- group_claim_path — never an API secret).
--
-- This table is that missing secret store. One row per idp_configs row
-- (config_id is the primary key and an ON DELETE CASCADE FK), holding
-- the credential SEALED, never in plaintext: `sealed` is the
-- AES-256-GCM blob produced by the same policy.PrivateKeyWrapper used
-- for policy signing-key seeds (nonce || ciphertext || tag), with the
-- tenant UUID bytes as GCM additional-authenticated-data. A blob
-- written for tenant A therefore cannot be unsealed under tenant B
-- even with the same master key, and a wrapper running in
-- PassthroughWrapper mode (dev / Postgres-TDE deployments) stores the
-- bytes verbatim — matching the webhook signing-secret and policy
-- key-wrap models already in the tree.
--
-- Lock safety: brand-new (empty) table, so CREATE TABLE takes no
-- table-rewrite lock. Every access pattern is primary-key-served (the
-- resolver looks up by config_id; the admin surface sets / clears by
-- config_id within the tenant), so no secondary index is created — a
-- plain CREATE INDEX is the table-rewrite-lock pattern the
-- migration-lint validator rejects, and there is nothing here it would
-- serve.

CREATE TABLE idp_directory_credentials (
    -- One credential per provider config. PK = config_id makes set a
    -- by-PK upsert and ties the credential's lifetime to its config.
    config_id  UUID        PRIMARY KEY REFERENCES idp_configs(id) ON DELETE CASCADE,
    -- Denormalised tenant_id so RLS can scope the row without a join
    -- back to idp_configs, mirroring every other tenant-scoped table.
    tenant_id  UUID        NOT NULL REFERENCES tenants(id),
    -- AES-256-GCM sealed JSON of the DirectoryCredential
    -- {base_url, token, subject}. nonce || ciphertext || tag, tenant
    -- UUID as AAD. Never returned to clients; only the SyncService
    -- credential resolver unseals it.
    sealed     BYTEA       NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE idp_directory_credentials ENABLE ROW LEVEL SECURITY;

-- Tenant-scoped policy: a request bound to sng.tenant_id sees only its
-- own directory credentials. Mirrors idp_configs_tenant (migration 034).
CREATE POLICY idp_directory_credentials_tenant ON idp_directory_credentials
    USING (tenant_id::text = current_setting('sng.tenant_id', true))
    WITH CHECK (tenant_id::text = current_setting('sng.tenant_id', true));

-- System policy: the leader-gated SyncService runs as a cross-tenant
-- background job (sng.system_role='true') and must read every tenant's
-- credential to reconcile the fleet.
CREATE POLICY idp_directory_credentials_system ON idp_directory_credentials
    USING (current_setting('sng.system_role', true) = 'true')
    WITH CHECK (current_setting('sng.system_role', true) = 'true');

CREATE TRIGGER idp_directory_credentials_set_updated_at
    BEFORE UPDATE ON idp_directory_credentials
    FOR EACH ROW EXECUTE FUNCTION sng_set_updated_at();
