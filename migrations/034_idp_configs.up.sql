-- Migration 034: Per-tenant OIDC identity-provider configurations for
-- mobile native SSO (control-plane IdP federation). Each row describes
-- one OIDC provider a tenant trusts (Google Workspace, Microsoft 365,
-- Zoho, Okta, or a generic custom OIDC issuer). The control plane
-- validates mobile-presented ID tokens against the matching config and
-- mints an SNG session bound to device + user identity.
--
-- Only the configuration needed to *validate* tokens is persisted
-- (issuer, client_id, allowed domains, group-claim path). OIDC tokens
-- themselves are never stored server-side.

CREATE TABLE idp_configs (
    id               UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id        UUID        NOT NULL REFERENCES tenants(id),
    provider_type    TEXT        NOT NULL CHECK (provider_type IN (
                                     'google_workspace',
                                     'microsoft365',
                                     'zoho',
                                     'okta',
                                     'custom_oidc'
                                 )),
    issuer_url       TEXT        NOT NULL,
    client_id        TEXT        NOT NULL,
    allowed_domains  TEXT[]      NOT NULL DEFAULT '{}',
    group_claim_path TEXT        NOT NULL DEFAULT '',
    enabled          BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE idp_configs ENABLE ROW LEVEL SECURITY;

-- Tenant-scoped policy: a request bound to sng.tenant_id sees only
-- its own provider configs. Mirrors every other tenant-scoped table.
CREATE POLICY idp_configs_tenant ON idp_configs
    USING (tenant_id::text = current_setting('sng.tenant_id', true))
    WITH CHECK (tenant_id::text = current_setting('sng.tenant_id', true));

-- System policy: background workers / cross-tenant jobs that set
-- sng.system_role='true' may read/write across tenants.
CREATE POLICY idp_configs_system ON idp_configs
    USING (current_setting('sng.system_role', true) = 'true')
    WITH CHECK (current_setting('sng.system_role', true) = 'true');

-- One provider config per (tenant, issuer): a tenant cannot register
-- the same OIDC issuer twice, which would make token-to-config
-- resolution ambiguous.
CREATE UNIQUE INDEX uq_idp_configs_tenant_issuer
    ON idp_configs (tenant_id, issuer_url);

CREATE INDEX idx_idp_configs_tenant
    ON idp_configs (tenant_id, created_at DESC);
