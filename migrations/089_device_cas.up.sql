-- Migration 089: Per-tenant device certificate authority.
-- Adds device_cas, a stable trust anchor for the claim-token device
-- enrollment flow. Before this, issueCertificate minted a throwaway CA
-- per call and discarded its key, so the device certificate chain
-- changed on every issuance and no mTLS verifier could ever pin it.
-- Each tenant now gets exactly one long-lived CA whose private key is
-- sealed at rest (AES-256-GCM under the operator key-wrap master, or
-- passthrough when no master is configured).

CREATE TABLE device_cas (
    tenant_id   UUID        PRIMARY KEY REFERENCES tenants(id),
    cert_pem    TEXT        NOT NULL,
    private_key BYTEA       NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- RLS policy on tenant_id.
ALTER TABLE device_cas ENABLE ROW LEVEL SECURITY;
CREATE POLICY device_cas_tenant ON device_cas
    USING (tenant_id::text = current_setting('sng.tenant_id', true))
    WITH CHECK (tenant_id::text = current_setting('sng.tenant_id', true));

-- Allow system-role bypass for cross-tenant operations.
CREATE POLICY device_cas_system ON device_cas
    USING (current_setting('sng.system_role', true) = 'true')
    WITH CHECK (current_setting('sng.system_role', true) = 'true');
