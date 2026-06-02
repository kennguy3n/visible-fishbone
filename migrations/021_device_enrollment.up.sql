-- Migration 021: Device enrollment tables.
-- Adds device_enrollments and device_certificates tables for the
-- claim-token enrollment flow (PROPOSAL.md §7, ARCHITECTURE.md §3.4).

CREATE TYPE device_enrollment_status AS ENUM ('enrolled', 'active', 'revoked');

CREATE TABLE device_enrollments (
    device_id   UUID        NOT NULL,
    tenant_id   UUID        NOT NULL REFERENCES tenants(id),
    public_key  BYTEA       NOT NULL CHECK (octet_length(public_key) = 32),
    status      device_enrollment_status NOT NULL DEFAULT 'enrolled',
    enrolled_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_cert_issued_at TIMESTAMPTZ,
    revoked_at  TIMESTAMPTZ,
    PRIMARY KEY (device_id, tenant_id)
);

-- RLS policy on tenant_id.
ALTER TABLE device_enrollments ENABLE ROW LEVEL SECURITY;
CREATE POLICY device_enrollments_tenant ON device_enrollments
    USING (tenant_id::text = current_setting('sng.tenant_id', true))
    WITH CHECK (tenant_id::text = current_setting('sng.tenant_id', true));

-- Allow system-role bypass for cross-tenant operations.
CREATE POLICY device_enrollments_system ON device_enrollments
    USING (current_setting('sng.system_role', true) = 'true')
    WITH CHECK (current_setting('sng.system_role', true) = 'true');

-- Partial unique index: only one active/enrolled enrollment per
-- (tenant_id, device_id). Revoked rows are excluded so a device
-- can be re-enrolled after revocation.
CREATE UNIQUE INDEX idx_device_enrollments_active
    ON device_enrollments (tenant_id, device_id)
    WHERE status != 'revoked';

CREATE TABLE device_certificates (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id   UUID        NOT NULL,
    tenant_id   UUID        NOT NULL REFERENCES tenants(id),
    serial      TEXT        NOT NULL,
    cert_pem    TEXT        NOT NULL,
    issued_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ NOT NULL,
    revoked_at  TIMESTAMPTZ
);

-- RLS policy on tenant_id.
ALTER TABLE device_certificates ENABLE ROW LEVEL SECURITY;
CREATE POLICY device_certificates_tenant ON device_certificates
    USING (tenant_id::text = current_setting('sng.tenant_id', true))
    WITH CHECK (tenant_id::text = current_setting('sng.tenant_id', true));

CREATE POLICY device_certificates_system ON device_certificates
    USING (current_setting('sng.system_role', true) = 'true')
    WITH CHECK (current_setting('sng.system_role', true) = 'true');

CREATE INDEX idx_device_certificates_device
    ON device_certificates (tenant_id, device_id);
