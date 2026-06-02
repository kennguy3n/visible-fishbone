-- Migration 018: SCIM external IDs
-- Adds index on users.external_id for SCIM filter fast path;
-- adds external_id to roles table for SCIM group mapping.

-- Index for SCIM filter queries: lookup by (tenant_id, external_id).
-- external_id already exists on users (see types.go); add an index
-- for the SCIM filter fast path.
CREATE INDEX IF NOT EXISTS idx_users_tenant_external_id
    ON users (tenant_id, external_id)
    WHERE external_id != '';

-- Roles: external_id for SCIM group mapping.
ALTER TABLE roles
    ADD COLUMN IF NOT EXISTS external_id TEXT NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS idx_roles_tenant_external_id
    ON roles (tenant_id, external_id)
    WHERE external_id != '' AND tenant_id IS NOT NULL;
