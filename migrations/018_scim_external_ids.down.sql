-- Rollback migration 018: SCIM external IDs.

DROP INDEX IF EXISTS idx_roles_tenant_external_id;
ALTER TABLE roles DROP COLUMN IF EXISTS external_id;

DROP INDEX IF EXISTS idx_users_tenant_external_id;
