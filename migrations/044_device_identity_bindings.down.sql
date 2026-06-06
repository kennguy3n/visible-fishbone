-- Reverse migration 044 (down): drop the device ↔ iam-core identity
-- binding table. Dropping the table removes its RLS policy, indexes,
-- and trigger implicitly.
DROP TRIGGER IF EXISTS device_identity_bindings_set_updated_at ON device_identity_bindings;
DROP POLICY IF EXISTS device_identity_bindings_tenant_isolation ON device_identity_bindings;
DROP TABLE IF EXISTS device_identity_bindings;
