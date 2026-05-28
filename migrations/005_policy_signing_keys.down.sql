ALTER TABLE policy_bundles DROP COLUMN IF EXISTS key_id;

DROP POLICY IF EXISTS policy_signing_keys_tenant_isolation ON policy_signing_keys;
DROP INDEX IF EXISTS policy_signing_keys_tenant_one_active_idx;
DROP INDEX IF EXISTS policy_signing_keys_tenant_active_idx;
DROP TABLE IF EXISTS policy_signing_keys;
