DROP POLICY IF EXISTS tenant_api_keys_tenant_isolation ON tenant_api_keys;
DROP INDEX IF EXISTS tenant_api_keys_tenant_created_idx;
DROP INDEX IF EXISTS tenant_api_keys_hash_idx;
DROP TABLE IF EXISTS tenant_api_keys;
