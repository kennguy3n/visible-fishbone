-- Down-migration for 001_initial_schema. Drops every object in
-- reverse dependency order so re-running `up` lands cleanly.

DROP TABLE IF EXISTS policy_bundles;
DROP TABLE IF EXISTS policy_graphs;
DROP TABLE IF EXISTS audit_log;
DROP TABLE IF EXISTS claim_tokens;
DROP TABLE IF EXISTS devices;
DROP TABLE IF EXISTS user_roles;
DROP TABLE IF EXISTS roles;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS sites;
DROP TABLE IF EXISTS tenants;

DROP FUNCTION IF EXISTS sng_set_updated_at();
