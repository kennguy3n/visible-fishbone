-- Down-migration for 002_role_bootstrap.
--
-- Mirror image of the up migration: revoke every privilege we
-- granted, in the same order (default privileges first, then the
-- concrete grants on existing objects). The role itself is left
-- in place — role lifecycle is an operator concern, not a schema
-- concern (see docs/deploy.md and the head comment in
-- 002_role_bootstrap.up.sql).
--
-- If `sng_app` was dropped out-of-band before this down migration
-- runs, every REVOKE below becomes a no-op (Postgres treats
-- "revoke from a role that no longer exists" as harmless), so the
-- down path is safe to re-run.

-- Revoke default privileges first so they don't get re-applied on
-- new objects created between the REVOKE on existing tables and
-- the next migration.
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    REVOKE SELECT, INSERT, UPDATE, DELETE ON TABLES FROM sng_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    REVOKE USAGE ON SEQUENCES FROM sng_app;

REVOKE USAGE ON ALL SEQUENCES IN SCHEMA public FROM sng_app;
REVOKE SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public FROM sng_app;
REVOKE USAGE ON SCHEMA public FROM sng_app;
