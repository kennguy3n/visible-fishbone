-- Down-migration for 002_role_bootstrap.
--
-- Mirror image of the up migration: revoke every privilege we
-- granted, in the same order (default privileges first, then the
-- concrete grants on existing objects). The role itself is left
-- in place — role lifecycle is an operator concern, not a schema
-- concern (see docs/deploy.md and the head comment in
-- 002_role_bootstrap.up.sql).
--
-- Robust against an out-of-band role drop. PostgreSQL raises
-- `ERROR: role "sng_app" does not exist` when REVOKE / ALTER
-- DEFAULT PRIVILEGES target a non-existent role; without the
-- DO-block guard below, dropping `sng_app` before running the
-- down migration would fail the entire migration and leave the
-- migration tracker in a dirty state. The guard makes the down
-- path truly idempotent: if the role is gone, the privileges
-- already cannot be exercised by anyone, so revoking them is a
-- no-op that we can skip.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'sng_app') THEN
        -- Revoke default privileges first so they don't get re-applied
        -- on new objects created between the REVOKE on existing tables
        -- and the next migration.
        EXECUTE 'ALTER DEFAULT PRIVILEGES IN SCHEMA public
                    REVOKE SELECT, INSERT, UPDATE, DELETE ON TABLES FROM sng_app';
        EXECUTE 'ALTER DEFAULT PRIVILEGES IN SCHEMA public
                    REVOKE USAGE ON SEQUENCES FROM sng_app';

        EXECUTE 'REVOKE USAGE ON ALL SEQUENCES IN SCHEMA public FROM sng_app';
        EXECUTE 'REVOKE SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public FROM sng_app';
        EXECUTE 'REVOKE USAGE ON SCHEMA public FROM sng_app';
    END IF;
END $$;
