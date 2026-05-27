-- ShieldNet Gateway (SNG) — runtime role bootstrap.
--
-- Grants the non-superuser runtime role (`sng_app`) the minimum
-- privileges the control-plane needs on the public schema:
--
--   * USAGE on the schema itself,
--   * SELECT/INSERT/UPDATE/DELETE on every table created by 001
--     (and any future migration — see ALTER DEFAULT PRIVILEGES
--     block at the bottom),
--   * USAGE on every sequence (so DEFAULT uuid_generate_v4() and
--     any future SERIAL columns work under `SET ROLE sng_app`).
--
-- The role itself is intentionally NOT created here. SNG's
-- deployment model treats role lifecycle as an operator concern,
-- not a schema concern:
--
--   * Production: a deploy admin pre-provisions `sng_app` once,
--     scoped by the org's IAM / database-access policy. The role
--     outlives any single migration cycle.
--   * Integration tests: the test harness creates an ephemeral
--     `sng_app` role inside each testcontainers postgres instance
--     before invoking the migration runner.
--
-- Both paths converge here: once `sng_app` exists, *this*
-- migration is the single source of truth for what `sng_app` can
-- and cannot do on the schema. See `docs/deploy.md` for the
-- runbook.
--
-- ROW LEVEL SECURITY. Tenant-scoped tables created by 001 enable
-- and FORCE row level security. `FORCE ROW LEVEL SECURITY` does
-- NOT apply to superusers (so the migration runner — typically a
-- superuser — bypasses RLS), but it DOES apply to `sng_app`. This
-- migration grants the DML privileges that let RLS *kick in*; it
-- does not weaken the policies themselves.

-- ---------------------------------------------------------------------
-- Fail loudly if `sng_app` is not provisioned.
--
-- Without this guard, every GRANT below would error out with the
-- somewhat opaque `role "sng_app" does not exist`. The DO block
-- surfaces the real remediation (see docs/deploy.md) instead.
-- ---------------------------------------------------------------------
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'sng_app') THEN
        RAISE EXCEPTION USING
            ERRCODE = 'undefined_object',
            MESSAGE = 'sng_app role missing; provision it before running migrations (see docs/deploy.md)',
            HINT    = 'CREATE ROLE sng_app NOINHERIT NOLOGIN; GRANT sng_app TO <migration_runner>;';
    END IF;
END $$;

-- ---------------------------------------------------------------------
-- Schema-level USAGE.
--
-- Without USAGE on `public`, `sng_app` cannot resolve any object
-- name in the schema regardless of table-level grants. Idempotent:
-- re-granting USAGE on an already-granted schema is a no-op.
-- ---------------------------------------------------------------------
GRANT USAGE ON SCHEMA public TO sng_app;

-- ---------------------------------------------------------------------
-- DML on every existing table.
--
-- Covers every table created by 001 (tenants, sites, users, roles,
-- user_roles, devices, claim_tokens, audit_log, policy_graphs,
-- policy_bundles). The blanket `ON ALL TABLES IN SCHEMA public`
-- form is intentional — explicit per-table grants would drift
-- silently as new migrations add tables, which was the exact
-- failure mode this migration is meant to close.
--
-- TRUNCATE / REFERENCES are NOT granted: the runtime role should
-- never bulk-wipe a table (use a `sng_admin` role for destructive
-- ops) and FK creation is a schema-time operation owned by the
-- migration runner, not the runtime role.
-- ---------------------------------------------------------------------
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO sng_app;

-- ---------------------------------------------------------------------
-- USAGE on sequences.
--
-- Several columns default to `uuid_generate_v4()` (no sequence),
-- but `policy_graphs.version`, `audit_log` ingestion counters, and
-- any future SERIAL/BIGSERIAL columns rely on sequences. USAGE
-- covers nextval/currval/setval which a runtime DML role needs.
-- ---------------------------------------------------------------------
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO sng_app;

-- ---------------------------------------------------------------------
-- Default privileges for future objects.
--
-- `ALTER DEFAULT PRIVILEGES` only applies to objects created AFTER
-- the statement is executed, BY the role that ran the statement.
-- Inside a migration this works because every future migration
-- also runs as the same migration runner (the role that owns the
-- default-privileges entry). Re-running this block is a no-op —
-- Postgres treats identical default-privilege rows as a single
-- entry.
--
-- This is what lets later migrations (003, 004, ...) add tables
-- WITHOUT needing to repeat the GRANT clauses: the runtime role
-- inherits DML automatically.
-- ---------------------------------------------------------------------
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO sng_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT USAGE ON SEQUENCES TO sng_app;
