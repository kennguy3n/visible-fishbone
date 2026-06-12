-- 066_capability_rollout
--
-- Per-tenant, per-capability STAGED-ENABLEMENT (rollout) state for the
-- platform's default-OFF capability gates. It turns flipping a gate
-- (ClamAV SWG ext-authz, shadow-IT NoOps auto-enforce, IdP directory
-- sync) from a binary on/off flag into a safe, observable
-- monitor->enforce progression driven by internal/service/rollout.
--
-- State model (see internal/service/rollout.State):
--   * off      — the default. The capability does not evaluate and does
--                NOT enforce. This is the state of EVERY tenant /
--                capability for which no row exists: absence == off, so a
--                fresh deployment enforces nothing and nothing
--                auto-advances.
--   * monitor  — dry-run. The capability evaluates and emits telemetry /
--                "would-have" verdicts but takes NO enforcement action.
--   * enforce  — full enforcement.
--
-- Honesty contract: the default for every tenant/capability is `off`.
-- Nothing in this schema (no DEFAULT, no trigger, no backfill) ever
-- advances a row toward enforcement; advancement is only ever an
-- explicit operator transition recorded through the rollout service.
-- The framework is a guardrail — it must never silently enable
-- enforcement.
--
-- `capability` is intentionally NOT constrained by a CHECK against a
-- fixed value list: the set of capabilities is owned by the Go enum
-- (internal/service/rollout.Capability) and is meant to be extensible,
-- so adding a capability must never require a schema migration. The
-- service validates the capability before any write; a CHECK here would
-- only duplicate that and turn every new capability into a migration.
--
-- One row per (tenant_id, capability); the composite PRIMARY KEY makes a
-- set a by-PK upsert, ties a row's lifetime to its tenant
-- (ON DELETE CASCADE), and serves every access pattern (get by PK, list
-- by tenant via the PK's leading column), so no secondary index is
-- created — a plain CREATE INDEX is the table-rewrite-lock pattern the
-- migration-lint validator rejects, and there is nothing here it would
-- serve.
--
-- Lock safety: CREATE TABLE on a brand-new (empty) table takes no
-- table-rewrite lock, and the trigger / RLS policies attach to that same
-- empty table in the migration runner's transaction, so no CONCURRENTLY
-- step is needed.

CREATE TABLE IF NOT EXISTS capability_rollout (
    -- Tenant the rollout state belongs to. ON DELETE CASCADE so a
    -- deleted tenant's rollout rows go with it.
    tenant_id  UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    -- Capability key, matching internal/service/rollout.Capability
    -- (e.g. 'clamav_swg', 'noops_autoenforce', 'idp_directory_sync').
    -- Validated by the service, deliberately not CHECK-constrained here
    -- (see header) so the enum can grow without a migration.
    capability TEXT        NOT NULL CHECK (capability <> ''),
    -- Current rollout state. Defaults to 'off' so even a row inserted
    -- without an explicit state is fail-closed; the only legal values
    -- are the three rollout states.
    state      TEXT        NOT NULL DEFAULT 'off'
                   CHECK (state IN ('off', 'monitor', 'enforce')),
    -- Human-readable reason for the most recent transition: the operator
    -- note on an advance/rollback, or the auto-rollback trigger detail
    -- (e.g. "deny_rate 0.42 exceeded threshold 0.10"). Empty on a freshly
    -- created row.
    reason     TEXT        NOT NULL DEFAULT '',
    -- Actor that drove the most recent transition: an operator's
    -- id/subject for a manual transition, or the "system" sentinel for an
    -- automatic rollback. Empty on a freshly created row.
    updated_by TEXT        NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, capability)
);

CREATE TRIGGER capability_rollout_set_updated_at
    BEFORE UPDATE ON capability_rollout
    FOR EACH ROW EXECUTE FUNCTION sng_set_updated_at();

-- ENABLE applies RLS to the runtime app role; FORCE extends it to the
-- table owner too, so even the migration/owner credentials cannot
-- bypass tenant isolation. Both are the documented standard for
-- tenant-scoped tables (see migrations 002, 037, 038, 059).
ALTER TABLE capability_rollout ENABLE ROW LEVEL SECURITY;
ALTER TABLE capability_rollout FORCE ROW LEVEL SECURITY;

-- Tenant-scoped policy: a request bound to sng.tenant_id sees only its
-- own rollout rows. The operator GET/POST surface runs tenant-scoped.
CREATE POLICY capability_rollout_tenant_isolation ON capability_rollout
    USING (tenant_id = NULLIF(current_setting('sng.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('sng.tenant_id', true), '')::uuid);

-- System policy: a cross-tenant background evaluator (sng.system_role
-- ='true') — e.g. the monitor-phase auto-rollback sweep — may read every
-- tenant's state and write a rollback, mirroring the cross-tenant
-- background access in migrations 038/059.
CREATE POLICY capability_rollout_system ON capability_rollout
    USING (current_setting('sng.system_role', true) = 'true')
    WITH CHECK (current_setting('sng.system_role', true) = 'true');
