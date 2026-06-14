-- 068_tenant_hibernation
--
-- Per-tenant SCALE-TO-ZERO (hibernation) state for the dormant-tenant
-- hibernation controller (internal/service/tenancy/hibernation). It is
-- Phase-1 dormancy's second half: where migration 063's last_active_at
-- + the SweepPlanner only reduce how OFTEN a dormant trial is processed,
-- this records the durable decision to actively park a tenant's ongoing
-- resource draw — telemetry ingest, NATS subscriptions, warm ClickHouse
-- partitions — until it shows activity again.
--
-- State model (see internal/service/tenancy/hibernation.State):
--   * active     — the default. Full telemetry fidelity, normal NATS
--                  subscriptions, tier-appropriate ClickHouse retention.
--                  This is the state of EVERY tenant for which no row
--                  exists: absence == active, so a fresh deployment
--                  hibernates nothing and the feature is inert until the
--                  leader-only controller (default-OFF gate) runs.
--   * hibernated — scale-to-zero. Non-security telemetry is sampled to
--                  near-zero, NATS subscriptions are condensed, and the
--                  tenant's ClickHouse retention is driven to the
--                  aggressive floor so its hot partitions age into the
--                  S3 cold tier. Security-relevant events (inspect_full)
--                  are NEVER sampled away. The first login / agent
--                  check-in / real request wakes the tenant back to
--                  active transparently.
--
-- Honesty contract: the default for every tenant is `active` (absence ==
-- active). Nothing in this schema (no DEFAULT toward hibernation, no
-- trigger, no backfill) ever parks a tenant; only the explicit,
-- default-OFF controller transitions a row to `hibernated`, and any
-- gate that reads this state fails safe toward MORE work (treats an
-- unreadable/absent state as active). hibernated_at / woke_at are an
-- audit trail of the most recent transition in each direction.
--
-- One row per tenant; the single-column PRIMARY KEY makes a set a by-PK
-- upsert, ties a row's lifetime to its tenant (ON DELETE CASCADE), and
-- serves every access pattern (get by PK, full cross-tenant scan for the
-- registry sync), so no secondary index is created — a plain CREATE
-- INDEX is the table-rewrite-lock pattern the migration-lint validator
-- rejects, and there is nothing here it would serve.
--
-- Lock safety: CREATE TABLE on a brand-new (empty) table takes no
-- table-rewrite lock, and the trigger / RLS policies attach to that same
-- empty table in the migration runner's transaction, so no CONCURRENTLY
-- step is needed (mirrors migrations 059 / 066).

CREATE TABLE IF NOT EXISTS tenant_hibernation (
    -- Tenant the hibernation state belongs to. ON DELETE CASCADE so a
    -- deleted tenant's hibernation row goes with it.
    tenant_id     UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    -- Current hibernation state. Defaults to 'active' so even a row
    -- inserted without an explicit state is fail-safe (full work); the
    -- only legal values are the two hibernation states.
    state         TEXT        NOT NULL DEFAULT 'active'
                      CHECK (state IN ('active', 'hibernated')),
    -- Human-readable reason for the most recent transition (e.g. the
    -- dormancy tier that triggered hibernation, or the wake source).
    -- Empty on a freshly created row.
    reason        TEXT        NOT NULL DEFAULT '',
    -- Audit trail: when the tenant was most recently hibernated and most
    -- recently woken. NULL until the corresponding transition occurs.
    hibernated_at TIMESTAMPTZ,
    woke_at       TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id)
);

CREATE TRIGGER tenant_hibernation_set_updated_at
    BEFORE UPDATE ON tenant_hibernation
    FOR EACH ROW EXECUTE FUNCTION sng_set_updated_at();

-- ENABLE applies RLS to the runtime app role; FORCE extends it to the
-- table owner too, so even the migration/owner credentials cannot
-- bypass tenant isolation. Both are the documented standard for
-- tenant-scoped tables (see migrations 002, 037, 038, 059, 066).
ALTER TABLE tenant_hibernation ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_hibernation FORCE ROW LEVEL SECURITY;

-- Tenant-scoped policy: a request bound to sng.tenant_id sees only its
-- own hibernation row. The metering cost endpoint and any future
-- tenant-scoped read run under this policy.
CREATE POLICY tenant_hibernation_tenant_isolation ON tenant_hibernation
    USING (tenant_id = NULLIF(current_setting('sng.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('sng.tenant_id', true), '')::uuid);

-- System policy: the cross-tenant leader-only hibernation controller and
-- the per-replica registry sync (sng.system_role='true') read every
-- tenant's state and write transitions, mirroring the cross-tenant
-- background access in migrations 038 / 059 / 066.
CREATE POLICY tenant_hibernation_system ON tenant_hibernation
    USING (current_setting('sng.system_role', true) = 'true')
    WITH CHECK (current_setting('sng.system_role', true) = 'true');
