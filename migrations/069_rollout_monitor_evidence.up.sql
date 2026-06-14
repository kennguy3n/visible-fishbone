-- 069_rollout_monitor_evidence
--
-- Durable backing for the WS-5 NoOps auto-promoter's monitor-phase
-- evidence (internal/service/rollout.MonitorMetricsRecorder). The
-- recorder is an in-process cache of the LATEST monitor (dry-run)
-- observation per (tenant, capability); on a leader failover that cache
-- starts empty and the promotion evidence has to re-accumulate from
-- scratch, so a capability that had nearly cleared its dwell window
-- effectively restarts its clock. This table lets the recorder
-- write-through each snapshot and rehydrate it on a new leader, so the
-- promotion clock survives a leader change.
--
-- Honesty contract: this is a CACHE of derived telemetry, not operator
-- intent. It never advances a rollout row by itself — the promoter still
-- applies the dwell window AND the auto-demote guardrail AND discards any
-- snapshot older than the capability's current monitor entry (the
-- freshness gate in autopromote.go), so a persisted snapshot can only
-- ever SPEED a promotion the guardrails already justify, never cause an
-- unsafe one. Losing this table (or its rows) is fail-safe: the recorder
-- falls back to its in-memory cache and a promotion is merely delayed.
--
-- `capability` is deliberately NOT CHECK-constrained against a fixed
-- value list, matching capability_rollout (066): the capability set is
-- owned by the Go enum (internal/service/rollout.Capability) and must be
-- extensible without a migration.
--
-- One row per (tenant_id, capability); the composite PRIMARY KEY makes a
-- write a by-PK upsert and serves every access pattern (get by PK), so no
-- secondary index is created (a plain CREATE INDEX is the
-- table-rewrite-lock pattern the migration-lint validator rejects, and
-- nothing here would use one).
--
-- Lock safety: CREATE TABLE on a brand-new (empty) table takes no
-- table-rewrite lock, and the trigger / RLS policies attach to that same
-- empty table in the migration runner's transaction, so no CONCURRENTLY
-- step is needed.

CREATE TABLE IF NOT EXISTS rollout_monitor_evidence (
    -- Tenant the evidence belongs to. ON DELETE CASCADE so a deleted
    -- tenant's evidence goes with it.
    tenant_id   UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    -- Capability key, matching internal/service/rollout.Capability
    -- (e.g. 'noops_autoenforce', 'idp_directory_sync'). Validated by the
    -- service, deliberately not CHECK-constrained here (see header).
    capability  TEXT        NOT NULL CHECK (capability <> ''),
    -- Latest monitor-phase observation snapshot (rollout.MonitorMetrics).
    -- Non-negative counts; rates are derived in Go, not stored.
    samples     BIGINT      NOT NULL DEFAULT 0 CHECK (samples >= 0),
    errors      BIGINT      NOT NULL DEFAULT 0 CHECK (errors  >= 0),
    denies      BIGINT      NOT NULL DEFAULT 0 CHECK (denies  >= 0),
    -- When the recorder observed this snapshot (its record time). The
    -- promoter compares it against the rollout row's monitor entry to
    -- discard stale evidence, so it is stored explicitly rather than
    -- inferred from updated_at.
    observed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, capability)
);

CREATE TRIGGER rollout_monitor_evidence_set_updated_at
    BEFORE UPDATE ON rollout_monitor_evidence
    FOR EACH ROW EXECUTE FUNCTION sng_set_updated_at();

-- ENABLE applies RLS to the runtime app role; FORCE extends it to the
-- table owner too, so even the migration/owner credentials cannot bypass
-- tenant isolation. Both are the documented standard for tenant-scoped
-- tables (see 066 and migrations 002, 037, 038, 059).
ALTER TABLE rollout_monitor_evidence ENABLE ROW LEVEL SECURITY;
ALTER TABLE rollout_monitor_evidence FORCE ROW LEVEL SECURITY;

-- Tenant-scoped policy: a request bound to sng.tenant_id sees only its
-- own evidence. The recorder reads and write-throughs tenant-scoped.
CREATE POLICY rollout_monitor_evidence_tenant_isolation ON rollout_monitor_evidence
    USING (tenant_id = NULLIF(current_setting('sng.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('sng.tenant_id', true), '')::uuid);

-- System policy: a cross-tenant background process (sng.system_role
-- ='true') — e.g. the leader-only promoter rehydrating evidence — may
-- read every tenant's snapshot and write-through, mirroring the
-- cross-tenant background access in 066 and migrations 038/059.
CREATE POLICY rollout_monitor_evidence_system ON rollout_monitor_evidence
    USING (current_setting('sng.system_role', true) = 'true')
    WITH CHECK (current_setting('sng.system_role', true) = 'true');
