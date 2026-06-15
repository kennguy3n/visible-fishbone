-- ShieldNet Gateway (SNG) — tenant-shard work distributor: worker registry.
--
-- WP2. Per-tenant background compute (the leader-gated periodic jobs in
-- cmd/sng-control) historically ran serially on a single elected leader
-- (internal/service/leader). At 5,000 tenants that single-leader
-- serialization is the throughput ceiling. The workshard distributor
-- (internal/service/workshard) replaces it with active/active ownership:
-- every replica registers here and heartbeats its liveness, and a
-- consistent hash (rendezvous/HRW) of tenant -> shard -> owning worker
-- spreads the work across all live replicas while a Postgres lease
-- (migration 077) guarantees exactly one worker owns a tenant at a time.
--
-- This table is the worker registry: one row per running replica, with a
-- heartbeat-extended liveness window. A worker is "live" while
-- expires_at > now(); a replica that crashes or is partitioned simply
-- stops heartbeating, its row expires, and its shards are reclaimed by
-- the survivors on their next assignment cycle. No operator action and
-- no manual shard configuration is required — scale is "add a replica",
-- self-healing is "a replica died".
--
-- NOT tenant-scoped. Worker identity is fleet-wide infrastructure state
-- (a replica serves every tenant's shards), carries no tenant data and
-- no PII, and is read/written only by the distributor in a system-role
-- transaction — so this mirrors the global app_registry / threat_intel_iocs
-- (no RLS, migration 051) rather than a per-tenant table. There is no
-- cross-tenant data here to isolate.
--
-- worker_id (a process-generated UUID, stable for a replica's lifetime)
-- is the natural primary key and serves every access pattern: heartbeat
-- is a by-PK upsert, and the only reads are a whole-table scan of live
-- workers and an expired-row sweep. The registry is bounded by the
-- replica count (tens, not millions), so those scans are sub-millisecond
-- and no secondary index is warranted — the same reasoning migrations
-- 051 and 069 apply (a standalone CREATE INDEX would also be the
-- table-rewrite-lock pattern the migration-lint validator guards).
--
-- Lock safety: CREATE TABLE on a brand-new (empty) table takes no
-- table-rewrite lock, so no CONCURRENTLY step is needed.

CREATE TABLE IF NOT EXISTS workshard_workers (
    -- Process-generated identity, stable for the replica's lifetime.
    worker_id         UUID        NOT NULL,
    -- Human/ops-facing label (hostname / pod name) for observability.
    -- Defaulted so a heartbeat that omits it still inserts cleanly.
    instance          TEXT        NOT NULL DEFAULT '',
    -- When this replica first registered (preserved across heartbeats).
    started_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Most recent heartbeat. Doubles as the row's mutation timestamp, so
    -- no separate updated_at column / trigger is needed.
    last_heartbeat_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Liveness deadline: the worker is live while now() < expires_at.
    -- Each heartbeat pushes it to now() + TTL; a missed heartbeat lets it
    -- lapse so survivors reclaim the shards.
    expires_at        TIMESTAMPTZ NOT NULL,

    PRIMARY KEY (worker_id)
);
