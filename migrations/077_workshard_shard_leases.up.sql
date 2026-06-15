-- ShieldNet Gateway (SNG) — tenant-shard work distributor: shard leases.
--
-- WP2, paired with the worker registry (migration 076). Tenants are
-- mapped to a fixed set of shards by the same FNV-1a hash the telemetry
-- store already shards on (internal/service/telemetry/clickhouse), and
-- each shard is owned by exactly one live worker. This table is the
-- ownership ledger: one row per shard the fleet currently owns, naming
-- the holding worker and its lease deadline.
--
-- Exactly-once-per-tenant guarantee. A worker may process a tenant only
-- while it holds a non-expired lease on that tenant's shard. Acquisition
-- is a single atomic upsert: INSERT ... ON CONFLICT (shard) DO UPDATE
-- ... WHERE the existing lease is already mine OR has expired. Because
-- the conflicting row is locked for the duration of the UPDATE, two
-- workers racing for the same shard serialise and exactly one wins; the
-- loser's UPDATE matches no row and it does not take the shard. A worker
-- whose heartbeats stop has its lease lapse (expires_at <= now()) and a
-- survivor reclaims the shard on its next cycle. The distributor adds a
-- local safety margin (it stops serving a shard before the DB lease
-- actually expires), so the previous owner has yielded before any
-- successor can acquire — no two workers ever process one tenant at once.
--
-- fence_token is a per-shard monotonic counter, bumped on every change
-- of ownership (takeover of a free/expired shard) and held steady across
-- a same-owner renewal. It mirrors the leader package's fencing token
-- (internal/service/leader/fencing.go): a job that writes shard-scoped
-- state can stamp the token it acted under so a delayed write from a
-- deposed owner is detectable and can be rejected.
--
-- NOT tenant-scoped. The ledger keys on the abstract shard number, holds
-- no tenant data and no PII, and is read/written only by the distributor
-- in a system-role transaction — so it mirrors the global app_registry /
-- threat_intel_iocs (no RLS, migration 051), not a per-tenant table.
-- (Tenant -> shard is a pure hash computed in Go; the tenant id never
-- lands in this table.)
--
-- shard is the natural primary key: acquisition/renewal is a by-PK
-- upsert and the table holds at most one row per shard (a small fixed
-- count, default 1024). Every other access — list the live leases, find
-- the ones a given worker holds, release the ones it no longer should —
-- scans that bounded, tiny table in well under a millisecond, so no
-- secondary index is warranted (the same reasoning migrations 051 and
-- 069 apply, and a standalone CREATE INDEX would be the table-rewrite-
-- lock pattern the migration-lint validator guards).
--
-- Lock safety: CREATE TABLE on a brand-new (empty) table takes no
-- table-rewrite lock, so no CONCURRENTLY step is needed.

CREATE TABLE IF NOT EXISTS workshard_shard_leases (
    -- Shard number in [0, shard_count). Tenant -> shard is FNV-1a(tenant)
    -- mod shard_count, computed in Go (never stored here).
    shard       INTEGER     NOT NULL CHECK (shard >= 0),
    -- The worker that currently holds this shard. Deliberately no FK to
    -- workshard_workers: a lease may briefly outlive its worker's
    -- registry row (the row is swept on a slightly longer horizon than
    -- the lease), and lease reclamation keys on expires_at, not on the
    -- registry row's continued existence.
    worker_id   UUID        NOT NULL,
    -- Per-shard fencing token: +1 on each ownership change, steady across
    -- a same-owner renewal. Starts at 1 on first acquisition.
    fence_token BIGINT      NOT NULL DEFAULT 0 CHECK (fence_token >= 0),
    -- When the current owner first took the shard (reset on takeover,
    -- preserved across renewals).
    acquired_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Most recent renewal. Doubles as the row's mutation timestamp, so no
    -- separate updated_at column / trigger is needed.
    renewed_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Lease deadline: the holder owns the shard while now() < expires_at.
    -- A lapsed lease is reclaimable by any worker.
    expires_at  TIMESTAMPTZ NOT NULL,

    PRIMARY KEY (shard)
);
