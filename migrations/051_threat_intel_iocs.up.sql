-- ShieldNet Gateway (SNG) — threat-intel IOC store durability.
--
-- Workstream 8 follow-up: the aggregated indicator-of-compromise
-- store (internal/service/ai IOCStore) is in-memory. On a
-- control-plane restart it starts empty and only re-warms as each
-- configured feed re-fetches on its schedule — with hourly feeds and
-- a slow or briefly-unreachable upstream that can leave a real
-- enforcement gap (live-traffic matching and demotion sync see no
-- indicators until warm-up completes).
--
-- This table is a single durable snapshot of the active indicator
-- set. The feed manager flushes it periodically and on graceful
-- shutdown; on boot the store restores from it before feeds start, so
-- enforcement is warm immediately and the feed warm-up merely
-- refreshes it.
--
-- NOT tenant-scoped. Threat-intel feeds are fleet-wide signals (a C2
-- IP is malicious for every tenant), so this mirrors the global
-- app_registry (no RLS) rather than the per-tenant
-- app_registry_overrides. Writes happen in a system-role transaction.
--
-- De-duplication identity is (type, value) — the same key the
-- in-memory store merges on — so it is the natural primary key.
--
-- Lock safety: CREATE TABLE on a brand-new (empty) table takes no
-- table-rewrite lock. No standalone secondary index is created — the
-- runner wraps each migration in a transaction (migration 041) inside
-- which CREATE INDEX CONCURRENTLY cannot run, and a plain CREATE INDEX
-- is the table-rewrite-lock pattern the migration-lint validator
-- rejects (mirroring migrations 048/049). The primary-key index is
-- built as part of CREATE TABLE, and the only access patterns are a
-- full-table LoadAll on boot and a whole-table ReplaceAll snapshot, so
-- no secondary index is needed.

CREATE TABLE IF NOT EXISTS threat_intel_iocs (
    -- Indicator category: domain / ip / url / hash (ai.IOCType).
    type         TEXT NOT NULL
                 CHECK (type IN ('domain', 'ip', 'url', 'hash')),
    -- Already-normalized indicator value (lowercase domain, canonical
    -- IP, normalized URL, lowercase-hex hash).
    value        TEXT NOT NULL,
    -- Digest algorithm for hash indicators (md5 / sha1 / sha256);
    -- empty for the other types.
    hash_algo    TEXT NOT NULL DEFAULT '',
    -- Originating feed label (e.g. "abuse.ch:urlhaus", "otx").
    source       TEXT NOT NULL DEFAULT '',
    -- Optional attribution carried from the feed.
    threat_actor TEXT NOT NULL DEFAULT '',
    campaign     TEXT NOT NULL DEFAULT '',
    -- Feed-supplied confidence in [0,1].
    confidence   DOUBLE PRECISION NOT NULL DEFAULT 0
                 CHECK (confidence >= 0 AND confidence <= 1),
    -- Observation window. NULL first_seen/last_seen means "unknown";
    -- NULL expires_at means the indicator never expires on its own
    -- (matching the in-memory store's zero-time semantics).
    first_seen   TIMESTAMPTZ,
    last_seen    TIMESTAMPTZ,
    expires_at   TIMESTAMPTZ,

    PRIMARY KEY (type, value)
);
