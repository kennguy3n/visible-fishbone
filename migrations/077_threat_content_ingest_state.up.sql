-- ShieldNet Gateway (SNG) — managed threat-content ingestion state.
--
-- WP3 (internal/service/threatfeed). One row per managed feed recording
-- the last ingestion outcome and the HTTP cache validators (ETag /
-- Last-Modified) that make the next refresh INCREMENTAL — an unchanged
-- upstream is confirmed with a conditional GET and skipped rather than
-- re-parsed. This is also the per-source health surface: an operator
-- sees, with zero per-tenant work, whether each curated feed is fresh
-- or failing and for how long.
--
-- Kept separate from the source registry (076) so a transient ingestion
-- failure never rewrites the registry row, and so the cursor can be
-- updated on the hot refresh path without locking the registry. There
-- is intentionally no foreign key to threat_content_sources: the engine
-- always seeds the registry before writing state, and decoupling avoids
-- a refresh-path failure if a source is being re-seeded concurrently
-- (mirroring the loose coupling of the other global threat tables).
--
-- NOT tenant-scoped; written in a system-role transaction, same as the
-- registry.
--
-- Lock safety: brand-new empty table, primary-key index only (built by
-- CREATE TABLE); the sole access pattern is a full-table ListIngestState
-- ordered by the primary key.

CREATE TABLE IF NOT EXISTS threat_content_ingest_state (
    -- References threat_content_sources.name (no FK — see header).
    source_name          TEXT PRIMARY KEY,
    -- Last fetch attempt / last usable parse. NULL until first seen.
    last_attempt_at      TIMESTAMPTZ,
    last_success_at      TIMESTAMPTZ,
    -- Most recent failure message; empty on success.
    last_error           TEXT NOT NULL DEFAULT '',
    -- Indicators the last successful parse contributed
    -- (post-normalization, pre-dedup).
    indicator_count      BIGINT NOT NULL DEFAULT 0
                         CHECK (indicator_count >= 0),
    -- Back-to-back failures since the last success; resets to 0 on any
    -- success. Bounds alerting / backoff.
    consecutive_failures BIGINT NOT NULL DEFAULT 0
                         CHECK (consecutive_failures >= 0),
    -- HTTP cache validators echoed back on the next conditional GET.
    etag                 TEXT NOT NULL DEFAULT '',
    last_modified        TEXT NOT NULL DEFAULT '',
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT now()
);
