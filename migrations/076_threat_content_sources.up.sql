-- ShieldNet Gateway (SNG) — managed threat-content source registry.
--
-- WP3 (internal/service/threatfeed): the MANAGED, no-ops threat-content
-- engine. Unlike the operator-configured, default-OFF threat-intel
-- delivery pipeline (internal/service/threatintel), this engine ships a
-- curated set of built-in reputable open feeds that are normalized,
-- deduplicated, scored, signed and distributed to every tenant by
-- default with ZERO per-tenant configuration.
--
-- This table is the operator-visible registry of which curated feeds
-- the platform ingests. It is SEEDED FROM CODE at boot from the
-- engine's built-in defaults (UpsertSources) — tenants never configure
-- it — and is the join target for the per-source health surface. The
-- weight column feeds the corroboration score (a more authoritative
-- feed contributes a higher base confidence).
--
-- NOT tenant-scoped. Managed threat content is a fleet-wide signal (the
-- same malicious domain is malicious for every tenant), so this mirrors
-- the global app_registry / threat_intel_iocs (no RLS) rather than a
-- per-tenant table. Writes happen in a system-role transaction.
--
-- Lock safety: CREATE TABLE on a brand-new (empty) table takes no
-- table-rewrite lock. No standalone secondary index is created — the
-- runner wraps each migration in a transaction (migration 041) inside
-- which CREATE INDEX CONCURRENTLY cannot run, and a plain CREATE INDEX
-- is the table-rewrite-lock pattern the migration-lint validator
-- rejects. The only access pattern is a full-table ListSources ordered
-- by the primary key, so the primary-key index (built as part of
-- CREATE TABLE) suffices.

CREATE TABLE IF NOT EXISTS threat_content_sources (
    -- Stable internal identifier (e.g. "abuse.ch:feodo").
    name                TEXT PRIMARY KEY,
    -- Human-facing label for the posture/health surface.
    display_name        TEXT NOT NULL DEFAULT '',
    -- Dominant indicator category the feed contributes
    -- (domain / ip / url / hash / mixed). Advisory only — each
    -- indicator's real type is decided by the parser.
    kind                TEXT NOT NULL DEFAULT 'mixed'
                        CHECK (kind IN ('domain', 'ip', 'url', 'hash', 'mixed')),
    -- Upstream feed URL; empty for an in-process bridge source.
    url                 TEXT NOT NULL DEFAULT '',
    -- Source trust weight in (0,1], folded into the corroboration score.
    weight              DOUBLE PRECISION NOT NULL DEFAULT 0.5
                        CHECK (weight > 0 AND weight <= 1),
    -- Whether the refresh loop ingests this source. A disabled source
    -- is retained for history/telemetry but skipped.
    enabled             BOOLEAN NOT NULL DEFAULT TRUE,
    -- Default indicator lifetime (seconds after last-seen) when the
    -- feed supplies no expiry. 0 means "never expires on its own".
    default_ttl_seconds BIGINT NOT NULL DEFAULT 0
                        CHECK (default_ttl_seconds >= 0),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
