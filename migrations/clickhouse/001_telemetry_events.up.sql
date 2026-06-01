-- ClickHouse migration 001: telemetry_events with per-tenant retention.
--
-- This migration documents the canonical DDL the
-- internal/service/telemetry/clickhouse.Writer creates via
-- EnsureSchema on every boot. It is checked into the repo as
-- the source-of-truth contract for operators running ClickHouse
-- outside the Go control-plane lifecycle (e.g. ad-hoc data
-- inspection clusters, replay clusters, ClickHouse Cloud
-- migrations).
--
-- Behaviour parity with EnsureSchema is enforced by
-- internal/service/telemetry/clickhouse/writer_test.go:
-- TestEnsureSchema_DDLMatchesMigrationFile.
--
-- Per-tenant retention model:
--   * retain_until is computed at insert by the writer from the
--     RetentionResolver, clamped to [30, 90] days.
--   * MergeTree TTL toDateTime(retain_until) auto-drops past-
--     retention rows on the next part-merge.
--   * The DEFAULT expression below is the floor applied to rows
--     inserted by a pre-retention upgrade window (i.e. by Go
--     code that hasn't been rebuilt yet).

CREATE TABLE IF NOT EXISTS telemetry_events (
    event_id        UUID,
    tenant_id       UUID,
    device_id       UUID,
    site_id         Nullable(UUID),
    timestamp       DateTime64(6, 'UTC'),
    event_class     LowCardinality(String),
    platform        LowCardinality(String),
    schema_version  UInt8,
    traffic_class   LowCardinality(String) DEFAULT 'inspect_full',
    bytes_in        UInt64 DEFAULT 0,
    bytes_out       UInt64 DEFAULT 0,
    payload         String,
    retain_until    DateTime64(6, 'UTC') DEFAULT (timestamp + INTERVAL 60 DAY),
    ingested_at     DateTime64(6, 'UTC') DEFAULT now64(6, 'UTC')
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(timestamp)
ORDER BY (tenant_id, event_class, traffic_class, timestamp, event_id)
TTL toDateTime(retain_until)
SETTINGS index_granularity = 8192;

-- Idempotent forward-migrations for tables that pre-date later
-- column additions. The Go EnsureSchema re-runs these on every
-- boot; this SQL is the bookkeeping copy for ops tooling that
-- bypasses the Go path.
ALTER TABLE telemetry_events
    ADD COLUMN IF NOT EXISTS traffic_class LowCardinality(String) DEFAULT 'inspect_full' AFTER schema_version;
ALTER TABLE telemetry_events
    ADD COLUMN IF NOT EXISTS bytes_in UInt64 DEFAULT 0 AFTER traffic_class;
ALTER TABLE telemetry_events
    ADD COLUMN IF NOT EXISTS bytes_out UInt64 DEFAULT 0 AFTER bytes_in;
ALTER TABLE telemetry_events
    ADD COLUMN IF NOT EXISTS retain_until DateTime64(6, 'UTC') DEFAULT (timestamp + INTERVAL 60 DAY) AFTER payload;
ALTER TABLE telemetry_events MODIFY TTL toDateTime(retain_until);
