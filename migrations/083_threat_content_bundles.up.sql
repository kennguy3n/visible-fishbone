-- ShieldNet Gateway (SNG) — managed threat-content signed bundle store.
--
-- WP3 (internal/service/threatfeed). Each row is one signed, versioned
-- managed-content bundle: the distributable artifact the engine builds
-- once centrally (ingest -> normalize -> dedup -> score -> expire ->
-- sign) and that is pushed to every tenant. Envelope is the
-- self-describing Ed25519 signed envelope (the same trust model as the
-- policy / IPS / threat-intel DNS bundles) that a consumer verifies
-- against the pinned platform key before applying.
--
-- Persisting the bundle makes distribution durable and
-- replica-independent: any control-plane replica can serve the current
-- managed posture from the latest row without re-running ingestion, and
-- a consumer reconnecting after a restart still sees the last good
-- bundle. This closes the warm-up gap the in-memory-only producer would
-- otherwise have.
--
-- Serial is the monotonically non-decreasing version (producer unix
-- seconds, advanced past the last serial) and the natural primary key.
-- A consumer pins the highest serial it has applied and ignores any
-- lower one, so an out-of-order delivery can never roll the feed back.
-- A serial collision (two replicas producing within the same second)
-- is resolved by the writer as last-writer-wins (ON CONFLICT DO UPDATE)
-- — both are valid managed content and monotonicity is preserved
-- without a re-sign loop.
--
-- NOT tenant-scoped; written in a system-role transaction. counts_by_type
-- is denormalized JSONB so the posture endpoint reports per-type
-- cardinality without decoding the envelope.
--
-- Lock safety: brand-new empty table, primary-key index only (built by
-- CREATE TABLE). LatestBundle (ORDER BY serial DESC LIMIT 1),
-- LatestSerial (MAX(serial)) and PruneBundles all ride the primary-key
-- index, so no secondary index is created (matching the migration-lint
-- table-rewrite-lock policy).

CREATE TABLE IF NOT EXISTS threat_content_bundles (
    -- Monotonic version (producer unix seconds, advanced past last).
    serial          BIGINT PRIMARY KEY
                    CHECK (serial > 0),
    -- Payload layout version stamped inside the bundle.
    schema_version  INTEGER NOT NULL DEFAULT 1
                    CHECK (schema_version >= 1),
    -- Producer timestamp (UTC).
    generated_at    TIMESTAMPTZ NOT NULL,
    -- Signing key label so the consumer selects the matching pinned key.
    key_id          TEXT NOT NULL DEFAULT '',
    -- Signature algorithm identifier (ed25519).
    algorithm       TEXT NOT NULL DEFAULT 'ed25519',
    -- Total indicator count in the bundle.
    indicator_count BIGINT NOT NULL DEFAULT 0
                    CHECK (indicator_count >= 0),
    -- Marshalled envelope size in bytes (telemetry).
    size_bytes      BIGINT NOT NULL DEFAULT 0
                    CHECK (size_bytes >= 0),
    -- Lowercase-hex SHA-256 of the envelope, to detect an unchanged
    -- bundle (skip re-publish) and for integrity.
    digest          TEXT NOT NULL DEFAULT '',
    -- Per-type indicator cardinality (domain/ip/cidr/url/hash).
    counts_by_type  JSONB NOT NULL DEFAULT '{}'::jsonb,
    -- The signed bundle JSON distributed to consumers.
    envelope        BYTEA NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
