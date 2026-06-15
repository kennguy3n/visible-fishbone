-- ShieldNet Gateway (SNG) — Application-ID catalog versioning (WP1).
--
-- The data plane (crates/sng-appid) identifies L7 applications from a
-- declarative, signed signature catalog instead of a hard-coded closed
-- set. This table is the monotonic version ledger for that catalog:
-- one row per published version, newest = highest serial.
--
-- NOT tenant-scoped. The catalog is a fleet-wide signal — the same
-- signature set identifies an app for every tenant — so this mirrors
-- the global app_registry / threat_intel_iocs (no RLS) rather than any
-- per-tenant table. Writes happen in a system-role transaction; the
-- tenant-facing surface is read-only (edges pull the signed bundle).
--
-- `serial` is a caller-supplied monotonic version number (the service
-- derives it from wall-clock seconds, falling back to previous+1), used
-- as the PRIMARY KEY. Replay/rollback protection is enforced at the
-- service+repository layer by rejecting a serial <= the current max.
--
-- `checksum` is the SHA-256 (hex) of the canonical signed payload, so
-- an operator can diff two versions without downloading both bundles.
--
-- Lock safety: CREATE TABLE on a brand-new (empty) table takes no
-- table-rewrite lock. The list/current queries (ORDER BY serial DESC
-- LIMIT n) are served by the primary-key index scanned backwards, so
-- no secondary index is created (a plain CREATE INDEX is the
-- table-rewrite-lock pattern the migration-lint validator rejects).

CREATE TABLE IF NOT EXISTS appid_catalog_versions (
    -- Monotonic version number. Higher = newer.
    serial         BIGINT      PRIMARY KEY,
    -- Catalog schema version the entries/bundle conform to.
    schema_version INTEGER     NOT NULL DEFAULT 1
                   CHECK (schema_version >= 1),
    -- Number of application signatures in this version.
    app_count      INTEGER     NOT NULL DEFAULT 0
                   CHECK (app_count >= 0),
    -- SHA-256 (hex) of the canonical signed payload.
    checksum       TEXT        NOT NULL DEFAULT '',
    -- Optional operator annotation (e.g. "initial seed", "rotate key").
    note           TEXT        NOT NULL DEFAULT '',
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
