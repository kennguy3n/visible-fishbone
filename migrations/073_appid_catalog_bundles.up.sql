-- ShieldNet Gateway (SNG) — Application-ID signed bundles (WP1).
--
-- The authoritative distribution artifact for each catalog version: the
-- Ed25519-signed canonical payload that edges pull, verify against the
-- pinned public key, and load into the data-plane matcher. Storing the
-- exact signed bytes (rather than re-signing on read) means every
-- tenant fetches an identical, verifiable artifact and the signature
-- stays valid for the life of the version.
--
-- NOT tenant-scoped (global catalog; no RLS), same rationale as 071.
--
-- One bundle per version: serial is both PRIMARY KEY and a FK to
-- appid_catalog_versions with ON DELETE CASCADE. public_key / payload /
-- signature are stored raw (BYTEA) — the API layer base64-encodes them
-- into the JSON envelope on read. Persisting the public key alongside
-- the signature lets a verifier confirm which key signed a historical
-- version across key rotations.
--
-- CurrentBundle reads ORDER BY serial DESC LIMIT 1, served by the
-- primary-key index scanned backwards, so no secondary index is needed.
--
-- Lock safety: CREATE TABLE on a brand-new empty table takes no
-- table-rewrite lock; no standalone CREATE INDEX.

CREATE TABLE IF NOT EXISTS appid_catalog_bundles (
    serial      BIGINT      PRIMARY KEY
                REFERENCES appid_catalog_versions (serial) ON DELETE CASCADE,
    -- Signature algorithm identifier (currently "ed25519").
    algorithm   TEXT        NOT NULL DEFAULT 'ed25519',
    -- Optional key identifier for rotation / pinning.
    key_id      TEXT        NOT NULL DEFAULT '',
    -- Raw Ed25519 public key (32 bytes) that signed this payload.
    public_key  BYTEA       NOT NULL,
    -- Canonical signed payload (a self-contained catalog document).
    payload     BYTEA       NOT NULL,
    -- Raw Ed25519 signature (64 bytes) over payload.
    signature   BYTEA       NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
