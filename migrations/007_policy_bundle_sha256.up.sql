-- 007_policy_bundle_sha256
--
-- Add a precomputed SHA-256 digest column to policy_bundles so the
-- agent-pull endpoint can serve HEAD / If-None-Match responses
-- without round-tripping the (potentially large) bundle BYTEA into
-- application memory just to recompute the ETag.
--
-- For polling agents the common case is "I already have the current
-- bundle, give me a 304". Before this column, that path still
-- loaded the full bundle bytes from Postgres because the ETag was
-- sha256(bundle) computed in Go. With the column in place the HEAD
-- and 304 paths only need the digest + signature + key_id +
-- created_at, all of which fit on the row itself.
--
-- Backfill uses pgcrypto's digest() so the stored digest is byte-
-- identical to the value Go's crypto/sha256.Sum256 would compute,
-- meaning existing in-flight client caches keyed on the prior ETag
-- continue to match after the migration. After backfill the column
-- is set NOT NULL so the application layer can rely on it.

BEGIN;

ALTER TABLE policy_bundles
    ADD COLUMN sha256 BYTEA;

UPDATE policy_bundles
SET sha256 = digest(bundle, 'sha256');

ALTER TABLE policy_bundles
    ALTER COLUMN sha256 SET NOT NULL,
    ADD CONSTRAINT policy_bundles_sha256_length_chk
        CHECK (octet_length(sha256) = 32);

COMMIT;
