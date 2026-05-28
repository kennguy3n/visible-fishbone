-- 007_policy_bundle_sha256 — rollback
--
-- Drops the precomputed digest column. The HEAD / If-None-Match
-- path will fall back to recomputing the digest in Go from the
-- bundle bytes (the pre-migration behaviour).

ALTER TABLE policy_bundles
    DROP CONSTRAINT IF EXISTS policy_bundles_sha256_length_chk;

ALTER TABLE policy_bundles
    DROP COLUMN IF EXISTS sha256;
