-- 067_dlp_edm_datasets (down)
--
-- Drop the Exact-Data-Match storage. The contents are operator-
-- registered sensitive-data digests (salted hashes + metadata), not
-- derived data: re-applying the up migration recreates empty tables, so
-- a tenant that re-registers its datasets is back to the same posture a
-- fresh deployment starts from. No plaintext is lost because none was
-- ever stored.
--
-- Digests are dropped before their parent datasets to respect the FK,
-- though DROP TABLE ... CASCADE would handle ordering either way.

DROP TABLE IF EXISTS dlp_edm_digests;

DROP TRIGGER IF EXISTS dlp_edm_datasets_set_updated_at ON dlp_edm_datasets;

DROP TABLE IF EXISTS dlp_edm_datasets;
