-- Reverse migration for DLP tables (Phase 4).
DROP POLICY IF EXISTS dlp_matches_tenant_isolation ON dlp_matches;
DROP TABLE IF EXISTS dlp_matches;

DROP POLICY IF EXISTS dlp_fingerprints_tenant_isolation ON dlp_fingerprints;
DROP TABLE IF EXISTS dlp_fingerprints;

DROP TRIGGER IF EXISTS dlp_policies_set_updated_at ON dlp_policies;
DROP POLICY IF EXISTS dlp_policies_tenant_isolation ON dlp_policies;
DROP TABLE IF EXISTS dlp_policies;
