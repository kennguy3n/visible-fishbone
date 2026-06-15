-- Reverse migration for the App-ID catalog version ledger.
-- Dropped last (entries/bundles reference it) — see 072/073 down.
DROP TABLE IF EXISTS appid_catalog_versions;
