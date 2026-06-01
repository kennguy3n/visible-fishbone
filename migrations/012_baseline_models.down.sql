-- 012_baseline_models (DOWN) — drop the baseline state.
--
-- Tables are dropped after the policies / indexes; the indexes
-- are auto-dropped with the table but we drop them explicitly
-- so the down migration is symmetrical with the up.

DROP POLICY IF EXISTS baseline_models_tenant_isolation ON baseline_models;
DROP INDEX IF EXISTS baseline_models_recent_idx;
DROP TABLE IF EXISTS baseline_models;
