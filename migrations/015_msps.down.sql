-- Rollback for 015_msps.up.sql.
--
-- Order matters: drop the FK column on tenants first so msps can
-- be dropped without violating the ON DELETE SET NULL contract,
-- then the join table, then the top-level table.
DROP INDEX IF EXISTS tenants_msp_idx;
ALTER TABLE tenants DROP COLUMN IF EXISTS msp_id;
DROP TABLE IF EXISTS msp_tenants;
DROP TABLE IF EXISTS msps;
