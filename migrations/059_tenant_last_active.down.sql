-- 059_tenant_last_active (down)
--
-- Restore the generic updated_at trigger on tenants and drop the
-- activity column + index. last_active_at is a derived signal,
-- reconstructed from the data path after re-applying the up migration.

DROP TRIGGER IF EXISTS tenants_set_updated_at ON tenants;
CREATE TRIGGER tenants_set_updated_at
    BEFORE UPDATE ON tenants
    FOR EACH ROW EXECUTE FUNCTION sng_set_updated_at();

DROP FUNCTION IF EXISTS sng_tenants_set_updated_at();

DROP INDEX IF EXISTS tenants_last_active_idx;

ALTER TABLE tenants
    DROP COLUMN IF EXISTS last_active_at;
