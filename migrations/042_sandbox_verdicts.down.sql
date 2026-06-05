-- Reverse migration for sandbox verdicts (down).
-- Dropping the table removes its RLS policy, indexes, and trigger
-- implicitly.
DROP TRIGGER IF EXISTS sandbox_verdicts_set_updated_at ON sandbox_verdicts;
DROP POLICY IF EXISTS sandbox_verdicts_tenant_isolation ON sandbox_verdicts;
DROP TABLE IF EXISTS sandbox_verdicts;
