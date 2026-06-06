-- Reverse migration 046 (down): drop the residency enforcement audit
-- table. Dropping the table removes its RLS policy and index
-- implicitly.
DROP POLICY IF EXISTS residency_audit_tenant_isolation ON residency_audit;
DROP TABLE IF EXISTS residency_audit;
