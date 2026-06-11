-- 062_policy_templates (DOWN) — drop the SME policy-template catalog
-- and per-tenant applied baselines.
--
-- Order: drop the RLS policy before its table; the global catalog
-- table has no dependents of its own. DROP TABLE removes the
-- primary-key indexes built by CREATE TABLE.

DROP POLICY IF EXISTS tenant_policy_templates_tenant_isolation ON tenant_policy_templates;
DROP TABLE IF EXISTS tenant_policy_templates;
DROP TABLE IF EXISTS policy_templates;
