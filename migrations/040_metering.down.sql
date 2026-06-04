-- Reverse migration for cost metering & budget guardrails (down).
-- Dropping each table removes its RLS policy, indexes, and trigger
-- implicitly.
DROP TRIGGER IF EXISTS tenant_budgets_set_updated_at ON tenant_budgets;
DROP POLICY IF EXISTS tenant_budgets_tenant_isolation ON tenant_budgets;
DROP TABLE IF EXISTS tenant_budgets;

DROP TRIGGER IF EXISTS tenant_usage_set_updated_at ON tenant_usage;
DROP POLICY IF EXISTS tenant_usage_tenant_isolation ON tenant_usage;
DROP TABLE IF EXISTS tenant_usage;
