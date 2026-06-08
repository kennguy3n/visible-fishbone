-- Reverse migration for IPS per-tenant rule categories (down).
-- Dropping the tables removes their RLS policies, indexes, and
-- triggers implicitly.
DROP TRIGGER IF EXISTS ips_rule_category_stats_set_updated_at ON ips_rule_category_stats;
DROP POLICY IF EXISTS ips_rule_category_stats_tenant_isolation ON ips_rule_category_stats;
DROP TABLE IF EXISTS ips_rule_category_stats;

DROP TRIGGER IF EXISTS ips_rule_categories_set_updated_at ON ips_rule_categories;
DROP POLICY IF EXISTS ips_rule_categories_tenant_isolation ON ips_rule_categories;
DROP TABLE IF EXISTS ips_rule_categories;
