-- Reverse migration for inline CASB (down).
-- Dropping the table removes its RLS policy, indexes, and trigger
-- implicitly.
DROP TRIGGER IF EXISTS inline_casb_rules_set_updated_at ON inline_casb_rules;
DROP POLICY IF EXISTS inline_casb_rules_tenant_isolation ON inline_casb_rules;
DROP TABLE IF EXISTS inline_casb_rules;
