-- 011_policy_graphs_is_draft — down migration.
--
-- Dropping the index first matters because the partial-index
-- predicate references the column we're about to remove.
DROP INDEX IF EXISTS policy_graphs_tenant_version_live_idx;
ALTER TABLE policy_graphs DROP COLUMN IF EXISTS is_draft;
