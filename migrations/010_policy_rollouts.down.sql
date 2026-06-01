-- 010_policy_rollouts (DOWN) — drop the rollout state machine.
--
-- Order matters: triggers + policies must be dropped before the
-- function / table; the function itself is independent of the
-- table so we drop it after the trigger.

DROP TRIGGER IF EXISTS policy_rollouts_stage_transition ON policy_rollouts;
DROP FUNCTION IF EXISTS policy_rollouts_check_transition();
DROP POLICY IF EXISTS policy_rollouts_tenant_isolation ON policy_rollouts;
DROP INDEX IF EXISTS policy_rollouts_graph_idx;
DROP INDEX IF EXISTS policy_rollouts_list_idx;
DROP INDEX IF EXISTS policy_rollouts_active_idx;
DROP TABLE IF EXISTS policy_rollouts;
