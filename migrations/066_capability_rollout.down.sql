-- 066_capability_rollout (down)
--
-- Drop the per-tenant capability rollout state. The state is operator
-- intent (which gates a tenant has advanced toward enforcement), not
-- derived data: re-applying the up migration creates an empty table in
-- which every tenant/capability is back to the default `off`, exactly
-- the fail-closed posture a fresh deployment starts from.

DROP TRIGGER IF EXISTS capability_rollout_set_updated_at ON capability_rollout;

DROP TABLE IF EXISTS capability_rollout;
