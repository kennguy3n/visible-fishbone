-- 069_rollout_monitor_evidence (down)
--
-- Drop the persisted monitor-phase evidence cache. The data is derived
-- telemetry (the latest dry-run observation per tenant/capability), not
-- operator intent: dropping it is fail-safe — the recorder falls back to
-- its in-memory cache and any in-flight promotion is merely delayed until
-- the evidence re-accumulates.

DROP TRIGGER IF EXISTS rollout_monitor_evidence_set_updated_at ON rollout_monitor_evidence;

DROP TABLE IF EXISTS rollout_monitor_evidence;
