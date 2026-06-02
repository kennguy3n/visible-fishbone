-- 011_policy_graphs_is_draft — Mark candidate graphs as drafts.
--
-- A policy graph is "current" when it is the highest-version row
-- that has been promoted (is_draft = false). Drafts are graphs
-- the operator has proposed but not yet promoted to live —
-- typically as part of an active rollout (see migration
-- 010_policy_rollouts). The dry-run / canary stages need to
-- store the proposed graph (so it can be FK'd from the
-- policy_rollouts row), but those stages must NOT change the
-- live policy. Without this flag, GetCurrentGraph would return
-- the proposed graph and the next call to /policy/compile would
-- promote it — defeating the dry-run isolation that the rollout
-- state machine is meant to provide.
--
-- Promotion (draft -> live) flips is_draft = false at
-- rollout-completion time. Rollback leaves is_draft = true so
-- the row remains queryable for audit but does not affect
-- GetCurrentGraph.
--
-- Backfill: existing rows pre-date the rollout API, so they are
-- all considered live (is_draft = false). The DEFAULT covers
-- the legacy path where CreateGraph callers don't supply the
-- column.
ALTER TABLE policy_graphs
    ADD COLUMN IF NOT EXISTS is_draft BOOLEAN NOT NULL DEFAULT false;

-- GetCurrentGraph is the hot path; an explicit partial index on
-- live rows makes the ORDER BY version DESC LIMIT 1 satisfy from
-- the index without scanning drafts.
CREATE INDEX IF NOT EXISTS policy_graphs_tenant_version_live_idx
    ON policy_graphs (tenant_id, version DESC)
    WHERE is_draft = false;
