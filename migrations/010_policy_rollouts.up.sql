-- 010_policy_rollouts — Progressive policy rollout state machine.
--
-- Tracks each proposed PolicyGraph as it advances through dry-run
-- (shadow / log-only on agents), canary (configurable percent of
-- the fleet enforces the new bundle, the rest stay on the
-- previous one), and full-fleet enforcement. Terminates in either
-- `completed` (operator promoted the proposed graph to canonical)
-- or `rolled_back` (operator pulled the rollout at any stage).
--
-- The state machine is enforced by a CHECK on the stage column
-- and a BEFORE UPDATE trigger that rejects illegal transitions —
-- this puts the invariant in the database so a buggy service
-- caller cannot leave the table in an impossible state
-- (e.g. completed -> canary).
--
-- RLS pattern mirrors policy_graphs / policy_signing_keys: a
-- single `tenant_isolation` USING clause that filters every read
-- and write on `sng.tenant_id` GUC equality. The migration
-- forces RLS so even superusers go through the policy when
-- connecting via the service role.

CREATE TABLE IF NOT EXISTS policy_rollouts (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id          UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    graph_id           UUID NOT NULL REFERENCES policy_graphs(id) ON DELETE RESTRICT,
    -- Nullable: the very first rollout on a tenant has no
    -- predecessor. ON DELETE SET NULL preserves the rollout audit
    -- trail even if an operator hard-deletes the previous graph.
    previous_graph_id  UUID REFERENCES policy_graphs(id) ON DELETE SET NULL,
    stage              TEXT NOT NULL DEFAULT 'dry_run',
    -- 0..100. Meaningful only when stage = 'canary'; we keep the
    -- value on the row across stage transitions so the audit
    -- record retains "we ran at N% before promoting / rolling
    -- back".
    canary_percent     INTEGER NOT NULL DEFAULT 0 CHECK (canary_percent >= 0 AND canary_percent <= 100),
    -- Free-form simulation_id from the simulator. Not FK'd —
    -- simulation runs are not persisted in this PR; the operator
    -- pastes the ID for audit if they want a paper trail.
    simulation_id      UUID,
    -- Optional; null when a rollback is triggered by automation
    -- (e.g. a fleet-wide error-rate alarm) rather than an
    -- operator action.
    created_by         UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    notes              TEXT,

    CONSTRAINT policy_rollouts_stage_check
        CHECK (stage IN ('dry_run', 'canary', 'full', 'completed', 'rolled_back'))
);

-- Hot-path index for GetActive: each tenant typically has at
-- most one in-flight rollout. We omit the partial-unique
-- constraint deliberately (the service layer is responsible for
-- the overlap policy — see internal/service/policy/canary.go).
CREATE INDEX IF NOT EXISTS policy_rollouts_active_idx
    ON policy_rollouts (tenant_id, created_at DESC)
    WHERE stage NOT IN ('completed', 'rolled_back');

-- Listing index for the operator-facing UI.
CREATE INDEX IF NOT EXISTS policy_rollouts_list_idx
    ON policy_rollouts (tenant_id, created_at DESC, id DESC);

-- Lookup-by-graph for the "what rollouts targeted this graph"
-- view.
CREATE INDEX IF NOT EXISTS policy_rollouts_graph_idx
    ON policy_rollouts (tenant_id, graph_id);

-- ---------------------------------------------------------------------
-- Monotone-forward stage-transition trigger.
--
-- The state machine: a row may transition
--   dry_run -> canary | full | rolled_back
--   canary  -> full | rolled_back
--   full    -> completed | rolled_back
-- Terminal states (completed, rolled_back) admit no further
-- transitions. Same-stage updates are allowed so the service can
-- patch canary_percent or notes without forcing a transition.
-- ---------------------------------------------------------------------

CREATE OR REPLACE FUNCTION policy_rollouts_check_transition()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.stage = OLD.stage THEN
        RETURN NEW;
    END IF;

    IF OLD.stage IN ('completed', 'rolled_back') THEN
        RAISE EXCEPTION 'policy_rollouts: rollout % already in terminal stage %', OLD.id, OLD.stage
            USING ERRCODE = '23514';
    END IF;

    IF NEW.stage = 'rolled_back' THEN
        RETURN NEW;
    END IF;

    IF OLD.stage = 'dry_run' AND NEW.stage IN ('canary', 'full') THEN
        RETURN NEW;
    END IF;
    IF OLD.stage = 'canary' AND NEW.stage = 'full' THEN
        RETURN NEW;
    END IF;
    IF OLD.stage = 'full' AND NEW.stage = 'completed' THEN
        RETURN NEW;
    END IF;

    RAISE EXCEPTION 'policy_rollouts: illegal transition % -> %', OLD.stage, NEW.stage
        USING ERRCODE = '23514';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER policy_rollouts_stage_transition
    BEFORE UPDATE OF stage ON policy_rollouts
    FOR EACH ROW
    EXECUTE FUNCTION policy_rollouts_check_transition();

-- ---------------------------------------------------------------------
-- Row-level security — tenant isolation via `sng.tenant_id` GUC.
-- ---------------------------------------------------------------------

ALTER TABLE policy_rollouts ENABLE ROW LEVEL SECURITY;
ALTER TABLE policy_rollouts FORCE ROW LEVEL SECURITY;
CREATE POLICY policy_rollouts_tenant_isolation ON policy_rollouts
    USING (tenant_id = NULLIF(current_setting('sng.tenant_id', true), '')::uuid);

COMMENT ON TABLE policy_rollouts IS
    'Progressive deployment of a proposed PolicyGraph: dry_run -> canary -> full, terminating in completed or rolled_back. See internal/repository/types.go PolicyRollout and internal/service/policy/canary.go.';
