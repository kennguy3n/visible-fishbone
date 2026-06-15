-- 070_policy_recommendations
--
-- Traffic-derived least-privilege policy recommendations. The
-- recommendation engine (internal/service/policyrec) replays a
-- tenant's recently-observed telemetry, synthesizes a minimal
-- default-deny allow-list that preserves the traffic the tenant
-- actually relies on, and stores the candidate graph here together
-- with the coverage / impact evidence that proves what applying it
-- would change. An operator can then apply a recommendation, which
-- stages the candidate_graph as a policy draft (policy.PutDraftGraph)
-- and feeds it into the existing canary-rollout path.
--
-- Honesty contract: this table never enforces anything by itself. The
-- candidate_graph only becomes live policy if an operator applies it
-- AND the existing rollout state machine promotes the resulting draft.
-- applied_graph_id is the provenance link from a recommendation to the
-- draft graph it produced.
--
-- RLS: tenant_isolation on tenant_id, matching every other
-- tenant-scoped table in the control plane. A system policy mirrors
-- migration 069 so a future leader-only scheduled generator can
-- synthesize recommendations across tenants without per-tenant request
-- context.
--
-- Lock safety: CREATE TABLE on a brand-new (empty) table takes no
-- table-rewrite lock; the indexes / RLS policies attach to that same
-- empty table in the migration runner's transaction, so no
-- CONCURRENTLY step is needed (the migration-lint validator exempts
-- indexes built on a table created in the same migration).

CREATE TABLE IF NOT EXISTS policy_recommendations (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id        UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    status           TEXT NOT NULL DEFAULT 'pending',
    -- Closed [window_start, window_end) telemetry window the
    -- recommendation was synthesized from.
    window_start     TIMESTAMPTZ NOT NULL,
    window_end       TIMESTAMPTZ NOT NULL,
    -- Synthesized candidate policy graph (a valid policy.Graph
    -- document: default-deny + least-privilege allow rules).
    candidate_graph  JSONB NOT NULL DEFAULT '{}',
    -- Typed evidence document (observed counts, per-domain rule
    -- counts, coverage, newly-denied samples, prev-vs-next impact).
    summary          JSONB NOT NULL DEFAULT '{}',
    -- Fraction (0..1) of observed permitted traffic the candidate
    -- still permits. Denormalized out of summary for cheap list
    -- rendering / sorting.
    coverage         DOUBLE PRECISION NOT NULL DEFAULT 0,
    rule_count       INTEGER NOT NULL DEFAULT 0,
    -- Draft policy graph created when the recommendation was applied;
    -- NULL until then. ON DELETE SET NULL so pruning a superseded
    -- draft does not delete the recommendation's audit trail.
    applied_graph_id UUID REFERENCES policy_graphs(id) ON DELETE SET NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    applied_at       TIMESTAMPTZ,
    -- Operator who applied / dismissed the recommendation; NULL for a
    -- still-pending row or an API-key actor with no user mapping.
    actor_id         UUID REFERENCES users(id) ON DELETE SET NULL,

    CONSTRAINT policy_recommendations_status_check
        CHECK (status IN ('pending', 'applied', 'dismissed')),
    CONSTRAINT policy_recommendations_coverage_check
        CHECK (coverage >= 0 AND coverage <= 1),
    CONSTRAINT policy_recommendations_rule_count_check
        CHECK (rule_count >= 0),
    CONSTRAINT policy_recommendations_window_check
        CHECK (window_end > window_start)
);

-- List access pattern: newest-first within a tenant, cursor-paginated
-- on (created_at, id) — matches repository.cursor's ordering.
CREATE INDEX IF NOT EXISTS policy_recommendations_tenant_idx
    ON policy_recommendations (tenant_id, created_at DESC, id DESC);

-- Operators poll for actionable (pending) recommendations; a partial
-- index keeps that scan tight as dismissed/applied rows accumulate.
CREATE INDEX IF NOT EXISTS policy_recommendations_pending_idx
    ON policy_recommendations (tenant_id, created_at DESC)
    WHERE status = 'pending';

ALTER TABLE policy_recommendations ENABLE ROW LEVEL SECURITY;
ALTER TABLE policy_recommendations FORCE ROW LEVEL SECURITY;

-- Tenant-scoped policy: a request bound to sng.tenant_id sees only its
-- own recommendations.
CREATE POLICY policy_recommendations_tenant_isolation ON policy_recommendations
    USING (tenant_id = NULLIF(current_setting('sng.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('sng.tenant_id', true), '')::uuid);

-- System policy: a cross-tenant background process (sng.system_role
-- ='true') — e.g. a future leader-only scheduled generator — may read
-- and write every tenant's recommendations, mirroring migration 069.
CREATE POLICY policy_recommendations_system ON policy_recommendations
    USING (current_setting('sng.system_role', true) = 'true')
    WITH CHECK (current_setting('sng.system_role', true) = 'true');
