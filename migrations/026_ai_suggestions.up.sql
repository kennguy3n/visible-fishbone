-- 026_ai_suggestions — AI policy tightening suggestions.
--
-- Stores AI-generated policy change suggestions with full review
-- workflow state. Each suggestion targets a specific rule and goes
-- through: pending -> approved/rejected -> (if approved) applied/rolled_back.
--
-- RLS: tenant_isolation on tenant_id, matching every other
-- tenant-scoped table in the control plane.

CREATE TABLE IF NOT EXISTS ai_policy_suggestions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    rule_id         TEXT NOT NULL,
    category        TEXT NOT NULL,
    suggestion_json JSONB NOT NULL DEFAULT '{}',
    confidence      DOUBLE PRECISION NOT NULL DEFAULT 0,
    status          TEXT NOT NULL DEFAULT 'pending',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    reviewed_at     TIMESTAMPTZ,
    reviewer_id     UUID REFERENCES users(id) ON DELETE SET NULL,
    feedback        TEXT,

    CONSTRAINT ai_policy_suggestions_category_check
        CHECK (category IN ('unused', 'shadowed', 'overly_permissive', 'deny_log')),
    CONSTRAINT ai_policy_suggestions_status_check
        CHECK (status IN ('pending', 'approved', 'rejected', 'applied', 'rolled_back')),
    CONSTRAINT ai_policy_suggestions_confidence_check
        CHECK (confidence >= 0 AND confidence <= 1)
);

CREATE INDEX IF NOT EXISTS ai_policy_suggestions_tenant_idx
    ON ai_policy_suggestions (tenant_id, created_at DESC, id DESC);

CREATE INDEX IF NOT EXISTS ai_policy_suggestions_status_idx
    ON ai_policy_suggestions (tenant_id, status)
    WHERE status = 'pending';

ALTER TABLE ai_policy_suggestions ENABLE ROW LEVEL SECURITY;
ALTER TABLE ai_policy_suggestions FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON ai_policy_suggestions
    USING (tenant_id = current_setting('sng.tenant_id')::uuid);
