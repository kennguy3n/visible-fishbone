-- Migration 030: Policy review schedule tables.
-- Adds policy_review_schedules for periodic review reminders.

CREATE TABLE policy_review_schedules (
    id                  UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID        NOT NULL REFERENCES tenants(id),
    policy_id           UUID        NOT NULL,
    last_reviewed_at    TIMESTAMPTZ,
    next_review_at      TIMESTAMPTZ,
    review_interval_days INT        NOT NULL DEFAULT 90,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- RLS policy on tenant_id.
ALTER TABLE policy_review_schedules ENABLE ROW LEVEL SECURITY;
CREATE POLICY policy_review_schedules_tenant ON policy_review_schedules
    USING (tenant_id::text = current_setting('sng.tenant_id', true))
    WITH CHECK (tenant_id::text = current_setting('sng.tenant_id', true));

CREATE POLICY policy_review_schedules_system ON policy_review_schedules
    USING (current_setting('sng.system_role', true) = 'true')
    WITH CHECK (current_setting('sng.system_role', true) = 'true');

-- Unique constraint on (tenant_id, policy_id).
CREATE UNIQUE INDEX idx_policy_review_schedules_tenant_policy
    ON policy_review_schedules (tenant_id, policy_id);
