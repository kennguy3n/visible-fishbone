-- 025_playbook_approvals — Approval workflow for playbook executions.
--
-- Tracks pending/approved/rejected/expired approvals for playbook
-- executions that require operator sign-off before proceeding.

CREATE TABLE IF NOT EXISTS playbook_approvals (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    execution_id    UUID NOT NULL REFERENCES playbook_executions(id) ON DELETE CASCADE,
    approver_id     UUID REFERENCES users(id) ON DELETE SET NULL,
    status          TEXT NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending', 'approved', 'rejected', 'expired')),
    expires_at      TIMESTAMPTZ NOT NULL,
    decided_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_playbook_approvals_tenant ON playbook_approvals(tenant_id);
CREATE INDEX idx_playbook_approvals_pending ON playbook_approvals(tenant_id, status)
    WHERE status = 'pending';
CREATE INDEX idx_playbook_approvals_execution ON playbook_approvals(execution_id);

ALTER TABLE playbook_approvals ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON playbook_approvals
    USING (tenant_id = current_setting('sng.tenant_id')::uuid);
