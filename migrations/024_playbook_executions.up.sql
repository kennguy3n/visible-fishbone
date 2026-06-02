-- 024_playbook_executions — Execution tracking for playbook runs.
--
-- playbook_executions tracks each invocation of a playbook.
-- playbook_step_results stores per-step outcomes within an execution.

CREATE TABLE IF NOT EXISTS playbook_executions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    playbook_id     UUID NOT NULL REFERENCES playbooks(id) ON DELETE CASCADE,
    status          TEXT NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending', 'running', 'completed', 'failed', 'rolled_back', 'awaiting_approval')),
    trigger_event   JSONB NOT NULL DEFAULT '{}'::jsonb,
    started_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_playbook_executions_tenant ON playbook_executions(tenant_id);
CREATE INDEX idx_playbook_executions_playbook ON playbook_executions(tenant_id, playbook_id);

ALTER TABLE playbook_executions ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON playbook_executions
    USING (tenant_id = current_setting('sng.tenant_id')::uuid);

CREATE TABLE IF NOT EXISTS playbook_step_results (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    execution_id    UUID NOT NULL REFERENCES playbook_executions(id) ON DELETE CASCADE,
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    step_order      INTEGER NOT NULL,
    status          TEXT NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending', 'running', 'completed', 'failed', 'skipped')),
    output          JSONB NOT NULL DEFAULT '{}'::jsonb,
    error           TEXT NOT NULL DEFAULT '',
    started_at      TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ,

    CONSTRAINT step_results_exec_order_unique UNIQUE (execution_id, step_order)
);

CREATE INDEX idx_step_results_execution ON playbook_step_results(execution_id);

ALTER TABLE playbook_step_results ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON playbook_step_results
    USING (tenant_id = current_setting('sng.tenant_id')::uuid);
