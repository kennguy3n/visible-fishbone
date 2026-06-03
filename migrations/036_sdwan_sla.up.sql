-- Migration 036: Per-tenant SD-WAN SLA policy templates. Each row is
-- a named set of path-quality thresholds (latency, loss, jitter,
-- throughput) for one SLA traffic class. The control plane CRUDs these
-- templates and compiles the active set into the SD-WAN slice of the
-- signed policy bundle; the `sng-sdwan` enforcement plane evaluates
-- live probe results against the compiled thresholds, raising
-- sustained-breach violations that drive automatic failover.
--
-- The default template set every tenant starts with:
--   business-critical  latency < 50 ms, loss < 0.1 %
--   real-time          jitter < 15 ms
--   best-effort        no SLA (all thresholds NULL)
--
-- A NULL threshold means "this metric does not gate the SLA"; an
-- all-NULL row (best-effort) therefore never reports a violation.

CREATE TABLE sdwan_sla_policies (
    id                  UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID        NOT NULL REFERENCES tenants(id),
    name                TEXT        NOT NULL,
    traffic_class       TEXT        NOT NULL CHECK (traffic_class IN (
                                        'business-critical',
                                        'real-time',
                                        'best-effort'
                                    )),
    max_latency_ms      DOUBLE PRECISION CHECK (max_latency_ms IS NULL OR max_latency_ms >= 0),
    max_loss_pct        DOUBLE PRECISION CHECK (max_loss_pct IS NULL OR (max_loss_pct >= 0 AND max_loss_pct <= 100)),
    max_jitter_ms       DOUBLE PRECISION CHECK (max_jitter_ms IS NULL OR max_jitter_ms >= 0),
    min_throughput_mbps DOUBLE PRECISION CHECK (min_throughput_mbps IS NULL OR min_throughput_mbps >= 0),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE sdwan_sla_policies ENABLE ROW LEVEL SECURITY;

-- Tenant-scoped policy: a request bound to sng.tenant_id sees only
-- its own SLA templates. Mirrors every other tenant-scoped table.
CREATE POLICY sdwan_sla_policies_tenant ON sdwan_sla_policies
    USING (tenant_id::text = current_setting('sng.tenant_id', true))
    WITH CHECK (tenant_id::text = current_setting('sng.tenant_id', true));

-- System policy: background workers / cross-tenant jobs that set
-- sng.system_role='true' may read/write across tenants.
CREATE POLICY sdwan_sla_policies_system ON sdwan_sla_policies
    USING (current_setting('sng.system_role', true) = 'true')
    WITH CHECK (current_setting('sng.system_role', true) = 'true');

-- One template name per tenant: the name is the operator-facing
-- handle used to address a template, so it must be unique within a
-- tenant.
CREATE UNIQUE INDEX uq_sdwan_sla_policies_tenant_name
    ON sdwan_sla_policies (tenant_id, name);

CREATE INDEX idx_sdwan_sla_policies_tenant
    ON sdwan_sla_policies (tenant_id, created_at DESC);
