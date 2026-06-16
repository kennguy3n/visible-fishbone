-- Migration 081: Per-tenant Digital Experience Monitoring (DEM)
-- target configuration. Each row is a critical SaaS endpoint a tenant
-- wants the edge to probe, on top of the code-defined managed default
-- set (so a no-ops SME configures nothing and still gets coverage).
--
-- `target_key` is the stable scoring dimension: it ties raw probe
-- results, experience-score samples, and per-target baseline state
-- together without a foreign key, so deleting a custom target leaves
-- its historical timeseries intact (retention prunes it on age) and
-- managed defaults — which are not rows here — share the same keyed
-- model. Managed defaults use their slug (e.g. `m365`); custom
-- targets must use a tenant-unique key.
--
-- `probe_kind` mirrors the edge `sng-dem` crate's ProbeKind tokens.
-- `interval_seconds` / `timeout_ms` are the bounded cost-model knobs:
-- a minimum 10 s interval and a 100 ms..30 s timeout keep a 5,000-
-- tenant fleet from generating a probe storm.

CREATE TABLE dem_targets (
    id               UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id        UUID        NOT NULL REFERENCES tenants(id),
    target_key       TEXT        NOT NULL,
    name             TEXT        NOT NULL,
    probe_kind       TEXT        NOT NULL CHECK (probe_kind IN (
                                     'dns', 'tcp', 'http', 'https'
                                 )),
    address          TEXT        NOT NULL,
    port             INTEGER     CHECK (port IS NULL OR (port >= 1 AND port <= 65535)),
    enabled          BOOLEAN     NOT NULL DEFAULT TRUE,
    interval_seconds INTEGER     NOT NULL DEFAULT 60 CHECK (
                                     interval_seconds >= 10 AND interval_seconds <= 3600
                                 ),
    timeout_ms       INTEGER     NOT NULL DEFAULT 5000 CHECK (
                                     timeout_ms >= 100 AND timeout_ms <= 30000
                                 ),
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE dem_targets ENABLE ROW LEVEL SECURITY;

-- Tenant-scoped policy: a request bound to sng.tenant_id sees only
-- its own DEM targets.
CREATE POLICY dem_targets_tenant ON dem_targets
    USING (tenant_id::text = current_setting('sng.tenant_id', true))
    WITH CHECK (tenant_id::text = current_setting('sng.tenant_id', true));

-- System policy: background workers / cross-tenant jobs that set
-- sng.system_role='true' may read/write across tenants.
CREATE POLICY dem_targets_system ON dem_targets
    USING (current_setting('sng.system_role', true) = 'true')
    WITH CHECK (current_setting('sng.system_role', true) = 'true');

-- One target key per tenant: the key is the addressing handle that
-- joins results / scores / state, so it must be unique within a
-- tenant.
CREATE UNIQUE INDEX uq_dem_targets_tenant_key
    ON dem_targets (tenant_id, target_key);

CREATE INDEX idx_dem_targets_tenant
    ON dem_targets (tenant_id, created_at DESC);
