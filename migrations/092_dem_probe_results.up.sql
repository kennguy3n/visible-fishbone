-- Migration 092: Raw DEM probe results ingested from the edge. One
-- row per probe of one target: a DNS / TCP / HTTP(S) sample with the
-- per-phase timings the `sng-dem` crate emits. A failed probe is a
-- first-class signal (`success = false` with an `error_kind`), never
-- an absence of data.
--
-- Rows are keyed by `target_key` (not an FK to dem_targets) because
-- managed default targets are code-defined and have no config row;
-- this keeps results uniform across managed and custom targets and
-- avoids a write-time FK lookup on the ingest hot path. Raw results
-- are short-lived (the service prunes them on age); the durable
-- signal lives in dem_experience_scores.

CREATE TABLE dem_probe_results (
    id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id    UUID        NOT NULL REFERENCES tenants(id),
    target_key   TEXT        NOT NULL,
    target_name  TEXT        NOT NULL,
    probe_kind   TEXT        NOT NULL CHECK (probe_kind IN (
                                 'dns', 'tcp', 'http', 'https'
                             )),
    success      BOOLEAN     NOT NULL,
    dns_ms       DOUBLE PRECISION CHECK (dns_ms IS NULL OR dns_ms >= 0),
    tcp_ms       DOUBLE PRECISION CHECK (tcp_ms IS NULL OR tcp_ms >= 0),
    tls_ms       DOUBLE PRECISION CHECK (tls_ms IS NULL OR tls_ms >= 0),
    ttfb_ms      DOUBLE PRECISION CHECK (ttfb_ms IS NULL OR ttfb_ms >= 0),
    total_ms     DOUBLE PRECISION CHECK (total_ms IS NULL OR total_ms >= 0),
    http_status  INTEGER     CHECK (http_status IS NULL OR (http_status >= 100 AND http_status <= 599)),
    error_kind   TEXT        CHECK (error_kind IS NULL OR error_kind IN (
                                 'timeout', 'dns', 'connect', 'tls', 'http', 'config', 'internal'
                             )),
    observed_at  TIMESTAMPTZ NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE dem_probe_results ENABLE ROW LEVEL SECURITY;

CREATE POLICY dem_probe_results_tenant ON dem_probe_results
    USING (tenant_id::text = current_setting('sng.tenant_id', true))
    WITH CHECK (tenant_id::text = current_setting('sng.tenant_id', true));

CREATE POLICY dem_probe_results_system ON dem_probe_results
    USING (current_setting('sng.system_role', true) = 'true')
    WITH CHECK (current_setting('sng.system_role', true) = 'true');

-- Window aggregation reads the most recent results for one target.
CREATE INDEX idx_dem_probe_results_tenant_target_observed
    ON dem_probe_results (tenant_id, target_key, observed_at DESC);

-- Retention sweep deletes by age across tenants (system role).
CREATE INDEX idx_dem_probe_results_created_at
    ON dem_probe_results (created_at);
