-- Migration 083: Per-tenant, per-target DEM experience-score samples.
-- One row per scoring window: a composite 0..100 experience score
-- (availability + latency) computed over a rolling window of raw
-- probe results, plus the supporting aggregates (availability ratio,
-- latency percentiles, sample count, window bounds). This is the
-- durable experience timeseries the UI charts and the longer-lived
-- signal that outlives raw results.
--
-- Keyed by `target_key` for the same managed/custom uniformity as
-- dem_probe_results.

CREATE TABLE dem_experience_scores (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID        NOT NULL REFERENCES tenants(id),
    target_key      TEXT        NOT NULL,
    target_name     TEXT        NOT NULL,
    score           DOUBLE PRECISION NOT NULL CHECK (score >= 0 AND score <= 100),
    availability    DOUBLE PRECISION NOT NULL CHECK (availability >= 0 AND availability <= 1),
    latency_p50_ms  DOUBLE PRECISION CHECK (latency_p50_ms IS NULL OR latency_p50_ms >= 0),
    latency_p95_ms  DOUBLE PRECISION CHECK (latency_p95_ms IS NULL OR latency_p95_ms >= 0),
    sample_count    INTEGER     NOT NULL CHECK (sample_count >= 0),
    window_seconds  INTEGER     NOT NULL CHECK (window_seconds > 0),
    window_start    TIMESTAMPTZ NOT NULL,
    window_end      TIMESTAMPTZ NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT dem_experience_scores_window_order CHECK (window_end >= window_start)
);

ALTER TABLE dem_experience_scores ENABLE ROW LEVEL SECURITY;

CREATE POLICY dem_experience_scores_tenant ON dem_experience_scores
    USING (tenant_id::text = current_setting('sng.tenant_id', true))
    WITH CHECK (tenant_id::text = current_setting('sng.tenant_id', true));

CREATE POLICY dem_experience_scores_system ON dem_experience_scores
    USING (current_setting('sng.system_role', true) = 'true')
    WITH CHECK (current_setting('sng.system_role', true) = 'true');

-- Per-target timeseries reads + "latest score per target" (DISTINCT
-- ON target_key ORDER BY created_at DESC).
CREATE INDEX idx_dem_experience_scores_tenant_target_created
    ON dem_experience_scores (tenant_id, target_key, created_at DESC);

-- Keyset pagination across all of a tenant's score samples
-- (created_at DESC, id DESC).
CREATE INDEX idx_dem_experience_scores_tenant_created
    ON dem_experience_scores (tenant_id, created_at DESC, id DESC);

-- Retention sweep deletes by age across tenants (system role).
CREATE INDEX idx_dem_experience_scores_created_at
    ON dem_experience_scores (created_at);
