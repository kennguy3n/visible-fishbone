-- Migration 094: Per-tenant, per-target rolling DEM baseline + alert
-- bookkeeping. Exactly one row per (tenant, target_key): the
-- exponentially-weighted moving average of the experience score and
-- its variance form the adaptive baseline degradation detection
-- compares each new score against (a drop below an absolute floor or
-- a statistically significant negative z-score). `last_alert_at`
-- enforces the per-target alert cooldown so a sustained outage raises
-- one alert, not a storm.
--
-- This is mutable hot state (upserted on every ingest), kept separate
-- from the append-only score timeseries so the baseline update never
-- rewrites history.

CREATE TABLE dem_target_state (
    id                UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id         UUID        NOT NULL REFERENCES tenants(id),
    target_key        TEXT        NOT NULL,
    target_name       TEXT        NOT NULL,
    ewma_score        DOUBLE PRECISION CHECK (ewma_score IS NULL OR (ewma_score >= 0 AND ewma_score <= 100)),
    ewma_variance     DOUBLE PRECISION CHECK (ewma_variance IS NULL OR ewma_variance >= 0),
    last_score        DOUBLE PRECISION CHECK (last_score IS NULL OR (last_score >= 0 AND last_score <= 100)),
    sample_count      BIGINT      NOT NULL DEFAULT 0 CHECK (sample_count >= 0),
    degraded          BOOLEAN     NOT NULL DEFAULT FALSE,
    last_alert_at     TIMESTAMPTZ,
    last_observed_at  TIMESTAMPTZ,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE dem_target_state ENABLE ROW LEVEL SECURITY;

CREATE POLICY dem_target_state_tenant ON dem_target_state
    USING (tenant_id::text = current_setting('sng.tenant_id', true))
    WITH CHECK (tenant_id::text = current_setting('sng.tenant_id', true));

CREATE POLICY dem_target_state_system ON dem_target_state
    USING (current_setting('sng.system_role', true) = 'true')
    WITH CHECK (current_setting('sng.system_role', true) = 'true');

-- One baseline row per tenant+target: the upsert conflict target.
CREATE UNIQUE INDEX uq_dem_target_state_tenant_key
    ON dem_target_state (tenant_id, target_key);
