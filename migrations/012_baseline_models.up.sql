-- 012_baseline_models — Per-tenant statistical baselines for
-- anomaly detection.
--
-- For each (tenant_id, dimension, window_seconds) we maintain
-- an online estimator of the centre + spread of the observed
-- distribution. Two estimators are stored in parallel:
--
--   1) Welford's running mean + M2 (sum of squared deviations
--      from the running mean). This gives a numerically stable
--      sample mean + variance over the full observed history
--      WITHOUT keeping every sample, which is critical for the
--      hot path that observes one bucket per minute per
--      dimension per tenant. The standard deviation is
--      sqrt(m2 / max(samples - 1, 1)); samples < 2 is the
--      cold-start regime where we cannot yet score deviation.
--
--   2) EWMA (exponentially-weighted moving average) + EWMVAR
--      (the EW variance, EW square of deviation from EWMA).
--      Captures recent shifts faster than the Welford estimator
--      — a sustained 2-3x increase in DNS query volume after a
--      malware outbreak should trip in single-digit minutes, not
--      after weeks of contamination dilutes the Welford mean.
--      Alpha is the per-(tenant, dimension) decay factor in
--      (0, 1]; alpha = 1 collapses EWMA to "last observation"
--      and alpha = 0 freezes the estimator.
--
-- The anomaly detector (internal/service/baseline/anomaly.go)
-- evaluates BOTH estimators and uses max(|z_welford|,
-- |z_ewma|) as the deviation score. This catches both "slow
-- drift" anomalies (Welford trips because the long-running mean
-- has not yet absorbed the new regime) AND "sudden spike"
-- anomalies (EWMA trips because alpha=0.1 brings the recent
-- regime into the mean quickly).
--
-- z_threshold is the per-(tenant, dimension) operator-tunable
-- z-score above which an alert is emitted. Default 3.0 captures
-- ~0.27% of normal observations under a Gaussian assumption,
-- which empirically is the right knee for "novel enough to wake
-- an operator". Per-tenant tuning lives in the alert.Feedback
-- loop (migration 013).
--
-- version is an optimistic-lock counter incremented on every
-- update. The Engine's update path is read-modify-write
-- (load baseline, fold new sample, write back) so concurrent
-- observers from a fan-out goroutine MUST NOT silently overwrite
-- each other — the postgres UPDATE includes `WHERE version =
-- $old_version` and a mismatch surfaces as ErrConflict to the
-- service layer, which retries.
--
-- RLS mirrors the policy_rollouts pattern: a single tenant
-- isolation policy keyed off sng.tenant_id, FORCE'd so the
-- service role goes through the policy.

CREATE TABLE IF NOT EXISTS baseline_models (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id            UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    -- A dotted-path label for the metric being modelled, e.g.
    -- "flow.bytes_total.unclassified", "dns.queries.NXDOMAIN",
    -- "auth.failures.password", "policy.deny_rate".
    -- Free-form on purpose: the catalog of built-in dimensions
    -- lives in internal/service/baseline/dimensions.go so it
    -- can evolve without a schema migration.
    dimension            TEXT NOT NULL,
    -- Bucket size in seconds. 60 (one-minute buckets) is the
    -- default; longer windows (3600 = hourly) for noisy metrics
    -- like total bytes_in across a multi-thousand-device tenant.
    window_seconds       INTEGER NOT NULL CHECK (window_seconds > 0),

    -- Welford state.
    samples              BIGINT  NOT NULL DEFAULT 0,
    mean                 DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    m2                   DOUBLE PRECISION NOT NULL DEFAULT 0.0,

    -- EWMA state. Cold-start (samples = 0) uses the first
    -- observation directly as the initial ewma; ewma_var grows
    -- from zero as deviations accumulate.
    ewma                 DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    ewma_var             DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    alpha                DOUBLE PRECISION NOT NULL DEFAULT 0.1
        CHECK (alpha > 0.0 AND alpha <= 1.0),

    -- Operator-tunable alerting threshold; the feedback loop in
    -- alert.Feedback adjusts this per-tenant in response to
    -- accumulated false-positive markers.
    z_threshold          DOUBLE PRECISION NOT NULL DEFAULT 3.0
        CHECK (z_threshold > 0.0),

    last_observed_at     TIMESTAMPTZ,
    last_updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Optimistic lock for read-modify-write updates.
    version              BIGINT NOT NULL DEFAULT 0,

    -- One model per (tenant, dimension, window). A request for
    -- a (tenant, dim) at a window we have no model for yields a
    -- cold-start insert; subsequent observations into the same
    -- tuple round-trip through this row.
    UNIQUE (tenant_id, dimension, window_seconds)
);

-- Hot path is GetForDimension; (tenant, dim, window) UNIQUE
-- index already satisfies that lookup. The list-for-tenant
-- (operator-facing) view orders by last_updated_at to surface
-- the most recently active models.
CREATE INDEX IF NOT EXISTS baseline_models_recent_idx
    ON baseline_models (tenant_id, last_updated_at DESC);

-- RLS.
ALTER TABLE baseline_models ENABLE ROW LEVEL SECURITY;
ALTER TABLE baseline_models FORCE ROW LEVEL SECURITY;
CREATE POLICY baseline_models_tenant_isolation ON baseline_models
    USING (tenant_id = NULLIF(current_setting('sng.tenant_id', true), '')::uuid);

COMMENT ON TABLE baseline_models IS
    'Per-tenant statistical baselines (Welford + EWMA) backing the anomaly detector. See internal/service/baseline/.';
