-- 013_alerts — Operator-facing alert store + suppression
-- rules + per-alert feedback.
--
-- The lifecycle of an alert:
--
--   open (default at emit time) --> acknowledged --> resolved
--                              \--> suppressed (silently muted
--                                   by a matching rule; never
--                                   notified)
--
-- "suppressed" is a terminal-ish state in the sense that no
-- notification is emitted, but the row is still persisted so an
-- operator reviewing the suppression rule can see what it
-- silenced (audit trail). Suppression matching happens at emit
-- time (alert.Router.Emit) — if a matching rule exists, the
-- alert is stored with state = 'suppressed' and the matching
-- rule id is recorded on `suppressed_by` for the audit trail.
--
-- Severity scale is the classic three-bucket info|warning|
-- critical mapping so SIEM exports (PR D) can map cleanly to
-- target systems without an N:M lookup table.
--
-- evidence is JSONB rather than columnar because the shape is
-- per-(kind, dimension) — flow.bytes_per_app_class produces
-- a different evidence payload than auth.failures, and we don't
-- want to bloat the schema with optional columns per dimension.
-- For SIEM-export consumers, the alert.Router stringifies the
-- evidence at emit time.
--
-- Table ordering: alert_suppressions is created first because
-- alerts.suppressed_by has an FK to it. PostgreSQL requires the
-- referenced table to exist before the FK is declared inside a
-- CREATE TABLE statement.

CREATE TABLE IF NOT EXISTS alert_suppressions (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id            UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- kind / dimension matchers. NULL = match any. Concrete
    -- string = exact match. We deliberately do not support glob
    -- patterns at the DB layer to keep the suppression-match
    -- query a simple equality test on indexable columns.
    kind                 TEXT,
    dimension            TEXT,

    -- Required: an operator MUST justify a suppression so the
    -- audit log captures "why does this alert never fire".
    reason               TEXT NOT NULL,

    -- created_by is nullable for two reasons:
    --   1) ON DELETE SET NULL on the FK — if we keep NOT NULL
    --      here, deleting any operator who has ever authored a
    --      suppression rule would fail with a constraint
    --      violation, which makes user-offboarding workflows
    --      brittle (the matching pattern is intentionally
    --      retained for audit; the link to the now-deleted
    --      user is what gets nulled).
    --   2) API-key-only operators have no user mapping (the
    --      auth middleware passes a nil actor), so requiring
    --      a non-null FK would 500 those callers. The audit
    --      surface logs the request principal separately
    --      regardless of whether a user_id is available.
    created_by           UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- NULL = never expires; the Router treats expires_at < now()
    -- as "not active" so a forgotten suppression doesn't outlive
    -- the operator who set it.
    expires_at           TIMESTAMPTZ,

    CONSTRAINT alert_suppressions_scope_nonempty
        CHECK (kind IS NOT NULL OR dimension IS NOT NULL)
);

CREATE TABLE IF NOT EXISTS alerts (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id            UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- Dotted-path alert kind. Convention: "<source>.<event>",
    -- e.g. "baseline.anomaly", "policy.deny_rate.spike",
    -- "auth.brute_force". The catalog of built-in kinds lives
    -- in internal/service/alert/kinds.go.
    kind                 TEXT NOT NULL,
    severity             TEXT NOT NULL DEFAULT 'warning',
    dimension            TEXT NOT NULL,

    -- Statistical context — copied off the baseline at emit time
    -- so the alert is self-explaining even if the baseline drifts
    -- after the fact.
    observed_value       DOUBLE PRECISION NOT NULL,
    baseline_mean        DOUBLE PRECISION NOT NULL,
    baseline_stddev      DOUBLE PRECISION NOT NULL,
    z_score              DOUBLE PRECISION NOT NULL,

    window_start         TIMESTAMPTZ NOT NULL,
    window_end           TIMESTAMPTZ NOT NULL,
    -- The bucket size in seconds of the underlying baseline
    -- model. Snapshot-copied here (rather than derived from
    -- window_end - window_start) so the feedback tuning loop
    -- can filter feedback rows by (dimension, window_seconds)
    -- without ambiguity: a 60s bucket and a 3600s bucket on the
    -- same dimension are independently-tuned series, and merging
    -- their FP rates would silently push the wrong threshold up.
    -- See PR #40 round-9 ANALYSIS_0002.
    window_seconds       INTEGER NOT NULL CHECK (window_seconds > 0),

    -- Human-facing one-liner; the Router formats this from the
    -- emit payload so the operator portal has something to show
    -- without re-rendering the evidence blob.
    summary              TEXT NOT NULL,
    evidence             JSONB NOT NULL DEFAULT '{}'::jsonb,

    state                TEXT NOT NULL DEFAULT 'open',

    suppressed_by        UUID REFERENCES alert_suppressions(id) ON DELETE SET NULL,
    acknowledged_by      UUID REFERENCES users(id) ON DELETE SET NULL,
    acknowledged_at      TIMESTAMPTZ,
    resolved_by          UUID REFERENCES users(id) ON DELETE SET NULL,
    resolved_at          TIMESTAMPTZ,

    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT alerts_severity_check
        CHECK (severity IN ('info', 'warning', 'critical')),
    CONSTRAINT alerts_state_check
        CHECK (state IN ('open', 'acknowledged', 'resolved', 'suppressed'))
);

CREATE TABLE IF NOT EXISTS alert_feedback (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id            UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    alert_id             UUID NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,

    -- true_positive: alert was actionable (do not adjust tuning)
    -- false_positive: alert was not actionable (tighten tuning)
    -- noise: alert was technically correct but operationally
    --        useless (e.g. periodic legitimate spike). Adjust
    --        tuning but less aggressively than false_positive.
    decision             TEXT NOT NULL,
    notes                TEXT,

    -- Nullable for the same reason as alert_suppressions.created_by:
    -- ON DELETE SET NULL + API-key callers without user mapping.
    -- The decision + alert_id are what the tuning loop needs, the
    -- author is metadata for the operator timeline.
    created_by           UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT alert_feedback_decision_check
        CHECK (decision IN ('true_positive', 'false_positive', 'noise')),
    -- One feedback per alert. If an operator wants to revise
    -- they DELETE + re-INSERT through the API rather than
    -- silently overwriting history.
    UNIQUE (alert_id)
);

-- ---- Indexes -------------------------------------------------

-- Listing index — operator portal lists "open alerts for this
-- tenant, newest first".
CREATE INDEX IF NOT EXISTS alerts_list_idx
    ON alerts (tenant_id, created_at DESC, id DESC);

-- State + recency index — the "open queue" hot path filters by
-- state = 'open' AND tenant_id, ordered by created_at DESC.
CREATE INDEX IF NOT EXISTS alerts_open_idx
    ON alerts (tenant_id, created_at DESC)
    WHERE state = 'open';

-- Dimension lookup — used by alert.Feedback to compute the
-- per-dimension false-positive rate when re-tuning a baseline.
CREATE INDEX IF NOT EXISTS alerts_dimension_idx
    ON alerts (tenant_id, dimension);

-- Suppression match index — the Router checks "is this (kind,
-- dimension) currently suppressed" on every emit. (tenant_id,
-- kind) covers the most common "wildcard dimension" case;
-- (tenant_id, dimension) covers the "wildcard kind" case.
CREATE INDEX IF NOT EXISTS alert_suppressions_kind_idx
    ON alert_suppressions (tenant_id, kind);
CREATE INDEX IF NOT EXISTS alert_suppressions_dimension_idx
    ON alert_suppressions (tenant_id, dimension);

-- Feedback aggregation — alert.Feedback scans feedback by tenant
-- + dimension to compute the FP rate per dimension.
CREATE INDEX IF NOT EXISTS alert_feedback_dimension_idx
    ON alert_feedback (tenant_id, alert_id, created_at DESC);

-- ---- RLS -----------------------------------------------------

ALTER TABLE alerts              ENABLE ROW LEVEL SECURITY;
ALTER TABLE alerts              FORCE ROW LEVEL SECURITY;
ALTER TABLE alert_suppressions  ENABLE ROW LEVEL SECURITY;
ALTER TABLE alert_suppressions  FORCE ROW LEVEL SECURITY;
ALTER TABLE alert_feedback      ENABLE ROW LEVEL SECURITY;
ALTER TABLE alert_feedback      FORCE ROW LEVEL SECURITY;

CREATE POLICY alerts_tenant_isolation ON alerts
    USING (tenant_id = NULLIF(current_setting('sng.tenant_id', true), '')::uuid);
CREATE POLICY alert_suppressions_tenant_isolation ON alert_suppressions
    USING (tenant_id = NULLIF(current_setting('sng.tenant_id', true), '')::uuid);
CREATE POLICY alert_feedback_tenant_isolation ON alert_feedback
    USING (tenant_id = NULLIF(current_setting('sng.tenant_id', true), '')::uuid);

COMMENT ON TABLE alerts IS
    'Operator-facing alerts produced by the baseline.Detector and other sources, with self-explaining statistical context.';
COMMENT ON TABLE alert_suppressions IS
    'Per-tenant suppression rules — match by kind and/or dimension, with required reason for audit.';
COMMENT ON TABLE alert_feedback IS
    'Operator feedback on alert quality, feeding the alert.Feedback tuning loop.';
