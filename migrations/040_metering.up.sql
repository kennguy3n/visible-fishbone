-- ShieldNet Gateway (SNG) — Cost Metering & Budget Guardrails.
--
-- Session K. Models per-tenant resource consumption (LLM inference,
-- URL-categorisation / malware feed lookups, telemetry write
-- amplification, archive + proxied bandwidth) and the per-tenant
-- budget limits that gate it.
--
-- The control-plane metering service
-- (internal/service/metering/service.go) keeps `sync/atomic`
-- counters on the hot path and flushes accumulated deltas into
-- `tenant_usage` every 60s via a single batch upsert; the
-- BudgetEnforcer (internal/service/metering/budget.go) reads
-- `tenant_budgets` to decide whether an operation is within its
-- soft / hard limit.
--
-- Adds two tables:
--   - tenant_usage   : per-tenant, per-meter consumption bucketed
--                      by billing period (one row per
--                      tenant+meter+period_start).
--   - tenant_budgets : per-tenant soft / hard limit overrides per
--                      meter. Tier defaults live in application
--                      config; only explicit overrides are stored.
--
-- Both are RLS-scoped to `sng.tenant_id`, matching every other
-- tenant-scoped table, with a `sng.system_role='true'` bypass so
-- the cross-tenant flush worker and the MSP/admin platform-wide
-- cost report can read / write every tenant's rows. The system
-- role is a GUC the application sets only on background / admin
-- transactions — it is not a DB role grant, so per-request
-- handlers remain strictly tenant-isolated.

CREATE TABLE IF NOT EXISTS tenant_usage (
    id           UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id    UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    -- Canonical meter name, e.g. 'llm_tokens_used', 'llm_calls',
    -- 'url_cat_lookups', 'malware_scans', 'clickhouse_rows_written',
    -- 's3_bytes_archived', 'bandwidth_proxied_bytes'. Kept as free
    -- TEXT (not a CHECK enum) so new meters do not require a schema
    -- migration; the service layer validates against the known-meter
    -- set in internal/service/metering.
    meter        TEXT        NOT NULL,
    -- Inclusive period_start / exclusive period_end bounds for the
    -- billing bucket this row accumulates. Daily meters use a
    -- one-day window; monthly meters use a calendar-month window.
    period_start DATE        NOT NULL,
    period_end   DATE        NOT NULL,
    -- Monotonic accumulated consumption for the period. bigint so a
    -- high-volume meter (bandwidth bytes) cannot overflow.
    value        BIGINT      NOT NULL DEFAULT 0 CHECK (value >= 0),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- One row per (tenant, meter, period). The flush worker relies
    -- on this to upsert deltas with
    -- `ON CONFLICT (tenant_id, meter, period_start) DO UPDATE
    --  SET value = tenant_usage.value + EXCLUDED.value`.
    CONSTRAINT tenant_usage_unique_period UNIQUE (tenant_id, meter, period_start)
);

-- Hot-path read: "current-period usage for a tenant" and the
-- monthly-history aggregation both scan by tenant then period.
CREATE INDEX IF NOT EXISTS idx_tenant_usage_tenant_period
    ON tenant_usage (tenant_id, period_start DESC);
-- Platform-wide cost report aggregates every tenant's rows for a
-- period; index the period so the cross-tenant scan is bounded.
CREATE INDEX IF NOT EXISTS idx_tenant_usage_period
    ON tenant_usage (period_start, meter);

CREATE TRIGGER tenant_usage_set_updated_at
    BEFORE UPDATE ON tenant_usage
    FOR EACH ROW EXECUTE FUNCTION sng_set_updated_at();

ALTER TABLE tenant_usage ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_usage FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_usage_tenant_isolation ON tenant_usage
    USING (
        tenant_id = NULLIF(current_setting('sng.tenant_id', true), '')::uuid
        OR NULLIF(current_setting('sng.system_role', true), '') = 'true'
    )
    WITH CHECK (
        tenant_id = NULLIF(current_setting('sng.tenant_id', true), '')::uuid
        OR NULLIF(current_setting('sng.system_role', true), '') = 'true'
    );

CREATE TABLE IF NOT EXISTS tenant_budgets (
    id          UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id   UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    meter       TEXT        NOT NULL,
    -- soft_limit: log + alert when exceeded but allow the operation.
    -- hard_limit: reject the operation (429 budget_exceeded). A NULL
    -- or non-positive value means "unbounded" for that side, letting
    -- an operator set only a soft alert without a hard cap.
    soft_limit  BIGINT      NOT NULL DEFAULT 0 CHECK (soft_limit >= 0),
    hard_limit  BIGINT      NOT NULL DEFAULT 0 CHECK (hard_limit >= 0),
    -- Budget reset cadence: 'daily' or 'monthly'.
    period      TEXT        NOT NULL DEFAULT 'monthly'
                CHECK (period IN ('daily', 'monthly')),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT tenant_budgets_unique_meter UNIQUE (tenant_id, meter)
);

CREATE INDEX IF NOT EXISTS idx_tenant_budgets_tenant
    ON tenant_budgets (tenant_id);

CREATE TRIGGER tenant_budgets_set_updated_at
    BEFORE UPDATE ON tenant_budgets
    FOR EACH ROW EXECUTE FUNCTION sng_set_updated_at();

ALTER TABLE tenant_budgets ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_budgets FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_budgets_tenant_isolation ON tenant_budgets
    USING (
        tenant_id = NULLIF(current_setting('sng.tenant_id', true), '')::uuid
        OR NULLIF(current_setting('sng.system_role', true), '') = 'true'
    )
    WITH CHECK (
        tenant_id = NULLIF(current_setting('sng.tenant_id', true), '')::uuid
        OR NULLIF(current_setting('sng.system_role', true), '') = 'true'
    );
