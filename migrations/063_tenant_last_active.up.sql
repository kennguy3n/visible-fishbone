-- 063_tenant_last_active
--
-- Phase 1 dormancy: give the tenant catalog a first-class activity
-- signal so periodic control-plane sweeps can visit dormant trials at
-- a reduced cadence instead of doing O(5000) work every cycle.
--
-- `tenants.status` only distinguishes active|suspended|deleted — a
-- busy enterprise and a months-idle trial are both 'active', so every
-- per-tenant sweep (e.g. internal/service/identity/idp_sync.go) treats
-- them identically. With ~5000 SME tenants, most of which are dormant
-- trials, that uniform fan-out is the dominant avoidable control-plane
-- cost. last_active_at lets a sweep planner bucket tenants by recency
-- and skip the dormant majority on most cycles.
--
-- last_active_at is advanced forward-only (and debounced) from the
-- data-plane "tenant was seen" path. NULL means never seen.

ALTER TABLE tenants
    ADD COLUMN IF NOT EXISTS last_active_at TIMESTAMPTZ;

-- Enumeration index for activity-tiered sweep planning: the planner
-- reads (id, last_active_at) for every live tenant once per cycle and
-- buckets them by recency. Partial on the live set, matching the
-- existing tenants_status_idx / tenants_tier_idx convention.
CREATE INDEX IF NOT EXISTS tenants_last_active_idx
    ON tenants (last_active_at)
    WHERE deleted_at IS NULL;

-- updated_at must keep tracking *configuration/state* changes (caches,
-- audit, and optimistic reads rely on it), so a high-rate activity
-- touch that only advances last_active_at must NOT churn it. The
-- generic sng_set_updated_at() trigger bumps updated_at on every
-- UPDATE; swap the tenants trigger for a tenants-specific function
-- that skips the bump when last_active_at is the only column changed.
--
-- The OLD-row masking trick (copy NEW.last_active_at onto a copy of
-- OLD, then compare whole rows) keeps this future-proof: any other
-- column change — including columns added by later migrations — still
-- bumps updated_at, because only last_active_at is equalised before
-- the comparison.
CREATE OR REPLACE FUNCTION sng_tenants_set_updated_at()
RETURNS TRIGGER AS $$
DECLARE
    old_masked tenants%ROWTYPE := OLD;
BEGIN
    old_masked.last_active_at := NEW.last_active_at;
    IF NEW IS DISTINCT FROM old_masked THEN
        NEW.updated_at = NOW();
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS tenants_set_updated_at ON tenants;
CREATE TRIGGER tenants_set_updated_at
    BEFORE UPDATE ON tenants
    FOR EACH ROW EXECUTE FUNCTION sng_tenants_set_updated_at();
