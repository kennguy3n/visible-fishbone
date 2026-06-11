-- Migration 059: cross-region tenant migration state machine (WS11).
--
-- Moving a tenant from one data-residency region to another is a
-- multi-step, long-running operation that touches several independent
-- planes — the tenant's customer-managed key envelopes (DEK re-wrap),
-- the ClickHouse telemetry partitions, the S3 cold-archive prefix, the
-- Cloud PoP assignment, and finally the tenant's own `region` column.
-- Any of those steps can fail or be interrupted (a control-plane
-- restart, a transient KMS/S3/ClickHouse error), so the migration must
-- be RESUMABLE and ROLLBACK-able rather than fire-and-forget.
--
-- This table is the durable state machine that makes that possible. It
-- records, per migration, the source/target region, the current state,
-- a per-step checkpoint (so a resumed run knows which steps already
-- completed and a rollback knows which to undo), and the dual-read flag
-- the read paths consult so no tenant traffic is dropped while data is
-- in flight between regions.
--
-- States (see internal/service/tenant.MigrationState):
--   * pending            — created, not yet started.
--   * rewrapping_keys     \
--   * copying_telemetry    | the forward data-movement steps, run in
--   * copying_objects      | this exact order. The tenant's region
--   * reassigning_pop      | column is NOT changed until the final
--   * updating_region     /  step, so reads keep resolving the source
--                            region for the whole window.
--   * completed          — all steps done; dual_read cleared.
--   * rolling_back       — a step failed; completed steps are being
--                          undone in reverse order.
--   * rolled_back        — rollback finished; tenant is back on the
--                          source region exactly as before.
--   * failed             — rollback itself could not complete; the
--                          migration needs operator intervention. This
--                          is the only state that is terminal-with-error.
--
-- Tenant-scoped under the same `sng.tenant_id` RLS GUC as every other
-- tenant table, PLUS the system-role escape hatch every cross-tenant
-- background worker uses (the resumable migration runner drives the
-- state machine without a per-request tenant context, exactly like the
-- PoP rebalancer in migration 038). One tenant can never read another
-- tenant's migration history.
--
-- Lock safety: CREATE TABLE on a brand-new (empty) table takes no
-- table-rewrite lock, and every index below is created on the same
-- empty table in the same transaction (the migration runner wraps each
-- file in a transaction), so no CONCURRENTLY step is needed.

CREATE TABLE IF NOT EXISTS tenant_migrations (
    id              UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id       UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    -- The region the tenant's data lived in when the migration was
    -- requested. Snapshotted at creation so a concurrent edit to
    -- tenants.region cannot corrupt an in-flight migration's notion of
    -- where it is copying FROM.
    source_region   TEXT        NOT NULL CHECK (source_region <> ''),
    -- The region the tenant is being moved TO. Must differ from
    -- source_region (a no-op migration is rejected at the service
    -- layer; the CHECK here is the database backstop).
    target_region   TEXT        NOT NULL CHECK (target_region <> ''),
    CONSTRAINT tenant_migrations_distinct_regions
        CHECK (source_region <> target_region),
    state           TEXT        NOT NULL DEFAULT 'pending' CHECK (state IN (
                        'pending',
                        'rewrapping_keys',
                        'copying_telemetry',
                        'copying_objects',
                        'reassigning_pop',
                        'updating_region',
                        'completed',
                        'rolling_back',
                        'rolled_back',
                        'failed')),
    -- While TRUE, read paths for this tenant must consult BOTH the
    -- source and target regions (dual-read) so an in-flight copy never
    -- hides data that has already moved or not-yet-moved. Set TRUE when
    -- the migration starts and cleared only on a terminal state.
    dual_read       BOOLEAN     NOT NULL DEFAULT FALSE,
    -- Per-step resumable checkpoint. Maps each step name to its status
    -- ("done"/"skipped"/"rolled_back") plus any metadata the step needs
    -- to roll itself back or to prove idempotency on resume (e.g. the
    -- count of objects copied, the previous PoP id). Opaque to SQL;
    -- owned by internal/service/tenant.RegionMigrator.
    checkpoint      JSONB       NOT NULL DEFAULT '{}'::jsonb,
    -- Human-readable detail for the current state — the failure reason
    -- when state is failed/rolling_back, empty otherwise.
    detail          TEXT        NOT NULL DEFAULT '',
    -- Monotonic attempt counter, bumped each time the runner (re)starts
    -- the forward pipeline. Lets an operator see a migration that is
    -- thrashing on a transient error.
    attempts        INTEGER     NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- When the forward pipeline first started, and when it reached a
    -- terminal state. NULL until those transitions happen.
    started_at      TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ
);

-- At most ONE in-flight (non-terminal) migration per tenant. Two
-- concurrent cross-region migrations for the same tenant would race on
-- every plane (re-wrap, partition copy, region column) and corrupt the
-- result, so the invariant is enforced in the database, not just the
-- service layer. Terminal rows (completed/rolled_back/failed) are
-- excluded so a tenant can be migrated again later (or retried after a
-- rolled_back attempt).
CREATE UNIQUE INDEX uq_tenant_migrations_active
    ON tenant_migrations (tenant_id)
    WHERE state NOT IN ('completed', 'rolled_back', 'failed');

-- The resumable runner scans for migrations that are mid-flight (not
-- terminal) to pick up where a crashed/restarted control plane left
-- off. Partial index keeps that scan O(in-flight) rather than O(all
-- migrations ever run).
CREATE INDEX idx_tenant_migrations_resumable
    ON tenant_migrations (state, updated_at)
    WHERE state NOT IN ('completed', 'rolled_back', 'failed');

-- Per-tenant history lookups (the status endpoint, audit) order newest
-- first.
CREATE INDEX idx_tenant_migrations_tenant_created
    ON tenant_migrations (tenant_id, created_at DESC);

CREATE TRIGGER tenant_migrations_set_updated_at
    BEFORE UPDATE ON tenant_migrations
    FOR EACH ROW EXECUTE FUNCTION sng_set_updated_at();

-- ENABLE applies RLS to the runtime app role; FORCE extends it to the
-- table owner too, so even the migration/owner credentials cannot
-- bypass tenant isolation. Both are the documented standard for
-- tenant-scoped tables (see migrations 002, 037, 038, 046).
ALTER TABLE tenant_migrations ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_migrations FORCE ROW LEVEL SECURITY;

-- Tenant-scoped policy: a request bound to sng.tenant_id sees only its
-- own migrations.
CREATE POLICY tenant_migrations_tenant_isolation ON tenant_migrations
    USING (tenant_id = NULLIF(current_setting('sng.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('sng.tenant_id', true), '')::uuid);

-- System policy: the cross-tenant migration runner (sng.system_role
-- ='true') may read/write across tenants to drive and resume the state
-- machine, mirroring the PoP rebalancer's access in migration 038.
CREATE POLICY tenant_migrations_system ON tenant_migrations
    USING (current_setting('sng.system_role', true) = 'true')
    WITH CHECK (current_setting('sng.system_role', true) = 'true');
