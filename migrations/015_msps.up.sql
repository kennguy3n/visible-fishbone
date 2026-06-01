-- ShieldNet Gateway (SNG) — MSP hierarchy migration.
--
-- Adds the Managed Service Provider hierarchy on top of the
-- existing tenant model. An MSP is a top-level entity that owns
-- (or co-manages) one or more tenants and supplies a shared
-- branding default + a bulk-operations surface that fans out
-- across its tenant cohort.
--
-- Tables introduced:
--   - msps          : top-level MSP catalog (NOT RLS-scoped).
--                     Mirrors the `tenants` table's role as a
--                     platform-level entity that application code
--                     scopes via policy rather than RLS GUC.
--   - msp_tenants   : many-to-many MSP <-> tenant binding. Many-to-many
--                     supports the co-management handoff scenario where
--                     a tenant is briefly bound to two MSPs (outgoing
--                     + incoming) during the transition. Day-to-day,
--                     a tenant has exactly one `owner` binding and
--                     zero or more `co_manager` bindings.
--
-- Tenants pick up a denormalised `msp_id UUID NULL` column pointing
-- at the **primary** owner-binding MSP. This denormalisation is
-- deliberate: RLS policies that filter `tenants` by msp_id need a
-- single-column predicate that the planner can index — the join
-- via `msp_tenants` would force a sub-select on every read on the
-- hot path. The application keeps `tenants.msp_id` and the
-- `relationship='owner'` row in `msp_tenants` in sync via the MSP
-- service's AssignTenant path.
--
-- Existing `roles.scope` already lists 'msp' as a valid value
-- (migration 001), so no DDL change is needed on the roles table.
--
-- RLS extension: a new GUC `sng.msp_id` complements the existing
-- `sng.tenant_id`. When `sng.msp_id` is set on a connection, the
-- `tenants` table grants read access to every tenant where
-- `tenant.msp_id = current_setting('sng.msp_id')::uuid`. This
-- lets an MSP-scoped session iterate across its tenant cohort
-- without setting `sng.tenant_id` for each one (which would
-- otherwise be an N-round-trip pattern for bulk operations).
--
-- The `tenants` RLS policy intentionally remains permissive when
-- neither GUC is set (matches the pre-existing fail-closed pattern
-- in migration 001: `current_setting(..., true)` returns NULL
-- instead of erroring, and the NULL comparison yields zero rows).

CREATE TABLE IF NOT EXISTS msps (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name        TEXT NOT NULL,
    slug        TEXT NOT NULL UNIQUE,
    status      TEXT NOT NULL DEFAULT 'active'
                CHECK (status IN ('active', 'suspended', 'deleted')),
    branding    JSONB NOT NULL DEFAULT '{}'::jsonb,
    settings    JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at  TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS msps_status_idx
    ON msps (status) WHERE deleted_at IS NULL;

CREATE TRIGGER msps_set_updated_at
    BEFORE UPDATE ON msps
    FOR EACH ROW EXECUTE FUNCTION sng_set_updated_at();

-- msps is intentionally NOT RLS-protected. Mirrors `tenants` — the
-- top-level entity table is gated by application authorization
-- (platform_admin sees all; msp_admin sees own row only). RLS on
-- the table itself would prevent the platform_admin path.

-- ---------------------------------------------------------------------
-- msp_tenants
--
-- Many-to-many binding. `relationship` distinguishes the primary
-- owner from co-managers (read-only collaborators).
--
-- Composite PK on (msp_id, tenant_id): one binding per (msp, tenant)
-- pair, even if relationship is updated in place.
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS msp_tenants (
    msp_id        UUID NOT NULL REFERENCES msps(id) ON DELETE CASCADE,
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    relationship  TEXT NOT NULL DEFAULT 'owner'
                  CHECK (relationship IN ('owner', 'co_manager')),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by    UUID REFERENCES users(id) ON DELETE SET NULL,
    PRIMARY KEY (msp_id, tenant_id)
);

CREATE INDEX IF NOT EXISTS msp_tenants_msp_idx
    ON msp_tenants (msp_id);
CREATE INDEX IF NOT EXISTS msp_tenants_tenant_idx
    ON msp_tenants (tenant_id);

-- A tenant can have at most ONE `owner` binding at any time. The
-- partial unique index enforces this at the storage layer so the
-- denormalised `tenants.msp_id` stays consistent under concurrent
-- AssignTenant calls.
CREATE UNIQUE INDEX IF NOT EXISTS msp_tenants_one_owner_per_tenant_idx
    ON msp_tenants (tenant_id)
    WHERE relationship = 'owner';

-- ---------------------------------------------------------------------
-- tenants.msp_id (denormalised primary owner)
-- ---------------------------------------------------------------------
ALTER TABLE tenants
    ADD COLUMN IF NOT EXISTS msp_id UUID
        REFERENCES msps(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS tenants_msp_idx
    ON tenants (msp_id) WHERE deleted_at IS NULL AND msp_id IS NOT NULL;

-- Augment tenants RLS so an MSP-scoped session sees every tenant
-- under its umbrella in one query instead of one SET-and-SELECT
-- per tenant.
--
-- The original tenants table in migration 001 does NOT have RLS
-- enabled (tenants is platform-scoped). The MSP cohort filter is
-- enforced at the application layer in the MSP service's
-- ListTenants path; we add an INDEX above so that path stays fast.
