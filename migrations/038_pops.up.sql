-- Migration 038: Cloud PoP (Point-of-Presence) service. Backs
-- Session F's cloud-delivered SWG/DNS/ZTNA edge for tenants without
-- an on-premise edge VM.
--
-- A PoP is a shared, multi-tenant deployment of the `sng-edge`
-- binary running in a cloud region. The control plane keeps a
-- registry of PoP locations, ingests their health beacons, and
-- routes cloud-only tenants to their nearest healthy PoP. Three
-- tables model that:
--
--   * pops                    — GLOBAL registry of PoP locations.
--                               A PoP is shared infrastructure, not
--                               owned by any one tenant, so it has
--                               NO tenant_id and NO RLS (mirrors the
--                               `tenants` table in migration 001,
--                               which is likewise un-scoped). The
--                               public `GET /api/v1/pops` bootstrap
--                               endpoint reads this table.
--   * pop_health              — append-only time-series of health
--                               beacons (one row per heartbeat).
--                               Also global: it describes shared
--                               infrastructure, not tenant data, so
--                               no RLS. Cross-tenant flow data NEVER
--                               lands here — only PoP-level resource
--                               counters.
--   * tenant_pop_assignments  — which PoP serves each cloud-only
--                               tenant. This IS tenant data, so it
--                               carries tenant_id and is RLS-scoped
--                               on the `sng.tenant_id` GUC exactly
--                               like every other tenant-scoped
--                               table (see migration 036).

-- ---------------------------------------------------------------------
-- pops — global PoP registry.
--
-- provider / capacity_tier are constrained to the closed sets the
-- control plane + edge understand. anycast_ip is the address clients
-- steer to (returned by the GeoDNS zone); dns_name is the per-PoP
-- hostname operators can target directly. `enabled` gates a PoP out
-- of auto-assignment without deleting its history.
-- ---------------------------------------------------------------------
CREATE TABLE pops (
    id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    region        TEXT        NOT NULL,
    provider      TEXT        NOT NULL CHECK (provider IN ('aws', 'gcp', 'azure')),
    anycast_ip    INET        NOT NULL,
    dns_name      TEXT        NOT NULL,
    capacity_tier TEXT        NOT NULL CHECK (capacity_tier IN ('small', 'medium', 'large')),
    enabled       BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- One PoP per region+provider pair: the operator addresses a PoP by
-- "the aws us-east-1 PoP", so that tuple must be unique.
CREATE UNIQUE INDEX uq_pops_region_provider ON pops (region, provider);

-- dns_name is the externally-resolvable handle clients enrol against;
-- it must be globally unique across the fleet.
CREATE UNIQUE INDEX uq_pops_dns_name ON pops (dns_name);

-- Hot path for AssignPoP / the public bootstrap list: only enabled
-- PoPs are candidates, so index them partially.
CREATE INDEX idx_pops_enabled ON pops (region) WHERE enabled;

CREATE TRIGGER pops_set_updated_at
    BEFORE UPDATE ON pops
    FOR EACH ROW EXECUTE FUNCTION sng_set_updated_at();

-- ---------------------------------------------------------------------
-- pop_health — append-only health beacons.
--
-- Health updates arrive over NATS (`sng.pop.{pop_id}.health`) and the
-- control plane persists each beacon so the admin health view and the
-- assignment logic can reason about recent load. Global (no RLS): the
-- counters describe shared infra capacity, never tenant traffic.
-- ON DELETE CASCADE so de-provisioning a PoP removes its history.
-- ---------------------------------------------------------------------
CREATE TABLE pop_health (
    pop_id             UUID        NOT NULL REFERENCES pops(id) ON DELETE CASCADE,
    reported_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    cpu_pct            REAL        NOT NULL CHECK (cpu_pct >= 0 AND cpu_pct <= 100),
    memory_pct         REAL        NOT NULL CHECK (memory_pct >= 0 AND memory_pct <= 100),
    active_connections INTEGER     NOT NULL CHECK (active_connections >= 0),
    bandwidth_mbps     REAL        NOT NULL CHECK (bandwidth_mbps >= 0),
    PRIMARY KEY (pop_id, reported_at)
);

-- Latest-beacon-per-PoP lookups order by reported_at descending.
CREATE INDEX idx_pop_health_pop_reported ON pop_health (pop_id, reported_at DESC);

-- ---------------------------------------------------------------------
-- tenant_pop_assignments — which PoP serves a cloud-only tenant.
--
-- Exactly one assignment per tenant (PRIMARY KEY on tenant_id): a
-- tenant is steered to a single home PoP at a time. `override` marks
-- an operator-pinned assignment so the auto-rebalancer leaves it
-- alone. Tenant-scoped → RLS on sng.tenant_id, with the standard
-- system-role escape hatch for cross-tenant background jobs (the
-- rebalancer), mirroring migration 036.
-- ---------------------------------------------------------------------
CREATE TABLE tenant_pop_assignments (
    tenant_id   UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    pop_id      UUID        NOT NULL REFERENCES pops(id) ON DELETE CASCADE,
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    override    BOOLEAN     NOT NULL DEFAULT FALSE,
    PRIMARY KEY (tenant_id)
);

-- Reverse lookup: "which tenants does this PoP serve?" — used by the
-- capacity rebalancer when a PoP signals it is overloaded.
CREATE INDEX idx_tenant_pop_assignments_pop ON tenant_pop_assignments (pop_id);

-- ENABLE applies RLS to the runtime app role; FORCE extends it to
-- the table owner too, so even a connection using the migration /
-- owner credentials cannot bypass tenant isolation. Both are the
-- documented standard for tenant-scoped tables (see migration 002
-- and 037_inline_casb).
ALTER TABLE tenant_pop_assignments ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_pop_assignments FORCE ROW LEVEL SECURITY;

-- Tenant-scoped policy: a request bound to sng.tenant_id sees only
-- its own assignment. Mirrors every other tenant-scoped table.
CREATE POLICY tenant_pop_assignments_tenant ON tenant_pop_assignments
    USING (tenant_id::text = current_setting('sng.tenant_id', true))
    WITH CHECK (tenant_id::text = current_setting('sng.tenant_id', true));

-- System policy: background workers / cross-tenant jobs (the
-- capacity rebalancer, the auto-assigner) that set
-- sng.system_role='true' may read/write across tenants.
CREATE POLICY tenant_pop_assignments_system ON tenant_pop_assignments
    USING (current_setting('sng.system_role', true) = 'true')
    WITH CHECK (current_setting('sng.system_role', true) = 'true');
