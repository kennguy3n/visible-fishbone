-- Migration 046: data-residency enforcement audit trail (Session 2C).
--
-- A tenant's designated data-residency region is its existing
-- `tenants.region` (migration 001). Enforcement is fail-closed in the
-- control plane: a telemetry / policy-bundle / cold-storage write whose
-- target region differs from (or cannot be proven to match) the
-- tenant's designated region is REJECTED. This table is the durable,
-- auditor-queryable record of those rejections — the evidence that
-- residency is actually enforced, not merely configured.
--
-- It is append-only in practice (the enforcer only ever INSERTs a row
-- when it denies a write) and tenant-scoped under the same
-- `sng.tenant_id` RLS GUC as every other tenant table, so one tenant
-- can never read another tenant's residency-violation history.
--
-- Lock safety: CREATE TABLE on a brand-new (empty) table takes no
-- table-rewrite lock. No secondary index is created: residency
-- rejections are rare (a misconfiguration signal, not steady-state
-- traffic), so the table stays small and tenant-scoped reads under RLS
-- are cheap on the primary key alone. Avoiding a secondary index also
-- keeps the migration lock-safe without a non-transactional CONCURRENTLY
-- step (the migration runner wraps each file in a transaction).

CREATE TABLE IF NOT EXISTS residency_audit (
    id                  UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id           UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    -- The data plane the rejected write targeted: one of the
    -- residency.Plane values (telemetry, policy_bundle, cold_storage).
    plane               TEXT        NOT NULL CHECK (plane IN ('telemetry', 'policy_bundle', 'cold_storage')),
    -- The tenant's designated residency region at decision time.
    designated_region   TEXT        NOT NULL CHECK (designated_region <> ''),
    -- The region the write would have landed in. May be empty when the
    -- target region could not be determined (which is itself a
    -- fail-closed rejection reason).
    attempted_region    TEXT        NOT NULL,
    -- Human-readable reason mirroring residency.Violation.Error().
    detail              TEXT        NOT NULL DEFAULT '',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE residency_audit ENABLE ROW LEVEL SECURITY;
ALTER TABLE residency_audit FORCE ROW LEVEL SECURITY;

CREATE POLICY residency_audit_tenant_isolation ON residency_audit
    USING (tenant_id = NULLIF(current_setting('sng.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('sng.tenant_id', true), '')::uuid);
