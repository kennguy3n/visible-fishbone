-- Migration 039: SOC2 Type II compliance evidence automation.
--
-- Adds the platform-level `compliance_evidence` table that tracks the
-- signed evidence bundles the SOC2 evidence collector produces
-- (internal/service/compliance/{soc2,evidence,scheduler}.go).
--
-- PLATFORM-LEVEL, NOT tenant-scoped: SOC2 Type II evidence attests to
-- the SNG *platform's own* controls (RBAC config, audit trail,
-- monitoring, availability), not any single tenant's data. There is
-- therefore no tenant_id column and deliberately NO row-level
-- security — the rows are only ever read/written by the platform
-- admin surface and the leader-only collector running under the
-- system role. Compare with `compliance_reports` (migration 023),
-- which IS per-tenant and RLS-scoped.
--
-- Each row records where the bundle lives (s3_key), when it was
-- collected (collected_at), and the Ed25519 signature over the bundle
-- bytes (signature, hex-encoded) so a verifier can prove the archived
-- bundle has not been tampered with. The bundle bytes themselves live
-- in S3 under a 7-year compliance-retention policy; this table is the
-- queryable index over them.

CREATE TABLE compliance_evidence (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    -- collection_type distinguishes the scheduler-driven weekly
    -- collections, the monthly audit-ready aggregations, and
    -- operator-triggered manual runs.
    collection_type TEXT        NOT NULL
        CONSTRAINT compliance_evidence_collection_type_chk
            CHECK (collection_type IN ('weekly', 'monthly', 'manual')),
    collected_at    TIMESTAMPTZ NOT NULL,
    -- s3_key is the object key the signed bundle was written to. It is
    -- unique: one stored object per evidence row.
    s3_key          TEXT        NOT NULL
        CONSTRAINT compliance_evidence_s3_key_unique UNIQUE,
    -- signature is the hex-encoded Ed25519 signature over the
    -- canonical bundle bytes.
    signature       TEXT        NOT NULL,
    status          TEXT        NOT NULL DEFAULT 'collected'
        CONSTRAINT compliance_evidence_status_chk
            CHECK (status IN ('collecting', 'collected', 'failed', 'aggregated')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- The list endpoint and the scheduler's gap-detection query both order
-- by collected_at DESC; index the sort key. A second composite index
-- supports "most recent collection of type X" lookups used by gap
-- detection and monthly aggregation.
CREATE INDEX idx_compliance_evidence_collected_at
    ON compliance_evidence (collected_at DESC);

CREATE INDEX idx_compliance_evidence_type_collected_at
    ON compliance_evidence (collection_type, collected_at DESC);
