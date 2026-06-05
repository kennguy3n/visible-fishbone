-- ShieldNet Gateway (SNG) — Sandbox verdicts migration.
--
-- Backs zero-day file analysis (Gap #7). When the SWG malware
-- stage (crates/sng-swg/src/malware.rs) sees a file whose SHA-256
-- it has no static verdict for, the control plane
-- (internal/service/sandbox) submits the file to a detonation
-- sandbox (Cuckoo / CAPEv2 / BYO webhook) and records the verdict
-- here, keyed by digest, so the same bytes are detonated at most
-- once across the fleet.
--
-- Adds one table:
--   - sandbox_verdicts : per-tenant detonation verdicts keyed by
--     file SHA-256.
--
-- RLS-scoped to `sng.tenant_id`, matching every other
-- tenant-scoped table.

CREATE TABLE IF NOT EXISTS sandbox_verdicts (
    id             UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id      UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    -- Lowercase hex SHA-256 of the analysed file. Unique per tenant
    -- so a re-submission upserts the existing row in place.
    sha256         TEXT        NOT NULL
                   CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    -- Disposition. 'unknown' only appears transiently while a
    -- submission is pending; a resolved row carries a real verdict.
    classification TEXT        NOT NULL DEFAULT 'unknown'
                   CHECK (classification IN
                       ('unknown', 'clean', 'suspicious', 'malicious', 'timeout')),
    -- Provider confidence in [0,1].
    confidence     DOUBLE PRECISION NOT NULL DEFAULT 0
                   CHECK (confidence >= 0 AND confidence <= 1),
    -- Provider id that produced the verdict ('cuckoo', 'cape',
    -- 'generic'). Free TEXT so a new provider needs no migration.
    provider       TEXT        NOT NULL DEFAULT '',
    -- Provider-side analysis id, retained so an operator can pull
    -- the full report from the sandbox UI. Empty until submitted.
    sandbox_id     TEXT        NOT NULL DEFAULT '',
    -- Short human-readable summary of the dominant signal.
    summary        TEXT        NOT NULL DEFAULT '',
    -- Submission lifecycle: pending | complete | error.
    status         TEXT        NOT NULL DEFAULT 'pending'
                   CHECK (status IN ('pending', 'complete', 'error')),
    -- When the provider finished analysis; NULL while pending.
    analyzed_at    TIMESTAMPTZ,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE (tenant_id, sha256)
);

-- Hot-path lookup: "do we already have a verdict for this digest?"
-- The UNIQUE constraint above already creates a (tenant_id, sha256)
-- index, so no extra lookup index is needed. This index serves the
-- verdict-list endpoint (most-recent first).
CREATE INDEX IF NOT EXISTS idx_sandbox_verdicts_tenant_created
    ON sandbox_verdicts (tenant_id, created_at DESC);

CREATE TRIGGER sandbox_verdicts_set_updated_at
    BEFORE UPDATE ON sandbox_verdicts
    FOR EACH ROW EXECUTE FUNCTION sng_set_updated_at();

ALTER TABLE sandbox_verdicts ENABLE ROW LEVEL SECURITY;
ALTER TABLE sandbox_verdicts FORCE ROW LEVEL SECURITY;

CREATE POLICY sandbox_verdicts_tenant_isolation ON sandbox_verdicts
    USING (tenant_id = NULLIF(current_setting('sng.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('sng.tenant_id', true), '')::uuid);
