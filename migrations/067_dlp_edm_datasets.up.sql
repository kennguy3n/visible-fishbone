-- 067_dlp_edm_datasets
--
-- Exact-Data-Match (EDM) storage for the DLP engine. An operator
-- registers a sensitive dataset (e.g. a customer-PII table) and the
-- endpoint classifier fires an `edm` rule when inspected content
-- contains any registered record. See crates/sng-dlp/src/edm.rs for the
-- matcher and wire format.
--
-- PLAINTEXT IS NEVER STORED. The honesty/privacy contract for the 5,000
-- SME tenants this serves is structural, not advisory:
--   * Each registered record is normalised (NFKC, case-folded,
--     punctuation-trimmed tokens) and hashed with HMAC-SHA256 under a
--     per-dataset random salt at registration time; the transient
--     normalised plaintext buffer is zeroized the instant it is hashed
--     (crates/sng-dlp/src/edm.rs::EdmDataset::register).
--   * This schema has NO column that holds a record value — only the
--     32-byte `salt` (a cryptographically-random value, NOT derived from
--     and revealing nothing about any record) and the 32-byte
--     HMAC-SHA256 `digest`s. A digest is a one-way function of a salted
--     record; the salt is required to test membership, so a leaked
--     dataset still cannot be brute-forced without it.
--   * Matching is membership-only: a hit reveals that some registered
--     record was present, never which bytes or where.
--
-- Two tables, normalised so a tenant's dataset can hold an unbounded
-- number of records without a wide row:
--   - dlp_edm_datasets : one row per (tenant, dataset key) — the salt,
--                        the token-window lengths present in the dataset,
--                        and operator metadata.
--   - dlp_edm_digests  : one row per salted record digest, owned by a
--                        dataset (ON DELETE CASCADE).
--
-- Lock safety: every statement below operates on a table CREATE'd
-- earlier in this same migration, so each table is brand-new and empty.
-- A CREATE INDEX on such a table takes no meaningful lock (the table is
-- invisible to other sessions until this migration commits) and is
-- exempt from the CONCURRENTLY rule — see internal/migrate/validator.go.

-- dlp_edm_datasets ------------------------------------------------------

CREATE TABLE IF NOT EXISTS dlp_edm_datasets (
    id           UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    -- Owning tenant. ON DELETE CASCADE so a deleted tenant's datasets
    -- (and, transitively, their digests) go with it.
    tenant_id    UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    -- Operator-chosen stable key referenced by an `edm` rule's
    -- `pattern_data` in the policy bundle. Unique per tenant.
    dataset_key  TEXT        NOT NULL CHECK (dataset_key <> ''),
    -- Human-readable label for the operator console. Not security
    -- relevant; never a record value.
    name         TEXT        NOT NULL DEFAULT '',
    -- Per-dataset cryptographically-random salt mixed into every
    -- HMAC-SHA256 digest. Random, NOT derived from any record, so it
    -- leaks nothing about the dataset; required to test membership.
    salt         BYTEA       NOT NULL CHECK (octet_length(salt) = 32),
    -- The distinct token-window lengths (1..=10) present in the dataset.
    -- The matcher only slides windows of these lengths, keeping
    -- detection linear in the content size. Stored so the bundle builder
    -- need not re-derive it.
    window_sizes SMALLINT[]  NOT NULL DEFAULT '{}',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- One dataset per (tenant, key). The unique index this builds leads
    -- with tenant_id, so it also serves the "list a tenant's datasets"
    -- access path — no separate tenant index is needed.
    UNIQUE (tenant_id, dataset_key)
);

CREATE TRIGGER dlp_edm_datasets_set_updated_at
    BEFORE UPDATE ON dlp_edm_datasets
    FOR EACH ROW EXECUTE FUNCTION sng_set_updated_at();

-- ENABLE applies RLS to the runtime app role; FORCE extends it to the
-- table owner too, so even the migration/owner credentials cannot
-- bypass tenant isolation (the documented standard for tenant-scoped
-- tables — see migrations 002, 037, 038, 059, 066).
ALTER TABLE dlp_edm_datasets ENABLE ROW LEVEL SECURITY;
ALTER TABLE dlp_edm_datasets FORCE ROW LEVEL SECURITY;

-- Tenant-scoped policy: a request bound to sng.tenant_id sees only its
-- own datasets.
CREATE POLICY dlp_edm_datasets_tenant_isolation ON dlp_edm_datasets
    USING (tenant_id = NULLIF(current_setting('sng.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('sng.tenant_id', true), '')::uuid);

-- System policy: a cross-tenant background job (sng.system_role='true')
-- — e.g. the bundle builder that ships datasets to endpoints — may read
-- every tenant's datasets, mirroring the cross-tenant background access
-- in migrations 038/059/066.
CREATE POLICY dlp_edm_datasets_system ON dlp_edm_datasets
    USING (current_setting('sng.system_role', true) = 'true')
    WITH CHECK (current_setting('sng.system_role', true) = 'true');

-- dlp_edm_digests -------------------------------------------------------

CREATE TABLE IF NOT EXISTS dlp_edm_digests (
    -- Owning dataset. ON DELETE CASCADE so re-registering or deleting a
    -- dataset cleanly replaces its digest set.
    dataset_id UUID  NOT NULL REFERENCES dlp_edm_datasets(id) ON DELETE CASCADE,
    -- Denormalised tenant_id so this table carries its own RLS predicate
    -- (RLS is per-table; a policy cannot reach through the FK). Kept
    -- consistent with the parent via the same-tenant CASCADE delete.
    tenant_id  UUID  NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    -- One salted HMAC-SHA256 digest of a normalised record window. This
    -- is the ONLY representation of a record that exists anywhere; the
    -- plaintext was zeroized at registration.
    digest     BYTEA NOT NULL CHECK (octet_length(digest) = 32),
    -- (dataset_id, digest) is the natural key: it dedupes identical
    -- records within a dataset and the leading dataset_id serves the hot
    -- path — "load every digest for this dataset" when compiling the
    -- bundle — so no secondary index is needed.
    PRIMARY KEY (dataset_id, digest)
);

ALTER TABLE dlp_edm_digests ENABLE ROW LEVEL SECURITY;
ALTER TABLE dlp_edm_digests FORCE ROW LEVEL SECURITY;

CREATE POLICY dlp_edm_digests_tenant_isolation ON dlp_edm_digests
    USING (tenant_id = NULLIF(current_setting('sng.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('sng.tenant_id', true), '')::uuid);

CREATE POLICY dlp_edm_digests_system ON dlp_edm_digests
    USING (current_setting('sng.system_role', true) = 'true')
    WITH CHECK (current_setting('sng.system_role', true) = 'true');
