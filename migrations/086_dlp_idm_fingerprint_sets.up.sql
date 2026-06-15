-- 086_dlp_idm_fingerprint_sets
--
-- Durable backing for WP4 IDM (Indexed Document Matching). A tenant
-- registers a *protected document* (a contract template, a price book,
-- source code, a board deck) and the control plane stores only its
-- winnowed shingle fingerprints — never the raw document. The data
-- plane (crates/sng-dlp::idm) loads these fingerprints into an inverted
-- index and flags partial/derivative copies of the protected document
-- in inspected content above a configurable containment threshold.
--
-- Privacy contract: this table stores ONLY fingerprints (8-byte
-- big-endian SHA-256-derived shingle hashes) plus metadata. The raw
-- protected-document bytes are fingerprinted once at upload time and
-- discarded; they are never persisted. Losing this table loses only
-- derived fingerprints, which a tenant can re-upload.
--
-- `fingerprints` is the concatenation of `fingerprint_count` 8-byte
-- big-endian u64 hashes, mirroring the existing dlp_fingerprints.hash
-- BYTEA convention (migration 017). The CHECK ties the blob length to
-- the count so a truncated/garbled write cannot be stored. The Go
-- winnowing port and the Rust edge produce byte-identical fingerprint
-- sets (locked by a cross-language golden-vector test), so a set
-- uploaded via the control plane matches what the edge computes.
--
-- Lock safety: CREATE TABLE on a brand-new (empty) table takes no
-- table-rewrite lock; the listing index, trigger and RLS policies all
-- attach to that same empty table in the migration runner's
-- transaction, so no CONCURRENTLY step is needed (the migration-lint
-- validator exempts an index built on a table created earlier in the
-- same migration).

CREATE TABLE IF NOT EXISTS dlp_idm_fingerprint_sets (
    id                UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    -- Owning tenant. ON DELETE CASCADE so a deleted tenant's protected
    -- document fingerprints go with it.
    tenant_id         UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    -- Human label for the protected document set, unique per tenant so a
    -- caller can address a set by name. Non-empty.
    name              TEXT        NOT NULL CHECK (name <> ''),
    description       TEXT        NOT NULL DEFAULT '',
    -- Fingerprinting parameters the set was built with. Stored so the
    -- edge rebuilds the index with the SAME parameters that produced the
    -- fingerprints; bounded to keep per-document cost predictable across
    -- 5,000 tenants. Defaults mirror crates/sng-dlp::idm
    -- (shingle 5, window 8, cap 2048).
    shingle_size      INT         NOT NULL CHECK (shingle_size BETWEEN 1 AND 64),
    window_size       INT         NOT NULL CHECK (window_size BETWEEN 1 AND 256),
    max_fingerprints  INT         NOT NULL CHECK (max_fingerprints BETWEEN 1 AND 65536),
    -- Winnowed shingle fingerprints: fingerprint_count contiguous 8-byte
    -- big-endian u64 hashes. Never the raw document.
    fingerprints      BYTEA       NOT NULL,
    fingerprint_count INT         NOT NULL CHECK (fingerprint_count >= 0),
    -- Size in bytes of the source document that was fingerprinted, kept
    -- for capacity reporting only (the bytes themselves are discarded).
    source_bytes      BIGINT      NOT NULL DEFAULT 0 CHECK (source_bytes >= 0),
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Integrity: the blob is exactly fingerprint_count * 8 bytes.
    CONSTRAINT dlp_idm_fingerprint_sets_blob_len
        CHECK (octet_length(fingerprints) = fingerprint_count * 8),
    -- Cap the stored blob defensively (max_fingerprints * 8 ceiling).
    CONSTRAINT dlp_idm_fingerprint_sets_blob_cap
        CHECK (fingerprint_count <= max_fingerprints),
    -- Address a set by (tenant, name); also the conflict target for
    -- name-collision detection mapped to ErrConflict in the repository.
    CONSTRAINT dlp_idm_fingerprint_sets_tenant_name_uniq UNIQUE (tenant_id, name)
);

-- Keyset-pagination support: list a tenant's sets newest-first by
-- (created_at, id). Built on a table created earlier in this same
-- migration, so a plain (non-CONCURRENTLY) index is lock-safe.
CREATE INDEX IF NOT EXISTS dlp_idm_fingerprint_sets_tenant_created_idx
    ON dlp_idm_fingerprint_sets (tenant_id, created_at DESC, id DESC);

CREATE TRIGGER dlp_idm_fingerprint_sets_set_updated_at
    BEFORE UPDATE ON dlp_idm_fingerprint_sets
    FOR EACH ROW EXECUTE FUNCTION sng_set_updated_at();

-- ENABLE applies RLS to the runtime app role; FORCE extends it to the
-- table owner too, so even the migration/owner credentials cannot bypass
-- tenant isolation (the documented standard for tenant-scoped tables;
-- see 066, 069 and migrations 002, 037, 038, 059).
ALTER TABLE dlp_idm_fingerprint_sets ENABLE ROW LEVEL SECURITY;
ALTER TABLE dlp_idm_fingerprint_sets FORCE ROW LEVEL SECURITY;

-- Tenant-scoped policy: a request bound to sng.tenant_id sees and writes
-- only its own protected-document fingerprint sets.
CREATE POLICY dlp_idm_fingerprint_sets_tenant_isolation ON dlp_idm_fingerprint_sets
    USING (tenant_id = NULLIF(current_setting('sng.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('sng.tenant_id', true), '')::uuid);

-- System policy: a cross-tenant background process (sng.system_role
-- ='true') — e.g. the data-plane distributor loading every tenant's
-- fingerprint sets onto the edge — may read across tenants, mirroring
-- the cross-tenant background access in 066/069 and migrations 038/059.
CREATE POLICY dlp_idm_fingerprint_sets_system ON dlp_idm_fingerprint_sets
    USING (current_setting('sng.system_role', true) = 'true')
    WITH CHECK (current_setting('sng.system_role', true) = 'true');
