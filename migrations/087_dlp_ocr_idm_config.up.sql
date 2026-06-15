-- 087_dlp_ocr_idm_config
--
-- Per-tenant configuration + status surface for the WP4 OCR and IDM
-- capabilities in crates/sng-dlp. One row per tenant holds the bounded
-- knobs the data plane reads to size its OCR decode limits and IDM
-- index parameters, plus the enable flags. The defaults mirror the
-- Rust crate's compiled-in defaults (OcrLimits::default and
-- crates/sng-dlp::idm DEFAULT_*), so a tenant that never touches this
-- table behaves exactly like the no-config edge — the table exists to
-- let a tenant *narrow* the bounds, never to require tuning.
--
-- No-ops contract: every knob is bounded by a CHECK so a tenant cannot
-- configure an unbounded OCR decode (which at 5,000 tenants would be a
-- shared-CPU/memory hazard). The edge still clamps to its own compiled
-- ceilings; this row can only make a tenant's limits tighter or equal,
-- never looser than the platform maximum.
--
-- One row per tenant keyed by tenant_id (a by-PK upsert serves the
-- single access pattern: get/put a tenant's config), so no secondary
-- index is created.
--
-- Lock safety: CREATE TABLE on a brand-new (empty) table takes no
-- table-rewrite lock; the trigger and RLS policies attach to that same
-- empty table in the migration runner's transaction.

CREATE TABLE IF NOT EXISTS dlp_ocr_idm_config (
    -- One row per tenant; the PK is the access path and the upsert key.
    tenant_id                UUID             PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    -- OCR: extract text from images so existing detectors run over it.
    ocr_enabled              BOOLEAN          NOT NULL DEFAULT true,
    -- Max decoded input size / dimension. Defaults mirror
    -- OcrLimits::default (4 MiB, 4096 px). Bounded so a tenant cannot
    -- request an unbounded decode.
    ocr_max_input_bytes      BIGINT           NOT NULL DEFAULT 4194304
                             CHECK (ocr_max_input_bytes BETWEEN 1024 AND 16777216),
    ocr_max_dimension        INT              NOT NULL DEFAULT 4096
                             CHECK (ocr_max_dimension BETWEEN 16 AND 8192),
    -- IDM: detect partial/derivative copies of protected documents.
    idm_enabled              BOOLEAN          NOT NULL DEFAULT true,
    -- Containment threshold above which a match is reported. Mirrors
    -- FINGERPRINT_SIMILARITY_THRESHOLD (0.8). (0,1].
    idm_similarity_threshold DOUBLE PRECISION NOT NULL DEFAULT 0.8
                             CHECK (idm_similarity_threshold > 0 AND idm_similarity_threshold <= 1),
    -- Default fingerprinting parameters for newly uploaded sets. Mirror
    -- crates/sng-dlp::idm DEFAULT_* (shingle 5, window 8, cap 2048) and
    -- share the bounds enforced on dlp_idm_fingerprint_sets.
    idm_shingle_size         INT              NOT NULL DEFAULT 5
                             CHECK (idm_shingle_size BETWEEN 1 AND 64),
    idm_window_size          INT              NOT NULL DEFAULT 8
                             CHECK (idm_window_size BETWEEN 1 AND 256),
    idm_max_fingerprints     INT              NOT NULL DEFAULT 2048
                             CHECK (idm_max_fingerprints BETWEEN 1 AND 65536),
    created_at               TIMESTAMPTZ      NOT NULL DEFAULT now(),
    updated_at               TIMESTAMPTZ      NOT NULL DEFAULT now()
);

CREATE TRIGGER dlp_ocr_idm_config_set_updated_at
    BEFORE UPDATE ON dlp_ocr_idm_config
    FOR EACH ROW EXECUTE FUNCTION sng_set_updated_at();

-- ENABLE + FORCE RLS: same tenant-isolation standard as the rest of the
-- tenant-scoped tables (see 069 and migrations 002, 037, 038, 059).
ALTER TABLE dlp_ocr_idm_config ENABLE ROW LEVEL SECURITY;
ALTER TABLE dlp_ocr_idm_config FORCE ROW LEVEL SECURITY;

CREATE POLICY dlp_ocr_idm_config_tenant_isolation ON dlp_ocr_idm_config
    USING (tenant_id = NULLIF(current_setting('sng.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('sng.tenant_id', true), '')::uuid);

-- System policy: the cross-tenant data-plane distributor reads every
-- tenant's OCR/IDM config when pushing configuration to the edge.
CREATE POLICY dlp_ocr_idm_config_system ON dlp_ocr_idm_config
    USING (current_setting('sng.system_role', true) = 'true')
    WITH CHECK (current_setting('sng.system_role', true) = 'true');
