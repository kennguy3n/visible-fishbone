-- 080_dlp_ocr_idm_config (down)
--
-- Drop the per-tenant OCR/IDM configuration. Dropping it is fail-safe:
-- the edge falls back to its compiled-in defaults (OcrLimits::default
-- and crates/sng-dlp::idm DEFAULT_*), which is exactly the behaviour of
-- a tenant that never wrote a config row.

DROP TRIGGER IF EXISTS dlp_ocr_idm_config_set_updated_at ON dlp_ocr_idm_config;

DROP TABLE IF EXISTS dlp_ocr_idm_config;
