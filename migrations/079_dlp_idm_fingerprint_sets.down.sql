-- 079_dlp_idm_fingerprint_sets (down)
--
-- Drop the IDM protected-document fingerprint store. The data is
-- derived (winnowed shingle fingerprints), not raw documents, so
-- dropping it loses only fingerprints a tenant can re-upload; the
-- data-plane index simply stops matching those documents.

DROP TRIGGER IF EXISTS dlp_idm_fingerprint_sets_set_updated_at ON dlp_idm_fingerprint_sets;

DROP TABLE IF EXISTS dlp_idm_fingerprint_sets;
