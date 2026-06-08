-- Reverse migration for the DLP ML model registry (down).
DROP POLICY IF EXISTS dlp_ml_model_assignments_tenant_isolation ON dlp_ml_model_assignments;
DROP TABLE IF EXISTS dlp_ml_model_assignments;

DROP POLICY IF EXISTS dlp_ml_models_tenant_isolation ON dlp_ml_models;
DROP TRIGGER IF EXISTS dlp_ml_models_set_updated_at ON dlp_ml_models;
DROP TABLE IF EXISTS dlp_ml_models;
