-- ClickHouse does not support DROP COLUMN IF EXISTS in all versions,
-- but the ALTER is idempotent on recent builds.
ALTER TABLE sng_telemetry DROP COLUMN IF EXISTS posture_risk_score;
ALTER TABLE sng_telemetry DROP COLUMN IF EXISTS dlp_classification;
ALTER TABLE sng_telemetry DROP COLUMN IF EXISTS dlp_policy_id;
ALTER TABLE sng_telemetry DROP COLUMN IF EXISTS casb_event_type;
ALTER TABLE sng_telemetry DROP COLUMN IF EXISTS casb_app_id;
