-- ClickHouse migration 002: CASB/DLP telemetry event columns.
--
-- Phase 4, Task 45: CASB + DLP Telemetry Integration.
--
-- Adds columns to sng_telemetry for CASB sync events, DLP match
-- events, and posture assessment events. All columns are optional
-- (DEFAULT values) so existing event rows are unaffected.

ALTER TABLE sng_telemetry
    ADD COLUMN IF NOT EXISTS casb_app_id LowCardinality(String) DEFAULT '' AFTER traffic_class;

ALTER TABLE sng_telemetry
    ADD COLUMN IF NOT EXISTS casb_event_type LowCardinality(String) DEFAULT '' AFTER casb_app_id;

ALTER TABLE sng_telemetry
    ADD COLUMN IF NOT EXISTS dlp_policy_id String DEFAULT '' AFTER casb_event_type;

ALTER TABLE sng_telemetry
    ADD COLUMN IF NOT EXISTS dlp_classification LowCardinality(String) DEFAULT '' AFTER dlp_policy_id;

ALTER TABLE sng_telemetry
    ADD COLUMN IF NOT EXISTS posture_risk_score UInt8 DEFAULT 0 AFTER dlp_classification;
