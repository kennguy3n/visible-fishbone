-- 065_dlp_review_event_context (down)
--
-- Drop the operator-triage context columns. They are derived from the
-- telemetry envelope and reconstructed from the data path after
-- re-applying the up migration.

ALTER TABLE dlp_review_queue
    DROP COLUMN IF EXISTS occurred_at,
    DROP COLUMN IF EXISTS device_id;
