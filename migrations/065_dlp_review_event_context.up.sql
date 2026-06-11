-- 065_dlp_review_event_context
--
-- Give a queued DLP review event the operator-triage context it was
-- missing: which device the flagged upload came from, and when the
-- upload actually happened at the edge.
--
-- Until now a row only carried created_at (the moment the control plane
-- enqueued it). A reviewer deciding whether to block an AI-app
-- destination needs to know the originating device (to scope the
-- decision / spot a single noisy endpoint) and the original event time
-- (enqueue can lag the edge event through the telemetry pipeline, so
-- created_at is not the time the user acted).
--
-- Both columns are nullable: they are populated from the telemetry
-- envelope (device_id / timestamp, both required there) for the AI-app
-- producer path, but a future producer — or an event enqueued before
-- this migration — may not supply them, and the queue must still accept
-- the row. device_id is stored as the bare identifier (no FK to
-- devices): it is triage metadata, must survive the device being
-- deleted, and a missing device must never fail an enqueue.
--
-- Lock safety: ADD COLUMN of a nullable column with no DEFAULT records
-- nothing per-row, so Postgres 11+ takes only a brief catalog lock and
-- never rewrites the table. No index is added — these are display-only
-- triage fields, not query predicates.

ALTER TABLE dlp_review_queue
    ADD COLUMN IF NOT EXISTS device_id   UUID,
    ADD COLUMN IF NOT EXISTS occurred_at TIMESTAMPTZ;
