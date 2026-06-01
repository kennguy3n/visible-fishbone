-- Reverse migration 001 — drop the sng_telemetry table.
--
-- WARNING: this drops all telemetry data. The S3 cold-tier
-- archive remains the durable record of truth; operators
-- intending a clean re-bootstrap should snapshot the archive
-- manifest first.

DROP TABLE IF EXISTS sng_telemetry;
