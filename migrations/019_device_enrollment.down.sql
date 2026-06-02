-- Rollback migration 019: Device enrollment tables.
DROP TABLE IF EXISTS device_certificates;
DROP TABLE IF EXISTS device_enrollments;
DROP TYPE IF EXISTS device_enrollment_status;
