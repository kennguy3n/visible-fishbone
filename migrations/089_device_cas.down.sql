-- Rollback migration 089: Per-tenant device certificate authority.
DROP TABLE IF EXISTS device_cas;
