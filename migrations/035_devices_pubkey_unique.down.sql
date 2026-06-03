-- Migration 035 (down): drop the per-tenant device public-key unique
-- index. Reverts to allowing duplicate Ed25519 keys within a tenant.
DROP INDEX IF EXISTS uq_devices_tenant_public_key;
