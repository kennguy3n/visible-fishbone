-- Migration 044: bind enrolled devices to their upstream iam-core
-- identity (Session 2A — iam-core integration).
--
-- ShieldNet keeps its existing Ed25519 device enrolment unchanged: a
-- device still proves possession of its key. This table adds the
-- missing link between that device key and the *person* who owns it as
-- known to the upstream identity provider (uneycom/iam-core). Without
-- it, SNG can authenticate a device but cannot answer "which iam-core
-- user does this device belong to?" — needed for per-user device
-- inventory, deprovisioning when iam-core blocks/deletes a user, and
-- attaching device posture to an identity in policy decisions.
--
-- The mapping is (iam_core_user_id, device_id, ed25519_public_key):
--   - iam_core_user_id   : the iam-core `sub` / user_id (opaque TEXT;
--                          iam-core ids are not SNG UUIDs).
--   - device_id          : FK to the local devices row.
--   - ed25519_public_key : the device key captured at binding time, so
--                          the binding survives even if the device row
--                          is later re-keyed (audit / forensics).
--
-- RLS-scoped to `sng.tenant_id`, matching every other tenant-scoped
-- table. A device belongs to exactly one identity within a tenant, so
-- (tenant_id, device_id) is UNIQUE — declared as a table constraint so
-- the ON CONFLICT (tenant_id, device_id) upsert in the repository has a
-- matching unique index, and so it is created as part of CREATE TABLE
-- rather than a separate (lock-flagged) CREATE INDEX. A single user may
-- own many devices, so (tenant_id, iam_core_user_id) is a non-unique
-- lookup index.
--
-- CREATE TABLE / CREATE INDEX on a brand-new (empty) table take no
-- table-rewrite lock, so this migration is lock-safe at scale. The
-- single non-concurrent lookup index mirrors the established pattern of
-- migrations 042 (sandbox_verdicts) and 043 (rbi_sessions), which
-- likewise create one index alongside a new table.

CREATE TABLE IF NOT EXISTS device_identity_bindings (
    id                  UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id           UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    device_id           UUID        NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    iam_core_user_id    TEXT        NOT NULL CHECK (iam_core_user_id <> ''),
    ed25519_public_key  TEXT        NOT NULL CHECK (ed25519_public_key <> ''),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- One identity binding per device within a tenant (re-binding the
    -- same device UPDATEs this row via ON CONFLICT on these columns).
    CONSTRAINT uq_device_identity_bindings_tenant_device UNIQUE (tenant_id, device_id)
);

-- "all devices owned by this iam-core user" lookup.
CREATE INDEX IF NOT EXISTS idx_device_identity_bindings_tenant_user
    ON device_identity_bindings (tenant_id, iam_core_user_id);

CREATE TRIGGER device_identity_bindings_set_updated_at
    BEFORE UPDATE ON device_identity_bindings
    FOR EACH ROW EXECUTE FUNCTION sng_set_updated_at();

ALTER TABLE device_identity_bindings ENABLE ROW LEVEL SECURITY;
ALTER TABLE device_identity_bindings FORCE ROW LEVEL SECURITY;

CREATE POLICY device_identity_bindings_tenant_isolation ON device_identity_bindings
    USING (tenant_id = NULLIF(current_setting('sng.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('sng.tenant_id', true), '')::uuid);
