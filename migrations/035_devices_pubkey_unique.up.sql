-- Migration 035: enforce that an Ed25519 device public key is unique
-- within a tenant.
--
-- Why: the mobile self-enrolment flow
-- (POST /tenants/{tenant_id}/devices/mobile/enroll) is idempotent —
-- re-enrolling the same device_key for a tenant must UPDATE the
-- existing device rather than create a duplicate. The service resolves
-- the existing device via DeviceRepository.GetByPublicKey before
-- deciding create-vs-update, but a lookup-then-create is racy on its
-- own: two concurrent first-enrolments of the same key could both miss
-- the lookup and both insert. This partial unique index closes that
-- race at the database level — the second INSERT fails with a unique
-- violation (surfaced as repository.ErrConflict), and the service
-- falls back to the update path. A device public key identifies
-- exactly one device, so this is the correct invariant regardless of
-- enrolment path (it also hardens the existing claim-token flow).
--
-- The index is PARTIAL (WHERE public_key_ed25519 IS NOT NULL) because
-- the column is nullable and the create path stores NULLIF(key, '')
-- — devices enrolled without a key (e.g. bulk CSV inventory imports)
-- leave it NULL, and Postgres treats multiple NULLs as distinct, so
-- those rows are never constrained against each other.
--
-- CONCURRENTLY is intentionally NOT used: golang-migrate wraps each
-- migration in a transaction and CREATE INDEX CONCURRENTLY cannot run
-- inside one. The devices table is small relative to a brief build-time
-- lock, and every other index in this schema is created non-concurrently.
CREATE UNIQUE INDEX IF NOT EXISTS uq_devices_tenant_public_key
    ON devices (tenant_id, public_key_ed25519)
    WHERE public_key_ed25519 IS NOT NULL;
