-- ShieldNet Gateway (SNG) — per-tenant Ed25519 signing key store.
--
-- Each tenant owns a set of Ed25519 signing keys used to sign
-- compiled policy bundles. Exactly one key per tenant is active at
-- any time (enforced by a partial unique index); the others are
-- rotated or revoked. Receivers verify a bundle by fetching the
-- public key whose `key_id` matches the `kid` field in the bundle
-- envelope.
--
-- Private-key storage: The raw Ed25519 seed (32 bytes) is stored in
-- the `private_key` column as BYTEA.  At-rest protection is
-- delegated to disk encryption / TDE, same as the
-- `webhook_endpoints.signing_secret` column (see 002_webhooks.up.sql
-- for the rationale). PR8 will introduce an optional KMS-wrapping
-- layer that replaces the plaintext seed with a KMS ciphertext blob.

CREATE TABLE policy_signing_keys (
    id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    key_id        TEXT NOT NULL,
    algorithm     TEXT NOT NULL CHECK (algorithm IN ('ed25519')),
    public_key    BYTEA NOT NULL,
    private_key   BYTEA NOT NULL,
    status        TEXT NOT NULL CHECK (status IN ('active', 'rotated', 'revoked')),
    activated_at  TIMESTAMPTZ NOT NULL,
    rotated_at    TIMESTAMPTZ,
    revoked_at    TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, key_id)
);

-- At most one active key per tenant. The partial unique index
-- makes concurrent rotation safe: the INSERT of the new active key
-- and the UPDATE of the old key's status to 'rotated' can happen
-- in the same transaction, and any interleaving that would create
-- two active keys is rejected by the constraint. This index also
-- serves as the fast-lookup path for the active-key probe; a
-- separate non-unique partial index with the same (tenant_id) +
-- WHERE clause would be fully redundant (Devin Review
-- #3312780989: write amplification with zero query benefit), so
-- we deliberately use only this one.
CREATE UNIQUE INDEX policy_signing_keys_tenant_one_active_idx
    ON policy_signing_keys (tenant_id)
    WHERE status = 'active';

ALTER TABLE policy_signing_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE policy_signing_keys FORCE ROW LEVEL SECURITY;
CREATE POLICY policy_signing_keys_tenant_isolation ON policy_signing_keys
    USING (tenant_id = NULLIF(current_setting('sng.tenant_id', true), '')::uuid);

-- Widen policy_bundles with a key_id column so receivers know which
-- public key to verify the signature against. Existing rows get a
-- NULL key_id (pre-rotation bundles signed with the ephemeral signer
-- from PR6). New rows will always carry a non-NULL key_id.
ALTER TABLE policy_bundles ADD COLUMN key_id TEXT;
