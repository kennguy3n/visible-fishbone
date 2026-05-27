-- ShieldNet Gateway (SNG) — initial schema migration.
--
-- Creates the multi-tenant control-plane catalog: tenants, sites,
-- users, roles, user_roles, devices, claim_tokens, audit_log,
-- policy_graphs, and policy_bundles.
--
-- Row Level Security (RLS) is enabled and FORCED on every
-- tenant-scoped table. The `sng_service` (or equivalent) role must
-- `SELECT set_config('sng.tenant_id', <uuid>, true)` inside the
-- transaction before any tenant-scoped query. All tenant policies
-- evaluate
--
--     current_setting('sng.tenant_id', /*missing_ok=*/true)
--
-- so a connection that has NOT set `sng.tenant_id` sees zero rows
-- instead of erroring out (mirrors sn360-security-platform's
-- fail-closed pattern). Errors would bubble up through any LEFT
-- JOIN, ORM cache, or connection-pool reuse path that forgot to set
-- the GUC.
--
-- The GUC name is intentionally `sng.tenant_id` (SNG namespace),
-- NOT `sn360.tenant_id` — the two products run side-by-side and a
-- shared GUC namespace would silently cross-couple their RLS
-- policies on connection pools that reuse psql sessions.

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ---------------------------------------------------------------------
-- updated_at trigger function.
--
-- Postgres has no built-in "ON UPDATE NOW()" semantics; we use a
-- shared trigger so the SQL stays declarative and every mutable
-- table can install the same trigger without copy-pasting the
-- function body.
-- ---------------------------------------------------------------------
CREATE OR REPLACE FUNCTION sng_set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- ---------------------------------------------------------------------
-- tenants
--
-- Top-level tenant table. NOT tenant-scoped (no RLS) — tenant rows
-- describe the tenants themselves. Application code enforces that
-- non-platform users only see their own row.
-- ---------------------------------------------------------------------
CREATE TABLE tenants (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name        TEXT NOT NULL,
    slug        TEXT NOT NULL UNIQUE,
    status      TEXT NOT NULL CHECK (status IN ('active', 'suspended', 'deleted')),
    region      TEXT,
    tier        TEXT NOT NULL CHECK (tier IN ('starter', 'professional', 'enterprise')),
    settings    JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at  TIMESTAMPTZ
);

CREATE INDEX tenants_status_idx ON tenants (status) WHERE deleted_at IS NULL;
CREATE INDEX tenants_tier_idx   ON tenants (tier)   WHERE deleted_at IS NULL;

CREATE TRIGGER tenants_set_updated_at
    BEFORE UPDATE ON tenants
    FOR EACH ROW EXECUTE FUNCTION sng_set_updated_at();

-- ---------------------------------------------------------------------
-- sites
--
-- A site is an enforcement scope owned by a tenant (a branch office,
-- a hub, a cloud PoP, or a remote-worker fleet).
-- ---------------------------------------------------------------------
CREATE TABLE sites (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id   UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    slug        TEXT NOT NULL,
    template    TEXT NOT NULL CHECK (template IN ('branch', 'hub', 'cloud_only', 'home_office')),
    config      JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, slug)
);

CREATE INDEX sites_tenant_idx       ON sites (tenant_id);
CREATE INDEX sites_template_idx     ON sites (tenant_id, template);

ALTER TABLE sites ENABLE ROW LEVEL SECURITY;
ALTER TABLE sites FORCE ROW LEVEL SECURITY;
CREATE POLICY sites_tenant_isolation ON sites
    USING (tenant_id = NULLIF(current_setting('sng.tenant_id', true), '')::uuid);

CREATE TRIGGER sites_set_updated_at
    BEFORE UPDATE ON sites
    FOR EACH ROW EXECUTE FUNCTION sng_set_updated_at();

-- ---------------------------------------------------------------------
-- users
--
-- An end-user identity inside a tenant. Authentication is performed
-- by the IdP; this table stores the projection used for
-- authorization decisions (RBAC) and audit trails.
-- ---------------------------------------------------------------------
CREATE TABLE users (
    id           UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id    UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    email        TEXT NOT NULL,
    name         TEXT,
    external_id  TEXT,
    idp_subject  TEXT,
    status       TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'deleted')),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX users_tenant_idx        ON users (tenant_id);
CREATE INDEX users_tenant_status_idx ON users (tenant_id, status);

-- Case-insensitive email uniqueness within a tenant: two users
-- in the same tenant cannot share the same email regardless of
-- letter case. The functional UNIQUE INDEX is the right primitive
-- for this — UNIQUE (tenant_id, email) alone would let
-- "Ada@example.com" and "ada@example.com" coexist.
CREATE UNIQUE INDEX users_tenant_email_lower_idx
    ON users (tenant_id, lower(email));

ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE users FORCE ROW LEVEL SECURITY;
CREATE POLICY users_tenant_isolation ON users
    USING (tenant_id = NULLIF(current_setting('sng.tenant_id', true), '')::uuid);

CREATE TRIGGER users_set_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION sng_set_updated_at();

-- ---------------------------------------------------------------------
-- roles
--
-- Roles can be either system-wide (tenant_id IS NULL) or
-- tenant-scoped (tenant_id IS NOT NULL). System roles seed every
-- new tenant (platform_admin, msp_admin, tenant_admin, etc.).
-- ---------------------------------------------------------------------
CREATE TABLE roles (
    id           UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id    UUID REFERENCES tenants(id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    permissions  JSONB NOT NULL DEFAULT '[]'::jsonb,
    scope        TEXT NOT NULL CHECK (scope IN ('platform', 'msp', 'tenant', 'site')),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, name)
);

CREATE INDEX roles_tenant_idx ON roles (tenant_id);

-- roles is intentionally NOT RLS-protected on tenant_id alone
-- (system roles have tenant_id IS NULL and must be readable from
-- every tenant context). Authorization at the application layer
-- restricts which roles a tenant_admin may assign.

-- ---------------------------------------------------------------------
-- user_roles
--
-- Many-to-many between users and roles. `scope_id` narrows the
-- assignment when the role's scope is `site` (scope_id == site id).
-- For tenant-scoped roles, scope_id is NULL.
--
-- Composite primary key uses COALESCE(scope_id, zero-uuid) so the
-- (user, role, NULL-scope) row remains unique. PostgreSQL treats
-- NULLs in a composite UNIQUE as distinct otherwise, allowing
-- duplicates that the application would have to dedupe.
-- ---------------------------------------------------------------------
CREATE TABLE user_roles (
    user_id             UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id             UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    scope_id            UUID,
    -- Generated column captures the NULL coalescing for the
    -- primary key. PostgreSQL treats NULLs inside a composite
    -- UNIQUE / PK as distinct otherwise, allowing duplicate
    -- (user, role, NULL) grants. Coalescing to the zero-UUID
    -- collapses them onto a single PK slot at storage time.
    scope_id_coalesced  UUID GENERATED ALWAYS AS
        (COALESCE(scope_id, '00000000-0000-0000-0000-000000000000'::uuid)) STORED,
    granted_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    granted_by          UUID,
    PRIMARY KEY (user_id, role_id, scope_id_coalesced)
);

CREATE INDEX user_roles_user_idx ON user_roles (user_id);
CREATE INDEX user_roles_role_idx ON user_roles (role_id);

-- ---------------------------------------------------------------------
-- devices
--
-- A device is an enrolled endpoint (Windows / macOS / Linux / iOS /
-- Android). `public_key_ed25519` is the device's public identity
-- key established at enrollment and used to authenticate subsequent
-- mTLS or signed-request flows.
-- ---------------------------------------------------------------------
CREATE TABLE devices (
    id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id           UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    site_id             UUID REFERENCES sites(id) ON DELETE SET NULL,
    name                TEXT NOT NULL,
    platform            TEXT NOT NULL CHECK (platform IN ('windows', 'macos', 'linux', 'ios', 'android')),
    public_key_ed25519  TEXT,
    enrolled_at         TIMESTAMPTZ,
    last_seen_at        TIMESTAMPTZ,
    status              TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'active', 'suspended', 'deleted')),
    posture             JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX devices_tenant_idx          ON devices (tenant_id);
CREATE INDEX devices_tenant_status_idx   ON devices (tenant_id, status);
CREATE INDEX devices_tenant_platform_idx ON devices (tenant_id, platform);
CREATE INDEX devices_site_idx            ON devices (site_id) WHERE site_id IS NOT NULL;

ALTER TABLE devices ENABLE ROW LEVEL SECURITY;
ALTER TABLE devices FORCE ROW LEVEL SECURITY;
CREATE POLICY devices_tenant_isolation ON devices
    USING (tenant_id = NULLIF(current_setting('sng.tenant_id', true), '')::uuid);

CREATE TRIGGER devices_set_updated_at
    BEFORE UPDATE ON devices
    FOR EACH ROW EXECUTE FUNCTION sng_set_updated_at();

-- ---------------------------------------------------------------------
-- claim_tokens
--
-- Short-lived one-time codes a tenant administrator hands to a
-- device to bootstrap enrollment. Only the SHA-256 hash is stored;
-- the plaintext lives in the operator's clipboard or paper printout.
-- ---------------------------------------------------------------------
CREATE TABLE claim_tokens (
    id           UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id    UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    token_hash   BYTEA NOT NULL UNIQUE,
    expires_at   TIMESTAMPTZ NOT NULL,
    redeemed_at  TIMESTAMPTZ,
    created_by   UUID,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX claim_tokens_tenant_idx ON claim_tokens (tenant_id);
CREATE INDEX claim_tokens_expires_idx ON claim_tokens (expires_at) WHERE redeemed_at IS NULL;

ALTER TABLE claim_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE claim_tokens FORCE ROW LEVEL SECURITY;
CREATE POLICY claim_tokens_tenant_isolation ON claim_tokens
    USING (tenant_id = NULLIF(current_setting('sng.tenant_id', true), '')::uuid);

-- ---------------------------------------------------------------------
-- audit_log
--
-- Append-only audit trail. No `updated_at`; once written, rows
-- are immutable. Application code enforces no-UPDATE / no-DELETE.
-- ---------------------------------------------------------------------
CREATE TABLE audit_log (
    id             UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id      UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    actor_id       UUID,
    action         TEXT NOT NULL,
    resource_type  TEXT NOT NULL,
    resource_id    UUID,
    details        JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX audit_log_tenant_idx          ON audit_log (tenant_id, created_at DESC);
CREATE INDEX audit_log_actor_idx           ON audit_log (tenant_id, actor_id, created_at DESC);
CREATE INDEX audit_log_resource_idx        ON audit_log (tenant_id, resource_type, resource_id, created_at DESC);
CREATE INDEX audit_log_action_idx          ON audit_log (tenant_id, action, created_at DESC);

ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_log FORCE ROW LEVEL SECURITY;
CREATE POLICY audit_log_tenant_isolation ON audit_log
    USING (tenant_id = NULLIF(current_setting('sng.tenant_id', true), '')::uuid);

-- ---------------------------------------------------------------------
-- policy_graphs
--
-- Versioned tenant policy graphs. Each row is a single immutable
-- compile snapshot of the typed policy model. UNIQUE (tenant_id,
-- version) keeps the version history monotonic.
-- ---------------------------------------------------------------------
CREATE TABLE policy_graphs (
    id                UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id         UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    version           INTEGER NOT NULL,
    graph             JSONB NOT NULL,
    compiled_at       TIMESTAMPTZ,
    compiler_version  TEXT,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, version)
);

CREATE INDEX policy_graphs_tenant_version_idx ON policy_graphs (tenant_id, version DESC);

ALTER TABLE policy_graphs ENABLE ROW LEVEL SECURITY;
ALTER TABLE policy_graphs FORCE ROW LEVEL SECURITY;
CREATE POLICY policy_graphs_tenant_isolation ON policy_graphs
    USING (tenant_id = NULLIF(current_setting('sng.tenant_id', true), '')::uuid);

-- ---------------------------------------------------------------------
-- policy_bundles
--
-- Compiled, signed bundles emitted by the policy compiler. One row
-- per (policy_graph, target_type). `target_type` covers edge,
-- endpoint, cloud, and mobile enforcement points.
-- ---------------------------------------------------------------------
CREATE TABLE policy_bundles (
    id                UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    policy_graph_id   UUID NOT NULL REFERENCES policy_graphs(id) ON DELETE CASCADE,
    target_type       TEXT NOT NULL CHECK (target_type IN ('edge', 'endpoint', 'cloud', 'mobile')),
    bundle            BYTEA NOT NULL,
    signature         BYTEA NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (policy_graph_id, target_type)
);

CREATE INDEX policy_bundles_graph_idx ON policy_bundles (policy_graph_id);

-- policy_bundles inherits tenant scoping from policy_graphs via FK
-- and the application layer; the bundle table itself doesn't carry
-- a tenant_id column to avoid denormalizing tenant ownership
-- (single source of truth lives on policy_graphs).
