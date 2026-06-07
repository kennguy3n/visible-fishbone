-- ShieldNet Gateway (SNG) — Remote Browser Isolation session
-- artifacts migration (Session 2D).
--
-- Records artifact transfers that crossed (or were attempted across)
-- the RBI isolation boundary: clipboard copy/paste and file
-- download/upload between the isolated render container and the
-- endpoint. The control plane appends one immutable row per gated
-- transfer so an operator can audit what data moved.
--
-- Every insert flows through the fail-closed data-residency Guard
-- (migration 046), so a row only ever lands in a region the tenant is
-- permitted to store data in.
--
-- RLS-scoped to `sng.tenant_id`, matching every other tenant-scoped
-- table.
--
-- Lock safety: CREATE TABLE on a brand-new (empty) table takes no
-- table-rewrite lock. No secondary index is created — the runner wraps
-- each migration file in a transaction (see migration 041), inside
-- which CREATE INDEX CONCURRENTLY cannot run, and a plain CREATE INDEX
-- is exactly the table-rewrite-lock pattern the migration-lint
-- validator rejects. The artifact list is an operator drill-down
-- (ListBySession), not a steady-state data-plane query, and reads are
-- already tenant-scoped under RLS, so the per-session scan stays cheap;
-- this mirrors the deliberate no-secondary-index decision of the
-- sibling append-only audit table in migration 046.

CREATE TABLE IF NOT EXISTS rbi_session_artifacts (
    id          UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id   UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    -- The RBI session this artifact transfer belongs to. Cascade so
    -- closing/deleting a session reaps its artifact records.
    session_id  UUID        NOT NULL REFERENCES rbi_sessions(id) ON DELETE CASCADE,
    -- What kind of transfer crossed the boundary.
    kind        TEXT        NOT NULL
                CHECK (kind IN ('clipboard', 'file_download', 'file_upload')),
    -- Which way it crossed: inbound (remote→endpoint) or outbound
    -- (endpoint→remote).
    direction   TEXT        NOT NULL
                CHECK (direction IN ('inbound', 'outbound')),
    -- Artifact filename for file transfers; empty for clipboard.
    filename    TEXT        NOT NULL DEFAULT '',
    -- Lowercase hex SHA-256 of the artifact bytes when the proxy
    -- hashed them; empty otherwise.
    sha256      TEXT        NOT NULL DEFAULT '',
    -- Artifact size in bytes (0 when unknown).
    size_bytes  BIGINT      NOT NULL DEFAULT 0,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE rbi_session_artifacts ENABLE ROW LEVEL SECURITY;
ALTER TABLE rbi_session_artifacts FORCE ROW LEVEL SECURITY;

CREATE POLICY rbi_session_artifacts_tenant_isolation ON rbi_session_artifacts
    USING (tenant_id = NULLIF(current_setting('sng.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('sng.tenant_id', true), '')::uuid);
