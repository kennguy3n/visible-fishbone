-- ShieldNet Gateway (SNG) — Remote Browser Isolation sessions migration.
--
-- Backs the RBI subsystem (Gap #8). When the SWG data plane decides
-- a URL triggers an RBI policy, the control plane creates a session
-- here, and the RBI proxy streams the page rendering from a
-- disposable headless-Chromium container. The session row tracks
-- the isolated browsing context for audit, tenant-scoped session
-- limits, and automatic expiry.
--
-- RLS-scoped to `sng.tenant_id`, matching every other
-- tenant-scoped table.

CREATE TABLE IF NOT EXISTS rbi_sessions (
    id          UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id   UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    -- The user whose request triggered RBI. May be NULL for
    -- API-key-driven requests without a user mapping.
    user_id     UUID,
    -- The original URL the user was trying to reach.
    target_url  TEXT        NOT NULL DEFAULT '',
    -- Session lifecycle: active, closed, expired.
    status      TEXT        NOT NULL DEFAULT 'active'
                CHECK (status IN ('active', 'closed', 'expired')),
    -- Wall-clock time after which the session is considered expired.
    -- The proxy refuses rendering after this; a cron/leader job
    -- updates the status column as a consistency cleanup.
    expires_at  TIMESTAMPTZ NOT NULL DEFAULT (NOW() + INTERVAL '15 minutes'),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- List active sessions for a tenant (operator dashboard).
CREATE INDEX IF NOT EXISTS idx_rbi_sessions_tenant_status
    ON rbi_sessions (tenant_id, status, created_at DESC);

CREATE TRIGGER rbi_sessions_set_updated_at
    BEFORE UPDATE ON rbi_sessions
    FOR EACH ROW EXECUTE FUNCTION sng_set_updated_at();

ALTER TABLE rbi_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE rbi_sessions FORCE ROW LEVEL SECURITY;

CREATE POLICY rbi_sessions_tenant_isolation ON rbi_sessions
    USING (tenant_id = NULLIF(current_setting('sng.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('sng.tenant_id', true), '')::uuid);
