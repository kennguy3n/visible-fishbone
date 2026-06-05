-- Reverse migration for RBI sessions (down).
DROP TRIGGER IF EXISTS rbi_sessions_set_updated_at ON rbi_sessions;
DROP POLICY IF EXISTS rbi_sessions_tenant_isolation ON rbi_sessions;
DROP TABLE IF EXISTS rbi_sessions;
