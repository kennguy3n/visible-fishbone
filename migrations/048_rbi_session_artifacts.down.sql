-- Reverse migration for RBI session artifacts (down).
DROP POLICY IF EXISTS rbi_session_artifacts_tenant_isolation ON rbi_session_artifacts;
DROP TABLE IF EXISTS rbi_session_artifacts;
