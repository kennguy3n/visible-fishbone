-- 013_alerts (DOWN) — drop alerts + suppressions + feedback.
--
-- Drop in reverse FK order: alert_feedback and the suppression
-- FK on alerts must go before the referenced tables.

DROP POLICY IF EXISTS alert_feedback_tenant_isolation     ON alert_feedback;
DROP POLICY IF EXISTS alert_suppressions_tenant_isolation ON alert_suppressions;
DROP POLICY IF EXISTS alerts_tenant_isolation             ON alerts;

DROP INDEX IF EXISTS alert_feedback_dimension_idx;
DROP INDEX IF EXISTS alert_suppressions_dimension_idx;
DROP INDEX IF EXISTS alert_suppressions_kind_idx;
DROP INDEX IF EXISTS alerts_dimension_idx;
DROP INDEX IF EXISTS alerts_open_idx;
DROP INDEX IF EXISTS alerts_list_idx;

DROP TABLE IF EXISTS alert_feedback;
DROP TABLE IF EXISTS alerts;
DROP TABLE IF EXISTS alert_suppressions;
