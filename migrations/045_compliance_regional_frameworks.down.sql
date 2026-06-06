-- Reverse migration 045: restore the original four-framework CHECK.
--
-- Rolling back is only safe if no rows hold a regional framework; if
-- any do, VALIDATE would fail and the down-migration would abort,
-- which is the correct fail-closed behaviour (do not silently drop the
-- constraint that protects data integrity). Operators rolling back
-- must first delete or re-classify regional reports.

ALTER TABLE compliance_reports
    DROP CONSTRAINT IF EXISTS compliance_reports_framework_check;

ALTER TABLE compliance_reports
    ADD CONSTRAINT compliance_reports_framework_check
    CHECK (framework IN ('PCI_DSS', 'HIPAA', 'SOC2', 'ISO_27001')) NOT VALID;

ALTER TABLE compliance_reports
    VALIDATE CONSTRAINT compliance_reports_framework_check;
