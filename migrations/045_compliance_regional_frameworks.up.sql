-- Migration 045: widen the compliance_reports.framework CHECK to the
-- regional frameworks added in Session 2C (PDPA, NESA/TDRA,
-- FDPIC/nDSG, BDSG/GDPR, CSA Cyber Essentials).
--
-- The framework set is kept in lock-step with
-- internal/service/compliance/types.go (ValidFrameworks): a regional
-- report is generated, scored, and evidence-packed by the SAME
-- ReportService pipeline as the four global frameworks, so the only
-- schema-level change required is admitting the new identifiers past
-- the column CHECK.
--
-- Lock safety: the original constraint (migration 022) was created
-- inline with the table, so Postgres named it
-- `compliance_reports_framework_check`. We DROP it (a fast catalog-only
-- operation) and re-ADD the widened constraint as NOT VALID, which is
-- also catalog-only — it does NOT scan the existing rows under ACCESS
-- EXCLUSIVE. The subsequent VALIDATE CONSTRAINT performs the scan under
-- a SHARE UPDATE EXCLUSIVE lock that does not block reads or writes.
-- Every existing row holds one of the original four frameworks, which
-- are a subset of the widened set, so validation always succeeds.

ALTER TABLE compliance_reports
    DROP CONSTRAINT IF EXISTS compliance_reports_framework_check;

ALTER TABLE compliance_reports
    ADD CONSTRAINT compliance_reports_framework_check
    CHECK (framework IN (
        'PCI_DSS', 'HIPAA', 'SOC2', 'ISO_27001',
        'PDPA', 'NESA_TDRA', 'FDPIC_NDSG', 'BDSG_GDPR', 'CSA_CE'
    )) NOT VALID;

ALTER TABLE compliance_reports
    VALIDATE CONSTRAINT compliance_reports_framework_check;
