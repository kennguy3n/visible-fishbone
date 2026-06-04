-- Reverse migration for SOC2 compliance evidence (down).
-- Dropping the table removes its indexes and constraints implicitly.
DROP TABLE IF EXISTS compliance_evidence;
