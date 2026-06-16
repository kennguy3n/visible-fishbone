-- Down migration 087: drop the continuous-compliance evidence-history table.
DROP TABLE IF EXISTS compliance_auto_evidence;
