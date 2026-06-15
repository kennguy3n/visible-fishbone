-- Down migration 096: drop the continuous-compliance collection-run table.
DROP TABLE IF EXISTS compliance_auto_runs;
