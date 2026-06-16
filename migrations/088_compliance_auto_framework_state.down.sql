-- Down migration 088: drop the continuous-compliance per-framework rollup table.
DROP TABLE IF EXISTS compliance_auto_framework_state;
