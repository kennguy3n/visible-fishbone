-- Down migration 097: drop the continuous-compliance control-status table.
DROP TABLE IF EXISTS compliance_auto_control_status;
