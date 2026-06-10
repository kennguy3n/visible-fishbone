-- 056_residency_audit_rbi_plane (down)
--
-- Restore the original telemetry/policy_bundle/cold_storage plane set.
-- residency_audit is append-only, so any 'rbi_artifact' rows recorded
-- while this migration was applied would violate the restored
-- constraint; delete them before re-adding it. (They could not have
-- existed before this migration, since the prior constraint rejected
-- them.)

DELETE FROM residency_audit WHERE plane = 'rbi_artifact';

ALTER TABLE residency_audit
    DROP CONSTRAINT IF EXISTS residency_audit_plane_check;

ALTER TABLE residency_audit
    ADD CONSTRAINT residency_audit_plane_check
    CHECK (plane IN ('telemetry', 'policy_bundle', 'cold_storage'));
