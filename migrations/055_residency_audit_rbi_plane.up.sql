-- 055_residency_audit_rbi_plane
--
-- Allow the 'rbi_artifact' residency plane in the residency_audit
-- CHECK constraint.
--
-- The domain model (internal/service/residency/residency.go) defines
-- PlaneRBIArtifact = "rbi_artifact", and it is wired into production
-- enforcement at cmd/sng-control/main.go via
-- residency.NewGuard(residencySvc, residency.PlaneRBIArtifact, ...).
-- Migration 046 created residency_audit before that plane existed, so
-- its plane CHECK only permits telemetry/policy_bundle/cold_storage.
--
-- The mismatch meant a residency rejection on an RBI artifact transfer
-- would fail the audit INSERT with a CHECK violation (SQLSTATE 23514).
-- Service.record() deliberately logs-and-swallows audit-write failures
-- so a denial is never turned into a mishandled allow — enforcement
-- still fails closed — but the rejection would not be durably recorded,
-- leaving a gap in the auditor-queryable residency-violation evidence.
-- This migration realigns the schema with the model so RBI-artifact
-- rejections are persisted like every other plane's.
--
-- key_management is intentionally NOT added: PlaneKeyManagement
-- rejections are audited through the platform audit log, not this
-- data-plane table (see keyprovider.go).
--
-- Lock safety: residency_audit only ever receives a row when a write is
-- denied (a rare misconfiguration signal), so the table is tiny; the
-- brief ACCESS EXCLUSIVE lock taken to re-add and validate the CHECK
-- scans a negligible number of rows.

ALTER TABLE residency_audit
    DROP CONSTRAINT IF EXISTS residency_audit_plane_check;

ALTER TABLE residency_audit
    ADD CONSTRAINT residency_audit_plane_check
    CHECK (plane IN ('telemetry', 'policy_bundle', 'cold_storage', 'rbi_artifact'));
