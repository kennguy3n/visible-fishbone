package repository

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// This file is the durability boundary for the continuous compliance
// evidence service (internal/service/complianceauto, WP6). It is a
// NEW repository surface deliberately kept in its own file so it does
// not co-edit the shared interfaces.go / types.go. The row structs are
// neutral, primitive-typed projections — the data layer does not import
// the complianceauto package (which owns the rich Framework / Status /
// Control enums); the service maps between these rows and its domain
// types at the composition root, mirroring ThreatIOC.
//
// Three append/upsert tables back this surface (migrations 096–099):
//
//   - compliance_auto_runs            one row per (tenant, sweep)
//   - compliance_auto_control_status  latest status per (tenant, fw, control)
//   - compliance_auto_evidence        append-only evidence history
//   - compliance_auto_framework_state per-(tenant, framework) rollup
//
// All four are tenant-scoped and RLS-protected; the leader-only
// collector drives the scheduled sweep under the system role.

// ComplianceAutoRunRow records a single evaluation sweep for a tenant —
// the wall-clock window plus the per-status control tallies. It is the
// parent audit record the status/evidence rows reference by RunID.
type ComplianceAutoRunRow struct {
	ID            uuid.UUID
	TenantID      uuid.UUID
	StartedAt     time.Time
	FinishedAt    time.Time
	ControlsTotal int
	ControlsPass  int
	ControlsFail  int
	ControlsNA    int
	CreatedAt     time.Time
}

// ComplianceAutoControlStatusRow is the latest evaluation of one control
// for a tenant under one framework. Status is one of
// "pass"/"fail"/"not_applicable". Details carries the structured
// evidence reference (what was observed, plus collector-specific facts)
// as JSON.
type ComplianceAutoControlStatusRow struct {
	ID          uuid.UUID
	TenantID    uuid.UUID
	Framework   string
	ControlID   string
	Status      string
	CollectorID string
	Summary     string
	Source      string
	Details     json.RawMessage
	ObservedAt  time.Time
	RunID       uuid.UUID
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// ComplianceAutoEvidenceRow is one immutable evidence observation in the
// append-only history. It mirrors the status row but is never updated:
// every sweep appends a fresh row so the posture time series is durable.
type ComplianceAutoEvidenceRow struct {
	ID          uuid.UUID
	TenantID    uuid.UUID
	RunID       uuid.UUID
	Framework   string
	ControlID   string
	CollectorID string
	Status      string
	Summary     string
	Source      string
	Details     json.RawMessage
	ObservedAt  time.Time
	CreatedAt   time.Time
}

// ComplianceAutoFrameworkStateRow is the pre-aggregated per-framework
// posture summary the collector upserts at the end of each sweep so the
// dashboard can render a tenant's score without scanning every control.
type ComplianceAutoFrameworkStateRow struct {
	ID            uuid.UUID
	TenantID      uuid.UUID
	Framework     string
	ControlsTotal int
	ControlsPass  int
	ControlsFail  int
	ControlsNA    int
	LastRunID     uuid.UUID
	EvaluatedAt   time.Time
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// ComplianceAutoEvaluation is the complete result of one evaluation
// sweep for a tenant, applied atomically by ApplyEvaluation: the run
// summary, every control's latest status, every appended evidence
// observation, and the per-framework rollups. The run's id/created_at
// are assigned by the implementation; the RunID/LastRunID fields on the
// child rows are ignored on input and stamped with the newly created run
// id, so callers build the slices without knowing the run id in advance.
type ComplianceAutoEvaluation struct {
	Run        ComplianceAutoRunRow
	Statuses   []ComplianceAutoControlStatusRow
	Evidence   []ComplianceAutoEvidenceRow
	Frameworks []ComplianceAutoFrameworkStateRow
}

// ComplianceAutoRLSStatus is the result of probing whether row-level
// security is genuinely enforced for the database role the control plane
// queries as — not merely whether an application-role NAME is configured.
// RLS is only effective when the effective role is neither a superuser
// nor carries the BYPASSRLS attribute; either one silently disables every
// RLS policy regardless of how the tables are defined.
type ComplianceAutoRLSStatus struct {
	// Role is the effective database role (current_user) the probe ran
	// as — the same role tenant-scoped queries adopt via SET LOCAL ROLE.
	Role string
	// Superuser reports rolsuper: a superuser bypasses all RLS.
	Superuser bool
	// BypassRLS reports rolbypassrls: this role bypasses all RLS.
	BypassRLS bool
	// Enforced is the derived verdict: RLS is enforced iff the role is
	// neither a superuser nor a BYPASSRLS role.
	Enforced bool
}

// ComplianceAutoRepository is the persistence surface for the continuous
// compliance evidence service. Every method is tenant-scoped: drivers
// set the RLS GUC for the duration of each call, and the leader-only
// collector reaches across tenants via the system-role path.
type ComplianceAutoRepository interface {
	// ApplyEvaluation persists an entire sweep for a tenant atomically:
	// the run summary, all control statuses, all evidence rows, and the
	// per-framework rollups are committed in a single transaction.
	// Either the whole posture advances or none of it does, so a
	// mid-sweep failure never leaves a partially-updated posture. The
	// implementation assigns the run id server-side and stamps it onto
	// the child rows. It returns the stored run row.
	ApplyEvaluation(ctx context.Context, tenantID uuid.UUID, eval ComplianceAutoEvaluation) (ComplianceAutoRunRow, error)

	// RecordRun persists a completed sweep summary and returns the
	// stored row (with server-assigned id/created_at).
	RecordRun(ctx context.Context, tenantID uuid.UUID, run ComplianceAutoRunRow) (ComplianceAutoRunRow, error)
	// LatestRun returns the most recent run for a tenant. Returns
	// ErrNotFound when the tenant has never been evaluated.
	LatestRun(ctx context.Context, tenantID uuid.UUID) (ComplianceAutoRunRow, error)

	// UpsertControlStatus inserts or replaces the latest status row
	// for a (tenant, framework, control) triple. The unique index on
	// (tenant_id, framework, control_id) is the conflict target.
	UpsertControlStatus(ctx context.Context, tenantID uuid.UUID, row ComplianceAutoControlStatusRow) (ComplianceAutoControlStatusRow, error)
	// ListControlStatus returns the latest status rows for a tenant.
	// An empty framework returns every framework; a non-empty
	// framework filters to it. Ordered by (framework, control_id).
	ListControlStatus(ctx context.Context, tenantID uuid.UUID, framework string) ([]ComplianceAutoControlStatusRow, error)

	// AppendEvidence records one immutable evidence observation.
	AppendEvidence(ctx context.Context, tenantID uuid.UUID, row ComplianceAutoEvidenceRow) (ComplianceAutoEvidenceRow, error)
	// ListEvidence returns evidence observations for a tenant newest
	// first, bounded by limit (<=0 selects a sane default). An empty
	// controlID returns every control; a non-empty controlID filters.
	ListEvidence(ctx context.Context, tenantID uuid.UUID, controlID string, limit int) ([]ComplianceAutoEvidenceRow, error)

	// UpsertFrameworkState inserts or replaces the per-framework
	// rollup for a tenant. The unique index on (tenant_id, framework)
	// is the conflict target.
	UpsertFrameworkState(ctx context.Context, tenantID uuid.UUID, row ComplianceAutoFrameworkStateRow) (ComplianceAutoFrameworkStateRow, error)
	// ListFrameworkState returns every per-framework rollup for a
	// tenant, ordered by framework.
	ListFrameworkState(ctx context.Context, tenantID uuid.UUID) ([]ComplianceAutoFrameworkStateRow, error)

	// RLSRuntimeStatus probes the live database to confirm row-level
	// security is genuinely enforced for the role the control plane
	// queries as: that role must be neither a superuser nor a BYPASSRLS
	// role, since either silently disables every policy. It is
	// platform-wide rather than tenant-scoped — it reads pg_roles for
	// current_user under the system path — so the tenant-isolation
	// control can attest real enforcement instead of trusting that an
	// app-role name happens to be configured.
	RLSRuntimeStatus(ctx context.Context) (ComplianceAutoRLSStatus, error)
}
