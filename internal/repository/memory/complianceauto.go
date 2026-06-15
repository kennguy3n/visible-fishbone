package memory

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// ComplianceAutoRepository is the in-memory
// repository.ComplianceAutoRepository (WP6). It is deliberately
// self-contained — it holds its own maps and mutex rather than fields on
// the shared memory.Store — because the WP6 repository layer must add
// NEW files only and must not co-edit memory/store.go. Construct one
// instance per test and reuse it; tenant isolation is enforced by
// filtering on tenant_id in every method, mirroring Postgres RLS.
type ComplianceAutoRepository struct {
	mu             sync.RWMutex
	runs           map[uuid.UUID]repository.ComplianceAutoRunRow
	controlStatus  map[uuid.UUID]repository.ComplianceAutoControlStatusRow
	evidence       map[uuid.UUID]repository.ComplianceAutoEvidenceRow
	evidenceOrder  map[uuid.UUID]int64
	frameworkState map[uuid.UUID]repository.ComplianceAutoFrameworkStateRow
	statusByKey    map[controlStatusKey]uuid.UUID
	frameworkByKey map[frameworkStateKey]uuid.UUID
	rlsStatus      repository.ComplianceAutoRLSStatus
	seq            int64
}

type controlStatusKey struct {
	tenantID  uuid.UUID
	framework string
	controlID string
}

type frameworkStateKey struct {
	tenantID  uuid.UUID
	framework string
}

// NewComplianceAutoRepository returns an empty in-memory repository. The
// RLS probe defaults to "enforced" because the in-memory backend models a
// correctly-configured platform; tests flip it via SetRLSStatus.
func NewComplianceAutoRepository() *ComplianceAutoRepository {
	return &ComplianceAutoRepository{
		runs:           make(map[uuid.UUID]repository.ComplianceAutoRunRow),
		controlStatus:  make(map[uuid.UUID]repository.ComplianceAutoControlStatusRow),
		evidence:       make(map[uuid.UUID]repository.ComplianceAutoEvidenceRow),
		evidenceOrder:  make(map[uuid.UUID]int64),
		frameworkState: make(map[uuid.UUID]repository.ComplianceAutoFrameworkStateRow),
		statusByKey:    make(map[controlStatusKey]uuid.UUID),
		frameworkByKey: make(map[frameworkStateKey]uuid.UUID),
		rlsStatus:      repository.ComplianceAutoRLSStatus{Role: "sng_app", Enforced: true},
	}
}

var _ repository.ComplianceAutoRepository = (*ComplianceAutoRepository)(nil)

// nextOrder returns a monotonically increasing counter used to break
// ties between rows sharing an identical timestamp so ordering is
// deterministic (the Postgres backend tie-breaks on id; the memory
// backend cannot rely on uuid ordering matching insert order).
func (r *ComplianceAutoRepository) nextOrder() int64 {
	r.seq++
	return r.seq
}

// ApplyEvaluation persists an entire sweep under a single lock so a
// posture read never observes a half-applied sweep, mirroring the
// Postgres single-transaction guarantee. The run id is assigned here and
// stamped onto every child row; the upsert keying matches the per-method
// implementations so repeated sweeps converge to the same state.
func (r *ComplianceAutoRepository) ApplyEvaluation(_ context.Context, tenantID uuid.UUID, eval repository.ComplianceAutoEvaluation) (repository.ComplianceAutoRunRow, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now().UTC()

	run := eval.Run
	run.ID = uuid.New()
	run.TenantID = tenantID
	if run.CreatedAt.IsZero() {
		run.CreatedAt = now
	}
	r.runs[run.ID] = run

	for _, row := range eval.Statuses {
		row.TenantID = tenantID
		row.RunID = run.ID
		row.Details = cloneJSON(row.Details)
		key := controlStatusKey{tenantID: tenantID, framework: row.Framework, controlID: row.ControlID}
		if existingID, ok := r.statusByKey[key]; ok {
			prev := r.controlStatus[existingID]
			row.ID = prev.ID
			row.CreatedAt = prev.CreatedAt
			row.UpdatedAt = now
			r.controlStatus[existingID] = row
			continue
		}
		row.ID = uuid.New()
		if row.CreatedAt.IsZero() {
			row.CreatedAt = now
		}
		row.UpdatedAt = now
		r.controlStatus[row.ID] = row
		r.statusByKey[key] = row.ID
	}

	for _, row := range eval.Evidence {
		row.ID = uuid.New()
		row.TenantID = tenantID
		row.RunID = run.ID
		row.Details = cloneJSON(row.Details)
		if row.CreatedAt.IsZero() {
			row.CreatedAt = now
		}
		r.evidence[row.ID] = row
		r.evidenceOrder[row.ID] = r.nextOrder()
	}

	for _, row := range eval.Frameworks {
		row.TenantID = tenantID
		row.LastRunID = run.ID
		key := frameworkStateKey{tenantID: tenantID, framework: row.Framework}
		if existingID, ok := r.frameworkByKey[key]; ok {
			prev := r.frameworkState[existingID]
			row.ID = prev.ID
			row.CreatedAt = prev.CreatedAt
			row.UpdatedAt = now
			r.frameworkState[existingID] = row
			continue
		}
		row.ID = uuid.New()
		if row.CreatedAt.IsZero() {
			row.CreatedAt = now
		}
		row.UpdatedAt = now
		r.frameworkState[row.ID] = row
		r.frameworkByKey[key] = row.ID
	}

	return run, nil
}

// --- runs -----------------------------------------------------------------

func (r *ComplianceAutoRepository) RecordRun(_ context.Context, tenantID uuid.UUID, run repository.ComplianceAutoRunRow) (repository.ComplianceAutoRunRow, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	run.ID = uuid.New()
	run.TenantID = tenantID
	if run.CreatedAt.IsZero() {
		run.CreatedAt = time.Now().UTC()
	}
	r.runs[run.ID] = run
	return run, nil
}

func (r *ComplianceAutoRepository) LatestRun(_ context.Context, tenantID uuid.UUID) (repository.ComplianceAutoRunRow, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var latest repository.ComplianceAutoRunRow
	found := false
	for _, run := range r.runs {
		if run.TenantID != tenantID {
			continue
		}
		if !found || run.StartedAt.After(latest.StartedAt) {
			latest = run
			found = true
		}
	}
	if !found {
		return repository.ComplianceAutoRunRow{}, repository.ErrNotFound
	}
	return latest, nil
}

// --- control status -------------------------------------------------------

func (r *ComplianceAutoRepository) UpsertControlStatus(_ context.Context, tenantID uuid.UUID, row repository.ComplianceAutoControlStatusRow) (repository.ComplianceAutoControlStatusRow, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	row.TenantID = tenantID
	row.Details = cloneJSON(row.Details)
	now := time.Now().UTC()
	key := controlStatusKey{tenantID: tenantID, framework: row.Framework, controlID: row.ControlID}
	if existingID, ok := r.statusByKey[key]; ok {
		prev := r.controlStatus[existingID]
		row.ID = prev.ID
		row.CreatedAt = prev.CreatedAt
		row.UpdatedAt = now
		r.controlStatus[existingID] = row
		return row, nil
	}
	row.ID = uuid.New()
	if row.CreatedAt.IsZero() {
		row.CreatedAt = now
	}
	row.UpdatedAt = now
	r.controlStatus[row.ID] = row
	r.statusByKey[key] = row.ID
	return row, nil
}

func (r *ComplianceAutoRepository) ListControlStatus(_ context.Context, tenantID uuid.UUID, framework string) ([]repository.ComplianceAutoControlStatusRow, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []repository.ComplianceAutoControlStatusRow
	for _, row := range r.controlStatus {
		if row.TenantID != tenantID {
			continue
		}
		if framework != "" && row.Framework != framework {
			continue
		}
		row.Details = cloneJSON(row.Details)
		out = append(out, row)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Framework != out[j].Framework {
			return out[i].Framework < out[j].Framework
		}
		return out[i].ControlID < out[j].ControlID
	})
	return out, nil
}

// --- evidence -------------------------------------------------------------

func (r *ComplianceAutoRepository) AppendEvidence(_ context.Context, tenantID uuid.UUID, row repository.ComplianceAutoEvidenceRow) (repository.ComplianceAutoEvidenceRow, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	row.ID = uuid.New()
	row.TenantID = tenantID
	row.Details = cloneJSON(row.Details)
	if row.CreatedAt.IsZero() {
		row.CreatedAt = time.Now().UTC()
	}
	r.evidence[row.ID] = row
	r.evidenceOrder[row.ID] = r.nextOrder()
	return row, nil
}

func (r *ComplianceAutoRepository) ListEvidence(_ context.Context, tenantID uuid.UUID, controlID string, limit int) ([]repository.ComplianceAutoEvidenceRow, error) {
	if limit <= 0 {
		limit = repository.DefaultPageLimit
	}
	if limit > repository.MaxPageLimit {
		limit = repository.MaxPageLimit
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []repository.ComplianceAutoEvidenceRow
	for _, row := range r.evidence {
		if row.TenantID != tenantID {
			continue
		}
		if controlID != "" && row.ControlID != controlID {
			continue
		}
		row.Details = cloneJSON(row.Details)
		out = append(out, row)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].ObservedAt.Equal(out[j].ObservedAt) {
			return out[i].ObservedAt.After(out[j].ObservedAt)
		}
		return r.evidenceOrder[out[i].ID] > r.evidenceOrder[out[j].ID]
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// --- framework state ------------------------------------------------------

func (r *ComplianceAutoRepository) UpsertFrameworkState(_ context.Context, tenantID uuid.UUID, row repository.ComplianceAutoFrameworkStateRow) (repository.ComplianceAutoFrameworkStateRow, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	row.TenantID = tenantID
	now := time.Now().UTC()
	key := frameworkStateKey{tenantID: tenantID, framework: row.Framework}
	if existingID, ok := r.frameworkByKey[key]; ok {
		prev := r.frameworkState[existingID]
		row.ID = prev.ID
		row.CreatedAt = prev.CreatedAt
		row.UpdatedAt = now
		r.frameworkState[existingID] = row
		return row, nil
	}
	row.ID = uuid.New()
	if row.CreatedAt.IsZero() {
		row.CreatedAt = now
	}
	row.UpdatedAt = now
	r.frameworkState[row.ID] = row
	r.frameworkByKey[key] = row.ID
	return row, nil
}

func (r *ComplianceAutoRepository) ListFrameworkState(_ context.Context, tenantID uuid.UUID) ([]repository.ComplianceAutoFrameworkStateRow, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []repository.ComplianceAutoFrameworkStateRow
	for _, row := range r.frameworkState {
		if row.TenantID != tenantID {
			continue
		}
		out = append(out, row)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Framework < out[j].Framework
	})
	return out, nil
}

// --- runtime RLS probe ----------------------------------------------------

// SetRLSStatus overrides the RLS probe result the repository reports.
// Tests use it to drive the tenant-isolation collector both ways without
// a real database role.
func (r *ComplianceAutoRepository) SetRLSStatus(status repository.ComplianceAutoRLSStatus) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rlsStatus = status
}

// RLSRuntimeStatus returns the configured in-memory RLS probe result. The
// in-memory backend has no real Postgres roles, so it reports a settable
// fixture (RLS enforced by default) rather than querying anything.
func (r *ComplianceAutoRepository) RLSRuntimeStatus(_ context.Context) (repository.ComplianceAutoRLSStatus, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.rlsStatus, nil
}
