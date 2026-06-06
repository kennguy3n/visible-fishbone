package memory

import (
	"context"
	"sort"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// defaultResidencyListLimit bounds List when the caller passes a
// non-positive limit, mirroring the Postgres implementation.
const defaultResidencyListLimit = 100

// validResidencyPlanes mirrors the Postgres CHECK constraint in
// migration 046 (plane IN ('telemetry','policy_bundle','cold_storage')).
// Keeping the set here makes the memory store a faithful test double:
// a Plane value Postgres would reject is rejected here too, so a test
// can't pass against memory and fail against Postgres.
var validResidencyPlanes = map[string]struct{}{
	"telemetry":     {},
	"policy_bundle": {},
	"cold_storage":  {},
}

// ResidencyAuditRepository is the memory-backed implementation of
// repository.ResidencyAuditRepository. Tenant isolation is enforced by
// filtering on tenant_id, mirroring the Postgres RLS policy.
type ResidencyAuditRepository struct{ s *Store }

// NewResidencyAuditRepository binds the Store to the interface.
func NewResidencyAuditRepository(s *Store) *ResidencyAuditRepository {
	return &ResidencyAuditRepository{s: s}
}

var _ repository.ResidencyAuditRepository = (*ResidencyAuditRepository)(nil)

func (r *ResidencyAuditRepository) Record(ctx context.Context, tenantID uuid.UUID, e repository.ResidencyAuditEntry) (repository.ResidencyAuditEntry, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.ResidencyAuditEntry{}, err
	}
	if tenantID == uuid.Nil || e.Plane == "" || e.DesignatedRegion == "" {
		return repository.ResidencyAuditEntry{}, repository.ErrInvalidArgument
	}
	if _, ok := validResidencyPlanes[e.Plane]; !ok {
		return repository.ResidencyAuditEntry{}, repository.ErrInvalidArgument
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	e.TenantID = tenantID
	if e.ID == uuid.Nil {
		e.ID = uuid.New()
	}
	if e.CreatedAt.IsZero() {
		e.CreatedAt = r.s.clock()
	}
	r.s.residencyAudit[e.ID] = e
	return e, nil
}

func (r *ResidencyAuditRepository) List(ctx context.Context, tenantID uuid.UUID, limit int) ([]repository.ResidencyAuditEntry, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return nil, err
	}
	if limit <= 0 {
		limit = defaultResidencyListLimit
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	var out []repository.ResidencyAuditEntry
	for _, e := range r.s.residencyAudit {
		if e.TenantID == tenantID {
			out = append(out, e)
		}
	}
	// Newest first; ID as a stable tiebreaker for equal timestamps so
	// tests are deterministic.
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.After(out[j].CreatedAt)
		}
		return out[i].ID.String() < out[j].ID.String()
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}
