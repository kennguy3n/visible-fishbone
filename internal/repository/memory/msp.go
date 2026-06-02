package memory

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// MSPRepository is the memory-backed implementation of
// repository.MSPRepository. Mirrors the TenantRepository shape —
// MSP is a top-level entity, NOT tenant-scoped, so the same
// "clone-on-read, mutate under store.mu" pattern applies.
//
// The denormalised tenants.msp_id column is maintained by
// touching r.s.tenants directly under r.s.mu inside the
// AssignTenant / UnassignTenant flows; we do NOT need a separate
// TenantRepository handle because the in-memory store is the
// single source of truth and both repos share `s.mu`. Holding
// s.mu across the msp_tenants insert + tenants.msp_id update is
// what gives us atomicity (crash mid-flow cannot leave the two
// storage sites inconsistent).
type MSPRepository struct {
	s *Store
}

// NewMSPRepository binds a Store. The denormalised tenants.msp_id
// pointer is maintained under r.s.mu directly; see AssignTenant /
// UnassignTenant for the atomicity story.
func NewMSPRepository(s *Store) *MSPRepository {
	return &MSPRepository{s: s}
}

var _ repository.MSPRepository = (*MSPRepository)(nil)

// --- CRUD on msps --------------------------------------------------

func (r *MSPRepository) Create(ctx context.Context, m repository.MSP) (repository.MSP, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.MSP{}, err
	}
	if m.Slug == "" {
		return repository.MSP{}, repository.ErrInvalidArgument
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if m.ID == uuid.Nil {
		m.ID = uuid.New()
	}
	for _, existing := range r.s.msps {
		if existing.Slug == m.Slug && existing.DeletedAt == nil {
			return repository.MSP{}, repository.ErrConflict
		}
	}
	now := r.s.clock()
	m.CreatedAt = now
	m.UpdatedAt = now
	if m.Status == "" {
		m.Status = repository.MSPStatusActive
	}
	m.Settings = cloneJSON(m.Settings)
	r.s.msps[m.ID] = m
	return cloneMSP(m), nil
}

func (r *MSPRepository) Get(ctx context.Context, id uuid.UUID) (repository.MSP, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.MSP{}, err
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	m, ok := r.s.msps[id]
	if !ok {
		return repository.MSP{}, repository.ErrNotFound
	}
	return cloneMSP(m), nil
}

// GetBySlug returns the active (non-soft-deleted) MSP carrying the
// given slug. After a soft-delete + slug-reuse cycle the underlying
// map can hold two rows with the same slug — the tombstone (with
// DeletedAt != nil) and the new active row — because Create only
// enforces uniqueness among non-deleted rows (mirroring the postgres
// partial unique index `WHERE deleted_at IS NULL`). Go map iteration
// order is undefined, so a naive scan would non-deterministically
// return either the live or the tombstoned row. Filtering on
// DeletedAt == nil keeps the lookup deterministic and aligned with
// the postgres backend.
func (r *MSPRepository) GetBySlug(ctx context.Context, slug string) (repository.MSP, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.MSP{}, err
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	for _, m := range r.s.msps {
		if m.Slug == slug && m.DeletedAt == nil {
			return cloneMSP(m), nil
		}
	}
	return repository.MSP{}, repository.ErrNotFound
}

func (r *MSPRepository) List(ctx context.Context, page repository.Page) (repository.PageResult[repository.MSP], error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.PageResult[repository.MSP]{}, err
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	all := make([]repository.MSP, 0, len(r.s.msps))
	for _, m := range r.s.msps {
		all = append(all, cloneMSP(m))
	}
	sorted := sortByCreatedAtDesc(all,
		func(m repository.MSP) time.Time { return m.CreatedAt },
		func(m repository.MSP) uuid.UUID { return m.ID },
		page.Normalize().Order,
	)
	return paginate(sorted, page, func(m repository.MSP) cursor {
		return cursor{CreatedAt: m.CreatedAt, ID: m.ID}
	}), nil
}

func (r *MSPRepository) Update(ctx context.Context, id uuid.UUID, patch repository.MSPPatch) (repository.MSP, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.MSP{}, err
	}
	// Defense-in-depth: reject empty Name / Slug here even though the
	// HTTP handler already 400s on `{"name": ""}` / `{"slug": ""}`.
	// Round-8 of Devin Review caught that the previous behaviour
	// (silently dropping the empty value via `if *patch.X != ""`)
	// diverged from the postgres backend (which would bind the empty
	// string into the NOT NULL column). Both behaviours are wrong for
	// an internal caller bypassing the handler. Failing fast with
	// ErrInvalidArgument is now consistent across backends; see the
	// matching guard in internal/repository/postgres/msp.go:182-208 for
	// the rationale.
	if patch.Name != nil && *patch.Name == "" {
		return repository.MSP{}, repository.ErrInvalidArgument
	}
	if patch.Slug != nil && *patch.Slug == "" {
		return repository.MSP{}, repository.ErrInvalidArgument
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	existing, ok := r.s.msps[id]
	if !ok {
		return repository.MSP{}, repository.ErrNotFound
	}
	// Soft-delete immutability: refuse to PATCH a row whose
	// status has been moved to the terminal 'deleted' state.
	// Round-13 of Devin Review on PR #42 flagged the previous
	// behaviour (mutating fields on a soft-deleted MSP) as 🚩
	// inconsistent with the resurrection guard enforced by the
	// handler on status transitions — both code paths now treat
	// 'deleted' as terminal. The postgres backend enforces the
	// same invariant via the `AND deleted_at IS NULL` WHERE
	// clause on the UPDATE statement.
	if existing.Status == repository.MSPStatusDeleted {
		return repository.MSP{}, repository.ErrForbidden
	}
	if patch.Slug != nil && *patch.Slug != existing.Slug {
		for otherID, other := range r.s.msps {
			if otherID == id {
				continue
			}
			if other.Slug == *patch.Slug && other.DeletedAt == nil {
				return repository.MSP{}, repository.ErrConflict
			}
		}
		existing.Slug = *patch.Slug
	}
	if patch.Name != nil {
		existing.Name = *patch.Name
	}
	if patch.Status != nil && *patch.Status != "" {
		existing.Status = *patch.Status
	}
	if patch.Branding != nil {
		existing.Branding = *patch.Branding
	}
	if patch.Settings != nil {
		existing.Settings = cloneJSON(*patch.Settings)
	}
	existing.UpdatedAt = r.s.clock()
	r.s.msps[existing.ID] = existing
	return cloneMSP(existing), nil
}

func (r *MSPRepository) UpdateStatus(ctx context.Context, id uuid.UUID, status repository.MSPStatus) (repository.MSP, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.MSP{}, err
	}
	switch status {
	case repository.MSPStatusActive, repository.MSPStatusSuspended, repository.MSPStatusDeleted:
	default:
		return repository.MSP{}, repository.ErrInvalidArgument
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	existing, ok := r.s.msps[id]
	if !ok {
		return repository.MSP{}, repository.ErrNotFound
	}
	existing.Status = status
	existing.UpdatedAt = r.s.clock()
	if status == repository.MSPStatusDeleted && existing.DeletedAt == nil {
		t := r.s.clock()
		existing.DeletedAt = &t
	}
	r.s.msps[id] = existing
	return cloneMSP(existing), nil
}

// TransitionStatus atomically updates the MSP status while refusing
// to mutate a soft-deleted row. The store mutex serialises the
// precondition check (`existing.Status != deleted`) with the
// status write, eliminating the TOCTOU window present in a
// Get-then-UpdateStatus pair (round-13 of Devin Review on PR #42
// — BUG_0001).
//
// `to` is restricted to MSPStatusActive or MSPStatusSuspended; the
// terminal MSPStatusDeleted transition is owned by Delete()
// because it cascades msp_tenants + tenants.msp_id under the same
// mutex.
//
// Returns ErrForbidden if the row's current status is 'deleted',
// ErrNotFound if the MSP does not exist, ErrInvalidArgument on a
// `to=deleted` call (use Delete() instead).
func (r *MSPRepository) TransitionStatus(ctx context.Context, id uuid.UUID, to repository.MSPStatus) (repository.MSP, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.MSP{}, err
	}
	switch to {
	case repository.MSPStatusActive, repository.MSPStatusSuspended:
	default:
		return repository.MSP{}, repository.ErrInvalidArgument
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	existing, ok := r.s.msps[id]
	if !ok {
		return repository.MSP{}, repository.ErrNotFound
	}
	if existing.Status == repository.MSPStatusDeleted {
		return repository.MSP{}, repository.ErrForbidden
	}
	existing.Status = to
	existing.UpdatedAt = r.s.clock()
	r.s.msps[id] = existing
	return cloneMSP(existing), nil
}

// Delete soft-deletes the MSP and cascades by clearing the
// denormalised tenants.msp_id pointer for every tenant whose
// owner binding is this MSP. The msp_tenants rows are also
// removed so the postgres ON DELETE CASCADE shape is mirrored.
//
// Returns ErrForbidden if the MSP is already deleted, ErrNotFound
// if it does not exist.
func (r *MSPRepository) Delete(ctx context.Context, id uuid.UUID) error {
	if err := errCtxIfNeeded(ctx); err != nil {
		return err
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	existing, ok := r.s.msps[id]
	if !ok {
		return repository.ErrNotFound
	}
	if existing.Status == repository.MSPStatusDeleted {
		return repository.ErrForbidden
	}
	// Cascade: remove every msp_tenants row for this MSP, and
	// clear the denormalised tenants.msp_id pointer on every
	// tenant that pointed at this MSP.
	for key, b := range r.s.mspTenants {
		if b.MSPID == id {
			delete(r.s.mspTenants, key)
		}
	}
	for tid, t := range r.s.tenants {
		if t.MSPID != nil && *t.MSPID == id {
			t.MSPID = nil
			t.UpdatedAt = r.s.clock()
			r.s.tenants[tid] = t
		}
	}
	existing.Status = repository.MSPStatusDeleted
	existing.UpdatedAt = r.s.clock()
	if existing.DeletedAt == nil {
		t := r.s.clock()
		existing.DeletedAt = &t
	}
	r.s.msps[id] = existing
	return nil
}

// --- Binding operations -------------------------------------------

// AssignTenant inserts (or replaces) the (msp, tenant) binding.
// When relationship is Owner, it also removes any pre-existing
// owner binding for the tenant (the partial UNIQUE index in
// migration 015 enforces at most one owner per tenant) and
// updates the denormalised tenants.msp_id pointer.
func (r *MSPRepository) AssignTenant(
	ctx context.Context,
	mspID, tenantID uuid.UUID,
	relationship repository.MSPRelationship,
	actor *uuid.UUID,
) (repository.MSPTenantBinding, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.MSPTenantBinding{}, err
	}
	if mspID == uuid.Nil || tenantID == uuid.Nil {
		return repository.MSPTenantBinding{}, repository.ErrInvalidArgument
	}
	if !relationship.IsValid() {
		return repository.MSPTenantBinding{}, repository.ErrInvalidArgument
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if _, ok := r.s.msps[mspID]; !ok {
		return repository.MSPTenantBinding{}, repository.ErrNotFound
	}
	if _, ok := r.s.tenants[tenantID]; !ok {
		return repository.MSPTenantBinding{}, repository.ErrNotFound
	}
	if relationship == repository.MSPRelationshipOwner {
		// Remove any existing owner binding for this tenant; the
		// partial UNIQUE index in migration 015 enforces at most
		// one owner per tenant.
		for key, b := range r.s.mspTenants {
			if b.TenantID == tenantID && b.Relationship == repository.MSPRelationshipOwner && key.MSPID != mspID {
				delete(r.s.mspTenants, key)
			}
		}
	}
	now := r.s.clock()
	binding := repository.MSPTenantBinding{
		MSPID:        mspID,
		TenantID:     tenantID,
		Relationship: relationship,
		CreatedAt:    now,
	}
	if actor != nil {
		v := *actor
		binding.CreatedBy = &v
	}
	r.s.mspTenants[mspTenantKey{MSPID: mspID, TenantID: tenantID}] = binding
	if relationship == repository.MSPRelationshipOwner {
		t := r.s.tenants[tenantID]
		id := mspID
		t.MSPID = &id
		t.UpdatedAt = now
		r.s.tenants[tenantID] = t
	}
	out := binding
	if binding.CreatedBy != nil {
		v := *binding.CreatedBy
		out.CreatedBy = &v
	}
	return out, nil
}

// UnassignTenant removes the (msp, tenant) binding. If the binding
// was an owner, the denormalised tenants.msp_id is also cleared.
func (r *MSPRepository) UnassignTenant(ctx context.Context, mspID, tenantID uuid.UUID) error {
	if err := errCtxIfNeeded(ctx); err != nil {
		return err
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	key := mspTenantKey{MSPID: mspID, TenantID: tenantID}
	binding, ok := r.s.mspTenants[key]
	if !ok {
		return repository.ErrNotFound
	}
	delete(r.s.mspTenants, key)
	if binding.Relationship == repository.MSPRelationshipOwner {
		t, ok := r.s.tenants[tenantID]
		if ok && t.MSPID != nil && *t.MSPID == mspID {
			t.MSPID = nil
			t.UpdatedAt = r.s.clock()
			r.s.tenants[tenantID] = t
		}
	}
	return nil
}

func (r *MSPRepository) ListTenants(ctx context.Context, mspID uuid.UUID, page repository.Page) (repository.PageResult[repository.MSPTenantBinding], error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.PageResult[repository.MSPTenantBinding]{}, err
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	all := make([]repository.MSPTenantBinding, 0)
	for key, b := range r.s.mspTenants {
		if key.MSPID == mspID {
			all = append(all, cloneBinding(b))
		}
	}
	sorted := sortByCreatedAtDesc(all,
		func(b repository.MSPTenantBinding) time.Time { return b.CreatedAt },
		func(b repository.MSPTenantBinding) uuid.UUID { return b.TenantID },
		page.Normalize().Order,
	)
	return paginate(sorted, page, func(b repository.MSPTenantBinding) cursor {
		return cursor{CreatedAt: b.CreatedAt, ID: b.TenantID}
	}), nil
}

func (r *MSPRepository) ListBindings(ctx context.Context, tenantID uuid.UUID) ([]repository.MSPTenantBinding, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return nil, err
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	out := make([]repository.MSPTenantBinding, 0)
	for key, b := range r.s.mspTenants {
		if key.TenantID == tenantID {
			out = append(out, cloneBinding(b))
		}
	}
	return out, nil
}

// cloneMSP returns a deep copy of an MSP row so callers cannot
// mutate stored bytes via the returned Settings RawMessage.
func cloneMSP(m repository.MSP) repository.MSP {
	out := m
	out.Settings = cloneJSON(m.Settings)
	if m.DeletedAt != nil {
		t := *m.DeletedAt
		out.DeletedAt = &t
	}
	return out
}

// cloneBinding returns a deep copy so callers cannot mutate the
// stored CreatedBy pointer.
func cloneBinding(b repository.MSPTenantBinding) repository.MSPTenantBinding {
	out := b
	if b.CreatedBy != nil {
		v := *b.CreatedBy
		out.CreatedBy = &v
	}
	return out
}
