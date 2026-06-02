package memory

import (
	"context"
	"encoding/json"
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
	// Default nil/empty Settings to "{}" so memory and postgres
	// both return a non-null JSON object on Get/Create
	// responses. Without this, a caller that omits Settings on
	// Create receives `null` from the memory backend but `{}` from
	// postgres (which has the same default at
	// internal/repository/postgres/msp.go:68-70). That cross-backend
	// divergence trips SDK code-gen and unmarshalling for clients
	// that expect Settings to always be a JSON object. Round-20 of
	// Devin Review on PR #42 (ANALYSIS_0001) flagged this; the fix
	// is to mirror the postgres default here so the response shape
	// is identical regardless of which backend handled the request.
	if len(m.Settings) == 0 {
		m.Settings = json.RawMessage(`{}`)
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

func (r *MSPRepository) List(ctx context.Context, page repository.Page, filter repository.MSPListFilter) (repository.PageResult[repository.MSP], error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.PageResult[repository.MSP]{}, err
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	all := make([]repository.MSP, 0, len(r.s.msps))
	for _, m := range r.s.msps {
		// Round-17 of Devin Review on PR #42 — filter
		// soft-deleted rows unless the admin caller opts in.
		// The lifecycle invariant is `(Status==Deleted ⇔
		// DeletedAt != nil)`, so either check is sufficient;
		// we check both for defence-in-depth against any
		// in-memory state that violates the invariant.
		if !filter.IncludeDeleted && (m.Status == repository.MSPStatusDeleted || m.DeletedAt != nil) {
			continue
		}
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
	// Reject `patch.Status = MSPStatusDeleted` at the repo boundary.
	// The handler already 400s on this via validMSPCreateStatus, but
	// an internal caller (admin tool, migration script, future RPC)
	// that constructs `MSPPatch{Status: &MSPStatusDeleted}` would
	// otherwise reach the SET clause below, write `status='deleted'`
	// onto the row, and skip the `deleted_at` stamping that Delete()
	// performs as part of the cascade. That produces the corrupt
	// `(status='deleted', deleted_at IS NULL)` state the lifecycle
	// invariant is designed to prevent, AND leaves msp_tenants /
	// tenants.msp_id pointing at the now-deleted MSP (Delete() is the
	// only path that cascades). Round-21 of Devin Review on PR #42
	// (ANALYSIS_0001) flagged this. The legal transition into
	// `deleted` is Delete(); the legal transitions to active /
	// suspended go through TransitionStatus. Both backends now refuse
	// `patch.Status='deleted'` with ErrInvalidArgument so the gap
	// closes regardless of which backend a caller hits.
	if patch.Status != nil && *patch.Status == repository.MSPStatusDeleted {
		return repository.MSP{}, repository.ErrInvalidArgument
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	existing, ok := r.s.msps[id]
	if !ok {
		return repository.MSP{}, repository.ErrNotFound
	}
	// Soft-delete immutability (defense-in-depth, round-14 of Devin
	// Review on PR #42 — ANALYSIS_0002): refuse to PATCH a row whose
	// status is 'deleted' OR whose deleted_at is set. Under the
	// lifecycle invariant `(status='deleted' ⇔ deleted_at != NULL)`
	// these two predicates are logically equivalent, but a hypothetical
	// corrupt row (e.g. status='deleted' with deleted_at IS NULL, or
	// vice versa) would otherwise bypass exactly one of the backends.
	// Round-13 introduced the `status == deleted` half of this guard;
	// round-14 mirrors the additional `deleted_at != nil` check so
	// postgres and memory enforce parity against the same failure
	// modes. The postgres backend has the matching `WHERE status <>
	// 'deleted' AND deleted_at IS NULL` clause on its UPDATE
	// statement.
	if existing.Status == repository.MSPStatusDeleted || existing.DeletedAt != nil {
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
	// Resurrection guard (round-17 of Devin Review on PR #42 —
	// ANALYSIS_0005). The handler-narrow MSPService interface
	// intentionally does not surface UpdateStatus, but the method
	// remains on the public MSPRepository interface for use by
	// admin tools / migrations. Without a guard here, an internal
	// caller could resurrect a soft-deleted row by writing
	// status='active' on top of `deleted_at != NULL`, producing
	// the corrupt (status='active', deleted_at != NULL) state that
	// breaks the lifecycle invariant `(status='deleted' ⇔
	// deleted_at != NULL)` and consequently breaks the partial
	// unique index on slug (postgres) / the slug uniqueness scan
	// (memory). The legal transition into deleted runs through
	// Delete() — which cascades msp_tenants + clears the
	// denormalised tenants.msp_id pointer — and the legal
	// transitions OUT of deleted... do not exist (deleted is
	// terminal by design). Refuse any UpdateStatus call that
	// targets a row whose Status or DeletedAt observe the deleted
	// state. Matched by the postgres backend's `WHERE status <>
	// 'deleted' AND deleted_at IS NULL` precondition on its UPDATE
	// statement.
	if existing.Status == repository.MSPStatusDeleted || existing.DeletedAt != nil {
		return repository.MSP{}, repository.ErrForbidden
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
	// Defense-in-depth (round-19 of Devin Review on PR #42 —
	// ANALYSIS_0002). Under the lifecycle invariant
	// `(Status==Deleted ⇔ DeletedAt != nil)` the Status check is
	// sufficient, but Update() checks BOTH predicates for parity
	// against any hypothetical corrupt row (status='deleted'
	// with deleted_at IS NULL, or vice versa — e.g. produced by
	// a partial migration or a buggy admin tool). Mirror the
	// belt-and-suspenders shape here so an internal caller using
	// TransitionStatus observes the same refusal regardless of
	// which side of the invariant the corruption manifests on.
	// Matched by the postgres backend's `WHERE status <>
	// 'deleted' AND deleted_at IS NULL` precondition.
	if existing.Status == repository.MSPStatusDeleted || existing.DeletedAt != nil {
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
	existing, ok := r.s.msps[mspID]
	if !ok {
		return repository.MSPTenantBinding{}, repository.ErrNotFound
	}
	// Reject binding creation against a soft-deleted MSP. Without
	// this guard the map lookup above surfaces tombstoned rows
	// (Status='deleted' with DeletedAt!=nil) as live, letting an
	// operator with a stale role grant race a concurrent Delete and
	// land a fresh binding on a row that is already invariant-broken
	// (`Delete` cascades msp_tenants and clears tenants.msp_id, but
	// can't rewind a write that hasn't happened yet). Update() and
	// TransitionStatus() both filter soft-deletes — AssignTenant was
	// the only writer in the MSP surface that didn't. Round-20 of
	// Devin Review on PR #42 (ANALYSIS_0002) flagged this; the
	// postgres mirror adds the same `AND deleted_at IS NULL`
	// predicate to its pre-flight check.
	if existing.DeletedAt != nil || existing.Status == repository.MSPStatusDeleted {
		return repository.MSPTenantBinding{}, repository.ErrForbidden
	}
	if _, ok := r.s.tenants[tenantID]; !ok {
		return repository.MSPTenantBinding{}, repository.ErrNotFound
	}
	bindingKey := mspTenantKey{MSPID: mspID, TenantID: tenantID}
	// Capture the previous relationship (if any) before the upsert so
	// we can correctly cascade a downgrade away from `owner` to the
	// denormalised `tenants.msp_id` pointer below. Round-14 of Devin
	// Review on PR #42 (ANALYSIS_0003) flagged that without this
	// lookup an `AssignTenant(mspID, tenantID, co_manager)` after a
	// prior `owner` binding for the same pair would leave the join
	// table reading `co_manager` while the denormalised column still
	// pointed at this MSP — a cross-storage-site drift.
	prev, hadPrev := r.s.mspTenants[bindingKey]
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
	r.s.mspTenants[bindingKey] = binding
	switch {
	case relationship == repository.MSPRelationshipOwner:
		t := r.s.tenants[tenantID]
		id := mspID
		t.MSPID = &id
		t.UpdatedAt = now
		r.s.tenants[tenantID] = t
	case hadPrev && prev.Relationship == repository.MSPRelationshipOwner:
		// Downgrade: the same (msp, tenant) binding flipped from
		// owner to a non-owner relationship. Clear the
		// denormalised pointer if it still references this MSP so
		// the join table and `tenants.msp_id` stay consistent.
		// The pointer is only cleared when it still names this
		// MSP — if some other MSP owner-bound this tenant in
		// between (unlikely under normal flows; the partial
		// UNIQUE index would block it for owner relationships)
		// we must not stomp their pointer.
		t := r.s.tenants[tenantID]
		if t.MSPID != nil && *t.MSPID == mspID {
			t.MSPID = nil
			t.UpdatedAt = now
			r.s.tenants[tenantID] = t
		}
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
