package memory

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// CASBNoOpsStore is the in-memory backend for the CASB NoOps pipeline
// (it satisfies casb.NoOpsStore): per-tenant app classifications, action
// policies, the append-only audit trail and the digest cursor. It is
// the test and single-node counterpart to the postgres implementation
// and mirrors its tenant isolation by filtering every read/write on
// tenant_id (the postgres path relies on RLS instead).
//
// It depends only on the repository row types (not the casb service
// package), so it does not form the casb -> policy -> middleware ->
// postgres -> casb import cycle. The casb.NoOpsStore interface is
// satisfied structurally; a compile-time assertion lives in the casb
// test package.
//
// It is self-contained — it holds its own mutex and maps rather than
// extending the shared Store — so it can be constructed standalone
// without touching store.go.
type CASBNoOpsStore struct {
	mu sync.RWMutex

	// classifications keyed by (tenant, app name).
	classifications map[classKey]repository.AppClassification
	// policies keyed by tenant.
	policies map[uuid.UUID]repository.ActionPolicy
	// actions is the append-only log, in insertion order.
	actions []repository.CASBAppAction
	// digest cursor keyed by tenant.
	digest map[uuid.UUID]repository.DigestState

	now func() time.Time
}

type classKey struct {
	tenant uuid.UUID
	app    string
}

// NewCASBNoOpsStore constructs an empty in-memory NoOps store.
func NewCASBNoOpsStore() *CASBNoOpsStore {
	return &CASBNoOpsStore{
		classifications: make(map[classKey]repository.AppClassification),
		policies:        make(map[uuid.UUID]repository.ActionPolicy),
		digest:          make(map[uuid.UUID]repository.DigestState),
		now:             func() time.Time { return time.Now().UTC() },
	}
}

// SetClock overrides the wall clock (tests).
func (r *CASBNoOpsStore) SetClock(fn func() time.Time) {
	if fn != nil {
		r.now = fn
	}
}

// --- classifications ------------------------------------------------------

func (r *CASBNoOpsStore) UpsertClassification(ctx context.Context, tenantID uuid.UUID, c repository.AppClassification) (repository.AppClassification, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.AppClassification{}, err
	}
	if tenantID == uuid.Nil || c.AppName == "" {
		return repository.AppClassification{}, repository.ErrInvalidArgument
	}
	c.TenantID = tenantID
	if c.ClassifiedAt.IsZero() {
		c.ClassifiedAt = r.now()
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.classifications[classKey{tenant: tenantID, app: c.AppName}] = c
	return c, nil
}

func (r *CASBNoOpsStore) GetClassification(ctx context.Context, tenantID uuid.UUID, appName string) (repository.AppClassification, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.AppClassification{}, err
	}
	if tenantID == uuid.Nil || appName == "" {
		return repository.AppClassification{}, repository.ErrInvalidArgument
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	c, ok := r.classifications[classKey{tenant: tenantID, app: appName}]
	if !ok {
		return repository.AppClassification{}, repository.ErrNotFound
	}
	return c, nil
}

func (r *CASBNoOpsStore) ListClassifications(ctx context.Context, tenantID uuid.UUID) ([]repository.AppClassification, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return nil, err
	}
	if tenantID == uuid.Nil {
		return nil, repository.ErrInvalidArgument
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []repository.AppClassification
	for k, v := range r.classifications {
		if k.tenant == tenantID {
			out = append(out, v)
		}
	}
	// Stable order (app name) so callers and tests see a deterministic
	// list regardless of map iteration order.
	sort.Slice(out, func(i, j int) bool { return out[i].AppName < out[j].AppName })
	return out, nil
}

// --- action policy --------------------------------------------------------

func (r *CASBNoOpsStore) GetActionPolicy(ctx context.Context, tenantID uuid.UUID) (repository.ActionPolicy, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.ActionPolicy{}, err
	}
	if tenantID == uuid.Nil {
		return repository.ActionPolicy{}, repository.ErrInvalidArgument
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.policies[tenantID]
	if !ok {
		return repository.ActionPolicy{}, repository.ErrNotFound
	}
	return p, nil
}

func (r *CASBNoOpsStore) UpsertActionPolicy(ctx context.Context, tenantID uuid.UUID, p repository.ActionPolicy) (repository.ActionPolicy, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.ActionPolicy{}, err
	}
	if tenantID == uuid.Nil {
		return repository.ActionPolicy{}, repository.ErrInvalidArgument
	}
	p.TenantID = tenantID
	p.UpdatedAt = r.now()
	r.mu.Lock()
	defer r.mu.Unlock()
	r.policies[tenantID] = p
	return p, nil
}

// --- audit trail ----------------------------------------------------------

func (r *CASBNoOpsStore) AppendAction(ctx context.Context, tenantID uuid.UUID, a repository.CASBAppAction) (repository.CASBAppAction, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.CASBAppAction{}, err
	}
	if tenantID == uuid.Nil || a.AppName == "" {
		return repository.CASBAppAction{}, repository.ErrInvalidArgument
	}
	a.TenantID = tenantID
	if a.ID == uuid.Nil {
		a.ID = uuid.New()
	}
	if a.CreatedAt.IsZero() {
		a.CreatedAt = r.now()
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.actions = append(r.actions, a)
	return a, nil
}

func (r *CASBNoOpsStore) ListActionsSince(ctx context.Context, tenantID uuid.UUID, since time.Time) ([]repository.CASBAppAction, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return nil, err
	}
	if tenantID == uuid.Nil {
		return nil, repository.ErrInvalidArgument
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []repository.CASBAppAction
	for _, a := range r.actions {
		if a.TenantID == tenantID && a.CreatedAt.After(since) {
			out = append(out, a)
		}
	}
	// Oldest first (created_at, then id as a stable tiebreaker for
	// actions sharing a timestamp).
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].ID.String() < out[j].ID.String()
		}
		return out[i].CreatedAt.Before(out[j].CreatedAt)
	})
	return out, nil
}

func (r *CASBNoOpsStore) ListActions(ctx context.Context, tenantID uuid.UUID, limit int) ([]repository.CASBAppAction, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return nil, err
	}
	if tenantID == uuid.Nil {
		return nil, repository.ErrInvalidArgument
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []repository.CASBAppAction
	for _, a := range r.actions {
		if a.TenantID == tenantID {
			out = append(out, a)
		}
	}
	// Newest first.
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].ID.String() > out[j].ID.String()
		}
		return out[i].CreatedAt.After(out[j].CreatedAt)
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// --- digest cursor --------------------------------------------------------

func (r *CASBNoOpsStore) GetDigestState(ctx context.Context, tenantID uuid.UUID) (repository.DigestState, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.DigestState{}, err
	}
	if tenantID == uuid.Nil {
		return repository.DigestState{}, repository.ErrInvalidArgument
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	st, ok := r.digest[tenantID]
	if !ok {
		return repository.DigestState{}, repository.ErrNotFound
	}
	return st, nil
}

func (r *CASBNoOpsStore) UpsertDigestState(ctx context.Context, tenantID uuid.UUID, st repository.DigestState) (repository.DigestState, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.DigestState{}, err
	}
	if tenantID == uuid.Nil {
		return repository.DigestState{}, repository.ErrInvalidArgument
	}
	st.TenantID = tenantID
	r.mu.Lock()
	defer r.mu.Unlock()
	r.digest[tenantID] = st
	return st, nil
}
