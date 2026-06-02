package memory

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// TenantRepository is the memory-backed TenantRepository
// implementation. Constructed via NewTenantRepository so callers
// always go through a typed constructor (avoids hand-typing the
// Store reference everywhere).
type TenantRepository struct{ s *Store }

// NewTenantRepository binds a Store to the TenantRepository interface.
func NewTenantRepository(s *Store) *TenantRepository { return &TenantRepository{s: s} }

// Compile-time assertion the type satisfies the interface.
var _ repository.TenantRepository = (*TenantRepository)(nil)

func (r *TenantRepository) Create(ctx context.Context, t repository.Tenant) (repository.Tenant, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.Tenant{}, err
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()

	if t.ID == uuid.Nil {
		t.ID = uuid.New()
	}
	if t.Slug == "" {
		return repository.Tenant{}, repository.ErrInvalidArgument
	}
	for _, existing := range r.s.tenants {
		if existing.Slug == t.Slug && existing.DeletedAt == nil {
			return repository.Tenant{}, repository.ErrConflict
		}
	}
	now := r.s.clock()
	t.CreatedAt = now
	t.UpdatedAt = now
	if t.Status == "" {
		t.Status = repository.TenantStatusActive
	}
	// Defensive clone before storing so a caller mutating their
	// own t.Settings slice after Create returns cannot corrupt the
	// row we just persisted (the cloneJSON here owns the backing
	// array on the stored row).
	t.Settings = cloneJSON(t.Settings)
	r.s.tenants[t.ID] = t
	// Defensive clone on the way out so the returned value has
	// independent backing arrays for Settings + freshly-allocated
	// MSPID / DeletedAt pointers — matching the cloneTenant pattern
	// applied to Get / GetBySlug / List / Update / UpdateStatus /
	// TransitionStatus / Delete / UpdateSettingsKey /
	// DeleteSettingsKey. Without this clone, a caller mutating the
	// returned Tenant.Settings (e.g. `created.Settings[0]^=0xff`)
	// would corrupt the in-memory store because both sides shared
	// the post-cloneJSON backing array. Round-18 of Devin Review on
	// PR #42 (ANALYSIS_0003) flagged the asymmetry vs every other
	// write path on this repo.
	return cloneTenant(t), nil
}

// cloneTenant returns a deep copy of the given tenant. All
// pointer-typed fields (MSPID, DeletedAt) and the JSONB Settings
// blob are allocated fresh so a caller mutating any field of the
// returned value cannot corrupt the stored row. Centralising the
// clone avoids the latent defensiveness gaps Devin Review flagged
// where Get cloned Settings but left *uuid.UUID / *time.Time
// pointers shared with the in-memory store.
func cloneTenant(t repository.Tenant) repository.Tenant {
	t.Settings = cloneJSON(t.Settings)
	if t.MSPID != nil {
		mspID := *t.MSPID
		t.MSPID = &mspID
	}
	if t.DeletedAt != nil {
		ts := *t.DeletedAt
		t.DeletedAt = &ts
	}
	return t
}

func (r *TenantRepository) Get(ctx context.Context, id uuid.UUID) (repository.Tenant, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.Tenant{}, err
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	t, ok := r.s.tenants[id]
	if !ok {
		return repository.Tenant{}, repository.ErrNotFound
	}
	return cloneTenant(t), nil
}

func (r *TenantRepository) GetBySlug(ctx context.Context, slug string) (repository.Tenant, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.Tenant{}, err
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	for _, t := range r.s.tenants {
		if t.Slug == slug {
			return cloneTenant(t), nil
		}
	}
	return repository.Tenant{}, repository.ErrNotFound
}

func (r *TenantRepository) List(ctx context.Context, page repository.Page) (repository.PageResult[repository.Tenant], error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.PageResult[repository.Tenant]{}, err
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	all := make([]repository.Tenant, 0, len(r.s.tenants))
	for _, t := range r.s.tenants {
		all = append(all, cloneTenant(t))
	}
	sorted := sortByCreatedAtDesc(all,
		func(t repository.Tenant) time.Time { return t.CreatedAt },
		func(t repository.Tenant) uuid.UUID { return t.ID },
		page.Normalize().Order,
	)
	return paginate(sorted, page, func(t repository.Tenant) cursor {
		return cursor{CreatedAt: t.CreatedAt, ID: t.ID}
	}), nil
}

func (r *TenantRepository) Update(ctx context.Context, id uuid.UUID, patch repository.TenantPatch) (repository.Tenant, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.Tenant{}, err
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	existing, ok := r.s.tenants[id]
	if !ok {
		return repository.Tenant{}, repository.ErrNotFound
	}
	if patch.Slug != nil && *patch.Slug != "" && *patch.Slug != existing.Slug {
		for otherID, other := range r.s.tenants {
			if otherID == id {
				continue
			}
			if other.Slug == *patch.Slug && other.DeletedAt == nil {
				return repository.Tenant{}, repository.ErrConflict
			}
		}
		existing.Slug = *patch.Slug
	}
	if patch.Name != nil && *patch.Name != "" {
		existing.Name = *patch.Name
	}
	// Region is intentionally allowed to be cleared (zero value
	// applied when the caller passes a non-nil *string of ""), so
	// no zero-value guard here. See the TenantPatch docstring.
	if patch.Region != nil {
		existing.Region = *patch.Region
	}
	if patch.Tier != nil && *patch.Tier != "" {
		existing.Tier = *patch.Tier
	}
	if patch.Settings != nil {
		existing.Settings = cloneJSON(*patch.Settings)
	}
	if patch.Status != nil && *patch.Status != "" {
		existing.Status = *patch.Status
	}
	existing.UpdatedAt = r.s.clock()
	r.s.tenants[existing.ID] = existing
	return cloneTenant(existing), nil
}

// UpdateSettingsKey atomically merges `value` into the tenants.settings
// JSONB document at top-level `key`. The store mutex is held across
// the unmarshal → mutate → marshal → write so concurrent callers
// cannot lose updates the way a service-side RMW could. Round-17 of
// Devin Review on PR #42 (ANALYSIS_0003) flagged the lost-update
// race that motivated this primitive. Returns ErrNotFound if the
// tenant row does not exist.
func (r *TenantRepository) UpdateSettingsKey(ctx context.Context, id uuid.UUID, key string, value json.RawMessage) (repository.Tenant, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.Tenant{}, err
	}
	if key == "" {
		return repository.Tenant{}, repository.ErrInvalidArgument
	}
	// Validate `value` is valid JSON before we hold the lock so a
	// malformed payload from a buggy caller does not park inside
	// the critical section.
	if !json.Valid(value) {
		return repository.Tenant{}, fmt.Errorf("update settings key %q: %w", key, repository.ErrInvalidArgument)
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	existing, ok := r.s.tenants[id]
	if !ok {
		return repository.Tenant{}, repository.ErrNotFound
	}
	settings := map[string]json.RawMessage{}
	if len(existing.Settings) > 0 && string(existing.Settings) != "null" {
		if err := json.Unmarshal(existing.Settings, &settings); err != nil {
			return repository.Tenant{}, fmt.Errorf("update settings key %q: decode: %w", key, err)
		}
	}
	settings[key] = append(json.RawMessage(nil), value...)
	encoded, err := json.Marshal(settings)
	if err != nil {
		return repository.Tenant{}, fmt.Errorf("update settings key %q: encode: %w", key, err)
	}
	existing.Settings = encoded
	existing.UpdatedAt = r.s.clock()
	r.s.tenants[existing.ID] = existing
	return cloneTenant(existing), nil
}

// DeleteSettingsKey atomically removes top-level `key` from
// tenants.settings. Same atomicity guarantees as UpdateSettingsKey.
// A no-op for keys not present.
func (r *TenantRepository) DeleteSettingsKey(ctx context.Context, id uuid.UUID, key string) (repository.Tenant, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.Tenant{}, err
	}
	if key == "" {
		return repository.Tenant{}, repository.ErrInvalidArgument
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	existing, ok := r.s.tenants[id]
	if !ok {
		return repository.Tenant{}, repository.ErrNotFound
	}
	if len(existing.Settings) == 0 || string(existing.Settings) == "null" {
		// No settings document → no-op, but still bump UpdatedAt
		// so callers see a stable returned row.
		existing.UpdatedAt = r.s.clock()
		r.s.tenants[existing.ID] = existing
		return cloneTenant(existing), nil
	}
	settings := map[string]json.RawMessage{}
	if err := json.Unmarshal(existing.Settings, &settings); err != nil {
		return repository.Tenant{}, fmt.Errorf("delete settings key %q: decode: %w", key, err)
	}
	delete(settings, key)
	encoded, err := json.Marshal(settings)
	if err != nil {
		return repository.Tenant{}, fmt.Errorf("delete settings key %q: encode: %w", key, err)
	}
	existing.Settings = encoded
	existing.UpdatedAt = r.s.clock()
	r.s.tenants[existing.ID] = existing
	return cloneTenant(existing), nil
}

// UpdateStatus mutates the tenant's status enum directly. Round-17
// of Devin Review on PR #42 (ANALYSIS_0005) flagged that this
// method could be used to resurrect a soft-deleted tenant
// (`deleted` → `active`/`suspended`), which would break the
// lifecycle invariant `(status='deleted' ⇔ deleted_at != NULL)`
// because `deleted_at` would stay stamped on a now-active row. The
// resurrection guard below rejects any transition out of `deleted`
// with ErrForbidden; operators that genuinely need to restore a
// tombstoned row must clear `deleted_at` via a dedicated restore
// path (not yet exposed). Idempotent self-transitions stay allowed
// (Delete→Delete) so callers that already handle that case keep
// working. TransitionStatus enforces the same invariant atomically
// for callers that want to gate on a known prior status.
func (r *TenantRepository) UpdateStatus(ctx context.Context, id uuid.UUID, status repository.TenantStatus) (repository.Tenant, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.Tenant{}, err
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	existing, ok := r.s.tenants[id]
	if !ok {
		return repository.Tenant{}, repository.ErrNotFound
	}
	switch status {
	case repository.TenantStatusActive, repository.TenantStatusSuspended, repository.TenantStatusDeleted:
	default:
		return repository.Tenant{}, repository.ErrInvalidArgument
	}
	// Resurrection guard: deleted is terminal. See doc above.
	if existing.Status == repository.TenantStatusDeleted && status != repository.TenantStatusDeleted {
		return repository.Tenant{}, repository.ErrForbidden
	}
	existing.Status = status
	existing.UpdatedAt = r.s.clock()
	if status == repository.TenantStatusDeleted && existing.DeletedAt == nil {
		t := r.s.clock()
		existing.DeletedAt = &t
	}
	r.s.tenants[id] = existing
	return cloneTenant(existing), nil
}

func (r *TenantRepository) TransitionStatus(ctx context.Context, id uuid.UUID, from, to repository.TenantStatus) (repository.Tenant, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.Tenant{}, err
	}
	switch to {
	case repository.TenantStatusActive, repository.TenantStatusSuspended, repository.TenantStatusDeleted:
	default:
		return repository.Tenant{}, repository.ErrInvalidArgument
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	existing, ok := r.s.tenants[id]
	if !ok {
		return repository.Tenant{}, repository.ErrNotFound
	}
	if existing.Status != from {
		return repository.Tenant{}, repository.ErrForbidden
	}
	existing.Status = to
	existing.UpdatedAt = r.s.clock()
	if to == repository.TenantStatusDeleted && existing.DeletedAt == nil {
		t := r.s.clock()
		existing.DeletedAt = &t
	}
	r.s.tenants[id] = existing
	return cloneTenant(existing), nil
}

// Delete soft-deletes a tenant atomically. Returns ErrForbidden if
// the tenant is already deleted (idempotency is the caller's
// concern; the repo enforces single-shot semantics).
func (r *TenantRepository) Delete(ctx context.Context, id uuid.UUID) error {
	if err := errCtxIfNeeded(ctx); err != nil {
		return err
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	existing, ok := r.s.tenants[id]
	if !ok {
		return repository.ErrNotFound
	}
	if existing.Status == repository.TenantStatusDeleted {
		return repository.ErrForbidden
	}
	existing.Status = repository.TenantStatusDeleted
	existing.UpdatedAt = r.s.clock()
	if existing.DeletedAt == nil {
		t := r.s.clock()
		existing.DeletedAt = &t
	}
	r.s.tenants[id] = existing
	return nil
}
