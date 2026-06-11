package memory

import (
	"context"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// AppRegistryRepository is the memory-backed
// AppRegistryRepository implementation. Mirrors the Postgres
// driver's semantics with one exception: the GIN domain index is
// approximated by a linear scan since the test catalog is small.
type AppRegistryRepository struct{ s *Store }

// NewAppRegistryRepository binds a Store.
func NewAppRegistryRepository(s *Store) *AppRegistryRepository {
	return &AppRegistryRepository{s: s}
}

var _ repository.AppRegistryRepository = (*AppRegistryRepository)(nil)

// AppRegistryOverrideRepository is the memory-backed
// AppRegistryOverrideRepository implementation. Tenant isolation
// is enforced by filtering on the row's tenant_id, mirroring what
// the Postgres RLS policy does.
type AppRegistryOverrideRepository struct{ s *Store }

// NewAppRegistryOverrideRepository binds a Store.
func NewAppRegistryOverrideRepository(s *Store) *AppRegistryOverrideRepository {
	return &AppRegistryOverrideRepository{s: s}
}

var _ repository.AppRegistryOverrideRepository = (*AppRegistryOverrideRepository)(nil)

// --- AppRegistry ----------------------------------------------------------

func (r *AppRegistryRepository) Create(ctx context.Context, app repository.AppRegistry) (repository.AppRegistry, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.AppRegistry{}, err
	}
	if err := validateAppRegistry(app); err != nil {
		return repository.AppRegistry{}, err
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if app.ID == uuid.Nil {
		app.ID = uuid.New()
	}
	for _, existing := range r.s.appRegistry {
		if strings.EqualFold(existing.Name, app.Name) {
			return repository.AppRegistry{}, repository.ErrConflict
		}
	}
	now := r.s.clock()
	app.CreatedAt = now
	app.UpdatedAt = now
	app = cloneAppRegistry(app)
	r.s.appRegistry[app.ID] = app
	return cloneAppRegistry(app), nil
}

func (r *AppRegistryRepository) Get(ctx context.Context, id uuid.UUID) (repository.AppRegistry, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.AppRegistry{}, err
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	app, ok := r.s.appRegistry[id]
	if !ok {
		return repository.AppRegistry{}, repository.ErrNotFound
	}
	return cloneAppRegistry(app), nil
}

func (r *AppRegistryRepository) GetByName(ctx context.Context, name string) (repository.AppRegistry, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.AppRegistry{}, err
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	for _, app := range r.s.appRegistry {
		if strings.EqualFold(app.Name, name) {
			return cloneAppRegistry(app), nil
		}
	}
	return repository.AppRegistry{}, repository.ErrNotFound
}

func (r *AppRegistryRepository) Update(ctx context.Context, app repository.AppRegistry) (repository.AppRegistry, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.AppRegistry{}, err
	}
	if app.ID == uuid.Nil {
		return repository.AppRegistry{}, repository.ErrInvalidArgument
	}
	if err := validateAppRegistry(app); err != nil {
		return repository.AppRegistry{}, err
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	existing, ok := r.s.appRegistry[app.ID]
	if !ok {
		return repository.AppRegistry{}, repository.ErrNotFound
	}
	// Name uniqueness is enforced; allow no-op if name unchanged.
	for otherID, other := range r.s.appRegistry {
		if otherID == app.ID {
			continue
		}
		if strings.EqualFold(other.Name, app.Name) {
			return repository.AppRegistry{}, repository.ErrConflict
		}
	}
	app.CreatedAt = existing.CreatedAt
	app.UpdatedAt = r.s.clock()
	app = cloneAppRegistry(app)
	r.s.appRegistry[app.ID] = app
	return cloneAppRegistry(app), nil
}

func (r *AppRegistryRepository) Delete(ctx context.Context, id uuid.UUID) error {
	if err := errCtxIfNeeded(ctx); err != nil {
		return err
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if _, ok := r.s.appRegistry[id]; !ok {
		return repository.ErrNotFound
	}
	delete(r.s.appRegistry, id)
	// Cascade-clean any overrides that referenced the deleted
	// app — Postgres does this via ON DELETE CASCADE; the memory
	// driver replicates the behaviour explicitly.
	for oid, ov := range r.s.appOverrides {
		if ov.AppID != nil && *ov.AppID == id {
			delete(r.s.appOverrides, oid)
		}
	}
	return nil
}

func (r *AppRegistryRepository) List(ctx context.Context, filter repository.AppRegistryFilter, page repository.Page) (repository.PageResult[repository.AppRegistry], error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.PageResult[repository.AppRegistry]{}, err
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	all := make([]repository.AppRegistry, 0, len(r.s.appRegistry))
	for _, app := range r.s.appRegistry {
		if filter.TrafficClass != "" && app.TrafficClass != filter.TrafficClass {
			continue
		}
		if filter.Scope != "" && app.Scope != filter.Scope {
			continue
		}
		if filter.Category != "" && !strings.EqualFold(app.Category, filter.Category) {
			continue
		}
		if filter.Region != "" {
			if !containsCI(app.Regions, filter.Region) {
				continue
			}
		}
		all = append(all, cloneAppRegistry(app))
	}
	sorted := sortByCreatedAtDesc(all,
		func(a repository.AppRegistry) time.Time { return a.CreatedAt },
		func(a repository.AppRegistry) uuid.UUID { return a.ID },
		page.Normalize().Order,
	)
	return paginate(sorted, page, func(a repository.AppRegistry) cursor {
		return cursor{CreatedAt: a.CreatedAt, ID: a.ID}
	}), nil
}

func (r *AppRegistryRepository) ListAll(ctx context.Context) ([]repository.AppRegistry, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return nil, err
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	out := make([]repository.AppRegistry, 0, len(r.s.appRegistry))
	for _, app := range r.s.appRegistry {
		out = append(out, cloneAppRegistry(app))
	}
	// Match the postgres ListAll ordering (ORDER BY name). The map
	// iteration above is non-deterministic; sorting by name keeps the
	// two backends consistent. Names are unique (Create rejects
	// case-insensitive duplicates), so this is a total order.
	sort.Slice(out, func(i, j int) bool {
		return out[i].Name < out[j].Name
	})
	return out, nil
}

func (r *AppRegistryRepository) ListWithMetadataURL(ctx context.Context) ([]repository.AppRegistry, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return nil, err
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	out := make([]repository.AppRegistry, 0, len(r.s.appRegistry))
	for _, app := range r.s.appRegistry {
		if app.MetadataURL == "" {
			continue
		}
		out = append(out, cloneAppRegistry(app))
	}
	return out, nil
}

// --- AppRegistryOverride --------------------------------------------------

func (r *AppRegistryOverrideRepository) Create(ctx context.Context, tenantID uuid.UUID, override repository.AppRegistryOverride) (repository.AppRegistryOverride, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.AppRegistryOverride{}, err
	}
	if tenantID == uuid.Nil {
		return repository.AppRegistryOverride{}, repository.ErrInvalidArgument
	}
	override.TenantID = tenantID
	if err := validateAppOverride(override); err != nil {
		return repository.AppRegistryOverride{}, err
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if override.ID == uuid.Nil {
		override.ID = uuid.New()
	}
	// Enforce the partial unique index: one active (tenant, app)
	// override per pair when app_id IS NOT NULL.
	if override.AppID != nil {
		for _, existing := range r.s.appOverrides {
			if existing.TenantID == tenantID && existing.AppID != nil && *existing.AppID == *override.AppID {
				return repository.AppRegistryOverride{}, repository.ErrConflict
			}
		}
	}
	now := r.s.clock()
	override.CreatedAt = now
	override.UpdatedAt = now
	override = cloneAppOverride(override)
	r.s.appOverrides[override.ID] = override
	return cloneAppOverride(override), nil
}

func (r *AppRegistryOverrideRepository) Get(ctx context.Context, tenantID, id uuid.UUID) (repository.AppRegistryOverride, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.AppRegistryOverride{}, err
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	ov, ok := r.s.appOverrides[id]
	if !ok || ov.TenantID != tenantID {
		return repository.AppRegistryOverride{}, repository.ErrNotFound
	}
	return cloneAppOverride(ov), nil
}

func (r *AppRegistryOverrideRepository) Delete(ctx context.Context, tenantID, id uuid.UUID) error {
	if err := errCtxIfNeeded(ctx); err != nil {
		return err
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	ov, ok := r.s.appOverrides[id]
	if !ok || ov.TenantID != tenantID {
		return repository.ErrNotFound
	}
	delete(r.s.appOverrides, id)
	return nil
}

func (r *AppRegistryOverrideRepository) List(ctx context.Context, tenantID uuid.UUID, page repository.Page) (repository.PageResult[repository.AppRegistryOverride], error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.PageResult[repository.AppRegistryOverride]{}, err
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	all := make([]repository.AppRegistryOverride, 0)
	for _, ov := range r.s.appOverrides {
		if ov.TenantID != tenantID {
			continue
		}
		all = append(all, cloneAppOverride(ov))
	}
	sorted := sortByCreatedAtDesc(all,
		func(o repository.AppRegistryOverride) time.Time { return o.CreatedAt },
		func(o repository.AppRegistryOverride) uuid.UUID { return o.ID },
		page.Normalize().Order,
	)
	return paginate(sorted, page, func(o repository.AppRegistryOverride) cursor {
		return cursor{CreatedAt: o.CreatedAt, ID: o.ID}
	}), nil
}

func (r *AppRegistryOverrideRepository) ListAll(ctx context.Context, tenantID uuid.UUID) ([]repository.AppRegistryOverride, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return nil, err
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	out := make([]repository.AppRegistryOverride, 0)
	for _, ov := range r.s.appOverrides {
		if ov.TenantID != tenantID {
			continue
		}
		out = append(out, cloneAppOverride(ov))
	}
	// Match the postgres ListAll ordering (created_at DESC, id DESC).
	// The map iteration above is non-deterministic, and callers such as
	// resolveTrafficClass pick the first matching override, so an
	// unordered result would make override precedence differ between the
	// memory and postgres backends.
	return sortByCreatedAtDesc(out,
		func(o repository.AppRegistryOverride) time.Time { return o.CreatedAt },
		func(o repository.AppRegistryOverride) uuid.UUID { return o.ID },
		repository.SortDesc,
	), nil
}

func (r *AppRegistryOverrideRepository) DeleteExpired(ctx context.Context, now time.Time) (int, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return 0, err
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	count := 0
	for id, ov := range r.s.appOverrides {
		if ov.ExpiresAt != nil && !ov.ExpiresAt.After(now) {
			delete(r.s.appOverrides, id)
			count++
		}
	}
	return count, nil
}

// --- helpers --------------------------------------------------------------

func validateAppRegistry(a repository.AppRegistry) error {
	if strings.TrimSpace(a.Name) == "" {
		return repository.ErrInvalidArgument
	}
	if !a.TrafficClass.IsValid() {
		return repository.ErrInvalidArgument
	}
	if !a.Scope.IsValid() {
		return repository.ErrInvalidArgument
	}
	if len(a.Domains) == 0 {
		return repository.ErrInvalidArgument
	}
	if a.Scope == repository.AppRegistryScopeRegional && len(a.Regions) == 0 {
		return repository.ErrInvalidArgument
	}
	return nil
}

func validateAppOverride(o repository.AppRegistryOverride) error {
	if !o.TrafficClassOverride.IsValid() {
		return repository.ErrInvalidArgument
	}
	hasApp := o.AppID != nil
	hasCustom := len(o.CustomDomains) > 0
	if hasApp == hasCustom {
		// xor: must have exactly one of the two — same as the
		// Postgres CHECK constraint.
		return repository.ErrInvalidArgument
	}
	return nil
}

func cloneAppRegistry(in repository.AppRegistry) repository.AppRegistry {
	out := in
	out.Regions = cloneStrings(in.Regions)
	out.Domains = cloneStrings(in.Domains)
	out.CertPins = cloneStrings(in.CertPins)
	if in.IPRanges != nil {
		out.IPRanges = make([]netip.Prefix, len(in.IPRanges))
		copy(out.IPRanges, in.IPRanges)
	}
	return out
}

func cloneAppOverride(in repository.AppRegistryOverride) repository.AppRegistryOverride {
	out := in
	out.CustomDomains = cloneStrings(in.CustomDomains)
	if in.AppID != nil {
		v := *in.AppID
		out.AppID = &v
	}
	if in.ExpiresAt != nil {
		t := *in.ExpiresAt
		out.ExpiresAt = &t
	}
	return out
}

func containsCI(haystack []string, needle string) bool {
	for _, h := range haystack {
		if strings.EqualFold(h, needle) {
			return true
		}
	}
	return false
}
