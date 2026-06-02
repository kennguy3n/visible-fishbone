package memory

import (
	"context"
	"sort"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// --- CASBConnectorRepository ---

type CASBConnectorRepository struct{ s *Store }

func NewCASBConnectorRepository(s *Store) *CASBConnectorRepository {
	return &CASBConnectorRepository{s: s}
}

var _ repository.CASBConnectorRepository = (*CASBConnectorRepository)(nil)

func (r *CASBConnectorRepository) Create(
	ctx context.Context,
	tenantID uuid.UUID,
	c repository.CASBConnector,
) (repository.CASBConnector, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.CASBConnector{}, err
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if tenantID == uuid.Nil {
		return repository.CASBConnector{}, repository.ErrInvalidArgument
	}
	if _, ok := r.s.tenants[tenantID]; !ok {
		return repository.CASBConnector{}, repository.ErrNotFound
	}
	if !c.Type.IsValid() {
		return repository.CASBConnector{}, repository.ErrInvalidArgument
	}
	if c.Name == "" {
		return repository.CASBConnector{}, repository.ErrInvalidArgument
	}
	for _, existing := range r.s.casbConnectors {
		if existing.TenantID == tenantID && existing.Name == c.Name {
			return repository.CASBConnector{}, repository.ErrConflict
		}
	}
	if c.ID == uuid.Nil {
		c.ID = uuid.New()
	}
	c.TenantID = tenantID
	now := r.s.clock()
	c.CreatedAt = now
	c.UpdatedAt = now
	if c.Status == "" {
		c.Status = repository.CASBConnectorStatusConfiguring
	}
	c.Config = cloneJSON(c.Config)
	c.Secret = cloneBytes(c.Secret)
	r.s.casbConnectors[c.ID] = c
	return cloneCASBConnector(c), nil
}

func (r *CASBConnectorRepository) Get(
	ctx context.Context,
	tenantID, id uuid.UUID,
) (repository.CASBConnector, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.CASBConnector{}, err
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	c, ok := r.s.casbConnectors[id]
	if !ok || c.TenantID != tenantID {
		return repository.CASBConnector{}, repository.ErrNotFound
	}
	return cloneCASBConnector(c), nil
}

func (r *CASBConnectorRepository) List(
	ctx context.Context,
	tenantID uuid.UUID,
	page repository.Page,
) (repository.PageResult[repository.CASBConnector], error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.PageResult[repository.CASBConnector]{}, err
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	all := make([]repository.CASBConnector, 0, len(r.s.casbConnectors))
	for _, c := range r.s.casbConnectors {
		if c.TenantID != tenantID {
			continue
		}
		all = append(all, cloneCASBConnector(c))
	}
	sorted := sortByCreatedAtDesc(all,
		func(c repository.CASBConnector) time.Time { return c.CreatedAt },
		func(c repository.CASBConnector) uuid.UUID { return c.ID },
		page.Normalize().Order,
	)
	return paginate(sorted, page, func(c repository.CASBConnector) cursor {
		return cursor{CreatedAt: c.CreatedAt, ID: c.ID}
	}), nil
}

func (r *CASBConnectorRepository) Update(
	ctx context.Context,
	tenantID uuid.UUID,
	c repository.CASBConnector,
) (repository.CASBConnector, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.CASBConnector{}, err
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	existing, ok := r.s.casbConnectors[c.ID]
	if !ok || existing.TenantID != tenantID {
		return repository.CASBConnector{}, repository.ErrNotFound
	}
	if c.Name != "" && c.Name != existing.Name {
		for _, other := range r.s.casbConnectors {
			if other.ID == existing.ID {
				continue
			}
			if other.TenantID == tenantID && other.Name == c.Name {
				return repository.CASBConnector{}, repository.ErrConflict
			}
		}
		existing.Name = c.Name
	}
	if len(c.Config) > 0 {
		existing.Config = cloneJSON(c.Config)
	}
	if len(c.Secret) > 0 {
		existing.Secret = cloneBytes(c.Secret)
	}
	if c.Status != "" {
		existing.Status = c.Status
	}
	if c.LastSyncAt != nil {
		t := *c.LastSyncAt
		existing.LastSyncAt = &t
	}
	existing.UpdatedAt = r.s.clock()
	r.s.casbConnectors[c.ID] = existing
	return cloneCASBConnector(existing), nil
}

func (r *CASBConnectorRepository) Delete(
	ctx context.Context,
	tenantID, id uuid.UUID,
) error {
	if err := errCtxIfNeeded(ctx); err != nil {
		return err
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	c, ok := r.s.casbConnectors[id]
	if !ok || c.TenantID != tenantID {
		return repository.ErrNotFound
	}
	delete(r.s.casbConnectors, id)
	return nil
}

func cloneCASBConnector(c repository.CASBConnector) repository.CASBConnector {
	c.Config = cloneJSON(c.Config)
	c.Secret = cloneBytes(c.Secret)
	return c
}

// --- CASBDiscoveredAppRepository ---

type CASBDiscoveredAppRepository struct{ s *Store }

func NewCASBDiscoveredAppRepository(s *Store) *CASBDiscoveredAppRepository {
	return &CASBDiscoveredAppRepository{s: s}
}

var _ repository.CASBDiscoveredAppRepository = (*CASBDiscoveredAppRepository)(nil)

func (r *CASBDiscoveredAppRepository) Upsert(
	ctx context.Context,
	tenantID uuid.UUID,
	app repository.CASBDiscoveredApp,
) (repository.CASBDiscoveredApp, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.CASBDiscoveredApp{}, err
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	// Find existing by (tenant_id, name).
	for id, existing := range r.s.casbDiscoveredApps {
		if existing.TenantID == tenantID && existing.Name == app.Name {
			existing.Vendor = app.Vendor
			existing.Category = app.Category
			existing.RiskScore = app.RiskScore
			existing.UsersCount = app.UsersCount
			existing.LastSeen = app.LastSeen
			r.s.casbDiscoveredApps[id] = existing
			return existing, nil
		}
	}
	if app.ID == uuid.Nil {
		app.ID = uuid.New()
	}
	app.TenantID = tenantID
	r.s.casbDiscoveredApps[app.ID] = app
	return app, nil
}

func (r *CASBDiscoveredAppRepository) List(
	ctx context.Context,
	tenantID uuid.UUID,
) ([]repository.CASBDiscoveredApp, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return nil, err
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	var apps []repository.CASBDiscoveredApp
	for _, a := range r.s.casbDiscoveredApps {
		if a.TenantID != tenantID {
			continue
		}
		apps = append(apps, a)
	}
	sort.Slice(apps, func(i, j int) bool {
		return apps[i].LastSeen.After(apps[j].LastSeen)
	})
	return apps, nil
}

func (r *CASBDiscoveredAppRepository) Get(
	ctx context.Context,
	tenantID, id uuid.UUID,
) (repository.CASBDiscoveredApp, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.CASBDiscoveredApp{}, err
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	a, ok := r.s.casbDiscoveredApps[id]
	if !ok || a.TenantID != tenantID {
		return repository.CASBDiscoveredApp{}, repository.ErrNotFound
	}
	return a, nil
}

// --- CASBPostureCheckRepository ---

type CASBPostureCheckRepository struct{ s *Store }

func NewCASBPostureCheckRepository(s *Store) *CASBPostureCheckRepository {
	return &CASBPostureCheckRepository{s: s}
}

var _ repository.CASBPostureCheckRepository = (*CASBPostureCheckRepository)(nil)

func (r *CASBPostureCheckRepository) Save(
	ctx context.Context,
	tenantID uuid.UUID,
	appID uuid.UUID,
	checks []repository.CASBPostureCheck,
) error {
	if err := errCtxIfNeeded(ctx); err != nil {
		return err
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	// Remove old checks for this app.
	for id, c := range r.s.casbPostureChecks {
		if c.TenantID == tenantID && c.AppID == appID {
			delete(r.s.casbPostureChecks, id)
		}
	}
	for _, c := range checks {
		if c.ID == uuid.Nil {
			c.ID = uuid.New()
		}
		c.TenantID = tenantID
		c.AppID = appID
		r.s.casbPostureChecks[c.ID] = c
	}
	return nil
}

func (r *CASBPostureCheckRepository) GetLatest(
	ctx context.Context,
	tenantID uuid.UUID,
	appID uuid.UUID,
) ([]repository.CASBPostureCheck, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return nil, err
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	var checks []repository.CASBPostureCheck
	for _, c := range r.s.casbPostureChecks {
		if c.TenantID == tenantID && c.AppID == appID {
			checks = append(checks, c)
		}
	}
	sort.Slice(checks, func(i, j int) bool {
		return checks[i].AssessedAt.After(checks[j].AssessedAt)
	})
	return checks, nil
}
