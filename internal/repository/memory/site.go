package memory

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// SiteRepository is the memory-backed SiteRepository implementation.
type SiteRepository struct{ s *Store }

// NewSiteRepository binds a Store to the SiteRepository interface.
func NewSiteRepository(s *Store) *SiteRepository { return &SiteRepository{s: s} }

var _ repository.SiteRepository = (*SiteRepository)(nil)

func (r *SiteRepository) Create(ctx context.Context, tenantID uuid.UUID, site repository.Site) (repository.Site, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.Site{}, err
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if tenantID == uuid.Nil {
		return repository.Site{}, repository.ErrInvalidArgument
	}
	if _, ok := r.s.tenants[tenantID]; !ok {
		return repository.Site{}, repository.ErrNotFound
	}
	if site.ID == uuid.Nil {
		site.ID = uuid.New()
	}
	if site.Slug == "" {
		return repository.Site{}, repository.ErrInvalidArgument
	}
	for _, existing := range r.s.sites {
		if existing.TenantID == tenantID && existing.Slug == site.Slug {
			return repository.Site{}, repository.ErrConflict
		}
	}
	site.TenantID = tenantID
	now := r.s.clock()
	site.CreatedAt = now
	site.UpdatedAt = now
	site.Config = cloneJSON(site.Config)
	r.s.sites[site.ID] = site
	return site, nil
}

func (r *SiteRepository) Get(ctx context.Context, tenantID, id uuid.UUID) (repository.Site, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.Site{}, err
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	s, ok := r.s.sites[id]
	if !ok || s.TenantID != tenantID {
		return repository.Site{}, repository.ErrNotFound
	}
	s.Config = cloneJSON(s.Config)
	return s, nil
}

func (r *SiteRepository) List(ctx context.Context, tenantID uuid.UUID, page repository.Page) (repository.PageResult[repository.Site], error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.PageResult[repository.Site]{}, err
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	all := make([]repository.Site, 0, len(r.s.sites))
	for _, s := range r.s.sites {
		if s.TenantID != tenantID {
			continue
		}
		s.Config = cloneJSON(s.Config)
		all = append(all, s)
	}
	sorted := sortByCreatedAtDesc(all,
		func(s repository.Site) time.Time { return s.CreatedAt },
		func(s repository.Site) uuid.UUID { return s.ID },
		page.Normalize().Order,
	)
	return paginate(sorted, page, func(s repository.Site) cursor {
		return cursor{CreatedAt: s.CreatedAt, ID: s.ID}
	}), nil
}

func (r *SiteRepository) Update(ctx context.Context, tenantID uuid.UUID, site repository.Site) (repository.Site, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.Site{}, err
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	existing, ok := r.s.sites[site.ID]
	if !ok || existing.TenantID != tenantID {
		return repository.Site{}, repository.ErrNotFound
	}
	if site.Slug != "" && site.Slug != existing.Slug {
		for id, other := range r.s.sites {
			if id == existing.ID {
				continue
			}
			if other.TenantID == tenantID && other.Slug == site.Slug {
				return repository.Site{}, repository.ErrConflict
			}
		}
		existing.Slug = site.Slug
	}
	if site.Name != "" {
		existing.Name = site.Name
	}
	if site.Template != "" {
		existing.Template = site.Template
	}
	if site.Config != nil {
		existing.Config = cloneJSON(site.Config)
	}
	existing.UpdatedAt = r.s.clock()
	r.s.sites[existing.ID] = existing
	out := existing
	out.Config = cloneJSON(existing.Config)
	return out, nil
}

func (r *SiteRepository) Delete(ctx context.Context, tenantID, id uuid.UUID) error {
	if err := errCtxIfNeeded(ctx); err != nil {
		return err
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	existing, ok := r.s.sites[id]
	if !ok || existing.TenantID != tenantID {
		return repository.ErrNotFound
	}
	delete(r.s.sites, id)
	// Detach any devices that referenced this site.
	for did, d := range r.s.devices {
		if d.SiteID != nil && *d.SiteID == id {
			d.SiteID = nil
			d.UpdatedAt = r.s.clock()
			r.s.devices[did] = d
		}
	}
	return nil
}
