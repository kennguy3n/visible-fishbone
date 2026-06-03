package memory

import (
	"context"
	"sort"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// IDPConfigRepository is the memory-backed idp_configs store.
type IDPConfigRepository struct{ s *Store }

// NewIDPConfigRepository binds a Store.
func NewIDPConfigRepository(s *Store) *IDPConfigRepository {
	return &IDPConfigRepository{s: s}
}

var _ repository.IDPConfigRepository = (*IDPConfigRepository)(nil)

func (r *IDPConfigRepository) Create(
	ctx context.Context,
	tenantID uuid.UUID,
	c repository.IDPConfig,
) (repository.IDPConfig, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.IDPConfig{}, err
	}
	if c.IssuerURL == "" || c.ClientID == "" {
		return repository.IDPConfig{}, repository.ErrInvalidArgument
	}
	if err := repository.ValidateIDPProviderType(c.ProviderType); err != nil {
		return repository.IDPConfig{}, err
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	// Enforce the unique (tenant_id, issuer_url) index.
	for _, ex := range r.s.idpConfigs {
		if ex.TenantID == tenantID && ex.IssuerURL == c.IssuerURL {
			return repository.IDPConfig{}, repository.ErrConflict
		}
	}
	if c.ID == uuid.Nil {
		c.ID = uuid.New()
	}
	c.TenantID = tenantID
	now := r.s.clock()
	c.CreatedAt = now
	c.UpdatedAt = now
	if c.AllowedDomains == nil {
		c.AllowedDomains = []string{}
	}
	r.s.idpConfigs[c.ID] = cloneIDPConfig(c)
	return cloneIDPConfig(c), nil
}

func (r *IDPConfigRepository) Get(
	ctx context.Context,
	tenantID, id uuid.UUID,
) (repository.IDPConfig, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.IDPConfig{}, err
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	c, ok := r.s.idpConfigs[id]
	if !ok || c.TenantID != tenantID {
		return repository.IDPConfig{}, repository.ErrNotFound
	}
	return cloneIDPConfig(c), nil
}

func (r *IDPConfigRepository) List(
	ctx context.Context,
	tenantID uuid.UUID,
) ([]repository.IDPConfig, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return nil, err
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	out := make([]repository.IDPConfig, 0)
	for _, c := range r.s.idpConfigs {
		if c.TenantID != tenantID {
			continue
		}
		out = append(out, cloneIDPConfig(c))
	}
	// Newest first, ties broken by ID for a deterministic order.
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].ID.String() > out[j].ID.String()
		}
		return out[i].CreatedAt.After(out[j].CreatedAt)
	})
	return out, nil
}

func (r *IDPConfigRepository) Update(
	ctx context.Context,
	tenantID uuid.UUID,
	c repository.IDPConfig,
) (repository.IDPConfig, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.IDPConfig{}, err
	}
	if c.IssuerURL == "" || c.ClientID == "" {
		return repository.IDPConfig{}, repository.ErrInvalidArgument
	}
	if err := repository.ValidateIDPProviderType(c.ProviderType); err != nil {
		return repository.IDPConfig{}, err
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	existing, ok := r.s.idpConfigs[c.ID]
	if !ok || existing.TenantID != tenantID {
		return repository.IDPConfig{}, repository.ErrNotFound
	}
	// Changing the issuer must not collide with another config.
	for id, ex := range r.s.idpConfigs {
		if id == c.ID {
			continue
		}
		if ex.TenantID == tenantID && ex.IssuerURL == c.IssuerURL {
			return repository.IDPConfig{}, repository.ErrConflict
		}
	}
	existing.ProviderType = c.ProviderType
	existing.IssuerURL = c.IssuerURL
	existing.ClientID = c.ClientID
	existing.AllowedDomains = cloneStringSlice(c.AllowedDomains)
	existing.GroupClaimPath = c.GroupClaimPath
	existing.Enabled = c.Enabled
	existing.UpdatedAt = r.s.clock()
	r.s.idpConfigs[c.ID] = existing
	return cloneIDPConfig(existing), nil
}

func (r *IDPConfigRepository) Delete(
	ctx context.Context,
	tenantID, id uuid.UUID,
) error {
	if err := errCtxIfNeeded(ctx); err != nil {
		return err
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	c, ok := r.s.idpConfigs[id]
	if !ok || c.TenantID != tenantID {
		return repository.ErrNotFound
	}
	delete(r.s.idpConfigs, id)
	return nil
}

func cloneIDPConfig(c repository.IDPConfig) repository.IDPConfig {
	c.AllowedDomains = cloneStringSlice(c.AllowedDomains)
	return c
}
