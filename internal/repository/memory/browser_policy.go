package memory

import (
	"context"
	"sort"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// BrowserPolicyRepository is the in-memory implementation of
// repository.BrowserPolicyRepository.
type BrowserPolicyRepository struct{ s *Store }

// NewBrowserPolicyRepository returns a BrowserPolicyRepository
// backed by the given Store.
func NewBrowserPolicyRepository(s *Store) *BrowserPolicyRepository {
	return &BrowserPolicyRepository{s: s}
}

func (r *BrowserPolicyRepository) Create(_ context.Context, tenantID uuid.UUID, p repository.BrowserPolicy) (repository.BrowserPolicy, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()

	now := r.s.clock()
	p.ID = uuid.New()
	p.TenantID = tenantID
	p.CreatedAt = now
	p.UpdatedAt = now
	if p.Rules == nil {
		p.Rules = []repository.BrowserRule{}
	}

	r.s.browserPolicies[p.ID] = p
	return cloneBrowserPolicy(p), nil
}

func (r *BrowserPolicyRepository) Get(_ context.Context, tenantID, id uuid.UUID) (repository.BrowserPolicy, error) {
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()

	p, ok := r.s.browserPolicies[id]
	if !ok || p.TenantID != tenantID {
		return repository.BrowserPolicy{}, repository.ErrNotFound
	}
	return cloneBrowserPolicy(p), nil
}

func (r *BrowserPolicyRepository) List(_ context.Context, tenantID uuid.UUID, page repository.Page) (repository.PageResult[repository.BrowserPolicy], error) {
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()

	var items []repository.BrowserPolicy
	for _, p := range r.s.browserPolicies {
		if p.TenantID == tenantID {
			items = append(items, cloneBrowserPolicy(p))
		}
	}
	sort.Slice(items, func(i, j int) bool {
		return orderBefore(
			cursor{CreatedAt: items[i].CreatedAt, ID: items[i].ID},
			cursor{CreatedAt: items[j].CreatedAt, ID: items[j].ID},
			page.Normalize().Order,
		)
	})
	return paginate(items, page, func(p repository.BrowserPolicy) cursor {
		return cursor{CreatedAt: p.CreatedAt, ID: p.ID}
	}), nil
}

func (r *BrowserPolicyRepository) Update(_ context.Context, tenantID, id uuid.UUID, patch repository.BrowserPolicyPatch) (repository.BrowserPolicy, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()

	p, ok := r.s.browserPolicies[id]
	if !ok || p.TenantID != tenantID {
		return repository.BrowserPolicy{}, repository.ErrNotFound
	}
	if patch.Name != nil {
		p.Name = *patch.Name
	}
	if patch.Rules != nil {
		p.Rules = patch.Rules
	}
	if patch.Action != nil {
		p.Action = *patch.Action
	}
	if patch.Scope != nil {
		p.Scope = *patch.Scope
	}
	if patch.Enabled != nil {
		p.Enabled = *patch.Enabled
	}
	p.UpdatedAt = r.s.clock()
	r.s.browserPolicies[id] = p
	return cloneBrowserPolicy(p), nil
}

func (r *BrowserPolicyRepository) Delete(_ context.Context, tenantID, id uuid.UUID) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()

	p, ok := r.s.browserPolicies[id]
	if !ok || p.TenantID != tenantID {
		return repository.ErrNotFound
	}
	delete(r.s.browserPolicies, id)
	return nil
}

func cloneBrowserPolicy(p repository.BrowserPolicy) repository.BrowserPolicy {
	rules := make([]repository.BrowserRule, len(p.Rules))
	copy(rules, p.Rules)
	p.Rules = rules
	return p
}
