package memory

import (
	"context"
	"sort"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// --- DLPPolicyRepository --------------------------------------------------

// DLPPolicyRepository is the memory-backed DLP policy store.
type DLPPolicyRepository struct{ s *Store }

// NewDLPPolicyRepository binds a Store.
func NewDLPPolicyRepository(s *Store) *DLPPolicyRepository {
	return &DLPPolicyRepository{s: s}
}

var _ repository.DLPPolicyRepository = (*DLPPolicyRepository)(nil)

func (r *DLPPolicyRepository) Create(
	ctx context.Context,
	tenantID uuid.UUID,
	p repository.DLPPolicy,
) (repository.DLPPolicy, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.DLPPolicy{}, err
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if tenantID == uuid.Nil {
		return repository.DLPPolicy{}, repository.ErrInvalidArgument
	}
	if _, ok := r.s.tenants[tenantID]; !ok {
		return repository.DLPPolicy{}, repository.ErrNotFound
	}
	if p.Name == "" {
		return repository.DLPPolicy{}, repository.ErrInvalidArgument
	}
	if p.ID == uuid.Nil {
		p.ID = uuid.New()
	}
	p.TenantID = tenantID
	now := r.s.clock()
	p.CreatedAt = now
	p.UpdatedAt = now
	p.Rules = cloneDLPRules(p.Rules)
	r.s.dlpPolicies[p.ID] = p
	return cloneDLPPolicy(p), nil
}

func (r *DLPPolicyRepository) Get(
	ctx context.Context,
	tenantID, id uuid.UUID,
) (repository.DLPPolicy, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.DLPPolicy{}, err
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	p, ok := r.s.dlpPolicies[id]
	if !ok || p.TenantID != tenantID {
		return repository.DLPPolicy{}, repository.ErrNotFound
	}
	return cloneDLPPolicy(p), nil
}

func (r *DLPPolicyRepository) List(
	ctx context.Context,
	tenantID uuid.UUID,
	page repository.Page,
) (repository.PageResult[repository.DLPPolicy], error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.PageResult[repository.DLPPolicy]{}, err
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	var items []repository.DLPPolicy
	for _, p := range r.s.dlpPolicies {
		if p.TenantID == tenantID {
			items = append(items, cloneDLPPolicy(p))
		}
	}
	sort.Slice(items, func(i, j int) bool {
		return orderBefore(
			cursor{CreatedAt: items[i].CreatedAt, ID: items[i].ID},
			cursor{CreatedAt: items[j].CreatedAt, ID: items[j].ID},
			page.Normalize().Order,
		)
	})
	return paginate(items, page, func(p repository.DLPPolicy) cursor {
		return cursor{CreatedAt: p.CreatedAt, ID: p.ID}
	}), nil
}

func (r *DLPPolicyRepository) Update(
	ctx context.Context,
	tenantID, id uuid.UUID,
	patch repository.DLPPolicyPatch,
) (repository.DLPPolicy, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.DLPPolicy{}, err
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	p, ok := r.s.dlpPolicies[id]
	if !ok || p.TenantID != tenantID {
		return repository.DLPPolicy{}, repository.ErrNotFound
	}
	if patch.Name != nil {
		p.Name = *patch.Name
	}
	if patch.Description != nil {
		p.Description = *patch.Description
	}
	if patch.Rules != nil {
		p.Rules = cloneDLPRules(*patch.Rules)
	}
	if patch.Action != nil {
		p.Action = *patch.Action
	}
	if patch.Enabled != nil {
		p.Enabled = *patch.Enabled
	}
	p.UpdatedAt = r.s.clock()
	r.s.dlpPolicies[id] = p
	return cloneDLPPolicy(p), nil
}

func (r *DLPPolicyRepository) Delete(
	ctx context.Context,
	tenantID, id uuid.UUID,
) error {
	if err := errCtxIfNeeded(ctx); err != nil {
		return err
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	p, ok := r.s.dlpPolicies[id]
	if !ok || p.TenantID != tenantID {
		return repository.ErrNotFound
	}
	delete(r.s.dlpPolicies, id)
	return nil
}

func (r *DLPPolicyRepository) ListEnabled(
	ctx context.Context,
	tenantID uuid.UUID,
) ([]repository.DLPPolicy, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return nil, err
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	var items []repository.DLPPolicy
	for _, p := range r.s.dlpPolicies {
		if p.TenantID == tenantID && p.Enabled {
			items = append(items, cloneDLPPolicy(p))
		}
	}
	sort.Slice(items, func(i, j int) bool {
		return items[i].CreatedAt.Before(items[j].CreatedAt)
	})
	return items, nil
}

// --- DLPFingerprintRepository ---------------------------------------------

// DLPFingerprintRepository is the memory-backed DLP fingerprint store.
type DLPFingerprintRepository struct{ s *Store }

// NewDLPFingerprintRepository binds a Store.
func NewDLPFingerprintRepository(s *Store) *DLPFingerprintRepository {
	return &DLPFingerprintRepository{s: s}
}

var _ repository.DLPFingerprintRepository = (*DLPFingerprintRepository)(nil)

func (r *DLPFingerprintRepository) Create(
	ctx context.Context,
	tenantID uuid.UUID,
	f repository.DLPFingerprint,
) (repository.DLPFingerprint, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.DLPFingerprint{}, err
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if tenantID == uuid.Nil {
		return repository.DLPFingerprint{}, repository.ErrInvalidArgument
	}
	if _, ok := r.s.tenants[tenantID]; !ok {
		return repository.DLPFingerprint{}, repository.ErrNotFound
	}
	if f.Name == "" {
		return repository.DLPFingerprint{}, repository.ErrInvalidArgument
	}
	if f.ID == uuid.Nil {
		f.ID = uuid.New()
	}
	f.TenantID = tenantID
	f.RegisteredAt = r.s.clock()
	f.Hash = cloneBytes(f.Hash)
	r.s.dlpFingerprints[f.ID] = f
	return cloneDLPFingerprint(f), nil
}

func (r *DLPFingerprintRepository) Get(
	ctx context.Context,
	tenantID, id uuid.UUID,
) (repository.DLPFingerprint, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.DLPFingerprint{}, err
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	f, ok := r.s.dlpFingerprints[id]
	if !ok || f.TenantID != tenantID {
		return repository.DLPFingerprint{}, repository.ErrNotFound
	}
	return cloneDLPFingerprint(f), nil
}

func (r *DLPFingerprintRepository) List(
	ctx context.Context,
	tenantID uuid.UUID,
	page repository.Page,
) (repository.PageResult[repository.DLPFingerprint], error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.PageResult[repository.DLPFingerprint]{}, err
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	var items []repository.DLPFingerprint
	for _, f := range r.s.dlpFingerprints {
		if f.TenantID == tenantID {
			items = append(items, cloneDLPFingerprint(f))
		}
	}
	sort.Slice(items, func(i, j int) bool {
		return orderBefore(
			cursor{CreatedAt: items[i].RegisteredAt, ID: items[i].ID},
			cursor{CreatedAt: items[j].RegisteredAt, ID: items[j].ID},
			page.Normalize().Order,
		)
	})
	return paginate(items, page, func(f repository.DLPFingerprint) cursor {
		return cursor{CreatedAt: f.RegisteredAt, ID: f.ID}
	}), nil
}

func (r *DLPFingerprintRepository) Delete(
	ctx context.Context,
	tenantID, id uuid.UUID,
) error {
	if err := errCtxIfNeeded(ctx); err != nil {
		return err
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	f, ok := r.s.dlpFingerprints[id]
	if !ok || f.TenantID != tenantID {
		return repository.ErrNotFound
	}
	delete(r.s.dlpFingerprints, id)
	return nil
}

func (r *DLPFingerprintRepository) ListAll(
	ctx context.Context,
	tenantID uuid.UUID,
) ([]repository.DLPFingerprint, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return nil, err
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	var items []repository.DLPFingerprint
	for _, f := range r.s.dlpFingerprints {
		if f.TenantID == tenantID {
			items = append(items, cloneDLPFingerprint(f))
		}
	}
	return items, nil
}

// --- DLPMatchRepository ---------------------------------------------------

// DLPMatchRepository is the memory-backed DLP match audit trail.
type DLPMatchRepository struct{ s *Store }

// NewDLPMatchRepository binds a Store.
func NewDLPMatchRepository(s *Store) *DLPMatchRepository {
	return &DLPMatchRepository{s: s}
}

var _ repository.DLPMatchRepository = (*DLPMatchRepository)(nil)

func (r *DLPMatchRepository) Create(
	ctx context.Context,
	tenantID uuid.UUID,
	m repository.DLPMatch,
) (repository.DLPMatch, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.DLPMatch{}, err
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if tenantID == uuid.Nil {
		return repository.DLPMatch{}, repository.ErrInvalidArgument
	}
	if m.ID == uuid.Nil {
		m.ID = uuid.New()
	}
	m.TenantID = tenantID
	m.MatchedAt = r.s.clock()
	m.Details = cloneJSON(m.Details)
	r.s.dlpMatches[m.ID] = m
	return cloneDLPMatch(m), nil
}

func (r *DLPMatchRepository) List(
	ctx context.Context,
	tenantID uuid.UUID,
	policyID *uuid.UUID,
	page repository.Page,
) (repository.PageResult[repository.DLPMatch], error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.PageResult[repository.DLPMatch]{}, err
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	var items []repository.DLPMatch
	for _, m := range r.s.dlpMatches {
		if m.TenantID != tenantID {
			continue
		}
		if policyID != nil && m.PolicyID != *policyID {
			continue
		}
		items = append(items, cloneDLPMatch(m))
	}
	sort.Slice(items, func(i, j int) bool {
		return orderBefore(
			cursor{CreatedAt: items[i].MatchedAt, ID: items[i].ID},
			cursor{CreatedAt: items[j].MatchedAt, ID: items[j].ID},
			page.Normalize().Order,
		)
	})
	return paginate(items, page, func(m repository.DLPMatch) cursor {
		return cursor{CreatedAt: m.MatchedAt, ID: m.ID}
	}), nil
}

// --- clone helpers --------------------------------------------------------

func cloneDLPRules(in []repository.DLPRule) []repository.DLPRule {
	if in == nil {
		return nil
	}
	out := make([]repository.DLPRule, len(in))
	copy(out, in)
	return out
}

func cloneDLPPolicy(p repository.DLPPolicy) repository.DLPPolicy {
	p.Rules = cloneDLPRules(p.Rules)
	return p
}

func cloneDLPFingerprint(f repository.DLPFingerprint) repository.DLPFingerprint {
	f.Hash = cloneBytes(f.Hash)
	return f
}

func cloneDLPMatch(m repository.DLPMatch) repository.DLPMatch {
	m.Details = cloneJSON(m.Details)
	return m
}
