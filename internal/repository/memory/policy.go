package memory

import (
	"context"
	"crypto/sha256"
	"sort"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// PolicyRepository is the memory-backed PolicyRepository
// implementation. Tracks both policy_graphs and policy_bundles in
// the same Store instance.
type PolicyRepository struct{ s *Store }

func NewPolicyRepository(s *Store) *PolicyRepository { return &PolicyRepository{s: s} }

var _ repository.PolicyRepository = (*PolicyRepository)(nil)

func (r *PolicyRepository) CreateGraph(ctx context.Context, tenantID uuid.UUID, g repository.PolicyGraph) (repository.PolicyGraph, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.PolicyGraph{}, err
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if tenantID == uuid.Nil {
		return repository.PolicyGraph{}, repository.ErrInvalidArgument
	}
	if _, ok := r.s.tenants[tenantID]; !ok {
		return repository.PolicyGraph{}, repository.ErrNotFound
	}
	if g.Version <= 0 {
		// Auto-increment when caller leaves Version unset.
		highest := 0
		for _, existing := range r.s.policyGraphs {
			if existing.TenantID == tenantID && existing.Version > highest {
				highest = existing.Version
			}
		}
		g.Version = highest + 1
	} else {
		for _, existing := range r.s.policyGraphs {
			if existing.TenantID == tenantID && existing.Version == g.Version {
				return repository.PolicyGraph{}, repository.ErrConflict
			}
		}
	}
	if g.ID == uuid.Nil {
		g.ID = uuid.New()
	}
	g.TenantID = tenantID
	g.CreatedAt = r.s.clock()
	g.Graph = cloneJSON(g.Graph)
	r.s.policyGraphs[g.ID] = g
	out := g
	out.Graph = cloneJSON(g.Graph)
	return out, nil
}

func (r *PolicyRepository) GetCurrentGraph(ctx context.Context, tenantID uuid.UUID) (repository.PolicyGraph, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.PolicyGraph{}, err
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	var best repository.PolicyGraph
	found := false
	for _, g := range r.s.policyGraphs {
		if g.TenantID != tenantID {
			continue
		}
		if !found || g.Version > best.Version {
			best = g
			found = true
		}
	}
	if !found {
		return repository.PolicyGraph{}, repository.ErrNotFound
	}
	out := best
	out.Graph = cloneJSON(best.Graph)
	return out, nil
}

func (r *PolicyRepository) ListGraphVersions(ctx context.Context, tenantID uuid.UUID, page repository.Page) (repository.PageResult[repository.PolicyGraph], error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.PageResult[repository.PolicyGraph]{}, err
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	all := make([]repository.PolicyGraph, 0, len(r.s.policyGraphs))
	for _, g := range r.s.policyGraphs {
		if g.TenantID != tenantID {
			continue
		}
		cp := g
		cp.Graph = cloneJSON(g.Graph)
		all = append(all, cp)
	}
	sort.SliceStable(all, func(i, j int) bool { return all[i].Version > all[j].Version })
	return paginate(all, page, func(g repository.PolicyGraph) cursor {
		return cursor{CreatedAt: g.CreatedAt, ID: g.ID}
	}), nil
}

func (r *PolicyRepository) CreateBundle(ctx context.Context, tenantID uuid.UUID, b repository.PolicyBundle) (repository.PolicyBundle, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.PolicyBundle{}, err
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	graph, ok := r.s.policyGraphs[b.PolicyGraphID]
	if !ok || graph.TenantID != tenantID {
		return repository.PolicyBundle{}, repository.ErrNotFound
	}
	switch b.TargetType {
	case repository.PolicyBundleTargetEdge, repository.PolicyBundleTargetEndpoint,
		repository.PolicyBundleTargetCloud, repository.PolicyBundleTargetMobile:
	default:
		return repository.PolicyBundle{}, repository.ErrInvalidArgument
	}
	for _, existing := range r.s.policyBundles {
		if existing.PolicyGraphID == b.PolicyGraphID && existing.TargetType == b.TargetType {
			return repository.PolicyBundle{}, repository.ErrConflict
		}
	}
	if b.ID == uuid.Nil {
		b.ID = uuid.New()
	}
	b.Bundle = cloneBytes(b.Bundle)
	b.Signature = cloneBytes(b.Signature)
	// Precompute sha256 mirroring the Postgres pgcrypto-backed
	// digest. The handler relies on Sha256 being populated so HEAD
	// / If-None-Match never has to recompute it from b.Bundle.
	sum := sha256.Sum256(b.Bundle)
	b.Sha256 = append([]byte(nil), sum[:]...)
	b.CreatedAt = r.s.clock()
	r.s.policyBundles[b.ID] = b
	out := b
	out.Bundle = cloneBytes(b.Bundle)
	out.Signature = cloneBytes(b.Signature)
	out.Sha256 = cloneBytes(b.Sha256)
	return out, nil
}

func (r *PolicyRepository) GetBundle(ctx context.Context, tenantID, id uuid.UUID) (repository.PolicyBundle, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.PolicyBundle{}, err
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	b, ok := r.s.policyBundles[id]
	if !ok {
		return repository.PolicyBundle{}, repository.ErrNotFound
	}
	graph, ok := r.s.policyGraphs[b.PolicyGraphID]
	if !ok || graph.TenantID != tenantID {
		return repository.PolicyBundle{}, repository.ErrNotFound
	}
	out := b
	out.Bundle = cloneBytes(b.Bundle)
	out.Signature = cloneBytes(b.Signature)
	out.Sha256 = cloneBytes(b.Sha256)
	return out, nil
}

func (r *PolicyRepository) GetLatestBundle(ctx context.Context, tenantID uuid.UUID, target repository.PolicyBundleTarget) (repository.PolicyBundle, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.PolicyBundle{}, err
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	var (
		best        repository.PolicyBundle
		bestVersion int
		found       bool
	)
	for _, b := range r.s.policyBundles {
		if b.TargetType != target {
			continue
		}
		graph, ok := r.s.policyGraphs[b.PolicyGraphID]
		if !ok || graph.TenantID != tenantID {
			continue
		}
		if !found || graph.Version > bestVersion || (graph.Version == bestVersion && b.CreatedAt.After(best.CreatedAt)) {
			best = b
			bestVersion = graph.Version
			found = true
		}
	}
	if !found {
		return repository.PolicyBundle{}, repository.ErrNotFound
	}
	out := best
	out.Bundle = cloneBytes(best.Bundle)
	out.Signature = cloneBytes(best.Signature)
	out.Sha256 = cloneBytes(best.Sha256)
	return out, nil
}

// GetLatestBundleMetadata mirrors GetLatestBundle but does not
// clone the bundle bytes — the handler's HEAD / 304 path never
// needs them. BundleSize is reported from the stored byte slice so
// HEAD can advertise Content-Length without a row-level COUNT.
func (r *PolicyRepository) GetLatestBundleMetadata(ctx context.Context, tenantID uuid.UUID, target repository.PolicyBundleTarget) (repository.PolicyBundleMetadata, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.PolicyBundleMetadata{}, err
	}
	switch target {
	case repository.PolicyBundleTargetEdge, repository.PolicyBundleTargetEndpoint,
		repository.PolicyBundleTargetCloud, repository.PolicyBundleTargetMobile:
	default:
		return repository.PolicyBundleMetadata{}, repository.ErrInvalidArgument
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	var (
		best        repository.PolicyBundle
		bestVersion int
		found       bool
	)
	for _, b := range r.s.policyBundles {
		if b.TargetType != target {
			continue
		}
		graph, ok := r.s.policyGraphs[b.PolicyGraphID]
		if !ok || graph.TenantID != tenantID {
			continue
		}
		if !found || graph.Version > bestVersion || (graph.Version == bestVersion && b.CreatedAt.After(best.CreatedAt)) {
			best = b
			bestVersion = graph.Version
			found = true
		}
	}
	if !found {
		return repository.PolicyBundleMetadata{}, repository.ErrNotFound
	}
	return repository.PolicyBundleMetadata{
		ID:            best.ID,
		PolicyGraphID: best.PolicyGraphID,
		TargetType:    best.TargetType,
		Signature:     cloneBytes(best.Signature),
		KeyID:         best.KeyID,
		Sha256:        cloneBytes(best.Sha256),
		BundleSize:    len(best.Bundle),
		CreatedAt:     best.CreatedAt,
	}, nil
}
