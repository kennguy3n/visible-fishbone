package memory

import (
	"context"
	"math"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// dem.go is the in-memory DEM repository used by service-layer
// tests. Per the WP5 shared-file discipline it does NOT extend the
// aggregate Store (memory/store.go); it self-contains its own maps
// and mutex, borrowing only the Store's injected clock so test
// timestamps stay deterministic.

// demStateKey mirrors the Postgres unique index
// uq_dem_target_state_tenant_key (tenant_id, target_key).
type demStateKey struct {
	TenantID  uuid.UUID
	TargetKey string
}

// DEMRepository is the memory-backed repository.DEMRepository.
type DEMRepository struct {
	s *Store

	mu      sync.RWMutex
	targets map[uuid.UUID]repository.DEMTarget
	results []repository.DEMProbeResult
	scores  map[uuid.UUID]repository.DEMExperienceScore
	states  map[demStateKey]repository.DEMTargetState
}

// NewDEMRepository binds a Store (for its clock) and initialises the
// self-contained tables.
func NewDEMRepository(s *Store) *DEMRepository {
	return &DEMRepository{
		s:       s,
		targets: map[uuid.UUID]repository.DEMTarget{},
		scores:  map[uuid.UUID]repository.DEMExperienceScore{},
		states:  map[demStateKey]repository.DEMTargetState{},
	}
}

var _ repository.DEMRepository = (*DEMRepository)(nil)

func clonePtr[T any](p *T) *T {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}

func cloneDEMTarget(t repository.DEMTarget) repository.DEMTarget {
	t.Port = clonePtr(t.Port)
	return t
}

func cloneDEMScore(s repository.DEMExperienceScore) repository.DEMExperienceScore {
	s.LatencyP50Ms = clonePtr(s.LatencyP50Ms)
	s.LatencyP95Ms = clonePtr(s.LatencyP95Ms)
	return s
}

func cloneDEMState(st repository.DEMTargetState) repository.DEMTargetState {
	st.EWMAScore = clonePtr(st.EWMAScore)
	st.EWMAVariance = clonePtr(st.EWMAVariance)
	st.LastScore = clonePtr(st.LastScore)
	st.LastAlertAt = clonePtr(st.LastAlertAt)
	st.LastObservedAt = clonePtr(st.LastObservedAt)
	return st
}

func cloneDEMResult(res repository.DEMProbeResult) repository.DEMProbeResult {
	res.DNSMs = clonePtr(res.DNSMs)
	res.TCPMs = clonePtr(res.TCPMs)
	res.TLSMs = clonePtr(res.TLSMs)
	res.TTFBMs = clonePtr(res.TTFBMs)
	res.TotalMs = clonePtr(res.TotalMs)
	res.HTTPStatus = clonePtr(res.HTTPStatus)
	return res
}

// -----------------------------------------------------------------------
// Targets
// -----------------------------------------------------------------------

// CreateTarget persists a new custom target, rejecting a duplicate
// (tenant, target_key) with ErrConflict.
func (r *DEMRepository) CreateTarget(
	ctx context.Context,
	tenantID uuid.UUID,
	t repository.DEMTarget,
) (repository.DEMTarget, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.DEMTarget{}, err
	}
	if tenantID == uuid.Nil || t.TargetKey == "" || t.Name == "" || t.ProbeKind == "" || t.Address == "" {
		return repository.DEMTarget{}, repository.ErrInvalidArgument
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, existing := range r.targets {
		if existing.TenantID == tenantID && existing.TargetKey == t.TargetKey {
			return repository.DEMTarget{}, repository.ErrConflict
		}
	}
	now := r.s.clock()
	if t.ID == uuid.Nil {
		t.ID = uuid.New()
	}
	t.TenantID = tenantID
	t.CreatedAt = now
	t.UpdatedAt = now
	r.targets[t.ID] = cloneDEMTarget(t)
	return cloneDEMTarget(t), nil
}

// GetTarget returns one target by id, scoped to tenant.
func (r *DEMRepository) GetTarget(
	ctx context.Context,
	tenantID, id uuid.UUID,
) (repository.DEMTarget, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.DEMTarget{}, err
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	t, ok := r.targets[id]
	if !ok || t.TenantID != tenantID {
		return repository.DEMTarget{}, repository.ErrNotFound
	}
	return cloneDEMTarget(t), nil
}

// UpdateTarget mutates the addressable fields of an existing target.
func (r *DEMRepository) UpdateTarget(
	ctx context.Context,
	tenantID uuid.UUID,
	t repository.DEMTarget,
) (repository.DEMTarget, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.DEMTarget{}, err
	}
	if tenantID == uuid.Nil || t.ID == uuid.Nil || t.Name == "" || t.ProbeKind == "" || t.Address == "" {
		return repository.DEMTarget{}, repository.ErrInvalidArgument
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	existing, ok := r.targets[t.ID]
	if !ok || existing.TenantID != tenantID {
		return repository.DEMTarget{}, repository.ErrNotFound
	}
	existing.Name = t.Name
	existing.ProbeKind = t.ProbeKind
	existing.Address = t.Address
	existing.Port = clonePtr(t.Port)
	existing.Enabled = t.Enabled
	existing.IntervalSeconds = t.IntervalSeconds
	existing.TimeoutMs = t.TimeoutMs
	existing.UpdatedAt = r.s.clock()
	r.targets[t.ID] = existing
	return cloneDEMTarget(existing), nil
}

// DeleteTarget removes a custom target by id.
func (r *DEMRepository) DeleteTarget(ctx context.Context, tenantID, id uuid.UUID) error {
	if err := errCtxIfNeeded(ctx); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	t, ok := r.targets[id]
	if !ok || t.TenantID != tenantID {
		return repository.ErrNotFound
	}
	delete(r.targets, id)
	return nil
}

// ListTargets enumerates a tenant's custom targets.
func (r *DEMRepository) ListTargets(
	ctx context.Context,
	tenantID uuid.UUID,
	page repository.Page,
) (repository.PageResult[repository.DEMTarget], error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.PageResult[repository.DEMTarget]{}, err
	}
	page = page.Normalize()
	r.mu.RLock()
	matched := make([]repository.DEMTarget, 0, len(r.targets))
	for _, t := range r.targets {
		if t.TenantID == tenantID {
			matched = append(matched, cloneDEMTarget(t))
		}
	}
	r.mu.RUnlock()
	sorted := sortByCreatedAtDesc(matched,
		func(t repository.DEMTarget) time.Time { return t.CreatedAt },
		func(t repository.DEMTarget) uuid.UUID { return t.ID },
		page.Order)
	return paginate(sorted, page, func(t repository.DEMTarget) cursor {
		return cursor{CreatedAt: t.CreatedAt, ID: t.ID}
	}), nil
}

// -----------------------------------------------------------------------
// Raw probe results
// -----------------------------------------------------------------------

// InsertProbeResults appends ingested samples for one tenant.
func (r *DEMRepository) InsertProbeResults(
	ctx context.Context,
	tenantID uuid.UUID,
	results []repository.DEMProbeResult,
) error {
	if err := errCtxIfNeeded(ctx); err != nil {
		return err
	}
	if tenantID == uuid.Nil {
		return repository.ErrInvalidArgument
	}
	if len(results) == 0 {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.s.clock()
	for _, res := range results {
		stored := cloneDEMResult(res)
		if stored.ID == uuid.Nil {
			stored.ID = uuid.New()
		}
		stored.TenantID = tenantID
		stored.CreatedAt = now
		r.results = append(r.results, stored)
	}
	return nil
}

// WindowAggregate rolls up one target's results observed at/after
// `since`, computing availability and latency percentiles
// (percentile_cont with linear interpolation, matching Postgres).
func (r *DEMRepository) WindowAggregate(
	ctx context.Context,
	tenantID uuid.UUID,
	targetKey string,
	since time.Time,
) (repository.DEMWindowAggregate, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.DEMWindowAggregate{}, err
	}
	if tenantID == uuid.Nil || targetKey == "" {
		return repository.DEMWindowAggregate{}, repository.ErrInvalidArgument
	}
	agg := repository.DEMWindowAggregate{TargetKey: targetKey}
	latencies := make([]float64, 0, 16)
	r.mu.RLock()
	for _, res := range r.results {
		if res.TenantID != tenantID || res.TargetKey != targetKey {
			continue
		}
		if res.ObservedAt.Before(since) {
			continue
		}
		agg.SampleCount++
		if res.Success {
			agg.SuccessCount++
			if lat, ok := coalesceLatency(res); ok {
				latencies = append(latencies, lat)
			}
		}
		if agg.WindowStart.IsZero() || res.ObservedAt.Before(agg.WindowStart) {
			agg.WindowStart = res.ObservedAt
		}
		if res.ObservedAt.After(agg.WindowEnd) {
			agg.WindowEnd = res.ObservedAt
		}
	}
	r.mu.RUnlock()
	if len(latencies) > 0 {
		sort.Float64s(latencies)
		p50 := percentileCont(latencies, 0.5)
		p95 := percentileCont(latencies, 0.95)
		agg.LatencyP50Ms = &p50
		agg.LatencyP95Ms = &p95
	}
	return agg, nil
}

// PruneProbeResults deletes raw results created before `before`.
func (r *DEMRepository) PruneProbeResults(ctx context.Context, before time.Time) (int64, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return 0, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	kept := r.results[:0:0]
	var removed int64
	for _, res := range r.results {
		if res.CreatedAt.Before(before) {
			removed++
			continue
		}
		kept = append(kept, res)
	}
	r.results = kept
	return removed, nil
}

// -----------------------------------------------------------------------
// Experience scores
// -----------------------------------------------------------------------

// InsertScore appends one experience-score sample.
func (r *DEMRepository) InsertScore(
	ctx context.Context,
	tenantID uuid.UUID,
	s repository.DEMExperienceScore,
) (repository.DEMExperienceScore, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.DEMExperienceScore{}, err
	}
	if tenantID == uuid.Nil || s.TargetKey == "" || s.TargetName == "" {
		return repository.DEMExperienceScore{}, repository.ErrInvalidArgument
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if s.ID == uuid.Nil {
		s.ID = uuid.New()
	}
	s.TenantID = tenantID
	s.CreatedAt = r.s.clock()
	r.scores[s.ID] = cloneDEMScore(s)
	return cloneDEMScore(s), nil
}

// ListScores enumerates score samples matching the filter.
func (r *DEMRepository) ListScores(
	ctx context.Context,
	tenantID uuid.UUID,
	filter repository.DEMScoreFilter,
	page repository.Page,
) (repository.PageResult[repository.DEMExperienceScore], error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.PageResult[repository.DEMExperienceScore]{}, err
	}
	page = page.Normalize()
	keySet := map[string]struct{}{}
	for _, k := range filter.TargetKeys {
		keySet[k] = struct{}{}
	}
	r.mu.RLock()
	matched := make([]repository.DEMExperienceScore, 0, len(r.scores))
	for _, s := range r.scores {
		if s.TenantID != tenantID {
			continue
		}
		if len(keySet) > 0 {
			if _, ok := keySet[s.TargetKey]; !ok {
				continue
			}
		}
		if !filter.Since.IsZero() && s.CreatedAt.Before(filter.Since) {
			continue
		}
		if !filter.Until.IsZero() && s.CreatedAt.After(filter.Until) {
			continue
		}
		matched = append(matched, cloneDEMScore(s))
	}
	r.mu.RUnlock()
	sorted := sortByCreatedAtDesc(matched,
		func(s repository.DEMExperienceScore) time.Time { return s.CreatedAt },
		func(s repository.DEMExperienceScore) uuid.UUID { return s.ID },
		page.Order)
	return paginate(sorted, page, func(s repository.DEMExperienceScore) cursor {
		return cursor{CreatedAt: s.CreatedAt, ID: s.ID}
	}), nil
}

// LatestScores returns the newest score per target_key for a tenant.
func (r *DEMRepository) LatestScores(
	ctx context.Context,
	tenantID uuid.UUID,
) ([]repository.DEMExperienceScore, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return nil, err
	}
	r.mu.RLock()
	latest := map[string]repository.DEMExperienceScore{}
	for _, s := range r.scores {
		if s.TenantID != tenantID {
			continue
		}
		cur, ok := latest[s.TargetKey]
		if !ok || scoreNewer(s, cur) {
			latest[s.TargetKey] = s
		}
	}
	r.mu.RUnlock()
	out := make([]repository.DEMExperienceScore, 0, len(latest))
	for _, s := range latest {
		out = append(out, cloneDEMScore(s))
	}
	out = sortByCreatedAtDesc(out,
		func(s repository.DEMExperienceScore) time.Time { return s.CreatedAt },
		func(s repository.DEMExperienceScore) uuid.UUID { return s.ID },
		repository.SortDesc)
	return out, nil
}

// PruneScores deletes score samples created before `before`.
func (r *DEMRepository) PruneScores(ctx context.Context, before time.Time) (int64, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return 0, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	var removed int64
	for id, s := range r.scores {
		if s.CreatedAt.Before(before) {
			delete(r.scores, id)
			removed++
		}
	}
	return removed, nil
}

// -----------------------------------------------------------------------
// Per-target rolling state
// -----------------------------------------------------------------------

// GetTargetState returns the baseline row for (tenant, target_key).
func (r *DEMRepository) GetTargetState(
	ctx context.Context,
	tenantID uuid.UUID,
	targetKey string,
) (repository.DEMTargetState, bool, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.DEMTargetState{}, false, err
	}
	if tenantID == uuid.Nil || targetKey == "" {
		return repository.DEMTargetState{}, false, repository.ErrInvalidArgument
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	st, ok := r.states[demStateKey{TenantID: tenantID, TargetKey: targetKey}]
	if !ok {
		return repository.DEMTargetState{}, false, nil
	}
	return cloneDEMState(st), true, nil
}

// UpsertTargetState inserts or updates the baseline row.
func (r *DEMRepository) UpsertTargetState(
	ctx context.Context,
	tenantID uuid.UUID,
	st repository.DEMTargetState,
) (repository.DEMTargetState, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.DEMTargetState{}, err
	}
	if tenantID == uuid.Nil || st.TargetKey == "" || st.TargetName == "" {
		return repository.DEMTargetState{}, repository.ErrInvalidArgument
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	key := demStateKey{TenantID: tenantID, TargetKey: st.TargetKey}
	now := r.s.clock()
	existing, ok := r.states[key]
	if ok {
		st.ID = existing.ID
		st.CreatedAt = existing.CreatedAt
	} else {
		if st.ID == uuid.Nil {
			st.ID = uuid.New()
		}
		st.CreatedAt = now
	}
	st.TenantID = tenantID
	st.UpdatedAt = now
	r.states[key] = cloneDEMState(st)
	return cloneDEMState(st), nil
}

// -----------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------

// coalesceLatency returns the best available timing for a successful
// probe (total → TTFB → TCP → DNS), matching the Postgres COALESCE.
func coalesceLatency(res repository.DEMProbeResult) (float64, bool) {
	for _, p := range []*float64{res.TotalMs, res.TTFBMs, res.TCPMs, res.DNSMs} {
		if p != nil {
			return *p, true
		}
	}
	return 0, false
}

// percentileCont computes percentile_cont(p) over a sorted slice
// with linear interpolation between adjacent ranks. `sorted` must be
// non-empty and ascending.
func percentileCont(sorted []float64, p float64) float64 {
	n := len(sorted)
	if n == 1 {
		return sorted[0]
	}
	rank := p * float64(n-1)
	lo := int(math.Floor(rank))
	hi := int(math.Ceil(rank))
	if lo == hi {
		return sorted[lo]
	}
	frac := rank - float64(lo)
	return sorted[lo] + frac*(sorted[hi]-sorted[lo])
}

// scoreNewer reports whether a sorts after b in (created_at, id)
// descending order — i.e. a is the newer sample.
func scoreNewer(a, b repository.DEMExperienceScore) bool {
	if !a.CreatedAt.Equal(b.CreatedAt) {
		return a.CreatedAt.After(b.CreatedAt)
	}
	return a.ID.String() > b.ID.String()
}
