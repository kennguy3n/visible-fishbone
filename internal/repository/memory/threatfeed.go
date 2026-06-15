package memory

import (
	"context"
	"runtime"
	"sort"
	"sync"
	"weak"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// This file is the in-memory backend for the managed threat-content
// engine's repository (repository.ThreatFeedRepository). It is a NEW,
// self-contained file: the shared memory Store (store.go) is co-owned by
// other work packages and must not be edited, so the managed engine's
// state cannot live as new fields on Store.
//
// Instead the state hangs off a package-private side table keyed by the
// owning Store. That preserves the backend's "one shared store"
// semantics — every NewThreatFeedRepository(s) for the same Store sees
// the same data, exactly like the field-on-Store repos — while keeping
// per-test isolation (each test builds a fresh Store) and touching no
// shared file. Timestamps still come from the Store's injected clock
// (r.s.clock()) so deterministic-clock tests behave identically to the
// other memory repos.
//
// The side table is keyed by a weak.Pointer[Store] and paired with a
// runtime.AddCleanup hook so it never keeps a Store alive: once a Store
// becomes unreachable (e.g. the fresh Store every test builds) it is
// reclaimed and its entry is deleted. Keying by a strong *Store would
// instead pin every Store ever constructed for the lifetime of the
// process — a genuine leak under a large test suite.

// threatFeedState is the mutable in-memory state for one Store's managed
// threat-content tables. Its own mutex guards it independently of the
// Store's lock so this addition never contends on (or deadlocks against)
// the shared store mutex.
type threatFeedState struct {
	mu      sync.RWMutex
	sources map[string]repository.ThreatFeedSource
	ingest  map[string]repository.ThreatFeedIngestState
	bundles map[int64]repository.ThreatFeedBundle
}

func newThreatFeedState() *threatFeedState {
	return &threatFeedState{
		sources: map[string]repository.ThreatFeedSource{},
		ingest:  map[string]repository.ThreatFeedIngestState{},
		bundles: map[int64]repository.ThreatFeedBundle{},
	}
}

var threatFeedStates = struct {
	mu sync.Mutex
	m  map[weak.Pointer[Store]]*threatFeedState
}{m: map[weak.Pointer[Store]]*threatFeedState{}}

// threatFeedStateFor lazily allocates and returns the managed
// threat-content state for a Store, so repeated repository constructions
// share one state per Store. weak.Make returns equal pointers for equal
// inputs, so a lookup while the Store is live behaves like an ordinary
// identity-keyed map.
func (s *Store) threatFeedStateFor() *threatFeedState {
	key := weak.Make(s)
	threatFeedStates.mu.Lock()
	defer threatFeedStates.mu.Unlock()
	if st := threatFeedStates.m[key]; st != nil {
		return st
	}
	st := newThreatFeedState()
	threatFeedStates.m[key] = st
	// Reclaim the entry once the Store is garbage-collected so the side
	// table never pins freed Stores. The cleanup captures only the weak
	// key (never the Store), so registering it does not itself keep the
	// Store alive and defeat the cleanup.
	runtime.AddCleanup(s, cleanupThreatFeedState, key)
	return st
}

// cleanupThreatFeedState removes a reclaimed Store's entry from the side
// table. It is a package-level function (not a closure over the Store) so
// it holds no strong reference back to the collected Store.
func cleanupThreatFeedState(key weak.Pointer[Store]) {
	threatFeedStates.mu.Lock()
	delete(threatFeedStates.m, key)
	threatFeedStates.mu.Unlock()
}

// ThreatFeedRepository is the in-memory managed threat-content
// repository.
type ThreatFeedRepository struct {
	s  *Store
	st *threatFeedState
}

// NewThreatFeedRepository constructs the in-memory managed
// threat-content repository bound to the Store's shared state.
func (s *Store) NewThreatFeedRepository() *ThreatFeedRepository {
	return &ThreatFeedRepository{s: s, st: s.threatFeedStateFor()}
}

var _ repository.ThreatFeedRepository = (*ThreatFeedRepository)(nil)

// --- source registry --------------------------------------------------

func (r *ThreatFeedRepository) UpsertSources(_ context.Context, sources []repository.ThreatFeedSource) error {
	if len(sources) == 0 {
		return nil
	}
	now := r.s.clock()
	r.st.mu.Lock()
	defer r.st.mu.Unlock()
	for _, src := range sources {
		if prev, ok := r.st.sources[src.Name]; ok {
			// Preserve the original CreatedAt so the registry reflects
			// first-seen, not last-upserted, and PRESERVE the operator-
			// owned Enabled flag so a manual disable survives the curated
			// boot re-seed (mirrors the postgres ON CONFLICT clause).
			src.CreatedAt = prev.CreatedAt
			src.Enabled = prev.Enabled
		} else {
			src.CreatedAt = now
		}
		src.UpdatedAt = now
		r.st.sources[src.Name] = src
	}
	return nil
}

func (r *ThreatFeedRepository) ListSources(_ context.Context) ([]repository.ThreatFeedSource, error) {
	r.st.mu.RLock()
	defer r.st.mu.RUnlock()
	out := make([]repository.ThreatFeedSource, 0, len(r.st.sources))
	for _, src := range r.st.sources {
		out = append(out, src)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// --- ingestion state --------------------------------------------------

func (r *ThreatFeedRepository) SaveIngestState(_ context.Context, state repository.ThreatFeedIngestState) error {
	state.UpdatedAt = r.s.clock()
	r.st.mu.Lock()
	defer r.st.mu.Unlock()
	r.st.ingest[state.SourceName] = state
	return nil
}

func (r *ThreatFeedRepository) ListIngestState(_ context.Context) ([]repository.ThreatFeedIngestState, error) {
	r.st.mu.RLock()
	defer r.st.mu.RUnlock()
	out := make([]repository.ThreatFeedIngestState, 0, len(r.st.ingest))
	for _, st := range r.st.ingest {
		out = append(out, st)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].SourceName < out[j].SourceName })
	return out, nil
}

// --- signed bundle versions -------------------------------------------

func (r *ThreatFeedRepository) SaveBundle(_ context.Context, bundle repository.ThreatFeedBundle) error {
	r.st.mu.Lock()
	defer r.st.mu.Unlock()
	if prev, ok := r.st.bundles[bundle.Serial]; ok {
		// Preserve the original CreatedAt on a serial collision so it marks
		// when the version was FIRST persisted, not last-overwritten. This
		// mirrors the postgres backend, whose ON CONFLICT clause omits
		// created_at; keeping the two backends identical means tests against
		// the in-memory store observe the same created_at-on-conflict
		// semantics as production.
		bundle.CreatedAt = prev.CreatedAt
	} else {
		bundle.CreatedAt = r.s.clock()
	}
	r.st.bundles[bundle.Serial] = cloneThreatFeedBundle(bundle)
	return nil
}

func (r *ThreatFeedRepository) LatestBundle(_ context.Context) (*repository.ThreatFeedBundle, error) {
	r.st.mu.RLock()
	defer r.st.mu.RUnlock()
	var (
		best  repository.ThreatFeedBundle
		found bool
	)
	for _, b := range r.st.bundles {
		if !found || b.Serial > best.Serial {
			best = b
			found = true
		}
	}
	if !found {
		return nil, repository.ErrNotFound
	}
	out := cloneThreatFeedBundle(best)
	return &out, nil
}

func (r *ThreatFeedRepository) LatestSerial(_ context.Context) (int64, error) {
	r.st.mu.RLock()
	defer r.st.mu.RUnlock()
	var maxSerial int64
	for serial := range r.st.bundles {
		if serial > maxSerial {
			maxSerial = serial
		}
	}
	return maxSerial, nil
}

func (r *ThreatFeedRepository) PruneBundles(_ context.Context, keep int) error {
	if keep <= 0 {
		return nil
	}
	r.st.mu.Lock()
	defer r.st.mu.Unlock()
	if len(r.st.bundles) <= keep {
		return nil
	}
	serials := make([]int64, 0, len(r.st.bundles))
	for serial := range r.st.bundles {
		serials = append(serials, serial)
	}
	// Sort descending and drop everything past the keep-th.
	sort.Slice(serials, func(i, j int) bool { return serials[i] > serials[j] })
	for _, serial := range serials[keep:] {
		delete(r.st.bundles, serial)
	}
	return nil
}

// cloneThreatFeedBundle deep-copies the mutable reference fields
// (Envelope bytes, CountsByType map) so a stored bundle is never
// aliased by a caller that later mutates the slice/map it passed in or
// received back.
func cloneThreatFeedBundle(b repository.ThreatFeedBundle) repository.ThreatFeedBundle {
	if b.Envelope != nil {
		env := make([]byte, len(b.Envelope))
		copy(env, b.Envelope)
		b.Envelope = env
	}
	if b.CountsByType != nil {
		counts := make(map[string]int, len(b.CountsByType))
		for k, v := range b.CountsByType {
			counts[k] = v
		}
		b.CountsByType = counts
	}
	return b
}
