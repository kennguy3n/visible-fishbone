package memory

import (
	"context"
	"sort"
	"sync"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// AppIDCatalogRepository is the memory-backed AppIDCatalogRepository.
// Unlike most memory repositories it does NOT hang its state off the
// shared Store: the catalog tables are new and adding fields to the
// shared memory/store.go would co-edit a hub file owned by no single
// work package. It is therefore fully self-contained, holding its own
// state behind its own RWMutex. Semantics mirror the Postgres driver:
// each version is an immutable triple (metadata, entries, signed
// bundle) and reads serve the highest serial.
type AppIDCatalogRepository struct {
	mu       sync.RWMutex
	versions []repository.AppIDCatalogVersion
	entries  map[int64][]repository.AppIDCatalogEntry
	bundles  map[int64]repository.AppIDCatalogBundle
}

// NewAppIDCatalogRepository returns a ready, empty catalog repository.
// The Store is accepted for constructor symmetry with the other
// memory repositories but is intentionally unused — this repository
// owns its state directly (see the type doc).
func NewAppIDCatalogRepository(_ *Store) *AppIDCatalogRepository {
	return &AppIDCatalogRepository{
		entries: map[int64][]repository.AppIDCatalogEntry{},
		bundles: map[int64]repository.AppIDCatalogBundle{},
	}
}

var _ repository.AppIDCatalogRepository = (*AppIDCatalogRepository)(nil)

// maxSerialLocked returns the highest published serial and whether any
// version exists. Caller holds at least the read lock.
func (r *AppIDCatalogRepository) maxSerialLocked() (int64, bool) {
	var (
		top   int64
		found bool
	)
	for _, v := range r.versions {
		if !found || v.Serial > top {
			top, found = v.Serial, true
		}
	}
	return top, found
}

// PublishVersion appends a new version atomically. A serial that does
// not strictly exceed the current maximum is rejected with ErrConflict
// so history cannot fork or regress, matching the Postgres primary-key
// guard.
func (r *AppIDCatalogRepository) PublishVersion(_ context.Context, version repository.AppIDCatalogVersion, entries []repository.AppIDCatalogEntry, bundle repository.AppIDCatalogBundle) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if cur, ok := r.maxSerialLocked(); ok && version.Serial <= cur {
		return repository.ErrConflict
	}

	cp := make([]repository.AppIDCatalogEntry, len(entries))
	for i, e := range entries {
		e.Serial = version.Serial
		cp[i] = cloneAppIDEntry(e)
	}
	bundle.Serial = version.Serial

	r.versions = append(r.versions, version)
	r.entries[version.Serial] = cp
	r.bundles[version.Serial] = cloneAppIDBundle(bundle)
	return nil
}

// CurrentVersion returns the highest-serial version metadata.
func (r *AppIDCatalogRepository) CurrentVersion(_ context.Context) (repository.AppIDCatalogVersion, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	serial, ok := r.maxSerialLocked()
	if !ok {
		return repository.AppIDCatalogVersion{}, repository.ErrNotFound
	}
	for _, v := range r.versions {
		if v.Serial == serial {
			return v, nil
		}
	}
	return repository.AppIDCatalogVersion{}, repository.ErrNotFound
}

// CurrentEntries returns the highest-serial version's entries sorted
// by app_id, as defensive copies.
func (r *AppIDCatalogRepository) CurrentEntries(_ context.Context) ([]repository.AppIDCatalogEntry, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	serial, ok := r.maxSerialLocked()
	if !ok {
		return nil, repository.ErrNotFound
	}
	src := r.entries[serial]
	out := make([]repository.AppIDCatalogEntry, len(src))
	for i, e := range src {
		out[i] = cloneAppIDEntry(e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].AppID < out[j].AppID })
	return out, nil
}

// CurrentBundleWithVersion returns the highest-serial version's signed
// bundle and its matching version metadata. Both are read under a
// single read-lock hold, so they always describe the same serial even
// if a publish is racing — the memory analogue of the Postgres
// single-statement join.
func (r *AppIDCatalogRepository) CurrentBundleWithVersion(_ context.Context) (repository.AppIDCatalogBundle, repository.AppIDCatalogVersion, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	serial, ok := r.maxSerialLocked()
	if !ok {
		return repository.AppIDCatalogBundle{}, repository.AppIDCatalogVersion{}, repository.ErrNotFound
	}
	for _, v := range r.versions {
		if v.Serial == serial {
			return cloneAppIDBundle(r.bundles[serial]), v, nil
		}
	}
	return repository.AppIDCatalogBundle{}, repository.AppIDCatalogVersion{}, repository.ErrNotFound
}

// ListVersions returns version metadata newest-first, capped at limit.
func (r *AppIDCatalogRepository) ListVersions(_ context.Context, limit int) ([]repository.AppIDCatalogVersion, error) {
	if limit <= 0 {
		limit = repository.DefaultPageLimit
	}
	if limit > repository.MaxPageLimit {
		limit = repository.MaxPageLimit
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]repository.AppIDCatalogVersion, len(r.versions))
	copy(out, r.versions)
	sort.Slice(out, func(i, j int) bool { return out[i].Serial > out[j].Serial })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// cloneAppIDEntry deep-copies an entry's slice fields so a later
// mutation of the caller's data cannot bleed into stored state
// (Postgres rows are likewise detached).
func cloneAppIDEntry(e repository.AppIDCatalogEntry) repository.AppIDCatalogEntry {
	e.SNISuffixes = cloneStrings(e.SNISuffixes)
	e.HostSuffixes = cloneStrings(e.HostSuffixes)
	e.JA3 = cloneStrings(e.JA3)
	e.BytePrefixes = cloneStrings(e.BytePrefixes)
	if e.Ports != nil {
		ports := make([]int, len(e.Ports))
		copy(ports, e.Ports)
		e.Ports = ports
	}
	return e
}

// cloneAppIDBundle deep-copies a bundle's byte fields.
func cloneAppIDBundle(b repository.AppIDCatalogBundle) repository.AppIDCatalogBundle {
	b.PublicKey = cloneBytes(b.PublicKey)
	b.Payload = cloneBytes(b.Payload)
	b.Signature = cloneBytes(b.Signature)
	return b
}
