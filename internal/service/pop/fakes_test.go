// Copyright 2026 ShieldNet Gateway contributors.
// SPDX-License-Identifier: LicenseRef-Proprietary

package pop

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// fakeStore is an in-memory Store double. It is deliberately simple
// (a map per table) but enforces the same invariants the Postgres
// store does — one assignment per tenant (PK on tenant_id), and
// not-found errors as repository.ErrNotFound — so service/registry
// tests exercise the real control-flow without standing up Postgres.
type fakeStore struct {
	mu          sync.Mutex
	pops        map[uuid.UUID]PoP
	health      map[uuid.UUID][]Health // append-only beacon log per PoP
	assignments map[uuid.UUID]Assignment

	// failure injection for error-path tests.
	createErr  error
	upsertErr  error
	listPoPErr error
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		pops:        map[uuid.UUID]PoP{},
		health:      map[uuid.UUID][]Health{},
		assignments: map[uuid.UUID]Assignment{},
	}
}

// seedPoP inserts an already-enabled PoP directly (bypassing the
// service validation) so tests can build a fleet quickly.
func (f *fakeStore) seedPoP(p PoP) PoP {
	f.mu.Lock()
	defer f.mu.Unlock()
	if p.ID == uuid.Nil {
		p.ID = uuid.New()
	}
	if p.CreatedAt.IsZero() {
		p.CreatedAt = time.Unix(0, 0).UTC()
	}
	p.UpdatedAt = p.CreatedAt
	f.pops[p.ID] = p
	return p
}

// seedHealth records a beacon without going through RecordHealth's
// locking ceremony (still safe; just a helper).
func (f *fakeStore) seedHealth(h Health) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.health[h.PoPID] = append(f.health[h.PoPID], h)
}

func (f *fakeStore) CreatePoP(_ context.Context, p PoP) (PoP, error) {
	if f.createErr != nil {
		return PoP{}, f.createErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if p.ID == uuid.Nil {
		p.ID = uuid.New()
	}
	now := time.Unix(100, 0).UTC()
	p.CreatedAt, p.UpdatedAt = now, now
	f.pops[p.ID] = p
	return p, nil
}

func (f *fakeStore) GetPoP(_ context.Context, id uuid.UUID) (PoP, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p, ok := f.pops[id]
	if !ok {
		return PoP{}, repository.ErrNotFound
	}
	return p, nil
}

func (f *fakeStore) ListPoPs(_ context.Context, onlyEnabled bool) ([]PoP, error) {
	if f.listPoPErr != nil {
		return nil, f.listPoPErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]PoP, 0, len(f.pops))
	for _, p := range f.pops {
		if onlyEnabled && !p.Enabled {
			continue
		}
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID.String() < out[j].ID.String() })
	return out, nil
}

func (f *fakeStore) RecordHealth(_ context.Context, h Health) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.health[h.PoPID] = append(f.health[h.PoPID], h)
	return nil
}

func (f *fakeStore) LatestHealth(_ context.Context, popID uuid.UUID) (Health, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	beacons := f.health[popID]
	if len(beacons) == 0 {
		return Health{}, repository.ErrNotFound
	}
	return latest(beacons), nil
}

func (f *fakeStore) LatestHealthAll(_ context.Context) (map[uuid.UUID]Health, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make(map[uuid.UUID]Health, len(f.health))
	for id, beacons := range f.health {
		if len(beacons) == 0 {
			continue
		}
		out[id] = latest(beacons)
	}
	return out, nil
}

func latest(beacons []Health) Health {
	best := beacons[0]
	for _, h := range beacons[1:] {
		if h.ReportedAt.After(best.ReportedAt) {
			best = h
		}
	}
	return best
}

func (f *fakeStore) GetAssignment(_ context.Context, tenantID uuid.UUID) (Assignment, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	a, ok := f.assignments[tenantID]
	if !ok {
		return Assignment{}, repository.ErrNotFound
	}
	return a, nil
}

func (f *fakeStore) UpsertAssignment(_ context.Context, a Assignment) (Assignment, error) {
	if f.upsertErr != nil {
		return Assignment{}, f.upsertErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	a.AssignedAt = time.Unix(200, 0).UTC()
	f.assignments[a.TenantID] = a
	return a, nil
}

func (f *fakeStore) ListAssignmentsByPoP(_ context.Context, popID uuid.UUID) ([]Assignment, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []Assignment
	for _, a := range f.assignments {
		if a.PoPID == popID {
			out = append(out, a)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].TenantID.String() < out[j].TenantID.String() })
	return out, nil
}

// fixedClock returns a clock func pinned to t.
func fixedClock(t time.Time) func() time.Time {
	return func() time.Time { return t }
}
