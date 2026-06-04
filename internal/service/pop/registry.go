// Copyright 2026 ShieldNet Gateway contributors.
// SPDX-License-Identifier: LicenseRef-Proprietary

package pop

import (
	"context"
	"math"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
)

// inf is the utilization sentinel for "never assign here" (no beacon
// or unknown capacity). math.Inf is not a constant, hence a var.
var inf = math.Inf(1)

// DefaultHealthTTL is how recent a PoP's last beacon must be for the
// PoP to count as healthy for assignment. Beacons older than this are
// treated as stale (the PoP likely died), so the PoP drops out of the
// healthy candidate set even though its row stays enabled.
const DefaultHealthTTL = 90 * time.Second

// registrySnapshot is the immutable in-memory view of the PoP fleet.
// It is published through an atomic.Pointer so the hot read path
// (AssignPoP, the public list endpoint) never takes a lock — readers
// load the current pointer and the swap is wait-free. Writers
// (periodic Refresh + per-beacon ApplyHealth) build a fresh snapshot
// and swap it in, copy-on-write, serialised by Registry.writeMu.
type registrySnapshot struct {
	// pops is the enabled+disabled fleet, sorted by (region, provider)
	// for deterministic iteration.
	pops []PoP
	// byID indexes pops for O(1) lookup. The PoP values are copies, so
	// sharing the map across readers is safe (never mutated in place).
	byID map[uuid.UUID]PoP
	// health is the latest beacon per PoP. Absence means "no beacon
	// seen yet" → unhealthy.
	health map[uuid.UUID]Health
}

func emptySnapshot() *registrySnapshot {
	return &registrySnapshot{byID: map[uuid.UUID]PoP{}, health: map[uuid.UUID]Health{}}
}

// Registry is the lock-free, in-memory cache of the PoP fleet,
// refreshed periodically from Postgres and updated in real time by
// NATS health beacons.
type Registry struct {
	store     Store
	snap      atomic.Pointer[registrySnapshot]
	writeMu   sync.Mutex // serialises snapshot rebuilds (writers only)
	healthTTL time.Duration
	clock     func() time.Time
}

// RegistryOption tunes a Registry.
type RegistryOption func(*Registry)

// WithHealthTTL overrides the staleness window for beacons.
func WithHealthTTL(ttl time.Duration) RegistryOption {
	return func(r *Registry) {
		if ttl > 0 {
			r.healthTTL = ttl
		}
	}
}

// withClock injects a clock for deterministic tests.
func withClock(clock func() time.Time) RegistryOption {
	return func(r *Registry) {
		if clock != nil {
			r.clock = clock
		}
	}
}

// NewRegistry builds an empty registry. Call Refresh to populate it
// from the store before serving traffic.
func NewRegistry(store Store, opts ...RegistryOption) *Registry {
	r := &Registry{
		store:     store,
		healthTTL: DefaultHealthTTL,
		clock:     func() time.Time { return time.Now().UTC() },
	}
	for _, o := range opts {
		o(r)
	}
	r.snap.Store(emptySnapshot())
	return r
}

// current returns the live snapshot. Never nil after construction.
func (r *Registry) current() *registrySnapshot {
	return r.snap.Load()
}

// Refresh reloads the full fleet + latest health from the store and
// swaps in a fresh snapshot. In-memory beacons newer than the
// persisted ones are preserved so a refresh never regresses a PoP's
// health to a stale DB row (beacons are applied in memory the instant
// they arrive and persisted on the same path, but the two can race).
func (r *Registry) Refresh(ctx context.Context) error {
	pops, err := r.store.ListPoPs(ctx, false)
	if err != nil {
		return err
	}
	dbHealth, err := r.store.LatestHealthAll(ctx)
	if err != nil {
		return err
	}

	r.writeMu.Lock()
	defer r.writeMu.Unlock()

	prev := r.current()
	byID := make(map[uuid.UUID]PoP, len(pops))
	for _, p := range pops {
		byID[p.ID] = p
	}

	health := make(map[uuid.UUID]Health, len(dbHealth))
	for id, h := range dbHealth {
		health[id] = h
	}
	// Keep any in-memory beacon that is newer than the DB row, but only
	// for PoPs that still exist.
	for id, mem := range prev.health {
		if _, ok := byID[id]; !ok {
			continue
		}
		if db, ok := health[id]; !ok || mem.ReportedAt.After(db.ReportedAt) {
			health[id] = mem
		}
	}

	sort.Slice(pops, func(i, j int) bool {
		if pops[i].Region != pops[j].Region {
			return pops[i].Region < pops[j].Region
		}
		return pops[i].Provider < pops[j].Provider
	})

	r.snap.Store(&registrySnapshot{pops: pops, byID: byID, health: health})
	return nil
}

// ApplyHealth folds a single beacon into the registry, copy-on-write.
// Beacons for unknown PoPs are dropped (a PoP must be registered
// before its beacons count). Out-of-order beacons (older than the one
// already held) are ignored so the latest reading always wins.
func (r *Registry) ApplyHealth(h Health) {
	r.writeMu.Lock()
	defer r.writeMu.Unlock()

	prev := r.current()
	if _, ok := prev.byID[h.PoPID]; !ok {
		return
	}
	if cur, ok := prev.health[h.PoPID]; ok && cur.ReportedAt.After(h.ReportedAt) {
		return
	}
	health := make(map[uuid.UUID]Health, len(prev.health)+1)
	for id, v := range prev.health {
		health[id] = v
	}
	health[h.PoPID] = h
	// pops / byID are immutable and unchanged, so the new snapshot
	// shares them with the old one.
	r.snap.Store(&registrySnapshot{pops: prev.pops, byID: prev.byID, health: health})
}

// Get returns the PoP by id and whether it is known.
func (r *Registry) Get(id uuid.UUID) (PoP, bool) {
	p, ok := r.current().byID[id]
	return p, ok
}

// Health returns the latest beacon for id and whether one is held.
func (r *Registry) Health(id uuid.UUID) (Health, bool) {
	h, ok := r.current().health[id]
	return h, ok
}

// All returns a copy of the full fleet (enabled and disabled).
func (r *Registry) All() []PoP {
	snap := r.current()
	out := make([]PoP, len(snap.pops))
	copy(out, snap.pops)
	return out
}

// Available returns the enabled PoPs — the set the public bootstrap
// endpoint advertises. The result is a fresh slice the caller owns.
func (r *Registry) Available() []PoP {
	snap := r.current()
	out := make([]PoP, 0, len(snap.pops))
	for _, p := range snap.pops {
		if p.Enabled {
			out = append(out, p)
		}
	}
	return out
}

// isHealthy reports whether the PoP has a fresh-enough beacon.
func (r *Registry) isHealthy(snap *registrySnapshot, id uuid.UUID) bool {
	h, ok := snap.health[id]
	if !ok {
		return false
	}
	return r.clock().Sub(h.ReportedAt) <= r.healthTTL
}

// utilization returns the PoP's load as a fraction in [0, +inf). It is
// the worst of connection / CPU / memory pressure so a PoP that is hot
// on any axis is treated as loaded. A PoP with an unknown capacity
// tier (MaxConnections == 0) or no beacon returns +Inf so it is never
// picked for a new assignment.
func utilization(p PoP, h Health, haveHealth bool) float64 {
	if !haveHealth {
		return inf
	}
	maxConns := p.CapacityTier.MaxConnections()
	if maxConns <= 0 {
		return inf
	}
	connUtil := float64(h.ActiveConnections) / float64(maxConns)
	worst := connUtil
	if cpu := h.CPUPct / 100; cpu > worst {
		worst = cpu
	}
	if mem := h.MemoryPct / 100; mem > worst {
		worst = mem
	}
	return worst
}
