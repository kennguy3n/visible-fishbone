// Copyright 2026 ShieldNet Gateway contributors.
// SPDX-License-Identifier: LicenseRef-Proprietary

package pop

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestRegistry_RefreshLoadsFleetAndHealth(t *testing.T) {
	t.Parallel()
	store := newFakeStore()
	p := store.seedPoP(PoP{Region: "us-east", AnycastIP: "203.0.113.1", CapacityTier: CapacityMedium, Enabled: true})
	store.seedHealth(Health{PoPID: p.ID, ReportedAt: time.Unix(500, 0).UTC(), ActiveConnections: 10})

	reg := NewRegistry(store)
	if err := reg.Refresh(context.Background()); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	got, ok := reg.Get(p.ID)
	if !ok || got.Region != "us-east" {
		t.Fatalf("Get(%s) = (%+v, %v)", p.ID, got, ok)
	}
	h, ok := reg.Health(p.ID)
	if !ok || h.ActiveConnections != 10 {
		t.Fatalf("Health(%s) = (%+v, %v)", p.ID, h, ok)
	}
}

func TestRegistry_RefreshPropagatesStoreError(t *testing.T) {
	t.Parallel()
	store := newFakeStore()
	store.listPoPErr = errors.New("db down")
	reg := NewRegistry(store)
	if err := reg.Refresh(context.Background()); err == nil {
		t.Fatal("expected refresh to surface store error")
	}
}

func TestRegistry_AvailableExcludesDisabled(t *testing.T) {
	t.Parallel()
	store := newFakeStore()
	store.seedPoP(PoP{Region: "a", AnycastIP: "203.0.113.1", CapacityTier: CapacitySmall, Enabled: true})
	store.seedPoP(PoP{Region: "b", AnycastIP: "203.0.113.2", CapacityTier: CapacitySmall, Enabled: false})
	reg := NewRegistry(store)
	if err := reg.Refresh(context.Background()); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if got := len(reg.Available()); got != 1 {
		t.Fatalf("Available() = %d, want 1", got)
	}
	if got := len(reg.All()); got != 2 {
		t.Fatalf("All() = %d, want 2", got)
	}
}

func TestRegistry_ApplyHealthDropsUnknownPoP(t *testing.T) {
	t.Parallel()
	store := newFakeStore()
	reg := NewRegistry(store)
	_ = reg.Refresh(context.Background())
	reg.ApplyHealth(Health{PoPID: uuid.New(), ReportedAt: time.Unix(1, 0).UTC()})
	if got := len(reg.current().health); got != 0 {
		t.Fatalf("health folded for unknown PoP: %d entries", got)
	}
}

func TestRegistry_ApplyHealthIgnoresOlderBeacon(t *testing.T) {
	t.Parallel()
	store := newFakeStore()
	p := store.seedPoP(PoP{Region: "a", AnycastIP: "203.0.113.1", CapacityTier: CapacityMedium, Enabled: true})
	reg := NewRegistry(store)
	_ = reg.Refresh(context.Background())

	newer := Health{PoPID: p.ID, ReportedAt: time.Unix(1000, 0).UTC(), ActiveConnections: 99}
	older := Health{PoPID: p.ID, ReportedAt: time.Unix(500, 0).UTC(), ActiveConnections: 1}
	reg.ApplyHealth(newer)
	reg.ApplyHealth(older) // must be ignored (out of order)

	h, _ := reg.Health(p.ID)
	if h.ActiveConnections != 99 {
		t.Fatalf("older beacon overwrote newer: ActiveConnections=%d", h.ActiveConnections)
	}
}

func TestRegistry_RefreshKeepsNewerInMemoryBeacon(t *testing.T) {
	t.Parallel()
	store := newFakeStore()
	p := store.seedPoP(PoP{Region: "a", AnycastIP: "203.0.113.1", CapacityTier: CapacityMedium, Enabled: true})
	store.seedHealth(Health{PoPID: p.ID, ReportedAt: time.Unix(100, 0).UTC(), ActiveConnections: 1})

	reg := NewRegistry(store)
	_ = reg.Refresh(context.Background())

	// A live beacon arrives that is newer than anything in the DB.
	reg.ApplyHealth(Health{PoPID: p.ID, ReportedAt: time.Unix(900, 0).UTC(), ActiveConnections: 42})
	// A refresh that only sees the old DB row must not regress it.
	_ = reg.Refresh(context.Background())

	h, _ := reg.Health(p.ID)
	if h.ActiveConnections != 42 {
		t.Fatalf("refresh regressed live beacon: ActiveConnections=%d, want 42", h.ActiveConnections)
	}
}

func TestRegistry_IsHealthyHonoursTTL(t *testing.T) {
	t.Parallel()
	now := time.Unix(10_000, 0).UTC()
	store := newFakeStore()
	fresh := store.seedPoP(PoP{Region: "a", AnycastIP: "203.0.113.1", CapacityTier: CapacityMedium, Enabled: true})
	stale := store.seedPoP(PoP{Region: "b", AnycastIP: "203.0.113.2", CapacityTier: CapacityMedium, Enabled: true})
	store.seedHealth(Health{PoPID: fresh.ID, ReportedAt: now.Add(-10 * time.Second)})
	store.seedHealth(Health{PoPID: stale.ID, ReportedAt: now.Add(-10 * time.Minute)})

	reg := NewRegistry(store, WithHealthTTL(90*time.Second), withClock(fixedClock(now)))
	_ = reg.Refresh(context.Background())
	snap := reg.current()
	if !reg.isHealthy(snap, fresh.ID) {
		t.Error("fresh PoP reported unhealthy")
	}
	if reg.isHealthy(snap, stale.ID) {
		t.Error("stale PoP reported healthy")
	}
}

func TestUtilization(t *testing.T) {
	t.Parallel()
	medium := PoP{CapacityTier: CapacityMedium} // 50k max conns
	// No beacon -> +Inf (never assignable).
	if u := utilization(medium, Health{}, false); u != inf {
		t.Errorf("no-beacon utilization = %v, want +Inf", u)
	}
	// Unknown capacity -> +Inf.
	if u := utilization(PoP{CapacityTier: "bogus"}, Health{ActiveConnections: 1}, true); u != inf {
		t.Errorf("unknown-tier utilization = %v, want +Inf", u)
	}
	// Worst-of: CPU dominates connection load.
	u := utilization(medium, Health{ActiveConnections: 5_000, CPUPct: 95, MemoryPct: 10}, true)
	if u < 0.94 || u > 0.96 {
		t.Errorf("utilization = %v, want ~0.95 (CPU-dominated)", u)
	}
}
