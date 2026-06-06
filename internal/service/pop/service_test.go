// Copyright 2026 ShieldNet Gateway contributors.
// SPDX-License-Identifier: LicenseRef-Proprietary

package pop

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// newTestService builds a service+registry over store with a pinned
// clock and the registry warmed from the store.
func newTestService(t *testing.T, store *fakeStore, now time.Time, opts ...Option) *Service {
	t.Helper()
	reg := NewRegistry(store, WithHealthTTL(90*time.Second), withClock(fixedClock(now)))
	if err := reg.Refresh(context.Background()); err != nil {
		t.Fatalf("warm registry: %v", err)
	}
	base := []Option{withServiceClock(fixedClock(now))}
	svc := NewService(store, reg, append(base, opts...)...)
	return svc
}

func freshBeacon(popID uuid.UUID, now time.Time, conns int) Health {
	return Health{PoPID: popID, ReportedAt: now.Add(-time.Second), ActiveConnections: conns}
}

func TestRegisterPoP_Validation(t *testing.T) {
	t.Parallel()
	now := time.Unix(10_000, 0).UTC()
	store := newFakeStore()
	svc := newTestService(t, store, now)

	cases := []struct {
		name string
		in   PoP
	}{
		{"missing region", PoP{DNSName: "a", Provider: ProviderAWS, CapacityTier: CapacitySmall, AnycastIP: "203.0.113.1"}},
		{"missing dns", PoP{Region: "us-east", Provider: ProviderAWS, CapacityTier: CapacitySmall, AnycastIP: "203.0.113.1"}},
		{"bad provider", PoP{Region: "us-east", DNSName: "a", Provider: "ibm", CapacityTier: CapacitySmall, AnycastIP: "203.0.113.1"}},
		{"bad tier", PoP{Region: "us-east", DNSName: "a", Provider: ProviderAWS, CapacityTier: "huge", AnycastIP: "203.0.113.1"}},
		{"bad ip", PoP{Region: "us-east", DNSName: "a", Provider: ProviderAWS, CapacityTier: CapacitySmall, AnycastIP: "nope"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := svc.RegisterPoP(context.Background(), c.in); !errors.Is(err, repository.ErrInvalidArgument) {
				t.Fatalf("err = %v, want ErrInvalidArgument", err)
			}
		})
	}
}

func TestRegisterPoP_PersistsAndRefreshes(t *testing.T) {
	t.Parallel()
	now := time.Unix(10_000, 0).UTC()
	store := newFakeStore()
	svc := newTestService(t, store, now)
	created, err := svc.RegisterPoP(context.Background(), PoP{
		Region: "us-east", DNSName: "edge.example.com", Provider: ProviderAWS,
		CapacityTier: CapacityMedium, AnycastIP: "203.0.113.1", Enabled: true,
	})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if _, ok := svc.Registry().Get(created.ID); !ok {
		t.Fatal("new PoP not visible in registry after register")
	}
}

func TestAssignPoP_RequiresTenant(t *testing.T) {
	t.Parallel()
	now := time.Unix(10_000, 0).UTC()
	svc := newTestService(t, newFakeStore(), now)
	if _, err := svc.AssignPoP(context.Background(), uuid.Nil, "203.0.113.1"); !errors.Is(err, repository.ErrInvalidArgument) {
		t.Fatalf("err = %v, want ErrInvalidArgument", err)
	}
}

func TestAssignPoP_RejectsBadClientIP(t *testing.T) {
	t.Parallel()
	now := time.Unix(10_000, 0).UTC()
	svc := newTestService(t, newFakeStore(), now)
	if _, err := svc.AssignPoP(context.Background(), uuid.New(), "not-an-ip"); !errors.Is(err, repository.ErrInvalidArgument) {
		t.Fatalf("err = %v, want ErrInvalidArgument", err)
	}
}

func TestAssignPoP_PicksLeastLoadedHealthy(t *testing.T) {
	t.Parallel()
	now := time.Unix(10_000, 0).UTC()
	store := newFakeStore()
	hot := store.seedPoP(PoP{Region: "us-east", AnycastIP: "203.0.113.1", CapacityTier: CapacityMedium, Enabled: true})
	cool := store.seedPoP(PoP{Region: "us-east", AnycastIP: "203.0.113.2", CapacityTier: CapacityMedium, Enabled: true})
	store.seedHealth(freshBeacon(hot.ID, now, 40_000)) // 0.8 util
	store.seedHealth(freshBeacon(cool.ID, now, 5_000)) // 0.1 util

	svc := newTestService(t, store, now)
	got, err := svc.AssignPoP(context.Background(), uuid.New(), "198.51.100.1")
	if err != nil {
		t.Fatalf("assign: %v", err)
	}
	if got.ID != cool.ID {
		t.Fatalf("assigned %s, want least-loaded %s", got.ID, cool.ID)
	}
}

func TestAssignPoP_PrefersClientRegion(t *testing.T) {
	t.Parallel()
	now := time.Unix(10_000, 0).UTC()
	store := newFakeStore()
	// The globally least-loaded PoP is in eu-west, but the client is
	// in us-east, so the (slightly busier) us-east PoP should win.
	usEast := store.seedPoP(PoP{Region: "us-east", AnycastIP: "203.0.113.1", CapacityTier: CapacityMedium, Enabled: true})
	euWest := store.seedPoP(PoP{Region: "eu-west", AnycastIP: "203.0.113.2", CapacityTier: CapacityMedium, Enabled: true})
	store.seedHealth(freshBeacon(usEast.ID, now, 10_000)) // 0.2 util
	store.seedHealth(freshBeacon(euWest.ID, now, 1_000))  // 0.02 util

	loc, err := NewStaticRegionLocator(map[string]string{"198.51.100.0/24": "us-east"})
	if err != nil {
		t.Fatalf("locator: %v", err)
	}
	svc := newTestService(t, store, now, WithRegionLocator(loc))
	got, err := svc.AssignPoP(context.Background(), uuid.New(), "198.51.100.5")
	if err != nil {
		t.Fatalf("assign: %v", err)
	}
	if got.ID != usEast.ID {
		t.Fatalf("assigned %s, want in-region %s", got.ID, usEast.ID)
	}
}

func TestAssignPoP_StickyUntilUnhealthy(t *testing.T) {
	t.Parallel()
	now := time.Unix(10_000, 0).UTC()
	store := newFakeStore()
	a := store.seedPoP(PoP{Region: "us-east", AnycastIP: "203.0.113.1", CapacityTier: CapacityMedium, Enabled: true})
	b := store.seedPoP(PoP{Region: "us-east", AnycastIP: "203.0.113.2", CapacityTier: CapacityMedium, Enabled: true})
	store.seedHealth(freshBeacon(a.ID, now, 30_000))
	store.seedHealth(freshBeacon(b.ID, now, 1_000)) // less loaded

	svc := newTestService(t, store, now)
	tenant := uuid.New()
	// Pre-existing assignment to the busier PoP a; it is still
	// healthy, so the sticky assignment must be honoured even though b
	// is less loaded.
	if _, err := store.UpsertAssignment(context.Background(), Assignment{TenantID: tenant, PoPID: a.ID}); err != nil {
		t.Fatalf("seed assignment: %v", err)
	}
	got, err := svc.AssignPoP(context.Background(), tenant, "198.51.100.1")
	if err != nil {
		t.Fatalf("assign: %v", err)
	}
	if got.ID != a.ID {
		t.Fatalf("sticky assignment broken: got %s, want %s", got.ID, a.ID)
	}
}

func TestAssignPoP_RehomesWhenStickyPoPStale(t *testing.T) {
	t.Parallel()
	now := time.Unix(10_000, 0).UTC()
	store := newFakeStore()
	dead := store.seedPoP(PoP{Region: "us-east", AnycastIP: "203.0.113.1", CapacityTier: CapacityMedium, Enabled: true})
	alive := store.seedPoP(PoP{Region: "us-east", AnycastIP: "203.0.113.2", CapacityTier: CapacityMedium, Enabled: true})
	store.seedHealth(Health{PoPID: dead.ID, ReportedAt: now.Add(-10 * time.Minute)}) // stale
	store.seedHealth(freshBeacon(alive.ID, now, 1_000))

	svc := newTestService(t, store, now)
	tenant := uuid.New()
	_, _ = store.UpsertAssignment(context.Background(), Assignment{TenantID: tenant, PoPID: dead.ID})

	got, err := svc.AssignPoP(context.Background(), tenant, "198.51.100.1")
	if err != nil {
		t.Fatalf("assign: %v", err)
	}
	if got.ID != alive.ID {
		t.Fatalf("did not re-home off stale PoP: got %s, want %s", got.ID, alive.ID)
	}
}

func TestAssignPoP_HonoursOverrideEvenWhenHot(t *testing.T) {
	t.Parallel()
	now := time.Unix(10_000, 0).UTC()
	store := newFakeStore()
	pinned := store.seedPoP(PoP{Region: "us-east", AnycastIP: "203.0.113.1", CapacityTier: CapacityMedium, Enabled: true})
	store.seedHealth(Health{PoPID: pinned.ID, ReportedAt: now.Add(-10 * time.Minute)}) // stale, but override

	svc := newTestService(t, store, now)
	tenant := uuid.New()
	_, _ = store.UpsertAssignment(context.Background(), Assignment{TenantID: tenant, PoPID: pinned.ID, Override: true})

	got, err := svc.AssignPoP(context.Background(), tenant, "198.51.100.1")
	if err != nil {
		t.Fatalf("assign: %v", err)
	}
	if got.ID != pinned.ID {
		t.Fatalf("override not honoured: got %s, want %s", got.ID, pinned.ID)
	}
}

func TestAssignPoP_ExhaustedWhenAllOverloaded(t *testing.T) {
	t.Parallel()
	now := time.Unix(10_000, 0).UTC()
	store := newFakeStore()
	p := store.seedPoP(PoP{Region: "us-east", AnycastIP: "203.0.113.1", CapacityTier: CapacityMedium, Enabled: true})
	store.seedHealth(freshBeacon(p.ID, now, 49_000)) // 0.98 > high-water

	svc := newTestService(t, store, now)
	if _, err := svc.AssignPoP(context.Background(), uuid.New(), "198.51.100.1"); !errors.Is(err, repository.ErrResourceExhausted) {
		t.Fatalf("err = %v, want ErrResourceExhausted", err)
	}
}

func TestSetAssignment_Validation(t *testing.T) {
	t.Parallel()
	now := time.Unix(10_000, 0).UTC()
	store := newFakeStore()
	disabled := store.seedPoP(PoP{Region: "us-east", AnycastIP: "203.0.113.1", CapacityTier: CapacityMedium, Enabled: false})
	svc := newTestService(t, store, now)

	if _, err := svc.SetAssignment(context.Background(), uuid.Nil, disabled.ID, true); !errors.Is(err, repository.ErrInvalidArgument) {
		t.Fatalf("nil tenant err = %v, want ErrInvalidArgument", err)
	}
	if _, err := svc.SetAssignment(context.Background(), uuid.New(), disabled.ID, true); !errors.Is(err, repository.ErrInvalidArgument) {
		t.Fatalf("disabled-pop err = %v, want ErrInvalidArgument", err)
	}
	if _, err := svc.SetAssignment(context.Background(), uuid.New(), uuid.New(), true); !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("unknown-pop err = %v, want ErrNotFound", err)
	}
}

func TestSetAssignment_PinsOverride(t *testing.T) {
	t.Parallel()
	now := time.Unix(10_000, 0).UTC()
	store := newFakeStore()
	p := store.seedPoP(PoP{Region: "us-east", AnycastIP: "203.0.113.1", CapacityTier: CapacityMedium, Enabled: true})
	svc := newTestService(t, store, now)
	tenant := uuid.New()
	got, err := svc.SetAssignment(context.Background(), tenant, p.ID, true)
	if err != nil {
		t.Fatalf("set assignment: %v", err)
	}
	if !got.Override || got.PoPID != p.ID {
		t.Fatalf("assignment = %+v, want override pin to %s", got, p.ID)
	}
}

func TestIngestHealth_PersistsAndFolds(t *testing.T) {
	t.Parallel()
	now := time.Unix(10_000, 0).UTC()
	store := newFakeStore()
	p := store.seedPoP(PoP{Region: "us-east", AnycastIP: "203.0.113.1", CapacityTier: CapacityMedium, Enabled: true})
	svc := newTestService(t, store, now)

	if err := svc.IngestHealth(context.Background(), Health{PoPID: p.ID, ActiveConnections: 7}); err != nil {
		t.Fatalf("ingest: %v", err)
	}
	// Persisted.
	if h, err := store.LatestHealth(context.Background(), p.ID); err != nil || h.ActiveConnections != 7 {
		t.Fatalf("LatestHealth = (%+v, %v)", h, err)
	}
	// Folded into the registry.
	if h, ok := svc.Registry().Health(p.ID); !ok || h.ActiveConnections != 7 {
		t.Fatalf("registry health = (%+v, %v)", h, ok)
	}
}

func TestIngestHealth_RejectsNilPoP(t *testing.T) {
	t.Parallel()
	now := time.Unix(10_000, 0).UTC()
	svc := newTestService(t, newFakeStore(), now)
	if err := svc.IngestHealth(context.Background(), Health{PoPID: uuid.Nil}); !errors.Is(err, repository.ErrInvalidArgument) {
		t.Fatalf("err = %v, want ErrInvalidArgument", err)
	}
}

func TestIngestHealth_ClampsFarFutureTimestamp(t *testing.T) {
	t.Parallel()
	now := time.Unix(10_000, 0).UTC()
	store := newFakeStore()
	p := store.seedPoP(PoP{Region: "us-east", AnycastIP: "203.0.113.1", CapacityTier: CapacityMedium, Enabled: true})
	svc := newTestService(t, store, now)

	// A beacon dated far in the future (a mis-set or hostile edge
	// clock) must be clamped to server time; otherwise the staleness
	// check clock().Sub(reported_at) goes negative and pins the PoP
	// healthy forever, and the future timestamp would shadow every
	// later honest beacon in the registry's latest-wins ordering.
	future := now.Add(time.Hour)
	if err := svc.IngestHealth(context.Background(), Health{PoPID: p.ID, ReportedAt: future, ActiveConnections: 3}); err != nil {
		t.Fatalf("ingest: %v", err)
	}
	h, ok := svc.Registry().Health(p.ID)
	if !ok {
		t.Fatalf("registry missing health for %s", p.ID)
	}
	if !h.ReportedAt.Equal(now) {
		t.Fatalf("ReportedAt = %s, want clamped to now %s", h.ReportedAt, now)
	}
	// Persisted copy is clamped too.
	if ph, err := store.LatestHealth(context.Background(), p.ID); err != nil || !ph.ReportedAt.Equal(now) {
		t.Fatalf("persisted ReportedAt = (%s, %v), want clamped to %s", ph.ReportedAt, err, now)
	}
}

func TestIngestHealth_KeepsWithinSkewTimestamp(t *testing.T) {
	t.Parallel()
	now := time.Unix(10_000, 0).UTC()
	store := newFakeStore()
	p := store.seedPoP(PoP{Region: "us-east", AnycastIP: "203.0.113.1", CapacityTier: CapacityMedium, Enabled: true})
	svc := newTestService(t, store, now)

	// A small forward skew (legitimate NTP drift, within tolerance) is
	// preserved rather than clamped.
	skewed := now.Add(5 * time.Second)
	if err := svc.IngestHealth(context.Background(), Health{PoPID: p.ID, ReportedAt: skewed, ActiveConnections: 3}); err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if h, ok := svc.Registry().Health(p.ID); !ok || !h.ReportedAt.Equal(skewed) {
		t.Fatalf("ReportedAt = %v (ok=%v), want preserved %s", h.ReportedAt, ok, skewed)
	}
}

func TestRebalance_MovesNonOverrideTenants(t *testing.T) {
	t.Parallel()
	now := time.Unix(10_000, 0).UTC()
	store := newFakeStore()
	hot := store.seedPoP(PoP{Region: "us-east", AnycastIP: "203.0.113.1", CapacityTier: CapacityMedium, Enabled: true})
	cool := store.seedPoP(PoP{Region: "us-east", AnycastIP: "203.0.113.2", CapacityTier: CapacityMedium, Enabled: true})
	store.seedHealth(freshBeacon(hot.ID, now, 49_000)) // overloaded
	store.seedHealth(freshBeacon(cool.ID, now, 1_000)) // headroom

	movable := uuid.New()
	pinned := uuid.New()
	_, _ = store.UpsertAssignment(context.Background(), Assignment{TenantID: movable, PoPID: hot.ID})
	_, _ = store.UpsertAssignment(context.Background(), Assignment{TenantID: pinned, PoPID: hot.ID, Override: true})

	svc := newTestService(t, store, now)
	moved, err := svc.Rebalance(context.Background())
	if err != nil {
		t.Fatalf("rebalance: %v", err)
	}
	if moved != 1 {
		t.Fatalf("moved = %d, want 1 (override tenant must stay)", moved)
	}
	if a, _ := store.GetAssignment(context.Background(), movable); a.PoPID != cool.ID {
		t.Fatalf("movable tenant on %s, want %s", a.PoPID, cool.ID)
	}
	if a, _ := store.GetAssignment(context.Background(), pinned); a.PoPID != hot.ID {
		t.Fatalf("override tenant moved off %s", hot.ID)
	}
}

// TestRebalance_BiasesToTenantRegionGroup verifies a rebalance moves a
// tenant to a PoP in its own region group when one has capacity, even
// if an out-of-group PoP is less loaded — consistent with AssignPoP's
// region bias. Without the bias the rebalancer would shed a SEA tenant
// onto the least-loaded DACH PoP, breaking residency alignment.
func TestRebalance_BiasesToTenantRegionGroup(t *testing.T) {
	t.Parallel()
	now := time.Unix(10_000, 0).UTC()
	store := newFakeStore()
	hot := seedHealthyPoP(store, "ap-southeast-1", CapacityMedium, now, 49_000) // overloaded SEA
	coolSEA := seedHealthyPoP(store, "ap-southeast-1", CapacityMedium, now, 9_000)
	// DACH PoP is *less* loaded, so a purely load-based pick would
	// choose it; the region bias must keep the SEA tenant in SEA.
	coolDACH := seedHealthyPoP(store, "eu-central-1", CapacityMedium, now, 10)

	movable := uuid.New()
	_, _ = store.UpsertAssignment(context.Background(), Assignment{TenantID: movable, PoPID: hot.ID})

	svc := newTestService(t, store, now, WithTenantRegionResolver(fakeRegionResolver{region: "SEA"}))
	moved, err := svc.Rebalance(context.Background())
	if err != nil {
		t.Fatalf("rebalance: %v", err)
	}
	if moved != 1 {
		t.Fatalf("moved = %d, want 1", moved)
	}
	a, _ := store.GetAssignment(context.Background(), movable)
	if a.PoPID != coolSEA.ID {
		t.Fatalf("rebalanced to %s, want in-group SEA PoP %s (not DACH %s)", a.PoPID, coolSEA.ID, coolDACH.ID)
	}
}

// TestRebalance_RegionGroupExhaustedFallsBackGlobal verifies that when
// no in-group PoP has capacity the rebalancer still sheds the tenant to
// a global alternative rather than stranding it on the hot PoP.
func TestRebalance_RegionGroupExhaustedFallsBackGlobal(t *testing.T) {
	t.Parallel()
	now := time.Unix(10_000, 0).UTC()
	store := newFakeStore()
	hot := seedHealthyPoP(store, "ap-southeast-1", CapacityMedium, now, 49_000) // only SEA PoP, overloaded
	coolDACH := seedHealthyPoP(store, "eu-central-1", CapacityMedium, now, 10)

	movable := uuid.New()
	_, _ = store.UpsertAssignment(context.Background(), Assignment{TenantID: movable, PoPID: hot.ID})

	svc := newTestService(t, store, now, WithTenantRegionResolver(fakeRegionResolver{region: "SEA"}))
	moved, err := svc.Rebalance(context.Background())
	if err != nil {
		t.Fatalf("rebalance: %v", err)
	}
	if moved != 1 {
		t.Fatalf("moved = %d, want 1 (availability over residency)", moved)
	}
	if a, _ := store.GetAssignment(context.Background(), movable); a.PoPID != coolDACH.ID {
		t.Fatalf("rebalanced to %s, want global fallback to DACH PoP %s", a.PoPID, coolDACH.ID)
	}
}

func TestOverloadedPoPs(t *testing.T) {
	t.Parallel()
	now := time.Unix(10_000, 0).UTC()
	store := newFakeStore()
	hot := store.seedPoP(PoP{Region: "a", AnycastIP: "203.0.113.1", CapacityTier: CapacityMedium, Enabled: true})
	cool := store.seedPoP(PoP{Region: "b", AnycastIP: "203.0.113.2", CapacityTier: CapacityMedium, Enabled: true})
	store.seedHealth(freshBeacon(hot.ID, now, 49_000))
	store.seedHealth(freshBeacon(cool.ID, now, 1_000))

	svc := newTestService(t, store, now)
	over := svc.OverloadedPoPs()
	if len(over) != 1 || over[0].ID != hot.ID {
		t.Fatalf("OverloadedPoPs = %+v, want [%s]", over, hot.ID)
	}
}
