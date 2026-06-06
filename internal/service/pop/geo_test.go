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

func TestRegionGroupFor(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in    string
		want  RegionGroup
		wantK bool
	}{
		{"SEA", RegionGroupSEA, true},
		{"sea", RegionGroupSEA, true},
		{" Sg ", RegionGroupSEA, true},
		{"singapore", RegionGroupSEA, true},
		{"ap-southeast-1", RegionGroupSEA, true},
		{"jakarta", RegionGroupSEA, true},
		{"GCC", RegionGroupGCC, true},
		{"dubai", RegionGroupGCC, true},
		{"riyadh", RegionGroupGCC, true},
		{"me-south-1", RegionGroupGCC, true},
		{"DACH", RegionGroupDACH, true},
		{"zurich", RegionGroupDACH, true},
		{"frankfurt", RegionGroupDACH, true},
		{"eu-central-1", RegionGroupDACH, true},
		{"eu-west-1", RegionGroupDACH, true},
		{"", "", false},
		{"antarctica", "", false},
		{"us-east-1", "", false},
	}
	for _, c := range cases {
		got, ok := RegionGroupFor(c.in)
		if ok != c.wantK || got != c.want {
			t.Errorf("RegionGroupFor(%q) = (%q,%v), want (%q,%v)", c.in, got, ok, c.want, c.wantK)
		}
	}
}

func TestPreferredPoPRegions(t *testing.T) {
	t.Parallel()
	if got := PreferredPoPRegions(RegionGroupSEA); len(got) != 1 || got[0] != "ap-southeast-1" {
		t.Errorf("SEA preferred = %v", got)
	}
	if got := PreferredPoPRegions(RegionGroupDACH); len(got) != 2 || got[0] != "eu-central-1" || got[1] != "eu-west-1" {
		t.Errorf("DACH preferred = %v", got)
	}
	if got := PreferredPoPRegions(RegionGroup("nope")); got != nil {
		t.Errorf("invalid group preferred = %v, want nil", got)
	}
	// Returned slice must be a copy (mutating it must not corrupt the
	// package table).
	got := PreferredPoPRegions(RegionGroupDACH)
	got[0] = "tampered"
	if PreferredPoPRegions(RegionGroupDACH)[0] != "eu-central-1" {
		t.Fatal("PreferredPoPRegions returned a shared slice; table was mutated")
	}
}

// fakeRegionResolver is a TenantRegionResolver double.
type fakeRegionResolver struct {
	region string
	err    error
}

func (f fakeRegionResolver) TenantRegion(context.Context, uuid.UUID) (string, error) {
	return f.region, f.err
}

// seedHealthyPoP seeds an enabled PoP in region with a fresh beacon
// reporting conns active connections.
func seedHealthyPoP(store *fakeStore, region string, tier CapacityTier, now time.Time, conns int) PoP {
	p := store.seedPoP(PoP{
		Region: region, Provider: ProviderAWS, CapacityTier: tier,
		DNSName: region + ".edge.example.com", AnycastIP: "203.0.113.1", Enabled: true,
	})
	store.seedHealth(freshBeacon(p.ID, now, conns))
	return p
}

func TestAssignPoP_TenantRegionBias(t *testing.T) {
	t.Parallel()
	now := time.Unix(10_000, 0).UTC()
	store := newFakeStore()
	// DACH PoP is *less* loaded than the SEA PoP, so a purely
	// load-based pick would choose DACH. The tenant-region bias must
	// still home a SEA tenant on the SEA PoP.
	sea := seedHealthyPoP(store, "ap-southeast-1", CapacityMedium, now, 9000)
	_ = seedHealthyPoP(store, "eu-central-1", CapacityMedium, now, 10)

	svc := newTestService(t, store, now, WithTenantRegionResolver(fakeRegionResolver{region: "SEA"}))
	got, err := svc.AssignPoP(context.Background(), uuid.New(), "")
	if err != nil {
		t.Fatalf("AssignPoP: %v", err)
	}
	if got.ID != sea.ID {
		t.Fatalf("assigned region %q (id %s), want SEA PoP %s", got.Region, got.ID, sea.ID)
	}
}

func TestAssignPoP_GroupExhaustedFallsBackGlobal(t *testing.T) {
	t.Parallel()
	now := time.Unix(10_000, 0).UTC()
	store := newFakeStore()
	// Only a DACH PoP exists; a SEA tenant must still be served
	// (availability over residency preference).
	dach := seedHealthyPoP(store, "eu-central-1", CapacityMedium, now, 10)

	svc := newTestService(t, store, now, WithTenantRegionResolver(fakeRegionResolver{region: "SEA"}))
	got, err := svc.AssignPoP(context.Background(), uuid.New(), "")
	if err != nil {
		t.Fatalf("AssignPoP: %v", err)
	}
	if got.ID != dach.ID {
		t.Fatalf("assigned %s, want global fallback to DACH PoP %s", got.ID, dach.ID)
	}
}

func TestAssignPoP_NoResolverIsLoadBased(t *testing.T) {
	t.Parallel()
	now := time.Unix(10_000, 0).UTC()
	store := newFakeStore()
	_ = seedHealthyPoP(store, "ap-southeast-1", CapacityMedium, now, 9000)
	light := seedHealthyPoP(store, "eu-central-1", CapacityMedium, now, 10)

	// No resolver wired → least-loaded wins regardless of region.
	svc := newTestService(t, store, now)
	got, err := svc.AssignPoP(context.Background(), uuid.New(), "")
	if err != nil {
		t.Fatalf("AssignPoP: %v", err)
	}
	if got.ID != light.ID {
		t.Fatalf("assigned %s, want least-loaded %s", got.ID, light.ID)
	}
}

func TestAssignPoP_ResolverErrorFallsBackLoadBased(t *testing.T) {
	t.Parallel()
	now := time.Unix(10_000, 0).UTC()
	store := newFakeStore()
	_ = seedHealthyPoP(store, "ap-southeast-1", CapacityMedium, now, 9000)
	light := seedHealthyPoP(store, "eu-central-1", CapacityMedium, now, 10)

	// A resolver error must not break assignment; it degrades to
	// load-based selection.
	svc := newTestService(t, store, now, WithTenantRegionResolver(fakeRegionResolver{err: errors.New("db down")}))
	got, err := svc.AssignPoP(context.Background(), uuid.New(), "")
	if err != nil {
		t.Fatalf("AssignPoP: %v", err)
	}
	if got.ID != light.ID {
		t.Fatalf("assigned %s, want least-loaded %s on resolver error", got.ID, light.ID)
	}
}

func TestAssignPoP_UnknownTenantRegionIsLoadBased(t *testing.T) {
	t.Parallel()
	now := time.Unix(10_000, 0).UTC()
	store := newFakeStore()
	_ = seedHealthyPoP(store, "ap-southeast-1", CapacityMedium, now, 9000)
	light := seedHealthyPoP(store, "eu-central-1", CapacityMedium, now, 10)

	svc := newTestService(t, store, now, WithTenantRegionResolver(fakeRegionResolver{region: "atlantis"}))
	got, err := svc.AssignPoP(context.Background(), uuid.New(), "")
	if err != nil {
		t.Fatalf("AssignPoP: %v", err)
	}
	if got.ID != light.ID {
		t.Fatalf("assigned %s, want least-loaded %s for unknown region", got.ID, light.ID)
	}
}
