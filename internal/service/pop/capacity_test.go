// Copyright 2026 ShieldNet Gateway contributors.
// SPDX-License-Identifier: LicenseRef-Proprietary

package pop

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestPlanRegion_Directions(t *testing.T) {
	t.Parallel()
	cfg := AutoscaleConfig{TargetTenantsPerPoP: 200, MaxTenantsPerPoP: 300, MinTenantsPerPoP: 50}
	cases := []struct {
		name        string
		tenants     int
		currentPoPs int
		wantRec     int
		wantDir     ScaleDirection
	}{
		{"empty region holds at one", 0, 1, 1, ScaleHold},
		{"at target holds within band", 200, 1, 1, ScaleHold},
		// avg 250 is between min(50) and max(300): hysteresis holds.
		{"over target but within band holds", 250, 1, 1, ScaleHold},
		// avg 302.5 > max(300): scale up to ceil(605/200)=4.
		{"over max scales up to target", 605, 2, 4, ScaleUp},
		// avg 450 > max: scale up to ceil(901/200)=5.
		{"well over max scales up multi", 901, 2, 5, ScaleUp},
		// avg 20 < min(50), multi-PoP: scale down to ceil(60/200)=1.
		{"under min multi scales down", 60, 3, 1, ScaleDown},
		// avg 42 < min, 5 PoPs: scale down to ceil(210/200)=2.
		{"under min scales down to target", 210, 5, 2, ScaleDown},
		// avg 10 < min but single PoP never drops below one.
		{"single pop never scales below one", 10, 1, 1, ScaleHold},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := planRegion("r", c.tenants, c.currentPoPs, cfg)
			if got.RecommendedPoPs != c.wantRec || got.Direction != c.wantDir {
				t.Fatalf("planRegion(t=%d,pops=%d) = (rec=%d,dir=%s), want (rec=%d,dir=%s)",
					c.tenants, c.currentPoPs, got.RecommendedPoPs, got.Direction, c.wantRec, c.wantDir)
			}
		})
	}
}

func TestAutoscaleConfig_WithDefaults(t *testing.T) {
	t.Parallel()
	// Partial override keeps band coherent: max must not fall below
	// target, min must not exceed target.
	got := AutoscaleConfig{TargetTenantsPerPoP: 500}.withDefaults()
	if got.TargetTenantsPerPoP != 500 {
		t.Errorf("target = %d, want 500", got.TargetTenantsPerPoP)
	}
	if got.MaxTenantsPerPoP < got.TargetTenantsPerPoP {
		t.Errorf("max %d < target %d", got.MaxTenantsPerPoP, got.TargetTenantsPerPoP)
	}
	if got.MinTenantsPerPoP > got.TargetTenantsPerPoP {
		t.Errorf("min %d > target %d", got.MinTenantsPerPoP, got.TargetTenantsPerPoP)
	}
	// Zero value resolves entirely to the package default.
	if (AutoscaleConfig{}).withDefaults() != DefaultAutoscaleConfig {
		t.Error("zero config did not resolve to DefaultAutoscaleConfig")
	}
}

func TestPlanRegionCapacity_AggregatesByRegion(t *testing.T) {
	t.Parallel()
	now := time.Unix(10_000, 0).UTC()
	store := newFakeStore()
	sea1 := seedHealthyPoP(store, "ap-southeast-1", CapacityMedium, now, 0)
	sea2 := seedHealthyPoP(store, "ap-southeast-1", CapacityMedium, now, 0)
	dach := seedHealthyPoP(store, "eu-central-1", CapacityMedium, now, 0)

	// 700 SEA tenants across 2 PoPs (avg 350 > max 300 → scale up to
	// ceil(700/200)=4); 10 DACH tenants on 1 PoP → hold.
	seedAssignments(store, sea1, 350)
	seedAssignments(store, sea2, 350)
	seedAssignments(store, dach, 10)

	svc := newTestService(t, store, now, WithAutoscaleConfig(AutoscaleConfig{TargetTenantsPerPoP: 200, MaxTenantsPerPoP: 300, MinTenantsPerPoP: 50}))
	plans, err := svc.PlanRegionCapacity(context.Background())
	if err != nil {
		t.Fatalf("PlanRegionCapacity: %v", err)
	}
	if len(plans) != 2 {
		t.Fatalf("got %d plans, want 2", len(plans))
	}
	// Sorted by region: ap-southeast-1 first.
	if plans[0].Region != "ap-southeast-1" || plans[0].ConnectedTenants != 700 ||
		plans[0].CurrentPoPs != 2 || plans[0].RecommendedPoPs != 4 || plans[0].Direction != ScaleUp {
		t.Errorf("SEA plan = %+v", plans[0])
	}
	if plans[1].Region != "eu-central-1" || plans[1].ConnectedTenants != 10 ||
		plans[1].Direction != ScaleHold {
		t.Errorf("DACH plan = %+v", plans[1])
	}
}

// seedAssignments homes n distinct tenants on the given PoP.
func seedAssignments(store *fakeStore, p PoP, n int) {
	store.mu.Lock()
	defer store.mu.Unlock()
	for i := 0; i < n; i++ {
		tid := uuid.New()
		store.assignments[tid] = Assignment{TenantID: tid, PoPID: p.ID, AssignedAt: time.Unix(200, 0).UTC()}
	}
}
