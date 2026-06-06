// Copyright 2026 ShieldNet Gateway contributors.
// SPDX-License-Identifier: LicenseRef-Proprietary

package pop

import (
	"context"
	"fmt"
	"math"
	"sort"

	"github.com/google/uuid"
)

// Capacity autoscale planning (Session 2B). The rebalancer in
// service.go reacts to *live* per-PoP load (health beacons) to relieve
// hot PoPs; the planner here works one level up, on the slower-moving
// signal of connected-tenant count per region, to recommend how many
// PoPs each region's cloud fleet should run. Its output drives the
// Terraform region-module `pop_desired_count` (and an operator
// dashboard), so scaling stays declarative — the control plane
// recommends, infrastructure-as-code provisions.
//
// Tenant count (not connection count) is the right autoscale signal at
// this layer because a cloud PoP runs sng-edge multi-tenant: each
// homed tenant carries a roughly bounded footprint (its policy bundle,
// its share of the shared inspection pipeline), so packing tenants per
// PoP within a target band keeps per-tenant cost inside the SME
// envelope while leaving the live rebalancer to smooth connection
// spikes underneath.

// ScaleDirection is the recommended change to a region's PoP count.
type ScaleDirection string

// Supported scale directions.
const (
	ScaleUp   ScaleDirection = "up"
	ScaleDown ScaleDirection = "down"
	ScaleHold ScaleDirection = "hold"
)

// AutoscaleConfig tunes the connected-tenant-per-PoP target band. The
// zero value is completed with DefaultAutoscaleConfig by the planner.
//
// The three bounds form a hysteresis band that keeps the
// recommendation from flapping: the planner only acts when the
// region's average load leaves the [min, max] band, and when it acts
// it sizes the fleet back to the target packing (not to the bound it
// just crossed). Sizing to target rather than to max means a region
// that crosses the upper bound lands comfortably in the middle of the
// band with headroom, instead of immediately sitting at the next
// trigger point.
type AutoscaleConfig struct {
	// TargetTenantsPerPoP is the steady-state packing the planner sizes
	// toward whenever it scales: RecommendedPoPs = ceil(tenants /
	// target).
	TargetTenantsPerPoP int
	// MaxTenantsPerPoP is the upper trigger: a region whose average
	// load exceeds it is scaled up (to the target packing). It must be
	// >= target; withDefaults enforces this.
	MaxTenantsPerPoP int
	// MinTenantsPerPoP is the lower trigger: a multi-PoP region whose
	// average load is below it is a scale-down candidate (to the target
	// packing, never below one PoP). It must be <= target; withDefaults
	// enforces this.
	MinTenantsPerPoP int
}

// DefaultAutoscaleConfig is the built-in target band. The values
// assume a medium cloud PoP comfortably serves a few hundred SME
// tenants; operators override per deployment.
var DefaultAutoscaleConfig = AutoscaleConfig{
	TargetTenantsPerPoP: 200,
	MaxTenantsPerPoP:    300,
	MinTenantsPerPoP:    50,
}

func (c AutoscaleConfig) withDefaults() AutoscaleConfig {
	d := DefaultAutoscaleConfig
	if c.TargetTenantsPerPoP > 0 {
		d.TargetTenantsPerPoP = c.TargetTenantsPerPoP
	}
	if c.MaxTenantsPerPoP > 0 {
		d.MaxTenantsPerPoP = c.MaxTenantsPerPoP
	}
	if c.MinTenantsPerPoP > 0 {
		d.MinTenantsPerPoP = c.MinTenantsPerPoP
	}
	// Keep the band coherent even after partial overrides.
	if d.MaxTenantsPerPoP < d.TargetTenantsPerPoP {
		d.MaxTenantsPerPoP = d.TargetTenantsPerPoP
	}
	if d.MinTenantsPerPoP > d.TargetTenantsPerPoP {
		d.MinTenantsPerPoP = d.TargetTenantsPerPoP
	}
	return d
}

// RegionCapacityPlan is the autoscale recommendation for one region's
// cloud PoP fleet.
type RegionCapacityPlan struct {
	Region           string         `json:"region"`
	ConnectedTenants int            `json:"connected_tenants"`
	CurrentPoPs      int            `json:"current_pops"`
	RecommendedPoPs  int            `json:"recommended_pops"`
	AvgTenantsPerPoP float64        `json:"avg_tenants_per_pop"`
	Direction        ScaleDirection `json:"direction"`
}

// PlanRegionCapacity computes a per-region autoscale recommendation
// from the current connected-tenant distribution. It runs under the
// system role (it reads every PoP's assignments cross-tenant) and is
// intended to be driven on the leader replica alongside Rebalance.
// Plans are returned sorted by region for deterministic output.
func (s *Service) PlanRegionCapacity(ctx context.Context) ([]RegionCapacityPlan, error) {
	cfg := s.autoscaleCfg()
	snap := s.registry.current()

	type regionAgg struct {
		tenants int
		pops    int
	}
	byRegion := make(map[string]*regionAgg)
	for _, p := range snap.pops {
		if !p.Enabled {
			continue
		}
		agg := byRegion[p.Region]
		if agg == nil {
			agg = &regionAgg{}
			byRegion[p.Region] = agg
		}
		agg.pops++
		assignments, err := s.store.ListAssignmentsByPoP(ctx, p.ID)
		if err != nil {
			return nil, fmt.Errorf("pop: capacity plan: list assignments for pop %s: %w", p.ID, err)
		}
		agg.tenants += len(assignments)
	}

	plans := make([]RegionCapacityPlan, 0, len(byRegion))
	for region, agg := range byRegion {
		plans = append(plans, planRegion(region, agg.tenants, agg.pops, cfg))
	}
	sort.Slice(plans, func(i, j int) bool { return plans[i].Region < plans[j].Region })
	return plans, nil
}

// autoscaleCfg returns the effective autoscale config. A future option
// can override it; today it is the package default, resolved through
// withDefaults so the band invariants always hold.
func (s *Service) autoscaleCfg() AutoscaleConfig {
	return s.autoscale.withDefaults()
}

// planRegion is the pure sizing core, separated for direct unit
// testing. currentPoPs is the count of enabled PoPs in the region (>=1
// for any region that appears here, since it is keyed off existing
// PoPs).
//
// It acts only when the region's average load leaves the [min, max]
// hysteresis band, and then sizes to the target packing:
//
//	avg > max               → scale up   to ceil(tenants/target)
//	avg < min (multi-PoP)   → scale down to ceil(tenants/target), >= 1
//	otherwise               → hold
//
// sizeToTarget is always >= current on a scale-up trigger and <=
// current on a scale-down trigger (because max >= target >= min), so
// the band guarantees the recommendation moves in the intended
// direction without flapping.
func planRegion(region string, tenants, currentPoPs int, cfg AutoscaleConfig) RegionCapacityPlan {
	plan := RegionCapacityPlan{
		Region:           region,
		ConnectedTenants: tenants,
		CurrentPoPs:      currentPoPs,
		RecommendedPoPs:  currentPoPs,
		Direction:        ScaleHold,
	}
	if currentPoPs <= 0 {
		return plan
	}
	avg := float64(tenants) / float64(currentPoPs)
	plan.AvgTenantsPerPoP = roundTo(avg, 2)

	sizeToTarget := int(math.Ceil(float64(tenants) / float64(cfg.TargetTenantsPerPoP)))
	if sizeToTarget < 1 {
		sizeToTarget = 1
	}

	switch {
	case avg > float64(cfg.MaxTenantsPerPoP):
		// Over the upper trigger: scale up to the target packing.
		if sizeToTarget > currentPoPs {
			plan.RecommendedPoPs = sizeToTarget
			plan.Direction = ScaleUp
		}
	case currentPoPs > 1 && avg < float64(cfg.MinTenantsPerPoP):
		// Under the lower trigger and we have a PoP to spare: scale
		// down to the target packing (never below one).
		if sizeToTarget < currentPoPs {
			plan.RecommendedPoPs = sizeToTarget
			plan.Direction = ScaleDown
		}
	}
	return plan
}

// roundTo rounds v to n decimal places.
func roundTo(v float64, n int) float64 {
	pow := math.Pow(10, float64(n))
	return math.Round(v*pow) / pow
}

// assignmentCounter is the cross-tenant assignment-listing surface the
// planner needs; declared for documentation and to keep the planner's
// dependency on Store explicit. (Store already satisfies it.)
var _ interface {
	ListAssignmentsByPoP(ctx context.Context, popID uuid.UUID) ([]Assignment, error)
} = (Store)(nil)
