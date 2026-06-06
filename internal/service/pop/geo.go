// Copyright 2026 ShieldNet Gateway contributors.
// SPDX-License-Identifier: LicenseRef-Proprietary

package pop

import (
	"context"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/region"
)

// Region-group taxonomy for tenant-region-biased PoP selection
// (Session 2B). A tenant carries a coarse region marker
// (repository.Tenant.Region) that may be a region-group code ("SEA"),
// a country / city ("SG", "dubai") or an AWS region string
// ("ap-southeast-1"). RegionGroupFor normalises any of those onto one
// of the canonical groups below, and PreferredPoPRegions maps a group
// to the ordered AWS regions whose cloud PoPs should serve that group.
//
// The mapping is deliberately a strong *preference*, not a hard
// constraint: AssignPoP biases toward in-group PoPs but falls back to
// the global least-loaded PoP when the tenant's region group has no
// PoP with available capacity, so a regional outage never strands a
// tenant. Compliance-grade hard pinning (data residency) is expressed
// separately via an operator override assignment, never by silently
// dropping the tenant on the floor here.

// RegionGroup is the coarse geography used to steer a tenant to the
// nearest cloud PoP fleet. It aliases the shared region taxonomy so
// the PoP manager and the traffic-classification engine resolve a
// tenant's region identically.
type RegionGroup = region.Group

// Supported region groups, re-exported from the shared taxonomy. These
// match the Terraform region modules (deploy/terraform/regions)
// one-for-one.
const (
	// RegionGroupSEA is South-East Asia (Singapore, Jakarta, Bangkok,
	// Kuala Lumpur), served from ap-southeast-1.
	RegionGroupSEA = region.GroupSEA
	// RegionGroupGCC is the Gulf Cooperation Council (Dubai, Riyadh),
	// served from me-south-1 (Bahrain).
	RegionGroupGCC = region.GroupGCC
	// RegionGroupDACH is the German-speaking EU (Zurich, Frankfurt,
	// Vienna), served from eu-central-1 and eu-west-1.
	RegionGroupDACH = region.GroupDACH
)

// preferredPoPRegions is the ordered AWS-region preference per group.
// Order is significant only as documentation of primary→secondary; the
// actual pick within a group is least-loaded (see pickBest), so a
// busier primary correctly sheds to a secondary in the same group.
var preferredPoPRegions = map[RegionGroup][]string{
	RegionGroupSEA:  {"ap-southeast-1"},
	RegionGroupGCC:  {"me-south-1"},
	RegionGroupDACH: {"eu-central-1", "eu-west-1"},
}

// RegionGroupFor normalises a tenant's coarse region marker onto a
// canonical region group, delegating to the shared region taxonomy. It
// returns ok=false for an empty or unrecognised marker, in which case
// the caller should fall back to non-grouped (client-IP / load-based)
// selection.
func RegionGroupFor(tenantRegion string) (RegionGroup, bool) {
	return region.GroupFor(tenantRegion)
}

// PreferredPoPRegions returns the ordered AWS regions whose PoPs should
// serve the group, or nil for an invalid group. The returned slice is
// a copy so callers cannot mutate the package table.
func PreferredPoPRegions(g RegionGroup) []string {
	src, ok := preferredPoPRegions[g]
	if !ok {
		return nil
	}
	out := make([]string, len(src))
	copy(out, src)
	return out
}

// TenantRegionResolver resolves a tenant's coarse region marker (the
// repository.Tenant.Region column) for region-biased PoP selection.
// It is intentionally narrow so the PoP service does not depend on the
// whole tenant repository; main wires an adapter over the tenant store.
type TenantRegionResolver interface {
	TenantRegion(ctx context.Context, tenantID uuid.UUID) (region string, err error)
}

// preferredRegionSet resolves the tenant's region group to the set of
// AWS regions to bias toward. It returns nil when no resolver is
// configured, the tenant has no region marker, or the marker does not
// map to a known group — every one of which means "no group bias,
// select on client-region / load alone".
func (s *Service) preferredRegionSet(ctx context.Context, tenantID uuid.UUID) map[string]bool {
	if s.tenantRegions == nil {
		return nil
	}
	region, err := s.tenantRegions.TenantRegion(ctx, tenantID)
	if err != nil {
		// A lookup failure must not break assignment; fall back to
		// load-based selection and leave a breadcrumb.
		s.logger.Warn("pop: tenant region lookup failed; using load-based selection",
			"tenant_id", tenantID.String(), "error", err)
		return nil
	}
	group, ok := RegionGroupFor(region)
	if !ok {
		return nil
	}
	regions := preferredPoPRegions[group]
	set := make(map[string]bool, len(regions))
	for _, r := range regions {
		set[r] = true
	}
	return set
}
