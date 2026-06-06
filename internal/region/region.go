// Copyright 2026 ShieldNet Gateway contributors.
// SPDX-License-Identifier: LicenseRef-Proprietary

// Package region defines ShieldNet's coarse geographic taxonomy
// (region groups) and the normalisation of the many ways a tenant's
// region can be spelled onto a canonical group.
//
// It is the single source of truth shared by the PoP manager (which
// maps a group to its cloud-PoP AWS regions for tenant-region-biased
// selection) and the traffic-classification engine (which pins
// regional trusted-app lists to a group). Keeping the taxonomy in one
// place prevents the two services from drifting — a SEA tenant must
// resolve to the same group whether it is being homed to a PoP or
// classified against the SEA trusted-app list.
package region

import "strings"

// Group is a coarse geography used to steer tenants to nearby
// infrastructure and to scope regional trusted-app lists.
type Group string

// Canonical region groups. These match the Terraform region modules
// (deploy/terraform/regions) and the regional seed data one-for-one.
const (
	// GroupSEA is South-East Asia (Singapore, Jakarta, Bangkok, Kuala
	// Lumpur).
	GroupSEA Group = "SEA"
	// GroupGCC is the Gulf Cooperation Council (Dubai, Riyadh,
	// Bahrain).
	GroupGCC Group = "GCC"
	// GroupDACH is the German-speaking EU (Zurich, Frankfurt, Vienna).
	GroupDACH Group = "DACH"
)

// Valid reports whether g is one of the canonical region groups.
func (g Group) Valid() bool {
	switch g {
	case GroupSEA, GroupGCC, GroupDACH:
		return true
	default:
		return false
	}
}

// aliases maps the many ways a region can be spelled onto a canonical
// group. Keys are lower-cased; GroupFor lower-cases and trims its
// input first. The same table resolves BOTH a tenant's region marker
// (repository.Tenant.Region) and an app's region codes
// (app_registry.regions), so a SEA tenant matches a SEA app regardless
// of which spelling each side used.
//
// Only UNAMBIGUOUS markers are listed: ISO country codes, city names,
// and AWS region strings, each of which belongs to exactly one group.
// Broad continental codes that appear in the seed data — "APAC", "EU",
// "MENA", "ANZ" — are deliberately NOT mapped: each spans more than
// one group (EU ⊋ DACH, APAC ⊋ SEA), so mapping them would leak one
// region's regional apps to another (e.g. a UK-only {EU,GB} app
// classifying a Swiss DACH tenant's traffic). Every regional seed row
// also carries the specific ISO country codes, so matching stays
// precise without the broad codes; a tenant stored with only a broad
// marker resolves to no group and safely falls back to global apps.
var aliases = map[string]Group{
	// South-East Asia
	"sea": GroupSEA,
	"sg":  GroupSEA, "singapore": GroupSEA, "sgp": GroupSEA,
	"id": GroupSEA, "jakarta": GroupSEA, "idn": GroupSEA, "indonesia": GroupSEA,
	"th": GroupSEA, "bangkok": GroupSEA, "tha": GroupSEA, "thailand": GroupSEA,
	"my": GroupSEA, "kl": GroupSEA, "kuala-lumpur": GroupSEA, "mys": GroupSEA, "malaysia": GroupSEA,
	"vn": GroupSEA, "vnm": GroupSEA, "vietnam": GroupSEA,
	"ph": GroupSEA, "phl": GroupSEA, "philippines": GroupSEA,
	"ap-southeast-1": GroupSEA, "ap-southeast-3": GroupSEA,
	// Gulf Cooperation Council
	"gcc": GroupGCC,
	"ae":  GroupGCC, "dubai": GroupGCC, "uae": GroupGCC, "abu-dhabi": GroupGCC, "are": GroupGCC,
	"sa": GroupGCC, "riyadh": GroupGCC, "ksa": GroupGCC, "sau": GroupGCC,
	"bh": GroupGCC, "bahrain": GroupGCC, "bhr": GroupGCC,
	"me-south-1": GroupGCC, "me-central-1": GroupGCC,
	// German-speaking EU
	"dach": GroupDACH,
	"ch":   GroupDACH, "zurich": GroupDACH, "che": GroupDACH, "switzerland": GroupDACH,
	"de": GroupDACH, "frankfurt": GroupDACH, "deu": GroupDACH, "germany": GroupDACH,
	"at": GroupDACH, "vienna": GroupDACH, "aut": GroupDACH, "austria": GroupDACH,
	"eu-central-1": GroupDACH, "eu-west-1": GroupDACH,
}

// GroupFor normalises a tenant's coarse region marker onto a canonical
// region group. It returns ok=false for an empty or unrecognised
// marker, in which case callers fall back to non-grouped behaviour
// (load-based PoP selection / global-only classification).
func GroupFor(tenantRegion string) (Group, bool) {
	key := strings.ToLower(strings.TrimSpace(tenantRegion))
	if key == "" {
		return "", false
	}
	// Accept an exact canonical group spelling regardless of case.
	if g := Group(strings.ToUpper(key)); g.Valid() {
		return g, true
	}
	g, ok := aliases[key]
	return g, ok
}
