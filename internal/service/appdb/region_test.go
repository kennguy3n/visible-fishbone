package appdb_test

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/service/appdb"
)

// fakeRegionResolver is an appdb.TenantRegionResolver double.
type fakeRegionResolver struct {
	region string
	err    error
}

func (f fakeRegionResolver) TenantRegion(context.Context, uuid.UUID) (string, error) {
	return f.region, f.err
}

func seedRegionalApp(t *testing.T, svc *appdb.Service, name string, cls repository.TrafficClass, regions []string, domains ...string) repository.AppRegistry {
	t.Helper()
	app, err := svc.CreateApp(context.Background(), repository.AppRegistry{
		Name:         name,
		Vendor:       "test",
		TrafficClass: cls,
		Scope:        repository.AppRegistryScopeRegional,
		Regions:      regions,
		Domains:      domains,
		IsSystem:     true,
	})
	if err != nil {
		t.Fatalf("seed regional app %q: %v", name, err)
	}
	return app
}

func TestResolveTrafficClass_RegionalAppInRegion(t *testing.T) {
	svc, tenantID := newTestService(t)
	svc.SetTenantRegionResolver(fakeRegionResolver{region: "SG"})
	seedRegionalApp(t, svc, "Grab", repository.TrafficClassTrustedDirect, []string{"SEA"}, "*.grab.com")

	cls, err := svc.ResolveTrafficClass(context.Background(), tenantID, "api.grab.com")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if cls != repository.TrafficClassTrustedDirect {
		t.Fatalf("class = %q, want trusted_direct for in-region tenant", cls)
	}
}

func TestResolveTrafficClass_RegionalAppOutOfRegionExcluded(t *testing.T) {
	svc, tenantID := newTestService(t)
	// Tenant is DACH; the SEA-only app must not classify its traffic.
	svc.SetTenantRegionResolver(fakeRegionResolver{region: "frankfurt"})
	seedRegionalApp(t, svc, "Grab", repository.TrafficClassTrustedDirect, []string{"SEA"}, "*.grab.com")

	cls, err := svc.ResolveTrafficClass(context.Background(), tenantID, "api.grab.com")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if cls != repository.TrafficClassInspectFull {
		t.Fatalf("class = %q, want inspect_full (regional app must not leak cross-region)", cls)
	}
}

func TestResolveTrafficClass_RegionalAppNoResolverExcluded(t *testing.T) {
	svc, tenantID := newTestService(t)
	// No resolver configured → regional apps apply to nobody (fail-safe).
	seedRegionalApp(t, svc, "Grab", repository.TrafficClassTrustedDirect, []string{"SEA"}, "*.grab.com")

	cls, err := svc.ResolveTrafficClass(context.Background(), tenantID, "api.grab.com")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if cls != repository.TrafficClassInspectFull {
		t.Fatalf("class = %q, want inspect_full when no region resolver", cls)
	}
}

func TestResolveTrafficClass_GlobalAppUnaffectedByRegion(t *testing.T) {
	svc, tenantID := newTestService(t)
	svc.SetTenantRegionResolver(fakeRegionResolver{region: "frankfurt"})
	// A global app applies regardless of the tenant's region.
	seedApp(t, svc, "Office", repository.TrafficClassTrustedDirect, "*.office.com")

	cls, err := svc.ResolveTrafficClass(context.Background(), tenantID, "outlook.office.com")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if cls != repository.TrafficClassTrustedDirect {
		t.Fatalf("class = %q, want trusted_direct (global app)", cls)
	}
}

func TestResolveTrafficClass_ResolverErrorFailsSafeGlobalOnly(t *testing.T) {
	svc, tenantID := newTestService(t)
	// A resolver error must not fail classification; it degrades to
	// global-only (regional apps excluded).
	svc.SetTenantRegionResolver(fakeRegionResolver{err: errors.New("db down")})
	seedRegionalApp(t, svc, "Grab", repository.TrafficClassTrustedDirect, []string{"SEA"}, "*.grab.com")
	seedApp(t, svc, "Office", repository.TrafficClassTrustedDirect, "*.office.com")

	regional, err := svc.ResolveTrafficClass(context.Background(), tenantID, "api.grab.com")
	if err != nil {
		t.Fatalf("resolve regional: %v", err)
	}
	if regional != repository.TrafficClassInspectFull {
		t.Fatalf("regional class = %q, want inspect_full on resolver error", regional)
	}
	global, err := svc.ResolveTrafficClass(context.Background(), tenantID, "outlook.office.com")
	if err != nil {
		t.Fatalf("resolve global: %v", err)
	}
	if global != repository.TrafficClassTrustedDirect {
		t.Fatalf("global class = %q, want trusted_direct on resolver error", global)
	}
}

// TestResolveTrafficClass_RealSeedConvention exercises the exact
// region-code convention the seed migrations use — a broad continental
// code plus specific ISO country codes, e.g. {APAC,SG,MY}. Matching
// must key off the ISO codes (which each resolve to one group) and
// ignore the broad code (which spans several groups), so:
//   - an {APAC,SG,MY} app classifies an SG (SEA) tenant, and
//   - an {EU,GB} app does NOT classify a DACH tenant (GB ∉ DACH and
//     the broad EU code is intentionally non-matching).
func TestResolveTrafficClass_RealSeedConvention(t *testing.T) {
	t.Run("ISO code matches in-group tenant", func(t *testing.T) {
		svc, tenantID := newTestService(t)
		svc.SetTenantRegionResolver(fakeRegionResolver{region: "SG"})
		seedRegionalApp(t, svc, "Shopee", repository.TrafficClassInspectLite,
			[]string{"APAC", "SG", "ID", "MY", "TH", "PH", "VN"}, "*.shopee.sg")

		cls, err := svc.ResolveTrafficClass(context.Background(), tenantID, "www.shopee.sg")
		if err != nil {
			t.Fatalf("resolve: %v", err)
		}
		if cls != repository.TrafficClassInspectLite {
			t.Fatalf("class = %q, want inspect_lite for in-group SEA tenant", cls)
		}
	})

	t.Run("broad-only code does not match", func(t *testing.T) {
		svc, tenantID := newTestService(t)
		svc.SetTenantRegionResolver(fakeRegionResolver{region: "SG"})
		// Region list carries ONLY the broad code — no ISO country
		// code resolves to a group, so the app applies to nobody.
		seedRegionalApp(t, svc, "BroadOnly", repository.TrafficClassTrustedDirect,
			[]string{"APAC"}, "*.broad.example")

		cls, err := svc.ResolveTrafficClass(context.Background(), tenantID, "x.broad.example")
		if err != nil {
			t.Fatalf("resolve: %v", err)
		}
		if cls != repository.TrafficClassInspectFull {
			t.Fatalf("class = %q, want inspect_full (broad-only region must not match)", cls)
		}
	})

	t.Run("EU+GB app does not leak to DACH tenant", func(t *testing.T) {
		svc, tenantID := newTestService(t)
		svc.SetTenantRegionResolver(fakeRegionResolver{region: "zurich"})
		seedRegionalApp(t, svc, "GOV.UK", repository.TrafficClassInspectLite,
			[]string{"EU", "GB"}, "*.gov.uk")

		cls, err := svc.ResolveTrafficClass(context.Background(), tenantID, "www.gov.uk")
		if err != nil {
			t.Fatalf("resolve: %v", err)
		}
		if cls != repository.TrafficClassInspectFull {
			t.Fatalf("class = %q, want inspect_full (UK app must not classify DACH tenant)", cls)
		}
	})
}

// TestResolveTrafficClass_OverrideWinsAcrossRegion guards the
// documented invariant that a tenant override "wins outright … and is
// not region-filtered" (docs/TRAFFIC_CLASSIFICATION.md). A DACH tenant
// that explicitly overrides a SEA-only app must see the override take
// effect even though the app's region group does not match — the
// override is explicit operator intent and the region filter only
// scopes the global baseline, never the override pass.
func TestResolveTrafficClass_OverrideWinsAcrossRegion(t *testing.T) {
	svc, tenantID := newTestService(t)
	svc.SetTenantRegionResolver(fakeRegionResolver{region: "zurich"}) // DACH
	app := seedRegionalApp(t, svc, "Grab", repository.TrafficClassTrustedDirect, []string{"SEA"}, "*.grab.com")

	// Without an override the SEA app must not classify a DACH tenant.
	if cls, err := svc.ResolveTrafficClass(context.Background(), tenantID, "api.grab.com"); err != nil {
		t.Fatalf("resolve baseline: %v", err)
	} else if cls != repository.TrafficClassInspectFull {
		t.Fatalf("baseline class = %q, want inspect_full (out-of-region app excluded)", cls)
	}

	// The tenant explicitly demotes the out-of-region app.
	if _, err := svc.CreateOverride(context.Background(), tenantID, nil, repository.AppRegistryOverride{
		AppID:                &app.ID,
		TrafficClassOverride: repository.TrafficClassBlock,
		Reason:               "operator blocks Grab for this tenant",
	}); err != nil {
		t.Fatalf("override: %v", err)
	}

	cls, err := svc.ResolveTrafficClass(context.Background(), tenantID, "api.grab.com")
	if err != nil {
		t.Fatalf("resolve override: %v", err)
	}
	if cls != repository.TrafficClassBlock {
		t.Fatalf("class = %q, want block (override wins outright, not region-filtered)", cls)
	}
}

// TestListEffective_OverrideForOutOfRegionAppSurfaces verifies the
// console's effective view includes an out-of-region app the tenant has
// explicitly overridden — the override must not be silently dropped by
// the region filter.
func TestListEffective_OverrideForOutOfRegionAppSurfaces(t *testing.T) {
	svc, tenantID := newTestService(t)
	svc.SetTenantRegionResolver(fakeRegionResolver{region: "zurich"}) // DACH
	sea := seedRegionalApp(t, svc, "Grab", repository.TrafficClassTrustedDirect, []string{"SEA"}, "*.grab.com")

	// Baseline: an out-of-region app with no override is not surfaced.
	eff, err := svc.ListEffective(context.Background(), tenantID)
	if err != nil {
		t.Fatalf("list effective baseline: %v", err)
	}
	for _, ea := range eff {
		if ea.App.ID == sea.ID {
			t.Fatalf("out-of-region app surfaced without an override: %+v", ea)
		}
	}

	if _, err := svc.CreateOverride(context.Background(), tenantID, nil, repository.AppRegistryOverride{
		AppID:                &sea.ID,
		TrafficClassOverride: repository.TrafficClassBlock,
		Reason:               "operator blocks Grab for this tenant",
	}); err != nil {
		t.Fatalf("override: %v", err)
	}

	eff, err = svc.ListEffective(context.Background(), tenantID)
	if err != nil {
		t.Fatalf("list effective override: %v", err)
	}
	var found *appdb.EffectiveApp
	for i := range eff {
		if eff[i].App.ID == sea.ID {
			found = &eff[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("overridden out-of-region app missing from effective view")
	}
	if found.Source != "override" || found.EffectiveClass != repository.TrafficClassBlock {
		t.Fatalf("effective row = %+v, want source=override class=block", *found)
	}
}

// TestCompileSteeringRules_OverrideForOutOfRegionAppIncluded verifies an
// override promoting an out-of-region app still contributes that app's
// domains to the compiled steering table — otherwise the override would
// be honoured by ResolveTrafficClass but missing from the bundle.
func TestCompileSteeringRules_OverrideForOutOfRegionAppIncluded(t *testing.T) {
	svc, tenantID := newTestService(t)
	svc.SetTenantRegionResolver(fakeRegionResolver{region: "zurich"}) // DACH
	sea := seedRegionalApp(t, svc, "Grab", repository.TrafficClassTrustedDirect, []string{"SEA"}, "grab.com")

	if _, err := svc.CreateOverride(context.Background(), tenantID, nil, repository.AppRegistryOverride{
		AppID:                &sea.ID,
		TrafficClassOverride: repository.TrafficClassBlock,
		Reason:               "operator blocks Grab for this tenant",
	}); err != nil {
		t.Fatalf("override: %v", err)
	}

	rs, err := svc.CompileSteeringRules(context.Background(), tenantID, repository.PolicyBundleTargetEdge)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	var blocked bool
	for _, c := range rs.Classes {
		if c.Class != repository.TrafficClassBlock {
			continue
		}
		for _, d := range c.Domains {
			if d == "grab.com" {
				blocked = true
			}
		}
	}
	if !blocked {
		t.Fatalf("override for out-of-region app missing from steering table: %+v", rs.Classes)
	}
}

func TestCompileSteeringRules_RegionalScoping(t *testing.T) {
	seaTenantClasses := func(t *testing.T, marker string) map[string]bool {
		t.Helper()
		svc, tenantID := newTestService(t)
		svc.SetTenantRegionResolver(fakeRegionResolver{region: marker})
		seedRegionalApp(t, svc, "Grab", repository.TrafficClassTrustedDirect, []string{"SEA"}, "grab.com")
		rs, err := svc.CompileSteeringRules(context.Background(), tenantID, repository.PolicyBundleTargetEdge)
		if err != nil {
			t.Fatalf("compile: %v", err)
		}
		domains := map[string]bool{}
		for _, c := range rs.Classes {
			if c.Class == repository.TrafficClassTrustedDirect {
				for _, d := range c.Domains {
					domains[d] = true
				}
			}
		}
		return domains
	}

	if got := seaTenantClasses(t, "SG"); !got["grab.com"] {
		t.Errorf("SEA tenant edge bundle missing grab.com: %v", got)
	}
	if got := seaTenantClasses(t, "zurich"); got["grab.com"] {
		t.Errorf("DACH tenant edge bundle leaked SEA app grab.com: %v", got)
	}
}
