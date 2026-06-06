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
