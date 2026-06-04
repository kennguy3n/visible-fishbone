// Copyright 2026 ShieldNet Gateway contributors.
// SPDX-License-Identifier: LicenseRef-Proprietary

package pop

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestNewZoneGenerator_Validation(t *testing.T) {
	t.Parallel()
	if _, err := NewZoneGenerator(GeoDNSConfig{Hostname: ""}); err == nil {
		t.Fatal("expected error for empty hostname")
	}
	if _, err := NewZoneGenerator(GeoDNSConfig{Hostname: "edge.sng.example.com", Policy: "bogus"}); err == nil {
		t.Fatal("expected error for invalid policy")
	}
	// Defaults applied.
	g, err := NewZoneGenerator(GeoDNSConfig{Hostname: "edge.sng.example.com"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if g.cfg.TTL != DefaultGeoDNSTTL {
		t.Fatalf("TTL default = %v, want %v", g.cfg.TTL, DefaultGeoDNSTTL)
	}
	if g.cfg.Policy != RoutingLatency {
		t.Fatalf("Policy default = %q, want %q", g.cfg.Policy, RoutingLatency)
	}
}

func TestZoneGenerator_Records(t *testing.T) {
	t.Parallel()
	g, err := NewZoneGenerator(GeoDNSConfig{
		Hostname: "edge.sng.example.com",
		TTL:      15 * time.Second,
		Policy:   RoutingWeighted,
	})
	if err != nil {
		t.Fatalf("new generator: %v", err)
	}

	enabledV4 := PoP{ID: uuid.New(), Region: "us-east", AnycastIP: "203.0.113.10", CapacityTier: CapacityLarge, Enabled: true}
	enabledV6 := PoP{ID: uuid.New(), Region: "eu-west", AnycastIP: "2001:db8::1", CapacityTier: CapacitySmall, Enabled: true}
	disabled := PoP{ID: uuid.New(), Region: "us-west", AnycastIP: "203.0.113.20", CapacityTier: CapacityMedium, Enabled: false}
	badIP := PoP{ID: uuid.New(), Region: "ap-south", AnycastIP: "not-an-ip", CapacityTier: CapacityMedium, Enabled: true}

	records := g.Records([]PoP{enabledV4, enabledV6, disabled, badIP})
	if len(records) != 2 {
		t.Fatalf("got %d records, want 2 (disabled + bad-IP skipped)", len(records))
	}

	byID := map[string]DNSRecord{}
	for _, r := range records {
		byID[r.SetIdentifier] = r
	}
	v4 := byID[enabledV4.ID.String()]
	if v4.Type != "A" {
		t.Errorf("v4 record type = %q, want A", v4.Type)
	}
	if v4.Weight != tierWeight(CapacityLarge) {
		t.Errorf("v4 weight = %d, want %d", v4.Weight, tierWeight(CapacityLarge))
	}
	if v4.TTL != 15*time.Second {
		t.Errorf("v4 TTL = %v, want 15s", v4.TTL)
	}
	if v4.Policy != RoutingWeighted {
		t.Errorf("v4 policy = %q, want weighted", v4.Policy)
	}
	v6 := byID[enabledV6.ID.String()]
	if v6.Type != "AAAA" {
		t.Errorf("v6 record type = %q, want AAAA", v6.Type)
	}
}

func TestZoneGenerator_Records_DeterministicOrder(t *testing.T) {
	t.Parallel()
	g, _ := NewZoneGenerator(GeoDNSConfig{Hostname: "edge.sng.example.com"})
	pops := []PoP{
		{ID: uuid.MustParse("ffffffff-0000-0000-0000-000000000000"), AnycastIP: "203.0.113.1", CapacityTier: CapacitySmall, Enabled: true},
		{ID: uuid.MustParse("00000000-0000-0000-0000-000000000001"), AnycastIP: "203.0.113.2", CapacityTier: CapacitySmall, Enabled: true},
	}
	records := g.Records(pops)
	if len(records) != 2 {
		t.Fatalf("got %d records, want 2", len(records))
	}
	if records[0].SetIdentifier >= records[1].SetIdentifier {
		t.Fatalf("records not sorted by SetIdentifier: %q then %q", records[0].SetIdentifier, records[1].SetIdentifier)
	}
}

func TestGeoDNSPublisher_Publish(t *testing.T) {
	t.Parallel()
	store := newFakeStore()
	store.seedPoP(PoP{Region: "us-east", AnycastIP: "203.0.113.10", CapacityTier: CapacityLarge, Enabled: true})
	store.seedPoP(PoP{Region: "us-west", AnycastIP: "203.0.113.20", CapacityTier: CapacitySmall, Enabled: false})

	reg := NewRegistry(store)
	if err := reg.Refresh(context.Background()); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	gen, _ := NewZoneGenerator(GeoDNSConfig{Hostname: "edge.sng.example.com"})
	provider := NewStaticDNSProvider()
	pub := NewGeoDNSPublisher(gen, provider, reg, nil)
	if err := pub.Publish(context.Background()); err != nil {
		t.Fatalf("publish: %v", err)
	}
	applied := provider.Applied("edge.sng.example.com")
	if len(applied) != 1 {
		t.Fatalf("applied %d records, want 1 (only the enabled PoP)", len(applied))
	}
}

func TestStaticRegionLocator_LongestPrefixWins(t *testing.T) {
	t.Parallel()
	loc, err := NewStaticRegionLocator(map[string]string{
		"10.0.0.0/8":    "us-east",
		"10.1.0.0/16":   "us-west",
		"2001:db8::/32": "eu-west",
	})
	if err != nil {
		t.Fatalf("new locator: %v", err)
	}
	cases := []struct {
		ip     string
		region string
		ok     bool
	}{
		{"10.1.2.3", "us-west", true},    // /16 beats /8
		{"10.2.2.3", "us-east", true},    // only /8 matches
		{"2001:db8::5", "eu-west", true}, // v6
		{"192.0.2.1", "", false},         // no match
	}
	for _, c := range cases {
		region, ok := loc.LocateRegion(netip.MustParseAddr(c.ip))
		if ok != c.ok || region != c.region {
			t.Errorf("LocateRegion(%s) = (%q, %v), want (%q, %v)", c.ip, region, ok, c.region, c.ok)
		}
	}
}

func TestNewStaticRegionLocator_RejectsBadPrefix(t *testing.T) {
	t.Parallel()
	if _, err := NewStaticRegionLocator(map[string]string{"not-a-cidr": "x"}); err == nil {
		t.Fatal("expected error for invalid prefix")
	}
}
