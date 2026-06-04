package main

import (
	"testing"

	"github.com/kennguy3n/visible-fishbone/internal/nats/schema"
)

func TestGeneratorDeterministic(t *testing.T) {
	cfg := GenConfig{Tenants: 50, Seed: 42, DuplicateRate: 0}
	g1, g2 := NewGenerator(cfg), NewGenerator(cfg)
	for i := 0; i < 1000; i++ {
		a, b := g1.Next(), g2.Next()
		if a.EventID != b.EventID || a.TenantID != b.TenantID || a.DeviceID != b.DeviceID {
			t.Fatalf("generators diverged at %d: %v vs %v", i, a.EventID, b.EventID)
		}
	}
}

func TestGeneratorEnvelopesValid(t *testing.T) {
	g := NewGenerator(GenConfig{Tenants: 20, Seed: 7})
	for i := 0; i < 2000; i++ {
		env := g.Next()
		if err := env.Validate(); err != nil {
			t.Fatalf("envelope %d invalid: %v", i, err)
		}
		if env.EventClass != schema.EventClassFlow {
			t.Fatalf("envelope %d class = %q, want flow", i, env.EventClass)
		}
		if _, err := schema.Marshal(env); err != nil {
			t.Fatalf("envelope %d marshal: %v", i, err)
		}
	}
}

func TestGeneratorDuplicateRate(t *testing.T) {
	const n = 100_000
	g := NewGenerator(GenConfig{Tenants: 200, Seed: 3, DuplicateRate: 0.10})
	seen := make(map[[16]byte]struct{}, n)
	dups := 0
	for i := 0; i < n; i++ {
		env := g.Next()
		if _, ok := seen[env.EventID]; ok {
			dups++
		} else {
			seen[env.EventID] = struct{}{}
		}
	}
	got := float64(dups) / float64(n)
	// Expect roughly 10% duplicates; allow a generous band for PRNG
	// variance and the warm-up before the ring fills.
	if got < 0.05 || got > 0.15 {
		t.Fatalf("observed duplicate rate = %.3f, want ~0.10", got)
	}
}

func TestGeneratorTenantPoolStable(t *testing.T) {
	g := NewGenerator(GenConfig{Tenants: 8, Seed: 99})
	if g.TenantCount() != 8 {
		t.Fatalf("tenant count = %d, want 8", g.TenantCount())
	}
	// TenantID wraps modulo the pool size.
	if g.TenantID(0) != g.TenantID(8) || g.TenantID(1) != g.TenantID(9) {
		t.Fatal("TenantID did not wrap modulo pool size")
	}
}
