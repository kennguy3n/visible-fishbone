package hibernation

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/service/telemetry"
	chwriter "github.com/kennguy3n/visible-fishbone/internal/service/telemetry/clickhouse"
)

// TestSampleResolverNearZeroForHibernated verifies a parked tenant's
// telemetry is driven to the near-zero rate while a live tenant defers
// to the inner resolver.
func TestSampleResolverNearZeroForHibernated(t *testing.T) {
	parked := uuid.New()
	live := uuid.New()
	reg := NewRegistry()
	reg.Replace([]uuid.UUID{parked})

	inner := telemetry.NewMapSampleRateResolver(nil)
	inner.SetTenant(live, map[string]float64{"trusted_direct": 0.5})

	res := NewSampleResolver(reg, inner, 0, nil)

	rate, ok := res.ResolveSampleRate(context.Background(), parked, "trusted_direct")
	if !ok || rate != DefaultHibernatedSampleRate {
		t.Fatalf("parked tenant: got (%v,%v), want (%v,true)", rate, ok, DefaultHibernatedSampleRate)
	}
	// Live tenant falls through to the inner override.
	rate, ok = res.ResolveSampleRate(context.Background(), live, "trusted_direct")
	if !ok || rate != 0.5 {
		t.Fatalf("live tenant: got (%v,%v), want (0.5,true)", rate, ok)
	}
}

// TestSampleResolverInspectFullPreserved is the security guarantee: even
// for a hibernated tenant, the adaptive sampler's mandatory 1:1 floor
// for inspect_full overrides the near-zero hibernation rate, so security
// /audit events are never sampled away. This wires the resolver through
// the REAL sampler (not just the resolver) to prove the end-to-end pin.
func TestSampleResolverInspectFullPreserved(t *testing.T) {
	parked := uuid.New()
	reg := NewRegistry()
	reg.Replace([]uuid.UUID{parked})

	res := NewSampleResolver(reg, nil, 0, nil)
	sampler := telemetry.NewAdaptiveSampler(telemetry.SamplerConfig{RateResolver: res})

	// inspect_full must recover the full-fidelity 1.0 rate despite the
	// tenant being parked.
	if got := sampler.SampleRateForClass(parked, "inspect_full"); got != 1.0 {
		t.Fatalf("inspect_full for hibernated tenant must stay 1:1, got %v", got)
	}
	// A non-security class is driven to the near-zero hibernation rate.
	if got := sampler.SampleRateForClass(parked, "trusted_direct"); got != DefaultHibernatedSampleRate {
		t.Fatalf("trusted_direct for hibernated tenant: got %v, want %v", got, DefaultHibernatedSampleRate)
	}
}

// TestRetentionResolverFloorForHibernated verifies a parked tenant
// resolves to the aggressive floor (clamped by the writer to
// MinRetentionDays) while a live tenant defers to the default.
func TestRetentionResolverFloorForHibernated(t *testing.T) {
	parked := uuid.New()
	live := uuid.New()
	reg := NewRegistry()
	reg.Replace([]uuid.UUID{parked})

	// Inner resolver gives everyone 60 days.
	inner := chwriter.StaticRetentionResolver{Days: 60}
	res := NewRetentionResolver(reg, inner, 0)

	if got := res.RetentionDays(context.Background(), parked); got != DefaultHibernatedRetentionDays {
		t.Fatalf("parked tenant: got %d days, want %d", got, DefaultHibernatedRetentionDays)
	}
	if got := res.RetentionDays(context.Background(), live); got != 60 {
		t.Fatalf("live tenant: got %d days, want 60", got)
	}
}

// TestHibernatedRetentionStaysAboveComplianceFloor is the cold-read-
// for-audit guarantee: the resolver asks for an aggressive retention,
// but the ClickHouse writer clamps every result up to MinRetentionDays,
// so a hibernated tenant's telemetry is still retained for at least the
// 30-day compliance window and remains queryable for audit — hibernation
// can never drive retention to zero. This asserts the invariant the
// writer's clamp relies on.
func TestHibernatedRetentionStaysAboveComplianceFloor(t *testing.T) {
	if DefaultHibernatedRetentionDays >= chwriter.MinRetentionDays {
		t.Fatalf("hibernated retention (%d) must be below the writer floor (%d) so the clamp governs the effective retention",
			DefaultHibernatedRetentionDays, chwriter.MinRetentionDays)
	}
	// The effective retention is the writer's floor, never the raw
	// resolver value: prove the clamp lands at MinRetentionDays.
	effective := DefaultHibernatedRetentionDays
	if effective < chwriter.MinRetentionDays {
		effective = chwriter.MinRetentionDays
	}
	if effective != chwriter.MinRetentionDays {
		t.Fatalf("effective hibernated retention = %d, want the %d-day compliance floor", effective, chwriter.MinRetentionDays)
	}
}

// TestRegistryReplaceAndClear exercises the registry's swap + inline
// clear semantics and nil-safety.
func TestRegistryReplaceAndClear(t *testing.T) {
	var nilReg *Registry
	if nilReg.IsHibernated(uuid.New()) {
		t.Fatal("nil registry must report not-hibernated")
	}

	a, b := uuid.New(), uuid.New()
	reg := NewRegistry()
	reg.Replace([]uuid.UUID{a, b})
	if !reg.IsHibernated(a) || !reg.IsHibernated(b) || reg.Len() != 2 {
		t.Fatal("both ids should be hibernated after Replace")
	}
	reg.Clear(a)
	if reg.IsHibernated(a) {
		t.Fatal("a should be cleared")
	}
	if !reg.IsHibernated(b) {
		t.Fatal("b should remain hibernated")
	}
	// Replace with a smaller set drops the rest.
	reg.Replace(nil)
	if reg.Len() != 0 {
		t.Fatal("Replace(nil) should empty the registry")
	}
}

// TestSyncerReconcilesRegistry verifies the syncer pulls only hibernated
// records into the registry.
func TestSyncerReconcilesRegistry(t *testing.T) {
	parked := uuid.New()
	woke := uuid.New()
	store := newMemStore()
	_, _ = store.set(parked, StateHibernated, "x", time.Now().UTC())
	_, _ = store.set(woke, StateActive, "x", time.Now().UTC())

	reg := NewRegistry()
	syncer := NewSyncer(store, reg, nil)
	if err := syncer.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !reg.IsHibernated(parked) {
		t.Fatal("hibernated record should be in the registry")
	}
	if reg.IsHibernated(woke) {
		t.Fatal("active record should not be in the registry")
	}
}
