package rollout_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
	"github.com/kennguy3n/visible-fishbone/internal/service/rollout"
)

// --- Item 2: per-tenant sticky_off / exclusion ---

// TestAutopilotExclusionsUnit covers the exclusion-set predicate: a
// whole-tenant exclusion masks every capability, a pair exclusion masks
// only its capability, and the zero value excludes nothing.
func TestAutopilotExclusionsUnit(t *testing.T) {
	t.Parallel()
	whole, paired, other := uuid.New(), uuid.New(), uuid.New()
	ex := rollout.NewAutopilotExclusions(
		[]uuid.UUID{whole},
		[]rollout.TenantCapability{{TenantID: paired, Capability: rollout.CapabilityNoOpsAutoEnforce}},
	)

	if !ex.Excludes(whole, rollout.CapabilityIDPDirectorySync) || !ex.Excludes(whole, rollout.CapabilityNoOpsAutoEnforce) {
		t.Fatalf("whole-tenant exclusion must cover every capability")
	}
	if !ex.Excludes(paired, rollout.CapabilityNoOpsAutoEnforce) {
		t.Fatalf("pair exclusion must cover its capability")
	}
	if ex.Excludes(paired, rollout.CapabilityIDPDirectorySync) {
		t.Fatalf("pair exclusion must NOT cover other capabilities")
	}
	if ex.Excludes(other, rollout.CapabilityNoOpsAutoEnforce) {
		t.Fatalf("unlisted tenant must not be excluded")
	}
	if ex.Empty() {
		t.Fatalf("populated set reports Empty")
	}
	var zero rollout.AutopilotExclusions
	if zero.Excludes(whole, rollout.CapabilityIDPDirectorySync) || !zero.Empty() {
		t.Fatalf("zero value must exclude nothing and report Empty")
	}
}

// TestAutopilotExclusionKeepsTenantOff is the headline Item-2 criterion:
// with AutoEnrol on fleet-wide, an EXCLUDED tenant is never touched by the
// autopilot (stays off / unmanaged) while a non-excluded tenant in the
// same sweep is enrolled — so an operator keeps one tenant off without
// disabling the autopilot fleet-wide.
func TestAutopilotExclusionKeepsTenantOff(t *testing.T) {
	t.Parallel()
	excluded, normal := uuid.New(), uuid.New()
	capID := rollout.CapabilityIDPDirectorySync

	policy := defaultPolicy()
	policy.Exclusions = rollout.NewAutopilotExclusions([]uuid.UUID{excluded}, nil)

	ap, svc, _, lister, _, _ := newAutopilotFixture(t, policy)
	lister.ids = []uuid.UUID{excluded, normal}
	ctx := context.Background()

	if err := ap.Sweep(ctx); err != nil {
		t.Fatalf("sweep: %v", err)
	}

	// Excluded tenant: untouched — still off (unmanaged, no row).
	if rec, _ := svc.Get(ctx, excluded, capID); rec.State != rollout.StateOff {
		t.Fatalf("excluded tenant state = %s, want off", rec.State)
	}
	// Non-excluded tenant: auto-enrolled to monitor.
	if rec, _ := svc.Get(ctx, normal, capID); rec.State != rollout.StateMonitor {
		t.Fatalf("normal tenant state = %s, want monitor", rec.State)
	}
}

// TestAutopilotExclusionIsPerCapability proves a pair exclusion masks
// only the named capability: the same tenant is left off for the excluded
// capability but still auto-enrolled for the others.
func TestAutopilotExclusionIsPerCapability(t *testing.T) {
	t.Parallel()
	tenant := uuid.New()

	policy := defaultPolicy()
	policy.Capabilities = []rollout.Capability{
		rollout.CapabilityIDPDirectorySync,
		rollout.CapabilityNoOpsAutoEnforce,
	}
	policy.Exclusions = rollout.NewAutopilotExclusions(nil,
		[]rollout.TenantCapability{{TenantID: tenant, Capability: rollout.CapabilityNoOpsAutoEnforce}})

	ap, svc, _, lister, _, _ := newAutopilotFixture(t, policy)
	lister.ids = []uuid.UUID{tenant}
	ctx := context.Background()

	if err := ap.Sweep(ctx); err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if rec, _ := svc.Get(ctx, tenant, rollout.CapabilityNoOpsAutoEnforce); rec.State != rollout.StateOff {
		t.Fatalf("excluded capability state = %s, want off", rec.State)
	}
	if rec, _ := svc.Get(ctx, tenant, rollout.CapabilityIDPDirectorySync); rec.State != rollout.StateMonitor {
		t.Fatalf("non-excluded capability state = %s, want monitor", rec.State)
	}
}

// --- Item 1: per-capability source mux ---

// TestCapabilitySourceMuxRoutesByCapability proves the mux dispatches each
// capability to its registered source and uses the fallback otherwise,
// and that an unregistered capability with no fallback yields "no
// evidence" (so it never auto-promotes).
func TestCapabilitySourceMuxRoutesByCapability(t *testing.T) {
	t.Parallel()
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0).UTC()}
	edge := rollout.NewMonitorMetricsRecorder(clk.Now)
	fallback := rollout.NewMonitorMetricsRecorder(clk.Now)
	tenant := uuid.New()
	ctx := context.Background()

	edge.Record(tenant, rollout.CapabilityClamAVSWG, rollout.MonitorMetrics{Samples: 7})
	fallback.Record(tenant, rollout.CapabilityNoOpsAutoEnforce, rollout.MonitorMetrics{Samples: 9})

	mux := rollout.NewCapabilitySourceMux(fallback).
		Register(rollout.CapabilityClamAVSWG, edge)

	// Registered capability -> its own source.
	if m, _, err := mux.MonitorMetrics(ctx, tenant, rollout.CapabilityClamAVSWG); err != nil || m.Samples != 7 {
		t.Fatalf("clamav via mux = (%+v, %v), want samples 7", m, err)
	}
	// Unregistered capability -> fallback.
	if m, _, err := mux.MonitorMetrics(ctx, tenant, rollout.CapabilityNoOpsAutoEnforce); err != nil || m.Samples != 9 {
		t.Fatalf("noops via mux = (%+v, %v), want samples 9 (fallback)", m, err)
	}

	// No fallback + unregistered -> zero evidence.
	bare := rollout.NewCapabilitySourceMux(nil)
	if m, at, err := bare.MonitorMetrics(ctx, tenant, rollout.CapabilityClamAVSWG); err != nil || m.Samples != 0 || !at.IsZero() {
		t.Fatalf("bare mux = (%+v, %v, %v), want zero evidence", m, at, err)
	}
}

// --- Item 3: persist / rebuild monitor evidence across leader failover ---

// TestRecorderPersistsAndHydratesAcrossFailover proves a store-backed
// recorder write-throughs each snapshot and that a FRESH recorder (the
// new leader, empty in-memory cache) sharing the same store hydrates the
// snapshot — with the original observed-at time preserved, which is what
// lets the promotion clock survive a leader change.
func TestRecorderPersistsAndHydratesAcrossFailover(t *testing.T) {
	t.Parallel()
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0).UTC()}
	store := memory.NewRolloutMonitorEvidenceRepository()
	tenant := uuid.New()
	capID := rollout.CapabilityNoOpsAutoEnforce
	ctx := context.Background()

	leader1 := rollout.NewMonitorMetricsRecorder(clk.Now, rollout.WithMonitorMetricsStore(store))
	recordedAt := clk.Now()
	leader1.Record(tenant, capID, rollout.MonitorMetrics{Samples: 300, Errors: 1, Denies: 5})

	// New leader: empty cache, same store.
	clk.Advance(2 * time.Hour)
	leader2 := rollout.NewMonitorMetricsRecorder(clk.Now, rollout.WithMonitorMetricsStore(store))
	m, at, err := leader2.MonitorMetrics(ctx, tenant, capID)
	if err != nil {
		t.Fatalf("hydrate: %v", err)
	}
	if m.Samples != 300 || m.Errors != 1 || m.Denies != 5 {
		t.Fatalf("hydrated metrics = %+v, want samples 300/errors 1/denies 5", m)
	}
	if !at.Equal(recordedAt) {
		t.Fatalf("hydrated observed-at = %v, want original %v", at, recordedAt)
	}

	// Without a store, a fresh recorder has no evidence to hydrate.
	leader2NoStore := rollout.NewMonitorMetricsRecorder(clk.Now)
	if m, _, _ := leader2NoStore.MonitorMetrics(ctx, tenant, capID); m.Samples != 0 {
		t.Fatalf("storeless fresh recorder samples = %d, want 0", m.Samples)
	}
}

// TestAutopilotPromotionClockSurvivesFailover is the end-to-end Item-3
// criterion: a tenant that dwelt in monitor with healthy evidence under
// one leader is promoted by a NEW leader (fresh recorder, evidence
// rehydrated from the store) once the dwell elapses — i.e. the promotion
// clock survived the failover. The contrast case (no store) stays in
// monitor, proving persistence is what carried the evidence across.
func TestAutopilotPromotionClockSurvivesFailover(t *testing.T) {
	t.Parallel()
	capID := rollout.CapabilityIDPDirectorySync
	tenant := uuid.New()

	run := func(t *testing.T, withStore bool) rollout.State {
		t.Helper()
		clk := &fakeClock{t: time.Unix(1_700_000_000, 0).UTC()}
		repo := memory.NewCapabilityRolloutRepository()
		repo.SetClock(clk.Now)
		svc, err := rollout.New(repo, rollout.WithThreshold(demoteThreshold), rollout.WithClock(clk.Now))
		if err != nil {
			t.Fatalf("new service: %v", err)
		}
		lister := &staticLister{ids: []uuid.UUID{tenant}}
		ctx := context.Background()

		var store rollout.MonitorMetricsStore
		if withStore {
			store = memory.NewRolloutMonitorEvidenceRepository()
		}
		recorderOpts := []rollout.RecorderOption{}
		if store != nil {
			recorderOpts = append(recorderOpts, rollout.WithMonitorMetricsStore(store))
		}

		// Leader 1: enrol the tenant and accrue healthy monitor evidence.
		leader1 := rollout.NewMonitorMetricsRecorder(clk.Now, recorderOpts...)
		ap1, err := rollout.NewAutopilot(svc, lister, leader1, defaultPolicy(), rollout.WithAutopilotClock(clk.Now))
		if err != nil {
			t.Fatalf("new autopilot 1: %v", err)
		}
		if err := ap1.Sweep(ctx); err != nil {
			t.Fatalf("sweep 1: %v", err)
		}
		if rec, _ := svc.Get(ctx, tenant, capID); rec.State != rollout.StateMonitor {
			t.Fatalf("after enrol state = %s, want monitor", rec.State)
		}
		leader1.Record(tenant, capID, rollout.MonitorMetrics{Samples: 500, Errors: 2, Denies: 10})

		// Dwell window elapses, then the leader fails over: a NEW recorder
		// (empty in-memory cache) sharing the same store, driving a new
		// autopilot over the SAME (persisted) rollout state.
		clk.Advance(25 * time.Hour)
		leader2 := rollout.NewMonitorMetricsRecorder(clk.Now, recorderOpts...)
		ap2, err := rollout.NewAutopilot(svc, lister, leader2, defaultPolicy(), rollout.WithAutopilotClock(clk.Now))
		if err != nil {
			t.Fatalf("new autopilot 2: %v", err)
		}
		if err := ap2.Sweep(ctx); err != nil {
			t.Fatalf("sweep 2 (post-failover): %v", err)
		}
		rec, _ := svc.Get(ctx, tenant, capID)
		return rec.State
	}

	if got := run(t, true); got != rollout.StateEnforce {
		t.Fatalf("with persisted evidence, post-failover state = %s, want enforce", got)
	}
	if got := run(t, false); got != rollout.StateMonitor {
		t.Fatalf("without persistence, post-failover state = %s, want monitor (evidence lost)", got)
	}
}
