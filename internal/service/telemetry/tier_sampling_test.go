package telemetry

import (
	"context"
	"errors"
	"math"
	"math/rand"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/nats/schema"
	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/service/tenancy"
)

func TestIsSecurityRelevantEventClass(t *testing.T) {
	secure := []schema.EventClass{schema.EventClassIPS, schema.EventClassZTNA, schema.EventClassDLP}
	for _, c := range secure {
		if !isSecurityRelevantEventClass(c) {
			t.Errorf("EventClass %q should be security-relevant", c)
		}
	}
	notSecure := []schema.EventClass{
		schema.EventClassFlow, schema.EventClassDNS, schema.EventClassHTTP,
		schema.EventClassSDWAN, schema.EventClassAgent, schema.EventClassPosture,
		schema.EventClassSystem, "",
	}
	for _, c := range notSecure {
		if isSecurityRelevantEventClass(c) {
			t.Errorf("EventClass %q should NOT be security-relevant", c)
		}
	}
}

func TestMapTierResolverFailSafe(t *testing.T) {
	ctx := context.Background()

	var nilR *MapTierResolver
	if tier, ok := nilR.ResolveTier(ctx, uuid.New()); ok || tier != tenancy.TierActive {
		t.Fatalf("nil resolver: got (%v,%v), want (active,false)", tier, ok)
	}
	if nilR.Len() != 0 {
		t.Errorf("nil resolver Len = %d, want 0", nilR.Len())
	}

	known := uuid.New()
	r := NewMapTierResolver(map[uuid.UUID]tenancy.Tier{known: tenancy.TierDormant})
	if tier, ok := r.ResolveTier(ctx, known); !ok || tier != tenancy.TierDormant {
		t.Fatalf("known tenant: got (%v,%v), want (dormant,true)", tier, ok)
	}
	// Unknown tenant fails safe to active.
	if tier, ok := r.ResolveTier(ctx, uuid.New()); ok || tier != tenancy.TierActive {
		t.Fatalf("unknown tenant: got (%v,%v), want (active,false)", tier, ok)
	}
	if r.Len() != 1 {
		t.Errorf("Len = %d, want 1", r.Len())
	}
}

func TestMapTierResolverReplaceIsAtomicCopy(t *testing.T) {
	ctx := context.Background()
	a, b := uuid.New(), uuid.New()
	r := NewMapTierResolver(nil)

	src := map[uuid.UUID]tenancy.Tier{a: tenancy.TierIdle}
	r.Replace(src)
	// Mutating the source after Replace must not affect the snapshot.
	src[a] = tenancy.TierActive
	src[b] = tenancy.TierDormant
	if tier, _ := r.ResolveTier(ctx, a); tier != tenancy.TierIdle {
		t.Errorf("snapshot leaked source mutation: tier = %v, want idle", tier)
	}
	if _, ok := r.ResolveTier(ctx, b); ok {
		t.Error("snapshot leaked a key added to source after Replace")
	}
}

func TestNewTierSamplingPolicyDefaults(t *testing.T) {
	p := NewTierSamplingPolicy(TierSamplingConfig{})
	if p.idleMult != DefaultIdleSampleMultiplier {
		t.Errorf("idleMult = %v, want default %v", p.idleMult, DefaultIdleSampleMultiplier)
	}
	if p.dormantMlt != DefaultDormantSampleMultiplier {
		t.Errorf("dormantMlt = %v, want default %v", p.dormantMlt, DefaultDormantSampleMultiplier)
	}
	if got := p.multiplier(tenancy.TierActive); got != 1.0 {
		t.Errorf("active multiplier = %v, want 1.0", got)
	}

	// Out-of-range multipliers are clamped.
	p2 := NewTierSamplingPolicy(TierSamplingConfig{IdleMultiplier: 5, DormantMultiplier: -1})
	if p2.idleMult != 1.0 {
		t.Errorf("idleMult clamp: got %v, want 1.0", p2.idleMult)
	}
	if p2.dormantMlt != 0 {
		t.Errorf("dormantMlt clamp: got %v, want 0", p2.dormantMlt)
	}
}

func TestTierPolicyTierForFailSafe(t *testing.T) {
	ctx := context.Background()
	// Nil policy and nil resolver both fail safe to active.
	var nilP *TierSamplingPolicy
	if got := nilP.tierFor(ctx, uuid.New()); got != tenancy.TierActive {
		t.Errorf("nil policy tierFor = %v, want active", got)
	}
	p := NewTierSamplingPolicy(TierSamplingConfig{Resolver: nil})
	if got := p.tierFor(ctx, uuid.New()); got != tenancy.TierActive {
		t.Errorf("nil resolver tierFor = %v, want active", got)
	}
}

// newTierSampler builds a sampler with a generous budget (so the
// adaptive path keeps everything and the tier multiplier is the only
// thing shedding load) and the given tenant→tier map.
func newTierSampler(clk *testClock, tiers map[uuid.UUID]tenancy.Tier, idleMult float64) *AdaptiveSampler {
	resolver := NewMapTierResolver(tiers)
	return NewAdaptiveSampler(SamplerConfig{
		Resolver: budgetResolver(1_000_000),
		Window:   time.Second,
		NowFunc:  clk.now,
		TierPolicy: NewTierSamplingPolicy(TierSamplingConfig{
			Resolver:       resolver,
			IdleMultiplier: idleMult,
		}),
	})
}

func TestDecideEventNoPolicyDelegatesToDecideClass(t *testing.T) {
	clk := newTestClock()
	s := NewAdaptiveSampler(SamplerConfig{
		Resolver: budgetResolver(1_000_000),
		Window:   time.Second,
		NowFunc:  clk.now,
	})
	tid, eid := uuid.New(), uuid.New()
	keep, sr, tier, tiered := s.DecideEvent(context.Background(), tid, eid, "", false)
	if tiered {
		t.Error("tiered should be false when no tier policy is wired")
	}
	if !keep || sr != 1.0 || tier != tenancy.TierActive {
		t.Errorf("got keep=%v sr=%v tier=%v, want true/1.0/active", keep, sr, tier)
	}
}

func TestDecideEventNilSampler(t *testing.T) {
	var s *AdaptiveSampler
	keep, sr, _, tiered := s.DecideEvent(context.Background(), uuid.New(), uuid.New(), "", false)
	if !keep || sr != 1.0 || tiered {
		t.Errorf("nil sampler: keep=%v sr=%v tiered=%v, want true/1.0/false", keep, sr, tiered)
	}
}

func TestDecideEventActiveFullFidelity(t *testing.T) {
	clk := newTestClock()
	tid := uuid.New()
	s := newTierSampler(clk, map[uuid.UUID]tenancy.Tier{tid: tenancy.TierActive}, 0)
	ctx := context.Background()
	r := rand.New(rand.NewSource(3))
	for i := 0; i < 1000; i++ {
		keep, sr, tier, tiered := s.DecideEvent(ctx, tid, newRandUUID(r), "", false)
		if !keep || sr != 1.0 {
			t.Fatalf("active tenant must keep at 1.0, got keep=%v sr=%v", keep, sr)
		}
		if !tiered || tier != tenancy.TierActive {
			t.Fatalf("got tiered=%v tier=%v, want true/active", tiered, tier)
		}
	}
}

func TestDecideEventDormantSecurityEventsOnly(t *testing.T) {
	clk := newTestClock()
	tid := uuid.New()
	s := newTierSampler(clk, map[uuid.UUID]tenancy.Tier{tid: tenancy.TierDormant}, 0)
	ctx := context.Background()
	r := rand.New(rand.NewSource(5))

	// Non-security events are all dropped.
	for i := 0; i < 1000; i++ {
		keep, _, tier, tiered := s.DecideEvent(ctx, tid, newRandUUID(r), "", false)
		if keep {
			t.Fatal("dormant tenant must drop a non-security event")
		}
		if !tiered || tier != tenancy.TierDormant {
			t.Fatalf("got tiered=%v tier=%v, want true/dormant", tiered, tier)
		}
	}

	// Security events are always kept at 1.0, in the dormant tier.
	for i := 0; i < 1000; i++ {
		keep, sr, _, _ := s.DecideEvent(ctx, tid, newRandUUID(r), "", true)
		if !keep || sr != 1.0 {
			t.Fatalf("dormant tenant must keep security event at 1.0, got keep=%v sr=%v", keep, sr)
		}
	}
}

func TestDecideEventDormantKeepsInspectFullCompliance(t *testing.T) {
	clk := newTestClock()
	tid := uuid.New()
	s := newTierSampler(clk, map[uuid.UUID]tenancy.Tier{tid: tenancy.TierDormant}, 0)
	ctx := context.Background()
	r := rand.New(rand.NewSource(9))
	inspectFull := string(repository.TrafficClassInspectFull)
	for i := 0; i < 1000; i++ {
		keep, sr, _, _ := s.DecideEvent(ctx, tid, newRandUUID(r), inspectFull, false)
		if !keep || sr != 1.0 {
			t.Fatalf("dormant tenant must keep inspect_full at 1.0, got keep=%v sr=%v", keep, sr)
		}
	}
}

func TestDecideEventIdleReducedSampling(t *testing.T) {
	clk := newTestClock()
	tid := uuid.New()
	const idleMult = 0.25
	s := newTierSampler(clk, map[uuid.UUID]tenancy.Tier{tid: tenancy.TierIdle}, idleMult)
	ctx := context.Background()
	r := rand.New(rand.NewSource(11))

	const n = 50_000
	kept := 0
	for i := 0; i < n; i++ {
		keep, sr, tier, tiered := s.DecideEvent(ctx, tid, newRandUUID(r), "", false)
		if !tiered || tier != tenancy.TierIdle {
			t.Fatalf("got tiered=%v tier=%v, want true/idle", tiered, tier)
		}
		if keep {
			kept++
			if math.Abs(sr-idleMult) > 1e-9 {
				t.Fatalf("kept event sample rate = %v, want %v", sr, idleMult)
			}
		}
	}
	frac := float64(kept) / n
	if math.Abs(frac-idleMult) > 0.01 {
		t.Errorf("idle keep fraction = %.3f, want ~%.2f", frac, idleMult)
	}
}

// TestDecideEventDeterministicAndMonotone proves the tier decision is a
// pure function of the event ID at a fixed tier rate, and that the kept
// set for a sparser idle multiplier is a subset of a denser one — the
// load-bearing determinism / subset property the de-bias scheme relies
// on.
func TestDecideEventDeterministicAndMonotone(t *testing.T) {
	clk := newTestClock()
	tid := uuid.New()
	ctx := context.Background()
	r := rand.New(rand.NewSource(13))

	dense := newTierSampler(clk, map[uuid.UUID]tenancy.Tier{tid: tenancy.TierIdle}, 0.5)
	sparse := newTierSampler(clk, map[uuid.UUID]tenancy.Tier{tid: tenancy.TierIdle}, 0.1)

	for i := 0; i < 5000; i++ {
		eid := newRandUUID(r)
		k1, _, _, _ := dense.DecideEvent(ctx, tid, eid, "", false)
		k1again, _, _, _ := dense.DecideEvent(ctx, tid, eid, "", false)
		if k1 != k1again {
			t.Fatal("DecideEvent is not deterministic for a fixed eventID + tier rate")
		}
		kSparse, _, _, _ := sparse.DecideEvent(ctx, tid, eid, "", false)
		if kSparse && !k1 {
			t.Fatal("subset property violated: kept at sparse rate but dropped at denser rate")
		}
	}
}

// TestDecideEventDormantDoesNotPerturbAdaptiveState proves the dormant
// shed stream never records an arrival, so it can't inflate the
// adaptive rate estimate and fight the autotuner.
func TestDecideEventDormantDoesNotPerturbAdaptiveState(t *testing.T) {
	clk := newTestClock()
	tid := uuid.New()
	s := newTierSampler(clk, map[uuid.UUID]tenancy.Tier{tid: tenancy.TierDormant}, 0)
	ctx := context.Background()
	r := rand.New(rand.NewSource(17))
	for i := 0; i < 10_000; i++ {
		s.DecideEvent(ctx, tid, newRandUUID(r), "", false)
	}
	// No samplerState should have been created for a dormant tenant whose
	// every event was shed without consulting the adaptive path.
	if _, ok := s.tenants[tid]; ok {
		t.Error("dormant shed stream created adaptive state (would inflate rate estimate)")
	}
}

func TestSampleRateForEventMatchesDecision(t *testing.T) {
	clk := newTestClock()
	tid := uuid.New()

	// Idle: recovered de-bias rate equals the configured multiplier.
	idle := newTierSampler(clk, map[uuid.UUID]tenancy.Tier{tid: tenancy.TierIdle}, 0.25)
	if got := idle.SampleRateForEvent(tid, "", false); math.Abs(got-0.25) > 1e-9 {
		t.Errorf("idle SampleRateForEvent = %v, want 0.25", got)
	}
	// Idle security event: floored to 1.0.
	if got := idle.SampleRateForEvent(tid, "", true); got != 1.0 {
		t.Errorf("idle security SampleRateForEvent = %v, want 1.0", got)
	}

	// Dormant non-security: would-have-dropped, recover conservative 1.0.
	dormant := newTierSampler(clk, map[uuid.UUID]tenancy.Tier{tid: tenancy.TierDormant}, 0)
	if got := dormant.SampleRateForEvent(tid, "", false); got != 1.0 {
		t.Errorf("dormant non-security SampleRateForEvent = %v, want 1.0", got)
	}
	// Dormant inspect_full: compliance floor 1.0.
	if got := dormant.SampleRateForEvent(tid, string(repository.TrafficClassInspectFull), false); got != 1.0 {
		t.Errorf("dormant inspect_full SampleRateForEvent = %v, want 1.0", got)
	}

	// No tier policy: defers to SampleRateForClass (1.0 for an unseen tenant).
	plain := NewAdaptiveSampler(SamplerConfig{Resolver: budgetResolver(1_000_000), NowFunc: clk.now})
	if got := plain.SampleRateForEvent(uuid.New(), "", false); got != 1.0 {
		t.Errorf("no-policy SampleRateForEvent = %v, want 1.0", got)
	}
}

// fakeActivityLister is a TenantActivityLister stub for refresher tests.
type fakeActivityLister struct {
	acts []repository.TenantActivity
	err  error
	hits int
}

func (f *fakeActivityLister) ListTenantActivity(_ context.Context) ([]repository.TenantActivity, error) {
	f.hits++
	if f.err != nil {
		return nil, f.err
	}
	return f.acts, nil
}

func ptrTime(t time.Time) *time.Time { return &t }

func TestTierRefresherClassifiesAndSwaps(t *testing.T) {
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	active := uuid.New()
	idle := uuid.New()
	dormant := uuid.New()
	never := uuid.New()
	lister := &fakeActivityLister{acts: []repository.TenantActivity{
		{ID: active, LastActiveAt: ptrTime(now.Add(-1 * time.Hour))},
		{ID: idle, LastActiveAt: ptrTime(now.Add(-3 * 24 * time.Hour))},
		{ID: dormant, LastActiveAt: ptrTime(now.Add(-30 * 24 * time.Hour))},
		{ID: never, LastActiveAt: nil},
	}}
	resolver := NewMapTierResolver(nil)
	ref := NewTierRefresher(TierRefresherConfig{
		Lister:   lister,
		Resolver: resolver,
		NowFunc:  func() time.Time { return now },
	})
	if err := ref.refresh(context.Background()); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	ctx := context.Background()
	cases := map[uuid.UUID]tenancy.Tier{
		active:  tenancy.TierActive,
		idle:    tenancy.TierIdle,
		dormant: tenancy.TierDormant,
		never:   tenancy.TierDormant,
	}
	for id, want := range cases {
		if got, _ := resolver.ResolveTier(ctx, id); got != want {
			t.Errorf("tenant %v: tier = %v, want %v", id, got, want)
		}
	}
}

func TestTierRefresherFailureKeepsPriorSnapshot(t *testing.T) {
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	tid := uuid.New()
	lister := &fakeActivityLister{acts: []repository.TenantActivity{
		{ID: tid, LastActiveAt: ptrTime(now.Add(-30 * 24 * time.Hour))},
	}}
	resolver := NewMapTierResolver(nil)
	ref := NewTierRefresher(TierRefresherConfig{
		Lister:   lister,
		Resolver: resolver,
		NowFunc:  func() time.Time { return now },
	})
	if err := ref.refresh(context.Background()); err != nil {
		t.Fatalf("first refresh: %v", err)
	}
	if got, _ := resolver.ResolveTier(context.Background(), tid); got != tenancy.TierDormant {
		t.Fatalf("after first refresh tier = %v, want dormant", got)
	}

	// A failing refresh must not blank the snapshot.
	lister.err = errors.New("db down")
	if err := ref.refresh(context.Background()); err == nil {
		t.Fatal("expected refresh error")
	}
	if got, ok := resolver.ResolveTier(context.Background(), tid); !ok || got != tenancy.TierDormant {
		t.Errorf("after failed refresh tier = (%v,%v), want (dormant,true) — prior snapshot lost", got, ok)
	}
}
func TestMetricsRecordTierDecisionSnapshot(t *testing.T) {
	var m Metrics
	m.recordTierDecision(tenancy.TierActive, true)
	m.recordTierDecision(tenancy.TierActive, true)
	m.recordTierDecision(tenancy.TierIdle, true)
	m.recordTierDecision(tenancy.TierIdle, false)
	m.recordTierDecision(tenancy.TierDormant, false)
	m.recordTierDecision(tenancy.TierDormant, false)
	m.recordTierDecision(tenancy.TierDormant, false)
	// Out-of-range tier must not panic and must be ignored.
	m.recordTierDecision(tenancy.Tier(99), true)

	s := m.Snapshot()
	if s.KeptByTier["active"] != 2 {
		t.Errorf("KeptByTier[active] = %d, want 2", s.KeptByTier["active"])
	}
	if s.KeptByTier["idle"] != 1 || s.DroppedByTier["idle"] != 1 {
		t.Errorf("idle kept/dropped = %d/%d, want 1/1", s.KeptByTier["idle"], s.DroppedByTier["idle"])
	}
	if s.DroppedByTier["dormant"] != 3 {
		t.Errorf("DroppedByTier[dormant] = %d, want 3", s.DroppedByTier["dormant"])
	}
	if s.KeptByTier["dormant"] != 0 {
		t.Errorf("KeptByTier[dormant] = %d, want 0", s.KeptByTier["dormant"])
	}
}

func TestTierRefresherRunStopsOnContextCancel(t *testing.T) {
	lister := &fakeActivityLister{}
	resolver := NewMapTierResolver(nil)
	ref := NewTierRefresher(TierRefresherConfig{
		Lister:   lister,
		Resolver: resolver,
		Interval: time.Hour,
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		ref.Run(ctx)
		close(done)
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after context cancel")
	}
	if lister.hits == 0 {
		t.Error("Run should refresh once immediately before ticking")
	}
}
