package rollout_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
	"github.com/kennguy3n/visible-fishbone/internal/service/rollout"
)

// demoteThreshold is the framework auto-demote guardrail used across the
// autopilot tests: the same shape main() wires.
var demoteThreshold = rollout.Threshold{MaxErrorRate: 0.05, MaxDenyRate: 0.20, MinSamples: 50}

// promoGuardrail is a promotion ceiling at least as strict as
// demoteThreshold, as NewAutopilot requires.
var promoGuardrail = rollout.Threshold{MaxErrorRate: 0.02, MaxDenyRate: 0.10, MinSamples: 100}

func newAutopilotFixture(t *testing.T, policy rollout.AutopilotPolicy, opts ...rollout.AutopilotOption) (*rollout.Autopilot, *rollout.Service, *memory.CapabilityRolloutRepository, *staticLister, *rollout.MonitorMetricsRecorder, *fakeClock) {
	t.Helper()
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0).UTC()}
	repo := memory.NewCapabilityRolloutRepository()
	repo.SetClock(clk.Now)
	svc, err := rollout.New(repo,
		rollout.WithThreshold(demoteThreshold),
		rollout.WithClock(clk.Now),
	)
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	lister := &staticLister{}
	recorder := rollout.NewMonitorMetricsRecorder(clk.Now)
	allOpts := append([]rollout.AutopilotOption{rollout.WithAutopilotClock(clk.Now)}, opts...)
	ap, err := rollout.NewAutopilot(svc, lister, recorder, policy, allOpts...)
	if err != nil {
		t.Fatalf("new autopilot: %v", err)
	}
	return ap, svc, repo, lister, recorder, clk
}

func defaultPolicy() rollout.AutopilotPolicy {
	return rollout.AutopilotPolicy{
		Capabilities:       []rollout.Capability{rollout.CapabilityIDPDirectorySync},
		AutoEnrol:          true,
		DwellWindow:        24 * time.Hour,
		MinSamples:         100,
		PromotionGuardrail: promoGuardrail,
	}
}

// TestAutopilotZeroClickEnrolThenPromote is the headline success
// criterion: a freshly-seeded tenant (no rollout row, unmanaged) reaches
// the protective enforce posture with ZERO operator clicks once the
// guardrails hold across the dwell window, and the audit trail records
// the autopilot as the actor with the guardrail evidence.
func TestAutopilotZeroClickEnrolThenPromote(t *testing.T) {
	t.Parallel()
	sink := &recordingSink{}
	obs := &countingObserver{}
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0).UTC()}
	repo := memory.NewCapabilityRolloutRepository()
	repo.SetClock(clk.Now)
	svc2, err := rollout.New(repo,
		rollout.WithThreshold(demoteThreshold),
		rollout.WithClock(clk.Now),
		rollout.WithTransitionSink(sink),
	)
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	lister := &staticLister{}
	recorder := rollout.NewMonitorMetricsRecorder(clk.Now)
	ap, err := rollout.NewAutopilot(svc2, lister, recorder, defaultPolicy(),
		rollout.WithAutopilotClock(clk.Now), rollout.WithAutopilotObserver(obs))
	if err != nil {
		t.Fatalf("new autopilot: %v", err)
	}

	tenant := uuid.New()
	lister.ids = []uuid.UUID{tenant}
	capID := rollout.CapabilityIDPDirectorySync
	ctx := context.Background()

	// Sweep 1: tenant is off/unmanaged -> autopilot enrols it to monitor.
	if err := ap.Sweep(ctx); err != nil {
		t.Fatalf("sweep 1: %v", err)
	}
	if rec, _ := svc2.Get(ctx, tenant, capID); rec.State != rollout.StateMonitor {
		t.Fatalf("after sweep 1 state = %s, want monitor", rec.State)
	}
	if obs.enrolled[capID] != 1 {
		t.Fatalf("enrolled count = %d, want 1", obs.enrolled[capID])
	}

	// Healthy dry-run evidence accrues during the monitor period.
	recorder.Record(tenant, capID, rollout.MonitorMetrics{Samples: 500, Errors: 2, Denies: 10})

	// Before the dwell window elapses, no promotion.
	clk.Advance(12 * time.Hour)
	if err := ap.Sweep(ctx); err != nil {
		t.Fatalf("sweep 2: %v", err)
	}
	if rec, _ := svc2.Get(ctx, tenant, capID); rec.State != rollout.StateMonitor {
		t.Fatalf("after sweep 2 (pre-dwell) state = %s, want monitor", rec.State)
	}
	if obs.blocked[capID]["dwell"] == 0 {
		t.Fatalf("expected a dwell block, got %+v", obs.blocked[capID])
	}

	// After the dwell window with healthy evidence -> promote to enforce.
	clk.Advance(13 * time.Hour) // total 25h in monitor > 24h dwell
	recorder.Record(tenant, capID, rollout.MonitorMetrics{Samples: 1000, Errors: 3, Denies: 20})
	if err := ap.Sweep(ctx); err != nil {
		t.Fatalf("sweep 3: %v", err)
	}
	rec, _ := svc2.Get(ctx, tenant, capID)
	if rec.State != rollout.StateEnforce {
		t.Fatalf("after sweep 3 state = %s, want enforce", rec.State)
	}
	if rec.UpdatedBy != rollout.AutopilotActor {
		t.Fatalf("promotion actor = %q, want %q", rec.UpdatedBy, rollout.AutopilotActor)
	}
	if obs.promoted[capID] != 1 {
		t.Fatalf("promoted count = %d, want 1", obs.promoted[capID])
	}

	// Audit trail: enrol (off->monitor) + promote (monitor->enforce), both
	// attributed to the autopilot, the promotion carrying the evidence.
	if len(sink.events) != 2 {
		t.Fatalf("sink saw %d transitions, want 2", len(sink.events))
	}
	if sink.events[0].from != rollout.StateOff || sink.events[0].rec.State != rollout.StateMonitor {
		t.Fatalf("first audited transition wrong: %+v", sink.events[0])
	}
	if sink.events[1].from != rollout.StateMonitor || sink.events[1].rec.State != rollout.StateEnforce {
		t.Fatalf("second audited transition wrong: %+v", sink.events[1])
	}
	if sink.events[1].rec.UpdatedBy != rollout.AutopilotActor || sink.events[1].rec.Reason == "" {
		t.Fatalf("promotion audit must record autopilot actor + reason: %+v", sink.events[1].rec)
	}

	// Idempotent: another sweep at enforce changes nothing.
	if err := ap.Sweep(ctx); err != nil {
		t.Fatalf("sweep 4: %v", err)
	}
	if len(sink.events) != 2 {
		t.Fatalf("idempotent sweep added transitions: %d", len(sink.events))
	}
}

// TestAutopilotGuardrailBlocksPromotion proves a would-have-block (deny)
// rate over the promotion ceiling but UNDER the demote threshold keeps the
// capability in monitor: it is neither promoted nor demoted.
func TestAutopilotGuardrailBlocksPromotion(t *testing.T) {
	t.Parallel()
	obs := &countingObserver{}
	ap, svc, _, lister, recorder, clk := newAutopilotFixture(t, defaultPolicy(),
		rollout.WithAutopilotObserver(obs))
	tenant := uuid.New()
	lister.ids = []uuid.UUID{tenant}
	capID := rollout.CapabilityIDPDirectorySync
	ctx := context.Background()

	// Operator-equivalent: enrol via the autopilot.
	if err := ap.Sweep(ctx); err != nil {
		t.Fatalf("enrol sweep: %v", err)
	}
	// Deny rate 0.15: above promo ceiling (0.10) but below demote (0.20).
	recorder.Record(tenant, capID, rollout.MonitorMetrics{Samples: 1000, Errors: 1, Denies: 150})
	clk.Advance(48 * time.Hour) // well past dwell

	if err := ap.Sweep(ctx); err != nil {
		t.Fatalf("guardrail sweep: %v", err)
	}
	rec, _ := svc.Get(ctx, tenant, capID)
	if rec.State != rollout.StateMonitor {
		t.Fatalf("state = %s, want monitor (blocked, not promoted, not demoted)", rec.State)
	}
	if obs.blocked[capID]["guardrail"] == 0 {
		t.Fatalf("expected a guardrail block, got %+v", obs.blocked[capID])
	}
	if obs.promoted[capID] != 0 {
		t.Fatalf("must not promote past a breached guardrail; promoted=%d", obs.promoted[capID])
	}
}

// TestAutopilotBreachDemotesAndBlocks proves that a reading breaching the
// demote threshold during monitor rolls the capability back to off (the
// existing auto-demote) and does not promote — even past the dwell window.
func TestAutopilotBreachDemotesAndBlocks(t *testing.T) {
	t.Parallel()
	obs := &countingObserver{}
	ap, svc, _, lister, recorder, clk := newAutopilotFixture(t, defaultPolicy(),
		rollout.WithAutopilotObserver(obs))
	tenant := uuid.New()
	lister.ids = []uuid.UUID{tenant}
	capID := rollout.CapabilityIDPDirectorySync
	ctx := context.Background()

	if err := ap.Sweep(ctx); err != nil {
		t.Fatalf("enrol sweep: %v", err)
	}
	// Error rate 0.10: breaches the demote threshold (0.05).
	recorder.Record(tenant, capID, rollout.MonitorMetrics{Samples: 1000, Errors: 100})
	clk.Advance(48 * time.Hour)

	if err := ap.Sweep(ctx); err != nil {
		t.Fatalf("breach sweep: %v", err)
	}
	rec, _ := svc.Get(ctx, tenant, capID)
	if rec.State != rollout.StateOff {
		t.Fatalf("state = %s, want off (auto-demoted)", rec.State)
	}
	if rec.UpdatedBy != rollout.SystemActor {
		t.Fatalf("demote actor = %q, want %q", rec.UpdatedBy, rollout.SystemActor)
	}
	if obs.demoted[capID] != 1 {
		t.Fatalf("demoted count = %d, want 1", obs.demoted[capID])
	}
	if obs.promoted[capID] != 0 {
		t.Fatalf("must not promote on a breach; promoted=%d", obs.promoted[capID])
	}
}

// TestAutopilotInsufficientSamplesBlocks proves promotion is withheld when
// the dry-run has too few observations to be meaningful, even with a
// perfect (zero-error, zero-deny) reading past the dwell window.
func TestAutopilotInsufficientSamplesBlocks(t *testing.T) {
	t.Parallel()
	obs := &countingObserver{}
	ap, svc, _, lister, recorder, clk := newAutopilotFixture(t, defaultPolicy(),
		rollout.WithAutopilotObserver(obs))
	tenant := uuid.New()
	lister.ids = []uuid.UUID{tenant}
	capID := rollout.CapabilityIDPDirectorySync
	ctx := context.Background()

	if err := ap.Sweep(ctx); err != nil {
		t.Fatalf("enrol sweep: %v", err)
	}
	recorder.Record(tenant, capID, rollout.MonitorMetrics{Samples: 10}) // < MinSamples 100
	clk.Advance(48 * time.Hour)
	if err := ap.Sweep(ctx); err != nil {
		t.Fatalf("samples sweep: %v", err)
	}
	if rec, _ := svc.Get(ctx, tenant, capID); rec.State != rollout.StateMonitor {
		t.Fatalf("state = %s, want monitor (insufficient samples)", rec.State)
	}
	if obs.blocked[capID]["insufficient_samples"] == 0 {
		t.Fatalf("expected an insufficient_samples block, got %+v", obs.blocked[capID])
	}
}

// TestAutopilotStaleMetricsBlock proves a snapshot recorded BEFORE the
// current monitor entry is not used as promotion evidence: it must be
// blocked as stale even past the dwell window.
func TestAutopilotStaleMetricsBlock(t *testing.T) {
	t.Parallel()
	obs := &countingObserver{}
	ap, svc, _, lister, recorder, clk := newAutopilotFixture(t, defaultPolicy(),
		rollout.WithAutopilotObserver(obs))
	tenant := uuid.New()
	lister.ids = []uuid.UUID{tenant}
	capID := rollout.CapabilityIDPDirectorySync
	ctx := context.Background()

	// Record healthy metrics BEFORE the tenant ever enters monitor.
	recorder.Record(tenant, capID, rollout.MonitorMetrics{Samples: 1000, Errors: 1, Denies: 5})
	clk.Advance(time.Hour)
	// Now enrol (monitor entry is stamped AFTER the snapshot above).
	if err := ap.Sweep(ctx); err != nil {
		t.Fatalf("enrol sweep: %v", err)
	}
	clk.Advance(48 * time.Hour) // past dwell, but the only snapshot is stale
	if err := ap.Sweep(ctx); err != nil {
		t.Fatalf("stale sweep: %v", err)
	}
	if rec, _ := svc.Get(ctx, tenant, capID); rec.State != rollout.StateMonitor {
		t.Fatalf("state = %s, want monitor (stale evidence)", rec.State)
	}
	if obs.blocked[capID]["stale_metrics"] == 0 {
		t.Fatalf("expected a stale_metrics block, got %+v", obs.blocked[capID])
	}
}

// TestAutopilotNoEnrolWhenDisabled proves that with AutoEnrol off the
// autopilot never creates a monitor row for an unmanaged tenant: it only
// promotes tenants an operator already moved into monitor.
func TestAutopilotNoEnrolWhenDisabled(t *testing.T) {
	t.Parallel()
	policy := defaultPolicy()
	policy.AutoEnrol = false
	ap, svc, _, lister, _, _ := newAutopilotFixture(t, policy)
	tenant := uuid.New()
	lister.ids = []uuid.UUID{tenant}
	capID := rollout.CapabilityIDPDirectorySync
	ctx := context.Background()

	if err := ap.Sweep(ctx); err != nil {
		t.Fatalf("sweep: %v", err)
	}
	// Still unmanaged: no row created.
	if _, managed := svc.GateState(ctx, tenant, capID); managed {
		t.Fatalf("AutoEnrol=false must not create a managed row")
	}
}

// TestAutopilotEnrolOnlyWhenDwellDisabled proves a DwellWindow <= 0 makes
// the autopilot enrol-only: it dry-runs tenants but never auto-enforces,
// no matter how healthy the metrics.
func TestAutopilotEnrolOnlyWhenDwellDisabled(t *testing.T) {
	t.Parallel()
	policy := defaultPolicy()
	policy.DwellWindow = 0
	ap, svc, _, lister, recorder, clk := newAutopilotFixture(t, policy)
	tenant := uuid.New()
	lister.ids = []uuid.UUID{tenant}
	capID := rollout.CapabilityIDPDirectorySync
	ctx := context.Background()

	if err := ap.Sweep(ctx); err != nil {
		t.Fatalf("enrol sweep: %v", err)
	}
	recorder.Record(tenant, capID, rollout.MonitorMetrics{Samples: 5000, Errors: 0, Denies: 0})
	clk.Advance(100 * 24 * time.Hour)
	if err := ap.Sweep(ctx); err != nil {
		t.Fatalf("promote sweep: %v", err)
	}
	if rec, _ := svc.Get(ctx, tenant, capID); rec.State != rollout.StateMonitor {
		t.Fatalf("state = %s, want monitor (enrol-only, promotion disabled)", rec.State)
	}
}

// TestAutopilotOnlyGovernsListedCapabilities proves a capability not in
// the policy set is never touched, even when another is auto-advanced.
func TestAutopilotOnlyGovernsListedCapabilities(t *testing.T) {
	t.Parallel()
	policy := defaultPolicy() // governs only IDPDirectorySync
	ap, svc, _, lister, _, _ := newAutopilotFixture(t, policy)
	tenant := uuid.New()
	lister.ids = []uuid.UUID{tenant}
	ctx := context.Background()

	if err := ap.Sweep(ctx); err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if rec, _ := svc.Get(ctx, tenant, rollout.CapabilityIDPDirectorySync); rec.State != rollout.StateMonitor {
		t.Fatalf("governed capID state = %s, want monitor", rec.State)
	}
	// An ungoverned capability stays unmanaged.
	if _, managed := svc.GateState(ctx, tenant, rollout.CapabilityClamAVSWG); managed {
		t.Fatalf("ungoverned capability must remain unmanaged")
	}
}

// TestNewAutopilotRejectsUnsafePolicies covers the construction-time
// guardrails that keep demotion strictly easier than promotion.
func TestNewAutopilotRejectsUnsafePolicies(t *testing.T) {
	t.Parallel()
	repo := memory.NewCapabilityRolloutRepository()
	lister := &staticLister{}
	recorder := rollout.NewMonitorMetricsRecorder(nil)

	newSvc := func(th rollout.Threshold) *rollout.Service {
		s, err := rollout.New(repo, rollout.WithThreshold(th))
		if err != nil {
			t.Fatalf("new service: %v", err)
		}
		return s
	}

	cases := []struct {
		name   string
		demote rollout.Threshold
		policy rollout.AutopilotPolicy
	}{
		{
			name:   "promotion enabled but demote disabled",
			demote: rollout.Threshold{},
			policy: rollout.AutopilotPolicy{DwellWindow: time.Hour, MinSamples: 100, PromotionGuardrail: promoGuardrail},
		},
		{
			name:   "promo error ceiling looser than demote",
			demote: rollout.Threshold{MaxErrorRate: 0.05, MinSamples: 50},
			policy: rollout.AutopilotPolicy{DwellWindow: time.Hour, MinSamples: 100, PromotionGuardrail: rollout.Threshold{MaxErrorRate: 0.10, MinSamples: 100}},
		},
		{
			name:   "promo guardrail unconfigured",
			demote: rollout.Threshold{MaxErrorRate: 0.05, MinSamples: 50},
			policy: rollout.AutopilotPolicy{DwellWindow: time.Hour, MinSamples: 100, PromotionGuardrail: rollout.Threshold{}},
		},
		{
			name:   "demote deny set but promo deny missing",
			demote: rollout.Threshold{MaxErrorRate: 0.05, MaxDenyRate: 0.20, MinSamples: 50},
			policy: rollout.AutopilotPolicy{DwellWindow: time.Hour, MinSamples: 100, PromotionGuardrail: rollout.Threshold{MaxErrorRate: 0.02, MinSamples: 100}},
		},
		{
			name:   "promo min samples below demote",
			demote: rollout.Threshold{MaxErrorRate: 0.05, MinSamples: 200},
			policy: rollout.AutopilotPolicy{DwellWindow: time.Hour, MinSamples: 100, PromotionGuardrail: rollout.Threshold{MaxErrorRate: 0.02, MinSamples: 100}},
		},
		{
			name:   "unknown capability",
			demote: rollout.Threshold{MaxErrorRate: 0.05, MinSamples: 50},
			policy: rollout.AutopilotPolicy{Capabilities: []rollout.Capability{"bogus"}, PromotionGuardrail: promoGuardrail},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := rollout.NewAutopilot(newSvc(c.demote), lister, recorder, c.policy)
			if !errors.Is(err, rollout.ErrAutopilotConfig) {
				t.Fatalf("NewAutopilot = %v, want ErrAutopilotConfig", err)
			}
		})
	}
}

func TestNewAutopilotRejectsNilDeps(t *testing.T) {
	t.Parallel()
	repo := memory.NewCapabilityRolloutRepository()
	svc, _ := rollout.New(repo)
	lister := &staticLister{}
	recorder := rollout.NewMonitorMetricsRecorder(nil)
	policy := rollout.AutopilotPolicy{}

	if _, err := rollout.NewAutopilot(nil, lister, recorder, policy); !errors.Is(err, rollout.ErrAutopilotConfig) {
		t.Fatalf("nil svc = %v, want ErrAutopilotConfig", err)
	}
	if _, err := rollout.NewAutopilot(svc, nil, recorder, policy); !errors.Is(err, rollout.ErrAutopilotConfig) {
		t.Fatalf("nil lister = %v, want ErrAutopilotConfig", err)
	}
	if _, err := rollout.NewAutopilot(svc, lister, nil, policy); !errors.Is(err, rollout.ErrAutopilotConfig) {
		t.Fatalf("nil source = %v, want ErrAutopilotConfig", err)
	}
}

// TestAutopilotSweepContinuesPastTenantError proves one tenant's read
// failure does not stop the fleet sweep, while the error is surfaced.
func TestAutopilotSweepSurfacesAndContinues(t *testing.T) {
	t.Parallel()
	ap, svc, _, lister, _, _ := newAutopilotFixture(t, defaultPolicy())
	good := uuid.New()
	lister.ids = []uuid.UUID{uuid.Nil, good} // uuid.Nil triggers ErrInvalidArgument in Get
	ctx := context.Background()

	err := ap.Sweep(ctx)
	if err == nil {
		t.Fatal("expected the nil-tenant error to be surfaced")
	}
	// The good tenant after the bad one is still enrolled.
	if rec, _ := svc.Get(ctx, good, rollout.CapabilityIDPDirectorySync); rec.State != rollout.StateMonitor {
		t.Fatalf("good tenant state = %s, want monitor (sweep continued past error)", rec.State)
	}
}

// TestMonitorMetricsRecorderRoundTrip covers the recorder's snapshot
// store/read/forget behaviour and its handling of invalid keys.
func TestMonitorMetricsRecorderRoundTrip(t *testing.T) {
	t.Parallel()
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0).UTC()}
	r := rollout.NewMonitorMetricsRecorder(clk.Now)
	tenant := uuid.New()
	capID := rollout.CapabilityClamAVSWG

	// Empty: zero metrics, zero time.
	if m, at, err := r.MonitorMetrics(context.Background(), tenant, capID); err != nil || at != (time.Time{}) || m.Samples != 0 {
		t.Fatalf("empty read = (%+v, %v, %v), want zeros", m, at, err)
	}
	// Invalid keys ignored.
	r.Record(uuid.Nil, capID, rollout.MonitorMetrics{Samples: 1})
	r.Record(tenant, rollout.Capability("bogus"), rollout.MonitorMetrics{Samples: 1})

	r.Record(tenant, capID, rollout.MonitorMetrics{Samples: 42, Errors: 1})
	m, at, err := r.MonitorMetrics(context.Background(), tenant, capID)
	if err != nil || m.Samples != 42 || at != clk.Now() {
		t.Fatalf("read = (%+v, %v, %v), want samples 42 @ clock", m, at, err)
	}
	r.Forget(tenant, capID)
	if m, _, _ := r.MonitorMetrics(context.Background(), tenant, capID); m.Samples != 0 {
		t.Fatalf("after Forget samples = %d, want 0", m.Samples)
	}
}

// --- test doubles ---

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type staticLister struct{ ids []uuid.UUID }

func (s *staticLister) ListActiveTenantIDs(context.Context) ([]uuid.UUID, error) {
	return s.ids, nil
}

type countingObserver struct {
	mu       sync.Mutex
	enrolled map[rollout.Capability]int
	promoted map[rollout.Capability]int
	demoted  map[rollout.Capability]int
	blocked  map[rollout.Capability]map[string]int
}

func (o *countingObserver) ensure() {
	if o.enrolled == nil {
		o.enrolled = map[rollout.Capability]int{}
		o.promoted = map[rollout.Capability]int{}
		o.demoted = map[rollout.Capability]int{}
		o.blocked = map[rollout.Capability]map[string]int{}
	}
}

func (o *countingObserver) Enrolled(c rollout.Capability) {
	o.mu.Lock()
	o.ensure()
	o.enrolled[c]++
	o.mu.Unlock()
}

func (o *countingObserver) Promoted(c rollout.Capability) {
	o.mu.Lock()
	o.ensure()
	o.promoted[c]++
	o.mu.Unlock()
}

func (o *countingObserver) Demoted(c rollout.Capability) {
	o.mu.Lock()
	o.ensure()
	o.demoted[c]++
	o.mu.Unlock()
}

func (o *countingObserver) PromotionBlocked(c rollout.Capability, reason string) {
	o.mu.Lock()
	o.ensure()
	if o.blocked[c] == nil {
		o.blocked[c] = map[string]int{}
	}
	o.blocked[c][reason]++
	o.mu.Unlock()
}
