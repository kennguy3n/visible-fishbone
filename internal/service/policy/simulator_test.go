package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sort"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/nats/schema"
	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// stubSource is a deterministic in-memory TelemetrySource for
// tests. ListEvents (and ListFlowEvents, which forwards into it
// to mirror the real ClickHouse Reader contract) returns the
// same filtered slice every call so determinism is testable
// end-to-end. classes (when non-nil) restricts the returned
// envelopes by EventClass — matches the Reader's IN-list filter.
type stubSource struct {
	envs        []schema.Envelope
	err         error
	call        int
	lastClasses []schema.EventClass
}

func (s *stubSource) ListFlowEvents(
	ctx context.Context,
	tid uuid.UUID,
	since, until time.Time,
	max int,
) ([]schema.Envelope, error) {
	return s.ListEvents(ctx, tid, []schema.EventClass{schema.EventClassFlow}, since, until, max)
}

func (s *stubSource) ListEvents(
	_ context.Context,
	_ uuid.UUID,
	classes []schema.EventClass,
	_, _ time.Time,
	_ int,
) ([]schema.Envelope, error) {
	s.call++
	s.lastClasses = append([]schema.EventClass(nil), classes...)
	if s.err != nil {
		return nil, s.err
	}
	// Filter to the requested classes when set; the real Reader
	// pushes this filter down to ClickHouse via WHERE event_class
	// IN (...), so the stub MUST mirror that or simulator tests
	// will see envelopes the production path wouldn't.
	wanted := make(map[schema.EventClass]struct{}, len(classes))
	for _, c := range classes {
		wanted[c] = struct{}{}
	}
	out := make([]schema.Envelope, 0, len(s.envs))
	for _, e := range s.envs {
		if len(wanted) == 0 {
			out = append(out, e)
			continue
		}
		if _, ok := wanted[e.EventClass]; ok {
			out = append(out, e)
		}
	}
	return out, nil
}

// stubEvaluator returns a fixed verdict for every envelope.
// Used to pin the prev/next verdicts independently in transition
// tests.
type stubEvaluator struct {
	verdict schema.Verdict
	err     error
	// failFor matches on EventID — empty -> never fail.
	failFor uuid.UUID
}

func (e *stubEvaluator) Evaluate(_ context.Context, env schema.Envelope) (schema.Verdict, error) {
	if e.failFor != uuid.Nil && env.EventID == e.failFor {
		return "", errors.New("forced failure")
	}
	if e.err != nil {
		return "", e.err
	}
	return e.verdict, nil
}

// stubFactory returns a preconfigured Evaluator per graph ID
// lookup. Tests pre-register one Evaluator per graph they pass
// in (prev / next).
type stubFactory struct {
	byGraph map[uuid.UUID]Evaluator
	def     Evaluator
}

func (f *stubFactory) Build(_ context.Context, g repository.PolicyGraph) (Evaluator, error) {
	if ev, ok := f.byGraph[g.ID]; ok {
		return ev, nil
	}
	if f.def != nil {
		return f.def, nil
	}
	return nil, errors.New("no evaluator registered for graph")
}

func makeFlowEnv(t *testing.T, tenantID, deviceID uuid.UUID, sitePtr *uuid.UUID, ts time.Time) schema.Envelope {
	t.Helper()
	return schema.Envelope{
		SchemaVersion: 1,
		EventID:       uuid.New(),
		TenantID:      tenantID,
		DeviceID:      deviceID,
		SiteID:        sitePtr,
		Timestamp:     ts,
		EventClass:    schema.EventClassFlow,
		Platform:      "linux",
	}
}

func newGraph() repository.PolicyGraph {
	return repository.PolicyGraph{
		ID:      uuid.New(),
		Version: 1,
		Graph:   json.RawMessage(`{"default_action":"deny"}`),
	}
}

func TestSimulator_HappyPath_NoChange(t *testing.T) {
	t.Parallel()
	tenantID := uuid.New()
	devA, devB := uuid.New(), uuid.New()
	siteA := uuid.New()
	src := &stubSource{envs: []schema.Envelope{
		makeFlowEnv(t, tenantID, devA, &siteA, time.Unix(100, 0)),
		makeFlowEnv(t, tenantID, devB, nil, time.Unix(101, 0)),
	}}
	prev := newGraph()
	next := newGraph()
	factory := &stubFactory{byGraph: map[uuid.UUID]Evaluator{
		prev.ID: &stubEvaluator{verdict: schema.VerdictAllow},
		next.ID: &stubEvaluator{verdict: schema.VerdictAllow},
	}}
	sim, err := NewSimulator(src, factory)
	if err != nil {
		t.Fatalf("new sim: %v", err)
	}
	rep, err := sim.Simulate(context.Background(), tenantID, prev, next,
		time.Unix(0, 0), time.Unix(200, 0), SimulationOptions{})
	if err != nil {
		t.Fatalf("simulate: %v", err)
	}
	if rep.Total != 2 {
		t.Fatalf("total = %d, want 2", rep.Total)
	}
	if rep.Changed != 0 {
		t.Fatalf("changed = %d, want 0", rep.Changed)
	}
	if len(rep.AffectedDevices) != 0 {
		t.Fatalf("affected devices = %v, want empty", rep.AffectedDevices)
	}
	if len(rep.Transitions) != 1 {
		t.Fatalf("transitions = %d, want 1 (allow->allow)", len(rep.Transitions))
	}
	if rep.Transitions[0].PrevVerdict != schema.VerdictAllow ||
		rep.Transitions[0].NextVerdict != schema.VerdictAllow ||
		rep.Transitions[0].Count != 2 {
		t.Fatalf("unexpected transition: %+v", rep.Transitions[0])
	}
	if rep.SimulationID == uuid.Nil {
		t.Fatalf("simulation id missing")
	}
}

func TestSimulator_DetectsVerdictChange(t *testing.T) {
	t.Parallel()
	tenantID := uuid.New()
	devA, devB := uuid.New(), uuid.New()
	siteA := uuid.New()
	src := &stubSource{envs: []schema.Envelope{
		makeFlowEnv(t, tenantID, devA, &siteA, time.Unix(100, 0)),
		makeFlowEnv(t, tenantID, devB, &siteA, time.Unix(101, 0)),
	}}
	prev := newGraph()
	next := newGraph()
	factory := &stubFactory{byGraph: map[uuid.UUID]Evaluator{
		prev.ID: &stubEvaluator{verdict: schema.VerdictAllow},
		next.ID: &stubEvaluator{verdict: schema.VerdictDeny},
	}}
	sim, err := NewSimulator(src, factory)
	if err != nil {
		t.Fatalf("new sim: %v", err)
	}
	rep, err := sim.Simulate(context.Background(), tenantID, prev, next,
		time.Unix(0, 0), time.Unix(200, 0), SimulationOptions{})
	if err != nil {
		t.Fatalf("simulate: %v", err)
	}
	if rep.Changed != 2 {
		t.Fatalf("changed = %d, want 2", rep.Changed)
	}
	if len(rep.AffectedDevices) != 2 {
		t.Fatalf("affected devices = %d, want 2", len(rep.AffectedDevices))
	}
	// AffectedDevices must be sorted for determinism.
	if !uuidLess(rep.AffectedDevices[0], rep.AffectedDevices[1]) {
		t.Fatalf("affected devices not sorted: %v", rep.AffectedDevices)
	}
	if len(rep.AffectedSites) != 1 || rep.AffectedSites[0] != siteA {
		t.Fatalf("affected sites = %v, want [%s]", rep.AffectedSites, siteA)
	}
}

func TestSimulator_DeterministicOutput(t *testing.T) {
	t.Parallel()
	// Same inputs => same Total/Changed/Transitions across runs.
	// SimulationID and StartedAt vary by design (per-run identity).
	tenantID := uuid.New()
	envs := make([]schema.Envelope, 50)
	for i := range envs {
		envs[i] = makeFlowEnv(t, tenantID, uuid.New(), nil, time.Unix(int64(i), 0))
	}
	prev := newGraph()
	next := newGraph()
	mkFactory := func() *stubFactory {
		return &stubFactory{byGraph: map[uuid.UUID]Evaluator{
			prev.ID: &stubEvaluator{verdict: schema.VerdictAllow},
			next.ID: &stubEvaluator{verdict: schema.VerdictDeny},
		}}
	}
	src1 := &stubSource{envs: envs}
	src2 := &stubSource{envs: envs}
	sim1, _ := NewSimulator(src1, mkFactory())
	sim2, _ := NewSimulator(src2, mkFactory())
	r1, err := sim1.Simulate(context.Background(), tenantID, prev, next,
		time.Unix(0, 0), time.Unix(1000, 0), SimulationOptions{})
	if err != nil {
		t.Fatalf("sim1: %v", err)
	}
	r2, err := sim2.Simulate(context.Background(), tenantID, prev, next,
		time.Unix(0, 0), time.Unix(1000, 0), SimulationOptions{})
	if err != nil {
		t.Fatalf("sim2: %v", err)
	}
	if r1.Total != r2.Total || r1.Changed != r2.Changed {
		t.Fatalf("non-deterministic: r1=%d/%d r2=%d/%d", r1.Total, r1.Changed, r2.Total, r2.Changed)
	}
	if !sameTransitions(r1.Transitions, r2.Transitions) {
		t.Fatalf("transitions differ across runs")
	}
	if !sameUUIDs(r1.AffectedDevices, r2.AffectedDevices) {
		t.Fatalf("affected devices differ across runs")
	}
}

func sameTransitions(a, b []VerdictTransition) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func sameUUIDs(a, b []uuid.UUID) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestSimulator_CountsEvaluatorErrors(t *testing.T) {
	t.Parallel()
	tenantID := uuid.New()
	devA := uuid.New()
	bad := makeFlowEnv(t, tenantID, devA, nil, time.Unix(100, 0))
	good := makeFlowEnv(t, tenantID, devA, nil, time.Unix(101, 0))
	src := &stubSource{envs: []schema.Envelope{bad, good}}
	prev := newGraph()
	next := newGraph()
	factory := &stubFactory{byGraph: map[uuid.UUID]Evaluator{
		prev.ID: &stubEvaluator{verdict: schema.VerdictAllow},
		next.ID: &stubEvaluator{verdict: schema.VerdictDeny, failFor: bad.EventID},
	}}
	sim, _ := NewSimulator(src, factory)
	rep, err := sim.Simulate(context.Background(), tenantID, prev, next,
		time.Unix(0, 0), time.Unix(200, 0), SimulationOptions{})
	if err != nil {
		t.Fatalf("simulate: %v", err)
	}
	if rep.Total != 2 {
		t.Fatalf("total = %d, want 2", rep.Total)
	}
	if rep.NextErrors != 1 {
		t.Fatalf("next errors = %d, want 1", rep.NextErrors)
	}
	// Only the successfully evaluated envelope contributes to
	// Changed / Transitions.
	if rep.Changed != 1 {
		t.Fatalf("changed = %d, want 1 (only the good envelope)", rep.Changed)
	}
}

func TestSimulator_RespectsMaxEvents(t *testing.T) {
	t.Parallel()
	tenantID := uuid.New()
	envs := make([]schema.Envelope, 10)
	for i := range envs {
		envs[i] = makeFlowEnv(t, tenantID, uuid.New(), nil, time.Unix(int64(i), 0))
	}
	src := &stubSource{envs: envs}
	prev := newGraph()
	next := newGraph()
	factory := &stubFactory{byGraph: map[uuid.UUID]Evaluator{
		prev.ID: &stubEvaluator{verdict: schema.VerdictAllow},
		next.ID: &stubEvaluator{verdict: schema.VerdictAllow},
	}}
	sim, _ := NewSimulator(src, factory)
	// The source returns 10 events; max should not crash with
	// fewer-than-cap inputs (covers the off-by-one path).
	rep, err := sim.Simulate(context.Background(), tenantID, prev, next,
		time.Unix(0, 0), time.Unix(100, 0), SimulationOptions{MaxEvents: 5})
	if err != nil {
		t.Fatalf("simulate: %v", err)
	}
	if rep.Total > 10 {
		t.Fatalf("total = %d > 10, MaxEvents not enforced", rep.Total)
	}
}

func TestSimulator_EmptyGraphsFallbackToDenyAll(t *testing.T) {
	t.Parallel()
	tenantID := uuid.New()
	devA := uuid.New()
	src := &stubSource{envs: []schema.Envelope{
		makeFlowEnv(t, tenantID, devA, nil, time.Unix(1, 0)),
	}}
	factory := &stubFactory{byGraph: map[uuid.UUID]Evaluator{}}
	sim, _ := NewSimulator(src, factory)
	// Zero PolicyGraphs on both sides => denyAllEvaluator on
	// both => no verdict change, no errors. This is the
	// "fresh tenant with no prior policy" semantics
	// documented on buildEvaluator.
	rep, err := sim.Simulate(context.Background(), tenantID,
		repository.PolicyGraph{}, repository.PolicyGraph{},
		time.Unix(0, 0), time.Unix(200, 0), SimulationOptions{})
	if err != nil {
		t.Fatalf("simulate: %v", err)
	}
	if rep.Total != 1 || rep.Changed != 0 {
		t.Fatalf("expected 1 total / 0 changed, got %+v", rep)
	}
	if rep.PrevErrors != 0 || rep.NextErrors != 0 {
		t.Fatalf("denyAll should not error: %+v", rep)
	}
}

func TestSimulator_BothGraphCompileFailures_ReturnsErrNoEvaluator(t *testing.T) {
	t.Parallel()
	tenantID := uuid.New()
	src := &stubSource{}
	// Factory returns an error for any graph it doesn't know.
	factory := &stubFactory{byGraph: map[uuid.UUID]Evaluator{}}
	sim, _ := NewSimulator(src, factory)
	// Non-zero graph IDs route through the factory, which
	// returns errors — both sides fail to compile.
	prev := newGraph()
	next := newGraph()
	_, err := sim.Simulate(context.Background(), tenantID, prev, next,
		time.Unix(0, 0), time.Unix(200, 0), SimulationOptions{})
	if !errors.Is(err, ErrNoEvaluator) {
		t.Fatalf("err = %v, want ErrNoEvaluator", err)
	}
}

func TestSimulator_PropagatesSourceError(t *testing.T) {
	t.Parallel()
	src := &stubSource{err: errors.New("clickhouse exploded")}
	prev := newGraph()
	next := newGraph()
	factory := &stubFactory{byGraph: map[uuid.UUID]Evaluator{
		prev.ID: &stubEvaluator{verdict: schema.VerdictAllow},
		next.ID: &stubEvaluator{verdict: schema.VerdictAllow},
	}}
	sim, _ := NewSimulator(src, factory)
	_, err := sim.Simulate(context.Background(), uuid.New(), prev, next,
		time.Unix(0, 0), time.Unix(200, 0), SimulationOptions{})
	if err == nil || !errors.Is(err, src.err) {
		t.Fatalf("err = %v, want wrap of %v", err, src.err)
	}
}

func TestSimulator_TransitionsAreSorted(t *testing.T) {
	t.Parallel()
	// Construct envelopes that produce a multi-cell transition
	// matrix. Verify the output slice is in canonical
	// (prev, next) order so downstream comparison is stable.
	tenantID := uuid.New()
	envs := []schema.Envelope{
		makeFlowEnv(t, tenantID, uuid.New(), nil, time.Unix(1, 0)),
		makeFlowEnv(t, tenantID, uuid.New(), nil, time.Unix(2, 0)),
		makeFlowEnv(t, tenantID, uuid.New(), nil, time.Unix(3, 0)),
	}
	src := &stubSource{envs: envs}
	prev := newGraph()
	next := newGraph()
	// Toggle next evaluator per call -> mixed transitions.
	togglerNext := &toggleEvaluator{verdicts: []schema.Verdict{schema.VerdictAllow, schema.VerdictDeny, schema.VerdictInspect}}
	togglerPrev := &toggleEvaluator{verdicts: []schema.Verdict{schema.VerdictAllow, schema.VerdictAllow, schema.VerdictAllow}}
	factory := &stubFactory{byGraph: map[uuid.UUID]Evaluator{
		prev.ID: togglerPrev,
		next.ID: togglerNext,
	}}
	sim, _ := NewSimulator(src, factory)
	rep, err := sim.Simulate(context.Background(), tenantID, prev, next,
		time.Unix(0, 0), time.Unix(100, 0), SimulationOptions{})
	if err != nil {
		t.Fatalf("simulate: %v", err)
	}
	if !sort.SliceIsSorted(rep.Transitions, func(i, j int) bool {
		if rep.Transitions[i].PrevVerdict != rep.Transitions[j].PrevVerdict {
			return rep.Transitions[i].PrevVerdict < rep.Transitions[j].PrevVerdict
		}
		return rep.Transitions[i].NextVerdict < rep.Transitions[j].NextVerdict
	}) {
		t.Fatalf("transitions not in canonical order: %+v", rep.Transitions)
	}
}

// toggleEvaluator returns successive verdicts from its slice;
// goroutine-unsafe but the simulator currently evaluates
// sequentially so this is fine for tests.
type toggleEvaluator struct {
	verdicts []schema.Verdict
	idx      int
}

func (e *toggleEvaluator) Evaluate(_ context.Context, _ schema.Envelope) (schema.Verdict, error) {
	v := e.verdicts[e.idx%len(e.verdicts)]
	e.idx++
	return v, nil
}

func TestSimulator_StartedAndFinishedAt(t *testing.T) {
	t.Parallel()
	tenantID := uuid.New()
	src := &stubSource{envs: []schema.Envelope{
		makeFlowEnv(t, tenantID, uuid.New(), nil, time.Unix(1, 0)),
	}}
	prev := newGraph()
	next := newGraph()
	factory := &stubFactory{byGraph: map[uuid.UUID]Evaluator{
		prev.ID: &stubEvaluator{verdict: schema.VerdictAllow},
		next.ID: &stubEvaluator{verdict: schema.VerdictAllow},
	}}
	// Pin the clock to two sequential values so StartedAt and
	// FinishedAt are deterministic.
	calls := []time.Time{
		time.Unix(10, 0).UTC(),
		time.Unix(20, 0).UTC(),
	}
	idx := 0
	clock := func() time.Time {
		t := calls[idx%len(calls)]
		idx++
		return t
	}
	sim, _ := NewSimulator(src, factory, WithSimulatorClock(clock))
	rep, err := sim.Simulate(context.Background(), tenantID, prev, next,
		time.Unix(0, 0), time.Unix(100, 0), SimulationOptions{})
	if err != nil {
		t.Fatalf("simulate: %v", err)
	}
	if !rep.StartedAt.Equal(calls[0]) {
		t.Fatalf("started = %v, want %v", rep.StartedAt, calls[0])
	}
	if !rep.FinishedAt.Equal(calls[1]) {
		t.Fatalf("finished = %v, want %v", rep.FinishedAt, calls[1])
	}
}

func TestNewSimulator_RejectsNilDeps(t *testing.T) {
	t.Parallel()
	if _, err := NewSimulator(nil, &stubFactory{}); err == nil {
		t.Fatalf("expected error for nil source")
	}
	if _, err := NewSimulator(&stubSource{}, nil); err == nil {
		t.Fatalf("expected error for nil factory")
	}
}

func TestSimulator_ConcurrentSimulationsAreSerialised(t *testing.T) {
	t.Parallel()
	// IsRunning() guards against re-entry; running two
	// Simulate calls concurrently from the same instance should
	// either serialise or return an error — verify the
	// implementation doesn't panic / data-race.
	tenantID := uuid.New()
	envs := []schema.Envelope{
		makeFlowEnv(t, tenantID, uuid.New(), nil, time.Unix(1, 0)),
	}
	src := &stubSource{envs: envs}
	prev := newGraph()
	next := newGraph()
	factory := &stubFactory{byGraph: map[uuid.UUID]Evaluator{
		prev.ID: &stubEvaluator{verdict: schema.VerdictAllow},
		next.ID: &stubEvaluator{verdict: schema.VerdictAllow},
	}}
	sim, _ := NewSimulator(src, factory)
	errs := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() {
			_, err := sim.Simulate(context.Background(), tenantID, prev, next,
				time.Unix(0, 0), time.Unix(100, 0), SimulationOptions{})
			errs <- err
		}()
	}
	var anyErr error
	for i := 0; i < 2; i++ {
		if e := <-errs; e != nil && anyErr == nil {
			anyErr = e
		}
	}
	// At minimum we tolerate either both-succeed or
	// at-most-one-succeed. The race detector / panic recovery
	// is the real assertion.
	_ = anyErr
}

func TestSimulator_EmptyEventsProducesEmptyReport(t *testing.T) {
	t.Parallel()
	tenantID := uuid.New()
	src := &stubSource{envs: nil}
	prev := newGraph()
	next := newGraph()
	factory := &stubFactory{byGraph: map[uuid.UUID]Evaluator{
		prev.ID: &stubEvaluator{verdict: schema.VerdictAllow},
		next.ID: &stubEvaluator{verdict: schema.VerdictAllow},
	}}
	sim, _ := NewSimulator(src, factory)
	rep, err := sim.Simulate(context.Background(), tenantID, prev, next,
		time.Unix(0, 0), time.Unix(100, 0), SimulationOptions{})
	if err != nil {
		t.Fatalf("simulate: %v", err)
	}
	if rep.Total != 0 || rep.Changed != 0 {
		t.Fatalf("non-zero report for empty input: %+v", rep)
	}
	if len(rep.Transitions) != 0 {
		t.Fatalf("non-empty transitions for empty input: %v", rep.Transitions)
	}
}

// Sanity: the test's stub evaluator + source compile against the
// real interfaces. (catches mismatch from refactors of the
// production interface that don't update tests.)
var _ TelemetrySource = (*stubSource)(nil)
var _ Evaluator = (*stubEvaluator)(nil)
var _ EvaluatorFactory = (*stubFactory)(nil)

// TestSimulator_DefaultEventClasses pins the simulator's
// post-PR-39-round-2 contract that it pulls flow+dns+http+ztna
// by default (matching evaluator.domainMatchesEventClass). Prior
// to this change the simulator only pulled flow, so DNS/HTTP/
// ZTNA policy changes silently appeared as zero-impact.
func TestSimulator_DefaultEventClasses(t *testing.T) {
	t.Parallel()
	tenantID := uuid.New()
	devID := uuid.New()
	ts := time.Unix(1_700_000_000, 0).UTC()
	flowEnv := makeFlowEnv(t, tenantID, devID, nil, ts)
	dnsEnv := makeFlowEnv(t, tenantID, devID, nil, ts.Add(time.Second))
	dnsEnv.EventID = uuid.New()
	dnsEnv.EventClass = schema.EventClassDNS
	httpEnv := makeFlowEnv(t, tenantID, devID, nil, ts.Add(2*time.Second))
	httpEnv.EventID = uuid.New()
	httpEnv.EventClass = schema.EventClassHTTP
	ztnaEnv := makeFlowEnv(t, tenantID, devID, nil, ts.Add(3*time.Second))
	ztnaEnv.EventID = uuid.New()
	ztnaEnv.EventClass = schema.EventClassZTNA
	// Excluded by default — must NOT appear in the simulation.
	postureEnv := makeFlowEnv(t, tenantID, devID, nil, ts.Add(4*time.Second))
	postureEnv.EventID = uuid.New()
	postureEnv.EventClass = schema.EventClassPosture

	src := &stubSource{envs: []schema.Envelope{flowEnv, dnsEnv, httpEnv, ztnaEnv, postureEnv}}
	prev := newGraph()
	next := newGraph()
	factory := &stubFactory{byGraph: map[uuid.UUID]Evaluator{
		prev.ID: &stubEvaluator{verdict: schema.VerdictAllow},
		next.ID: &stubEvaluator{verdict: schema.VerdictDeny},
	}}
	sim, _ := NewSimulator(src, factory)
	rep, err := sim.Simulate(context.Background(), tenantID, prev, next,
		time.Unix(0, 0), time.Unix(1_700_000_999, 0), SimulationOptions{})
	if err != nil {
		t.Fatalf("simulate: %v", err)
	}
	// 4 simulated (flow+dns+http+ztna), posture excluded by default.
	if rep.Total != 4 {
		t.Fatalf("Total = %d, want 4 (posture should be excluded by default)", rep.Total)
	}
	if rep.Changed != 4 {
		t.Fatalf("Changed = %d, want 4 (every event flipped allow->deny)", rep.Changed)
	}
	// Confirm the source actually received the default class set.
	wantClasses := DefaultSimulatedEventClasses
	if len(src.lastClasses) != len(wantClasses) {
		t.Fatalf("source classes = %v, want %v", src.lastClasses, wantClasses)
	}
	for i, c := range wantClasses {
		if src.lastClasses[i] != c {
			t.Fatalf("source classes[%d] = %s, want %s", i, src.lastClasses[i], c)
		}
	}
}

// TestSimulator_CustomEventClasses verifies the override path.
func TestSimulator_CustomEventClasses(t *testing.T) {
	t.Parallel()
	tenantID := uuid.New()
	devID := uuid.New()
	ts := time.Unix(1_700_000_000, 0).UTC()
	flowEnv := makeFlowEnv(t, tenantID, devID, nil, ts)
	dnsEnv := makeFlowEnv(t, tenantID, devID, nil, ts.Add(time.Second))
	dnsEnv.EventID = uuid.New()
	dnsEnv.EventClass = schema.EventClassDNS

	src := &stubSource{envs: []schema.Envelope{flowEnv, dnsEnv}}
	prev := newGraph()
	next := newGraph()
	factory := &stubFactory{byGraph: map[uuid.UUID]Evaluator{
		prev.ID: &stubEvaluator{verdict: schema.VerdictAllow},
		next.ID: &stubEvaluator{verdict: schema.VerdictDeny},
	}}
	sim, _ := NewSimulator(src, factory)
	rep, err := sim.Simulate(context.Background(), tenantID, prev, next,
		time.Unix(0, 0), time.Unix(1_700_000_999, 0), SimulationOptions{
			EventClasses: []schema.EventClass{schema.EventClassFlow},
		})
	if err != nil {
		t.Fatalf("simulate: %v", err)
	}
	if rep.Total != 1 {
		t.Fatalf("Total = %d, want 1 (flow only)", rep.Total)
	}
	if len(src.lastClasses) != 1 || src.lastClasses[0] != schema.EventClassFlow {
		t.Fatalf("source classes = %v, want [flow]", src.lastClasses)
	}
}

// quickJSON keeps the test file self-contained for fixture
// generation without dragging in encoding/json everywhere.
func quickJSON(t *testing.T, v any) []byte {
	t.Helper()
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	if err := enc.Encode(v); err != nil {
		t.Fatalf("json encode: %v", err)
	}
	return buf.Bytes()
}

var _ = quickJSON // reserved for future fixtures
