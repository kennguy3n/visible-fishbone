package rollout_test

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
	"github.com/kennguy3n/visible-fishbone/internal/service/rollout"
)

func newService(t *testing.T, opts ...rollout.Option) (*rollout.Service, uuid.UUID) {
	t.Helper()
	repo := memory.NewCapabilityRolloutRepository()
	svc, err := rollout.New(repo, opts...)
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	return svc, uuid.New()
}

func TestNewRejectsNilRepo(t *testing.T) {
	t.Parallel()
	if _, err := rollout.New(nil); !errors.Is(err, repository.ErrInvalidArgument) {
		t.Fatalf("New(nil) = %v, want ErrInvalidArgument", err)
	}
}

func TestGetDefaultsToOff(t *testing.T) {
	t.Parallel()
	svc, tenantID := newService(t)
	for _, c := range rollout.AllCapabilities() {
		rec, err := svc.Get(context.Background(), tenantID, c)
		if err != nil {
			t.Fatalf("Get(%s): %v", c, err)
		}
		if rec.State != rollout.StateOff {
			t.Fatalf("Get(%s).State = %s, want off (default)", c, rec.State)
		}
	}
}

func TestListReturnsEveryCapabilityDefaultingOff(t *testing.T) {
	t.Parallel()
	svc, tenantID := newService(t)

	// Advance just one capability; List must still report all of them.
	if _, err := svc.Transition(context.Background(), tenantID, rollout.CapabilityClamAVSWG,
		rollout.TransitionInput{To: rollout.StateMonitor, Actor: "op"}); err != nil {
		t.Fatalf("transition: %v", err)
	}

	recs, err := svc.List(context.Background(), tenantID)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(recs) != len(rollout.AllCapabilities()) {
		t.Fatalf("List len = %d, want %d", len(recs), len(rollout.AllCapabilities()))
	}
	got := make(map[rollout.Capability]rollout.State, len(recs))
	for _, r := range recs {
		got[r.Capability] = r.State
	}
	if got[rollout.CapabilityClamAVSWG] != rollout.StateMonitor {
		t.Fatalf("clamav_swg = %s, want monitor", got[rollout.CapabilityClamAVSWG])
	}
	if got[rollout.CapabilityNoOpsAutoEnforce] != rollout.StateOff {
		t.Fatalf("noops_autoenforce = %s, want off (default)", got[rollout.CapabilityNoOpsAutoEnforce])
	}
}

func TestTransitionHappyPathAndAudit(t *testing.T) {
	t.Parallel()
	sink := &recordingSink{}
	svc, tenantID := newService(t, rollout.WithTransitionSink(sink))
	ctx := context.Background()
	capID := rollout.CapabilityIDPDirectorySync

	// off -> monitor -> enforce, then rollback enforce -> off.
	steps := []struct {
		to   rollout.State
		from rollout.State
	}{
		{rollout.StateMonitor, rollout.StateOff},
		{rollout.StateEnforce, rollout.StateMonitor},
		{rollout.StateOff, rollout.StateEnforce},
	}
	for _, s := range steps {
		rec, err := svc.Transition(ctx, tenantID, capID, rollout.TransitionInput{
			To: s.to, Actor: "operator-1", Reason: "staged rollout",
		})
		if err != nil {
			t.Fatalf("transition to %s: %v", s.to, err)
		}
		if rec.State != s.to {
			t.Fatalf("state = %s, want %s", rec.State, s.to)
		}
		if rec.UpdatedBy != "operator-1" {
			t.Fatalf("updated_by = %q, want operator-1", rec.UpdatedBy)
		}
	}
	if len(sink.events) != 3 {
		t.Fatalf("sink saw %d transitions, want 3", len(sink.events))
	}
	if sink.events[0].from != rollout.StateOff || sink.events[0].rec.State != rollout.StateMonitor {
		t.Fatalf("first transition recorded wrong: %+v", sink.events[0])
	}
}

func TestTransitionRejectsSkipWithoutFlag(t *testing.T) {
	t.Parallel()
	svc, tenantID := newService(t)
	ctx := context.Background()
	capID := rollout.CapabilityNoOpsAutoEnforce

	_, err := svc.Transition(ctx, tenantID, capID, rollout.TransitionInput{
		To: rollout.StateEnforce, Actor: "op",
	})
	if !errors.Is(err, rollout.ErrSkipNotAllowed) {
		t.Fatalf("off->enforce without flag = %v, want ErrSkipNotAllowed", err)
	}
	// State must be unchanged (still off) after a rejected transition.
	rec, _ := svc.Get(ctx, tenantID, capID)
	if rec.State != rollout.StateOff {
		t.Fatalf("state after rejected skip = %s, want off", rec.State)
	}

	// With the override it succeeds.
	rec, err = svc.Transition(ctx, tenantID, capID, rollout.TransitionInput{
		To: rollout.StateEnforce, AllowSkip: true, Actor: "op",
	})
	if err != nil {
		t.Fatalf("off->enforce with allow_skip: %v", err)
	}
	if rec.State != rollout.StateEnforce {
		t.Fatalf("state = %s, want enforce", rec.State)
	}
}

func TestTransitionValidation(t *testing.T) {
	t.Parallel()
	svc, tenantID := newService(t)
	ctx := context.Background()

	if _, err := svc.Transition(ctx, tenantID, rollout.Capability("bogus"),
		rollout.TransitionInput{To: rollout.StateMonitor, Actor: "op"}); !errors.Is(err, rollout.ErrInvalidCapability) {
		t.Fatalf("bad capability = %v, want ErrInvalidCapability", err)
	}
	if _, err := svc.Transition(ctx, tenantID, rollout.CapabilityClamAVSWG,
		rollout.TransitionInput{To: rollout.State("bogus"), Actor: "op"}); !errors.Is(err, rollout.ErrInvalidState) {
		t.Fatalf("bad state = %v, want ErrInvalidState", err)
	}
	if _, err := svc.Transition(ctx, tenantID, rollout.CapabilityClamAVSWG,
		rollout.TransitionInput{To: rollout.StateMonitor}); !errors.Is(err, repository.ErrInvalidArgument) {
		t.Fatalf("missing actor = %v, want ErrInvalidArgument", err)
	}
	if _, err := svc.Transition(ctx, uuid.Nil, rollout.CapabilityClamAVSWG,
		rollout.TransitionInput{To: rollout.StateMonitor, Actor: "op"}); !errors.Is(err, repository.ErrInvalidArgument) {
		t.Fatalf("nil tenant = %v, want ErrInvalidArgument", err)
	}
}

func TestEvaluateAutoRollback(t *testing.T) {
	t.Parallel()
	sink := &recordingSink{}
	svc, tenantID := newService(t,
		rollout.WithThreshold(rollout.Threshold{MaxErrorRate: 0.1, MinSamples: 50}),
		rollout.WithTransitionSink(sink),
	)
	ctx := context.Background()
	capID := rollout.CapabilityClamAVSWG

	// Not monitoring (off): nothing to roll back regardless of metrics.
	if _, rolled, err := svc.EvaluateAutoRollback(ctx, tenantID, capID,
		rollout.MonitorMetrics{Samples: 100, Errors: 100}); err != nil || rolled {
		t.Fatalf("auto-rollback while off: rolled=%v err=%v, want false/nil", rolled, err)
	}

	// Advance to monitor.
	if _, err := svc.Transition(ctx, tenantID, capID,
		rollout.TransitionInput{To: rollout.StateMonitor, Actor: "op"}); err != nil {
		t.Fatalf("advance to monitor: %v", err)
	}

	// Healthy metrics: no rollback.
	if _, rolled, err := svc.EvaluateAutoRollback(ctx, tenantID, capID,
		rollout.MonitorMetrics{Samples: 100, Errors: 1}); err != nil || rolled {
		t.Fatalf("healthy metrics rolled=%v err=%v, want false/nil", rolled, err)
	}

	// Breaching metrics: auto-rollback to off, recorded by the system actor.
	rec, rolled, err := svc.EvaluateAutoRollback(ctx, tenantID, capID,
		rollout.MonitorMetrics{Samples: 100, Errors: 25})
	if err != nil || !rolled {
		t.Fatalf("breach rolled=%v err=%v, want true/nil", rolled, err)
	}
	if rec.State != rollout.StateOff {
		t.Fatalf("post-rollback state = %s, want off", rec.State)
	}
	if rec.UpdatedBy != rollout.SystemActor {
		t.Fatalf("rollback actor = %q, want %q", rec.UpdatedBy, rollout.SystemActor)
	}
	if rec.Reason == "" {
		t.Fatal("rollback must record a reason")
	}

	// Enforce is past the monitor guardrail: auto-rollback never touches it.
	if _, err := svc.Transition(ctx, tenantID, capID,
		rollout.TransitionInput{To: rollout.StateMonitor, Actor: "op"}); err != nil {
		t.Fatalf("re-advance to monitor: %v", err)
	}
	if _, err := svc.Transition(ctx, tenantID, capID,
		rollout.TransitionInput{To: rollout.StateEnforce, Actor: "op"}); err != nil {
		t.Fatalf("advance to enforce: %v", err)
	}
	if _, rolled, _ := svc.EvaluateAutoRollback(ctx, tenantID, capID,
		rollout.MonitorMetrics{Samples: 100, Errors: 100}); rolled {
		t.Fatal("auto-rollback must not act on an enforcing capability")
	}
}

func TestEffectiveStateFailsClosed(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	tenantID := uuid.New()

	// A repo that errors on every read must yield off (fail-closed), not
	// the last-known or any non-off state.
	failing, err := rollout.New(faultyRepo{err: errors.New("db down")})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if got := failing.EffectiveState(ctx, tenantID, rollout.CapabilityClamAVSWG); got != rollout.StateOff {
		t.Fatalf("EffectiveState on read error = %s, want off (fail-closed)", got)
	}

	// A healthy repo reflects the stored state.
	svc, tid := newService(t)
	if _, err := svc.Transition(ctx, tid, rollout.CapabilityClamAVSWG,
		rollout.TransitionInput{To: rollout.StateMonitor, Actor: "op"}); err != nil {
		t.Fatalf("transition: %v", err)
	}
	if got := svc.EffectiveState(ctx, tid, rollout.CapabilityClamAVSWG); got != rollout.StateMonitor {
		t.Fatalf("EffectiveState = %s, want monitor", got)
	}
	// Unknown capability and nil tenant also fail closed.
	if got := svc.EffectiveState(ctx, tid, rollout.Capability("bogus")); got != rollout.StateOff {
		t.Fatalf("EffectiveState(bad cap) = %s, want off", got)
	}
	if got := svc.EffectiveState(ctx, uuid.Nil, rollout.CapabilityClamAVSWG); got != rollout.StateOff {
		t.Fatalf("EffectiveState(nil tenant) = %s, want off", got)
	}
}

// --- test doubles ---

type sinkEvent struct {
	rec  rollout.Record
	from rollout.State
}

type recordingSink struct{ events []sinkEvent }

func (s *recordingSink) OnTransition(_ context.Context, rec rollout.Record, from rollout.State) {
	s.events = append(s.events, sinkEvent{rec: rec, from: from})
}

// faultyRepo fails every read, to prove EffectiveState fails closed.
type faultyRepo struct{ err error }

func (f faultyRepo) Get(context.Context, uuid.UUID, rollout.Capability) (rollout.Record, error) {
	return rollout.Record{}, f.err
}

func (f faultyRepo) List(context.Context, uuid.UUID) ([]rollout.Record, error) {
	return nil, f.err
}

func (f faultyRepo) Upsert(context.Context, uuid.UUID, rollout.Record) (rollout.Record, error) {
	return rollout.Record{}, f.err
}
