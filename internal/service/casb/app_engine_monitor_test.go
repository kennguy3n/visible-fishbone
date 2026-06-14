package casb_test

import (
	"context"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/service/casb"
	"github.com/kennguy3n/visible-fishbone/internal/service/rollout"
)

// fakeMonitorSink captures the per-tenant monitor evidence the engine
// records, so the tests can assert what the WS-5 auto-promoter would read.
type fakeMonitorSink struct {
	mu    sync.Mutex
	calls []monitorSinkCall
}

type monitorSinkCall struct {
	tenantID   uuid.UUID
	capability rollout.Capability
	metrics    rollout.MonitorMetrics
}

func (s *fakeMonitorSink) Record(tenantID uuid.UUID, c rollout.Capability, m rollout.MonitorMetrics) {
	s.mu.Lock()
	s.calls = append(s.calls, monitorSinkCall{tenantID, c, m})
	s.mu.Unlock()
}

func (s *fakeMonitorSink) snapshot() []monitorSinkCall {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]monitorSinkCall(nil), s.calls...)
}

// TestReconcileTenant_MonitorRecordsEvidence proves the noops_autoenforce
// dry-run feeds the auto-promoter: a MANAGED-monitor tenant's reconcile
// records a per-tenant snapshot whose Denies count the would-have
// auto-enforce verdicts (the would-have-block volume), with no
// enforcement taken.
func TestReconcileTenant_MonitorRecordsEvidence(t *testing.T) {
	fx := newEngineFixture(t)
	fx.enforcer.created = true
	fx.engine.SetEnforcer(fx.enforcer)
	fx.engine.SetRolloutGate(stubAutoEnforceGate{state: rollout.StateMonitor, managed: true})
	sink := &fakeMonitorSink{}
	fx.engine.SetMonitorMetricsSink(sink)

	tid := fx.newTenant(t)
	ctx := context.Background()

	devices := 50
	app := repository.CASBDiscoveredApp{Name: "Telegram", Category: "messaging", ActiveDeviceCount: &devices}
	if _, err := fx.apps.Upsert(ctx, tid, app); err != nil {
		t.Fatalf("seed app: %v", err)
	}

	if err := fx.engine.ReconcileTenant(ctx, tid); err != nil {
		t.Fatalf("ReconcileTenant: %v", err)
	}

	// No enforcement in monitor.
	if fx.enforcer.callCount() != 0 {
		t.Fatalf("enforcer calls = %d, want 0 (monitor dry-run)", fx.enforcer.callCount())
	}

	calls := sink.snapshot()
	if len(calls) != 1 {
		t.Fatalf("sink Record calls = %d, want 1", len(calls))
	}
	got := calls[0]
	if got.tenantID != tid {
		t.Fatalf("recorded tenant = %s, want %s", got.tenantID, tid)
	}
	if got.capability != rollout.CapabilityNoOpsAutoEnforce {
		t.Fatalf("recorded capability = %s, want noops_autoenforce", got.capability)
	}
	// Telegram is a high-risk unsanctioned app: it would auto-enforce, so
	// it contributes one sample and one deny, no errors.
	if got.metrics.Samples != 1 || got.metrics.Denies != 1 || got.metrics.Errors != 0 {
		t.Fatalf("recorded metrics = %+v, want samples 1 / denies 1 / errors 0", got.metrics)
	}
}

// TestReconcileTenant_EnforceModeRecordsNoEvidence proves evidence is a
// MONITOR-only signal: in enforce the engine is already applying, so it
// records nothing for the promoter to read (there is nothing to promote
// toward), and in off it is recommend-only.
func TestReconcileTenant_EnforceModeRecordsNoEvidence(t *testing.T) {
	for _, tc := range []struct {
		name  string
		state rollout.State
	}{
		{"enforce", rollout.StateEnforce},
		{"managed-off", rollout.StateOff},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fx := newEngineFixture(t)
			fx.enforcer.created = true
			fx.engine.SetEnforcer(fx.enforcer)
			fx.engine.SetRolloutGate(stubAutoEnforceGate{state: tc.state, managed: true})
			sink := &fakeMonitorSink{}
			fx.engine.SetMonitorMetricsSink(sink)

			tid := fx.newTenant(t)
			ctx := context.Background()
			devices := 50
			app := repository.CASBDiscoveredApp{Name: "Telegram", Category: "messaging", ActiveDeviceCount: &devices}
			if _, err := fx.apps.Upsert(ctx, tid, app); err != nil {
				t.Fatalf("seed app: %v", err)
			}
			if err := fx.engine.ReconcileTenant(ctx, tid); err != nil {
				t.Fatalf("ReconcileTenant: %v", err)
			}
			if calls := sink.snapshot(); len(calls) != 0 {
				t.Fatalf("sink Record calls = %d, want 0 in %s", len(calls), tc.name)
			}
		})
	}
}

// TestReconcileTenant_NilSinkSafe proves the sink is optional: a
// monitor-mode reconcile with no sink wired runs without panicking (nil
// is a no-op, so wiring is fail-safe).
func TestReconcileTenant_NilSinkSafe(t *testing.T) {
	fx := newEngineFixture(t)
	fx.engine.SetRolloutGate(stubAutoEnforceGate{state: rollout.StateMonitor, managed: true})
	// No SetMonitorMetricsSink call.
	tid := fx.newTenant(t)
	ctx := context.Background()
	devices := 50
	app := repository.CASBDiscoveredApp{Name: "Telegram", Category: "messaging", ActiveDeviceCount: &devices}
	if _, err := fx.apps.Upsert(ctx, tid, app); err != nil {
		t.Fatalf("seed app: %v", err)
	}
	if err := fx.engine.ReconcileTenant(ctx, tid); err != nil {
		t.Fatalf("ReconcileTenant: %v", err)
	}
}

// Ensure the rollout recorder satisfies the casb sink interface (the
// production wiring binds them).
var _ casb.MonitorMetricsSink = (*rollout.MonitorMetricsRecorder)(nil)
