package telemetry

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/nats/schema"
)

type capturedDLP struct {
	tenant, device uuid.UUID
	ev             schema.DLPEvent
	ts             time.Time
}

type fakeDLPObserver struct{ calls []capturedDLP }

func (f *fakeDLPObserver) ObserveDLP(_ context.Context, tenantID, deviceID uuid.UUID, ev schema.DLPEvent, ts time.Time) {
	f.calls = append(f.calls, capturedDLP{tenantID, deviceID, ev, ts})
}

func coachEvent() schema.DLPEvent {
	return schema.DLPEvent{
		DestinationApp: "chatgpt",
		Action:         schema.DLPActionCoach,
		Severity:       "high",
		Confidence:     0.92,
		Findings: []schema.DLPFinding{
			{Kind: schema.DLPFindingSecret, Label: "github_token", Count: 2, MaxConfidence: 0.99, Severity: "high"},
		},
	}
}

func TestObserveDLP_EnqueuesCoachEvent(t *testing.T) {
	obs := &fakeDLPObserver{}
	e := env(t, schema.EventClassDLP, coachEvent())
	observeDLP(context.Background(), obs, e)
	if len(obs.calls) != 1 {
		t.Fatalf("expected 1 enqueue, got %d", len(obs.calls))
	}
	got := obs.calls[0]
	if got.tenant != e.TenantID || got.device != e.DeviceID || !got.ts.Equal(e.Timestamp) {
		t.Fatalf("envelope metadata not propagated: %+v", got)
	}
	if got.ev.DestinationApp != "chatgpt" || got.ev.Action != schema.DLPActionCoach {
		t.Fatalf("event not propagated: %+v", got.ev)
	}
	if len(got.ev.Findings) != 1 || got.ev.Findings[0].Label != "github_token" {
		t.Fatalf("findings not propagated: %+v", got.ev.Findings)
	}
}

func TestObserveDLP_SkipsMonitorAndBlock(t *testing.T) {
	// Monitor is audit-only; block was already refused at the edge.
	// Neither is a pending human decision, so neither is enqueued.
	for _, action := range []schema.DLPAction{schema.DLPActionMonitor, schema.DLPActionBlock} {
		obs := &fakeDLPObserver{}
		ev := coachEvent()
		ev.Action = action
		observeDLP(context.Background(), obs, env(t, schema.EventClassDLP, ev))
		if len(obs.calls) != 0 {
			t.Fatalf("action %q must not be enqueued: %+v", action, obs.calls)
		}
	}
}

func TestObserveDLP_IgnoresOtherClasses(t *testing.T) {
	obs := &fakeDLPObserver{}
	observeDLP(context.Background(), obs, env(t, schema.EventClassDNS, schema.DNSEvent{
		Query: "slack.com", QType: "A", Verdict: schema.VerdictAllow,
	}))
	if len(obs.calls) != 0 {
		t.Fatalf("non-DLP class should not be observed: %+v", obs.calls)
	}
}

func TestObserveDLP_NilObserverNoPanic(t *testing.T) {
	observeDLP(context.Background(), nil, env(t, schema.EventClassDLP, coachEvent()))
}
