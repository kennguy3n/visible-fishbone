package telemetry

import (
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/nats/schema"
)

type capturedActivity struct {
	tenant uuid.UUID
	seen   time.Time
}

type fakeActivityObserver struct{ calls []capturedActivity }

func (f *fakeActivityObserver) Observe(tenantID uuid.UUID, seen time.Time) {
	f.calls = append(f.calls, capturedActivity{tenantID, seen})
}

func TestObserveActivity_ReportsTenantAndTimestamp(t *testing.T) {
	obs := &fakeActivityObserver{}
	e := env(t, schema.EventClassDNS, schema.DNSEvent{
		Query: "acme.slack.com", QType: "A", Verdict: schema.VerdictAllow,
	})
	observeActivity(obs, e)
	if len(obs.calls) != 1 {
		t.Fatalf("expected 1 observe, got %+v", obs.calls)
	}
	if obs.calls[0].tenant != e.TenantID || !obs.calls[0].seen.Equal(e.Timestamp) {
		t.Fatalf("tenant/timestamp not propagated: %+v want %v@%v", obs.calls[0], e.TenantID, e.Timestamp)
	}
}

func TestObserveActivity_AnyEventClass(t *testing.T) {
	// Unlike shadow-IT, a Flow event (not DNS/HTTP) still marks the
	// tenant active — any durably-written event is activity.
	obs := &fakeActivityObserver{}
	observeActivity(obs, env(t, schema.EventClassFlow, schema.FlowEvent{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2", Protocol: "tcp", Verdict: schema.VerdictAllow,
	}))
	if len(obs.calls) != 1 {
		t.Fatalf("flow event should still record activity: %+v", obs.calls)
	}
}

func TestObserveActivity_NilObserverNoPanic(t *testing.T) {
	observeActivity(nil, env(t, schema.EventClassDNS, schema.DNSEvent{
		Query: "slack.com", QType: "A", Verdict: schema.VerdictAllow,
	}))
}

func TestObserveActivity_NilTenantSkipped(t *testing.T) {
	obs := &fakeActivityObserver{}
	e := env(t, schema.EventClassDNS, schema.DNSEvent{
		Query: "slack.com", QType: "A", Verdict: schema.VerdictAllow,
	})
	e.TenantID = uuid.Nil
	observeActivity(obs, e)
	if len(obs.calls) != 0 {
		t.Fatalf("nil tenant should be skipped: %+v", obs.calls)
	}
}
