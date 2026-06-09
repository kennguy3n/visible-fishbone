package telemetry

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/vmihailenco/msgpack/v5"

	"github.com/kennguy3n/visible-fishbone/internal/nats/schema"
)

type capturedHost struct {
	tenant, device uuid.UUID
	host           string
	ts             time.Time
}

type fakeShadowObserver struct{ calls []capturedHost }

func (f *fakeShadowObserver) ObserveHost(tenantID, deviceID uuid.UUID, host string, ts time.Time) {
	f.calls = append(f.calls, capturedHost{tenantID, deviceID, host, ts})
}

func env(t *testing.T, cls schema.EventClass, payload schema.Payload) schema.Envelope {
	t.Helper()
	pl, err := schema.PackPayload(payload)
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	return schema.Envelope{
		SchemaVersion: schema.SchemaVersion, EventID: uuid.New(),
		TenantID: uuid.New(), DeviceID: uuid.New(),
		Timestamp: time.Unix(1700000000, 0).UTC(), EventClass: cls,
		Platform: schema.PlatformLinux, Payload: pl,
	}
}

func TestObserveShadowIT_DNS(t *testing.T) {
	obs := &fakeShadowObserver{}
	e := env(t, schema.EventClassDNS, schema.DNSEvent{
		Query: "acme.slack.com", QType: "A", Verdict: schema.VerdictAllow,
	})
	observeShadowIT(obs, e)
	if len(obs.calls) != 1 || obs.calls[0].host != "acme.slack.com" {
		t.Fatalf("unexpected calls: %+v", obs.calls)
	}
	if obs.calls[0].tenant != e.TenantID || !obs.calls[0].ts.Equal(e.Timestamp) {
		t.Fatalf("envelope metadata not propagated: %+v", obs.calls[0])
	}
}

func TestObserveShadowIT_HTTPHostThenSNI(t *testing.T) {
	// Host present → Host wins over SNI.
	obs := &fakeShadowObserver{}
	observeShadowIT(obs, env(t, schema.EventClassHTTP, schema.HTTPEvent{
		Method: "GET", Host: "files.box.com", SNI: "ignored.example.com", Verdict: schema.VerdictAllow,
	}))
	if len(obs.calls) != 1 || obs.calls[0].host != "files.box.com" {
		t.Fatalf("Host should win: %+v", obs.calls)
	}

	// Host empty → fall back to the TLS SNI. An empty Host fails
	// HTTPEvent.Validate (producer-side), but the consumer decode
	// path is UnpackPayload, which does not validate — so simulate
	// the wire bytes directly to exercise the SNI fallback.
	rawPayload, err := msgpack.Marshal(schema.HTTPEvent{
		Method: "CONNECT", Host: "", SNI: "github.com", Verdict: schema.VerdictInspect,
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	obs2 := &fakeShadowObserver{}
	observeShadowIT(obs2, schema.Envelope{
		SchemaVersion: schema.SchemaVersion, EventID: uuid.New(),
		TenantID: uuid.New(), DeviceID: uuid.New(),
		Timestamp: time.Unix(1700000000, 0).UTC(), EventClass: schema.EventClassHTTP,
		Platform: schema.PlatformLinux, Payload: rawPayload,
	})
	if len(obs2.calls) != 1 || obs2.calls[0].host != "github.com" {
		t.Fatalf("SNI fallback failed: %+v", obs2.calls)
	}
}

func TestObserveShadowIT_IgnoresOtherClasses(t *testing.T) {
	obs := &fakeShadowObserver{}
	observeShadowIT(obs, env(t, schema.EventClassFlow, schema.FlowEvent{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2", Protocol: "tcp", Verdict: schema.VerdictAllow,
	}))
	if len(obs.calls) != 0 {
		t.Fatalf("flow event should not be observed: %+v", obs.calls)
	}
}

func TestObserveShadowIT_NilObserverNoPanic(t *testing.T) {
	observeShadowIT(nil, env(t, schema.EventClassDNS, schema.DNSEvent{
		Query: "slack.com", QType: "A", Verdict: schema.VerdictAllow,
	}))
}
