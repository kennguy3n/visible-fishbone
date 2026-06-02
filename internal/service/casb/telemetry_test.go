package casb_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/service/casb"
)

type stubPublisher struct {
	events []publishedEvent
}

type publishedEvent struct {
	subject string
	data    []byte
}

func (s *stubPublisher) Publish(_ context.Context, subject string, data []byte) error {
	s.events = append(s.events, publishedEvent{subject: subject, data: data})
	return nil
}

func TestTelemetryEmitter_CASBSync(t *testing.T) {
	t.Parallel()
	pub := &stubPublisher{}
	emitter := casb.NewTelemetryEmitter(pub, "sng", nil)
	tid := uuid.New()

	err := emitter.EmitCASBSync(context.Background(), tid, json.RawMessage(`{"app":"slack"}`))
	if err != nil {
		t.Fatalf("emit: %v", err)
	}
	if len(pub.events) != 1 {
		t.Fatalf("events = %d, want 1", len(pub.events))
	}
	expected := "sng." + tid.String() + ".telemetry.casb"
	if pub.events[0].subject != expected {
		t.Fatalf("subject = %q, want %q", pub.events[0].subject, expected)
	}
}

func TestTelemetryEmitter_DLPMatch(t *testing.T) {
	t.Parallel()
	pub := &stubPublisher{}
	emitter := casb.NewTelemetryEmitter(pub, "sng", nil)
	tid := uuid.New()

	err := emitter.EmitDLPMatch(context.Background(), tid, json.RawMessage(`{"policy":"ssn"}`))
	if err != nil {
		t.Fatalf("emit: %v", err)
	}
	expected := "sng." + tid.String() + ".telemetry.dlp"
	if pub.events[0].subject != expected {
		t.Fatalf("subject = %q, want %q", pub.events[0].subject, expected)
	}
}

func TestTelemetryEmitter_Posture(t *testing.T) {
	t.Parallel()
	pub := &stubPublisher{}
	emitter := casb.NewTelemetryEmitter(pub, "sng", nil)
	tid := uuid.New()

	err := emitter.EmitPosture(context.Background(), tid, json.RawMessage(`{"score":42}`))
	if err != nil {
		t.Fatalf("emit: %v", err)
	}
	expected := "sng." + tid.String() + ".telemetry.posture"
	if pub.events[0].subject != expected {
		t.Fatalf("subject = %q, want %q", pub.events[0].subject, expected)
	}
}

func TestTelemetryEmitter_NilPublisher(t *testing.T) {
	t.Parallel()
	emitter := casb.NewTelemetryEmitter(nil, "sng", nil)
	if err := emitter.EmitCASBSync(context.Background(), uuid.New(), json.RawMessage(`{}`)); err != nil {
		t.Fatalf("nil publisher should not error: %v", err)
	}
}

func TestTelemetryEmitter_EventPayload(t *testing.T) {
	t.Parallel()
	pub := &stubPublisher{}
	emitter := casb.NewTelemetryEmitter(pub, "sng", nil)

	_ = emitter.EmitCASBSync(context.Background(), uuid.New(), json.RawMessage(`{"test":true}`))

	var ev casb.TelemetryEvent
	if err := json.Unmarshal(pub.events[0].data, &ev); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if ev.EventType != casb.TelemetryEventCASBSync {
		t.Fatalf("event_type = %q, want %q", ev.EventType, casb.TelemetryEventCASBSync)
	}
	if ev.TrafficClass != "inspect_full" {
		t.Fatalf("traffic_class = %q, want inspect_full", ev.TrafficClass)
	}
}
