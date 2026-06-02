// Package casb — telemetry.go wires CASB, DLP, and posture
// assessment events into the existing NATS telemetry pipeline
// (Phase 4, Task 45).
//
// Subject conventions:
//   - CASB sync events → sng.<tenant>.telemetry.casb
//   - DLP match events → sng.<tenant>.telemetry.dlp
//   - Posture assessment events → sng.<tenant>.telemetry.posture
//
// All events carry a traffic_class dimension so ClickHouse can
// route them into the per-class aggregation buckets.
package casb

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
)

// TelemetryPublisher is the interface used by the telemetry
// emitter to publish events on NATS subjects. Satisfied by
// *nats.Publisher.
type TelemetryPublisher interface {
	Publish(ctx context.Context, subject string, data []byte) error
}

// TelemetryEventType enumerates the CASB/DLP event kinds.
type TelemetryEventType string

const (
	TelemetryEventCASBSync TelemetryEventType = "casb_sync"
	TelemetryEventDLPMatch TelemetryEventType = "dlp_match"
	TelemetryEventPosture  TelemetryEventType = "posture_assessment"
)

// TelemetryEvent is a CASB/DLP/posture event envelope published
// to NATS.
type TelemetryEvent struct {
	EventID      uuid.UUID          `json:"event_id"`
	TenantID     uuid.UUID          `json:"tenant_id"`
	EventType    TelemetryEventType `json:"event_type"`
	TrafficClass string             `json:"traffic_class"`
	Timestamp    time.Time          `json:"timestamp"`
	Payload      json.RawMessage    `json:"payload"`
}

// TelemetryEmitter publishes CASB/DLP/posture events to NATS.
type TelemetryEmitter struct {
	pub           TelemetryPublisher
	subjectPrefix string
	logger        *slog.Logger
}

// NewTelemetryEmitter returns a ready-to-use emitter.
// `subjectPrefix` defaults to "sng" when empty.
func NewTelemetryEmitter(pub TelemetryPublisher, subjectPrefix string, logger *slog.Logger) *TelemetryEmitter {
	if logger == nil {
		logger = slog.Default()
	}
	if subjectPrefix == "" {
		subjectPrefix = "sng"
	}
	return &TelemetryEmitter{pub: pub, subjectPrefix: subjectPrefix, logger: logger}
}

// EmitCASBSync publishes a CASB sync telemetry event.
func (e *TelemetryEmitter) EmitCASBSync(ctx context.Context, tenantID uuid.UUID, payload json.RawMessage) error {
	return e.emit(ctx, tenantID, TelemetryEventCASBSync, "telemetry.casb", payload)
}

// EmitDLPMatch publishes a DLP match telemetry event.
func (e *TelemetryEmitter) EmitDLPMatch(ctx context.Context, tenantID uuid.UUID, payload json.RawMessage) error {
	return e.emit(ctx, tenantID, TelemetryEventDLPMatch, "telemetry.dlp", payload)
}

// EmitPosture publishes a posture assessment telemetry event.
func (e *TelemetryEmitter) EmitPosture(ctx context.Context, tenantID uuid.UUID, payload json.RawMessage) error {
	return e.emit(ctx, tenantID, TelemetryEventPosture, "telemetry.posture", payload)
}

func (e *TelemetryEmitter) emit(ctx context.Context, tenantID uuid.UUID, eventType TelemetryEventType, suffix string, payload json.RawMessage) error {
	if e.pub == nil {
		return nil
	}
	ev := TelemetryEvent{
		EventID:      uuid.New(),
		TenantID:     tenantID,
		EventType:    eventType,
		TrafficClass: "inspect_full",
		Timestamp:    time.Now().UTC(),
		Payload:      payload,
	}
	data, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("marshal telemetry event: %w", err)
	}
	subject := fmt.Sprintf("%s.%s.%s", e.subjectPrefix, tenantID.String(), suffix)
	if err := e.pub.Publish(ctx, subject, data); err != nil {
		e.logger.Error("casb telemetry publish failed", "subject", subject, "err", err)
		return err
	}
	return nil
}
