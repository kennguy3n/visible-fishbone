// Package schema defines the typed event envelope and per-class
// payload structs the control plane sends and receives over NATS
// JetStream. Wire format is MessagePack (github.com/vmihailenco/
// msgpack/v5) for compactness — JSON is reserved for the audit
// log and REST APIs where human readability matters.
//
// Every event carries:
//
//   - A common Envelope (schema version, tenant/site/device IDs,
//     EventID for dedup, timestamp, event class, platform).
//   - A typed payload struct matching the EventClass.
//
// To add a new event class:
//
//  1. Add the EventClass constant below.
//  2. Define a new payload struct with msgpack-tagged fields.
//  3. Add a Validate() method.
//  4. Add a round-trip test in envelope_test.go.
package schema

import (
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/vmihailenco/msgpack/v5"
)

// SchemaVersion is the wire-format version of the envelope. Bumped
// when a backwards-incompatible change is made.
const SchemaVersion uint8 = 1

// EventClass enumerates the supported telemetry/event variants.
type EventClass string

const (
	EventClassFlow    EventClass = "flow"
	EventClassDNS     EventClass = "dns"
	EventClassHTTP    EventClass = "http"
	EventClassIPS     EventClass = "ips"
	EventClassZTNA    EventClass = "ztna"
	EventClassSDWAN   EventClass = "sdwan"
	EventClassAgent   EventClass = "agent"
	EventClassPosture EventClass = "posture"
)

// IsValid reports whether c is a known event class.
func (c EventClass) IsValid() bool {
	switch c {
	case EventClassFlow, EventClassDNS, EventClassHTTP,
		EventClassIPS, EventClassZTNA, EventClassSDWAN,
		EventClassAgent, EventClassPosture:
		return true
	}
	return false
}

// Platform enumerates the supported endpoint platforms. Mirrors
// repository.DevicePlatform exactly so the same set crosses the
// wire.
type Platform string

const (
	PlatformWindows Platform = "windows"
	PlatformMacOS   Platform = "macos"
	PlatformLinux   Platform = "linux"
	PlatformIOS     Platform = "ios"
	PlatformAndroid Platform = "android"
)

// IsValid reports whether p is a known platform.
func (p Platform) IsValid() bool {
	switch p {
	case PlatformWindows, PlatformMacOS, PlatformLinux,
		PlatformIOS, PlatformAndroid:
		return true
	}
	return false
}

// Verdict enumerates the disposition the edge / endpoint applied
// to a flow / DNS query / HTTP request / etc. Stable across event
// classes so downstream consumers can filter uniformly.
type Verdict string

const (
	VerdictAllow   Verdict = "allow"
	VerdictDeny    Verdict = "deny"
	VerdictInspect Verdict = "inspect"
	VerdictAlert   Verdict = "alert"
	VerdictLog     Verdict = "log"
)

// IsValid reports whether v is a known verdict.
func (v Verdict) IsValid() bool {
	switch v {
	case VerdictAllow, VerdictDeny, VerdictInspect, VerdictAlert, VerdictLog:
		return true
	}
	return false
}

// Envelope is the common header for every wire-format event.
// Field names use short msgpack tags to keep wire size minimal —
// telemetry channels carry millions of events/sec at scale.
type Envelope struct {
	SchemaVersion uint8      `msgpack:"v"`
	EventID       uuid.UUID  `msgpack:"id"`
	TenantID      uuid.UUID  `msgpack:"tid"`
	DeviceID      uuid.UUID  `msgpack:"did"`
	SiteID        *uuid.UUID `msgpack:"sid,omitempty"`
	Timestamp     time.Time  `msgpack:"ts"`
	EventClass    EventClass `msgpack:"cls"`
	Platform      Platform   `msgpack:"plt"`
	// TrafficClass hoists the per-flow classification decision
	// (see internal/service/appdb) so the telemetry writer can
	// promote it to a ClickHouse column without round-tripping
	// the payload. Optional — legacy producers that pre-date
	// traffic classification omit it; the writer applies the
	// "inspect_full" default (the conservative baseline). Carried
	// on the envelope rather than inside FlowEvent so the same
	// dimension is available for DNS / HTTP / ZTNA events. This
	// is the single source of truth — FlowEvent does NOT carry a
	// parallel field.
	TrafficClass string `msgpack:"tc,omitempty"`
	// BytesIn and BytesOut hoist the per-flow byte counters out
	// of the FlowEvent payload onto the envelope. The telemetry
	// writer promotes these to dedicated ClickHouse columns so
	// per-class byte totals can be SUMmed via column aggregates
	// — the previous implementation tried to JSONExtract them
	// from the MessagePack payload, which always returned zero
	// and silently broke the cost-attribution chart. Non-flow
	// event classes leave these at zero; the omitempty tags keep
	// them off the wire when unused so per-event overhead stays
	// flat. Producers MUST use WrapFlowEvent (below) when wrapping
	// a FlowEvent so the envelope and payload byte counters can
	// never disagree.
	BytesIn  uint64 `msgpack:"bi,omitempty"`
	BytesOut uint64 `msgpack:"bo,omitempty"`
	// Payload is the MessagePack-encoded class-specific payload.
	// Stored as opaque bytes so decoders can sniff EventClass
	// first and dispatch to the right type without round-tripping
	// the whole envelope a second time.
	Payload []byte `msgpack:"pl"`
}

// Validate enforces required-field invariants on the envelope.
// Returns an error wrapping ErrInvalid for any missing or invalid
// field — callers can use errors.Is for branching.
func (e Envelope) Validate() error {
	if e.SchemaVersion == 0 {
		return fmt.Errorf("schema_version is required: %w", ErrInvalid)
	}
	if e.EventID == uuid.Nil {
		return fmt.Errorf("event_id is required: %w", ErrInvalid)
	}
	if e.TenantID == uuid.Nil {
		return fmt.Errorf("tenant_id is required: %w", ErrInvalid)
	}
	if e.DeviceID == uuid.Nil {
		return fmt.Errorf("device_id is required: %w", ErrInvalid)
	}
	if e.Timestamp.IsZero() {
		return fmt.Errorf("timestamp is required: %w", ErrInvalid)
	}
	if !e.EventClass.IsValid() {
		return fmt.Errorf("event_class %q is invalid: %w", e.EventClass, ErrInvalid)
	}
	if !e.Platform.IsValid() {
		return fmt.Errorf("platform %q is invalid: %w", e.Platform, ErrInvalid)
	}
	if len(e.Payload) == 0 {
		return fmt.Errorf("payload is required: %w", ErrInvalid)
	}
	return nil
}

// ErrInvalid is returned by Validate methods. Wrap with %w so
// callers can use errors.Is.
var ErrInvalid = errors.New("schema: invalid event")

// Marshal serializes the envelope to MessagePack bytes.
func Marshal(e Envelope) ([]byte, error) {
	if err := e.Validate(); err != nil {
		return nil, err
	}
	out, err := msgpack.Marshal(&e)
	if err != nil {
		return nil, fmt.Errorf("msgpack marshal envelope: %w", err)
	}
	return out, nil
}

// Unmarshal decodes MessagePack bytes into an Envelope and runs
// Validate. The Payload field remains opaque; the caller must
// decode it using the typed payload helper matching EventClass.
func Unmarshal(b []byte) (Envelope, error) {
	var e Envelope
	if err := msgpack.Unmarshal(b, &e); err != nil {
		return Envelope{}, fmt.Errorf("msgpack unmarshal envelope: %w", err)
	}
	if err := e.Validate(); err != nil {
		return Envelope{}, err
	}
	return e, nil
}

// WrapFlowEvent builds an Envelope around a FlowEvent and copies
// the byte counters and traffic class onto the envelope so the
// telemetry writer can hoist them to dedicated ClickHouse columns
// without round-tripping the payload. Producers should always
// route flow-event envelopes through this helper so envelope and
// payload counters cannot drift.
//
// envMeta supplies the envelope metadata (tenant/device/site/
// timestamp/platform/event-id) and any non-flow envelope fields.
// Its EventClass is overridden to EventClassFlow and its
// TrafficClass argument is preserved (callers pass the per-flow
// classification decision separately from FlowEvent because the
// classification is a transport-layer concern, not flow-payload
// data).
func WrapFlowEvent(envMeta Envelope, trafficClass string, flow FlowEvent) (Envelope, error) {
	payload, err := PackPayload(flow)
	if err != nil {
		return Envelope{}, err
	}
	envMeta.EventClass = EventClassFlow
	envMeta.TrafficClass = trafficClass
	envMeta.BytesIn = flow.BytesIn
	envMeta.BytesOut = flow.BytesOut
	envMeta.Payload = payload
	return envMeta, nil
}

// PackPayload marshals any msgpack-serializable typed payload into
// the opaque bytes the envelope carries.
func PackPayload(payload any) ([]byte, error) {
	b, err := msgpack.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("msgpack marshal payload: %w", err)
	}
	return b, nil
}

// UnpackPayload reverses PackPayload into the supplied typed pointer.
func UnpackPayload(b []byte, dst any) error {
	if err := msgpack.Unmarshal(b, dst); err != nil {
		return fmt.Errorf("msgpack unmarshal payload: %w", err)
	}
	return nil
}
