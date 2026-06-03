package schema_test

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/vmihailenco/msgpack/v5"

	"github.com/kennguy3n/visible-fishbone/internal/nats/schema"
)

func sampleEnvelope(t *testing.T) schema.Envelope {
	t.Helper()
	env, err := schema.WrapFlowEvent(
		schema.Envelope{
			SchemaVersion: schema.SchemaVersion,
			EventID:       uuid.New(),
			TenantID:      uuid.New(),
			DeviceID:      uuid.New(),
			Timestamp:     time.Now().UTC(),
			Platform:      schema.PlatformLinux,
		},
		"trusted_direct",
		schema.FlowEvent{
			SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
			SrcPort: 1024, DstPort: 443,
			Protocol: "tcp", Verdict: schema.VerdictAllow,
			BytesIn: 1000, BytesOut: 500, DurationMs: 100,
		},
	)
	if err != nil {
		t.Fatalf("wrap flow event: %v", err)
	}
	return env
}

func TestEnvelope_RoundTrip(t *testing.T) {
	t.Parallel()
	env := sampleEnvelope(t)
	b, err := schema.Marshal(env)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got, err := schema.Unmarshal(b)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.EventID != env.EventID || got.TenantID != env.TenantID {
		t.Errorf("ids mismatch")
	}
	if got.EventClass != env.EventClass || got.Platform != env.Platform {
		t.Errorf("enums mismatch")
	}
	if !got.Timestamp.Equal(env.Timestamp) {
		t.Errorf("ts mismatch: got %v, want %v", got.Timestamp, env.Timestamp)
	}
	var fe schema.FlowEvent
	if err := schema.UnpackPayload(got.Payload, &fe); err != nil {
		t.Fatalf("unpack: %v", err)
	}
	if fe.SrcIP != "10.0.0.1" || fe.Verdict != schema.VerdictAllow {
		t.Errorf("payload mismatch: %+v", fe)
	}
}

func TestEnvelope_ValidateRejects(t *testing.T) {
	t.Parallel()
	base := sampleEnvelope(t)
	mutations := map[string]func(*schema.Envelope){
		"zero schema":   func(e *schema.Envelope) { e.SchemaVersion = 0 },
		"zero event_id": func(e *schema.Envelope) { e.EventID = uuid.Nil },
		"zero tenant":   func(e *schema.Envelope) { e.TenantID = uuid.Nil },
		"zero device":   func(e *schema.Envelope) { e.DeviceID = uuid.Nil },
		"zero ts":       func(e *schema.Envelope) { e.Timestamp = time.Time{} },
		"bad class":     func(e *schema.Envelope) { e.EventClass = "bogus" },
		"bad platform":  func(e *schema.Envelope) { e.Platform = "bogus" },
		"bad tc":        func(e *schema.Envelope) { e.TrafficClass = "bogus" },
		"empty payload": func(e *schema.Envelope) { e.Payload = nil },
	}
	for name, mutate := range mutations {
		e := base
		mutate(&e)
		_, err := schema.Marshal(e)
		if !errors.Is(err, schema.ErrInvalid) {
			t.Errorf("%s: err = %v, want ErrInvalid", name, err)
		}
	}
}

func TestFlowEvent_Validate(t *testing.T) {
	t.Parallel()
	cases := []schema.FlowEvent{
		{SrcIP: "bad", DstIP: "10.0.0.1", Protocol: "tcp", Verdict: schema.VerdictAllow},
		{SrcIP: "10.0.0.1", DstIP: "bad", Protocol: "tcp", Verdict: schema.VerdictAllow},
		{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", Protocol: "", Verdict: schema.VerdictAllow},
		{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", Protocol: "tcp", Verdict: "bogus"},
	}
	for i, c := range cases {
		if err := c.Validate(); !errors.Is(err, schema.ErrInvalid) {
			t.Errorf("case %d: err = %v", i, err)
		}
	}
	good := schema.FlowEvent{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", Protocol: "tcp", Verdict: schema.VerdictAllow}
	if err := good.Validate(); err != nil {
		t.Errorf("good: %v", err)
	}
}

func TestDNSEvent_Validate(t *testing.T) {
	t.Parallel()
	bad := []schema.DNSEvent{
		{Query: "", QType: "A", Verdict: schema.VerdictAllow},
		{Query: "x", QType: "", Verdict: schema.VerdictAllow},
		{Query: "x", QType: "A", Verdict: "?"},
	}
	for i, c := range bad {
		if err := c.Validate(); !errors.Is(err, schema.ErrInvalid) {
			t.Errorf("case %d: err = %v", i, err)
		}
	}
	if err := (schema.DNSEvent{Query: "x", QType: "A", Verdict: schema.VerdictAllow}.Validate()); err != nil {
		t.Errorf("good: %v", err)
	}
}

func TestHTTPEvent_Validate(t *testing.T) {
	t.Parallel()
	bad := []schema.HTTPEvent{
		{Method: "", Host: "h", Verdict: schema.VerdictAllow},
		{Method: "GET", Host: "", Verdict: schema.VerdictAllow},
		{Method: "GET", Host: "h", Verdict: ""},
	}
	for i, c := range bad {
		if err := c.Validate(); !errors.Is(err, schema.ErrInvalid) {
			t.Errorf("case %d: err = %v", i, err)
		}
	}
	if err := (schema.HTTPEvent{Method: "GET", Host: "h", Verdict: schema.VerdictAllow}.Validate()); err != nil {
		t.Errorf("good: %v", err)
	}
}

func TestIPSEvent_Validate(t *testing.T) {
	t.Parallel()
	bad := []schema.IPSEvent{
		{RuleID: "", Severity: "high", Action: "block"},
		{RuleID: "r", Severity: "", Action: "block"},
		{RuleID: "r", Severity: "high", Action: ""},
	}
	for i, c := range bad {
		if err := c.Validate(); !errors.Is(err, schema.ErrInvalid) {
			t.Errorf("case %d: err = %v", i, err)
		}
	}
}

func TestZTNAEvent_Validate(t *testing.T) {
	t.Parallel()
	bad := []schema.ZTNAEvent{
		{AppID: "", Decision: "allow", Reason: "allow"},
		{AppID: "app", Decision: "", Reason: "allow"},
		// Reason is required: mirrors the Rust-side ZtnaDecisionReason
		// wire contract — without it, dashboards bucketing denies by
		// cause would collapse distinct structural failures into a
		// single bucket, defeating the purpose of the field.
		{AppID: "app", Decision: "deny", Reason: ""},
	}
	for i, c := range bad {
		if err := c.Validate(); !errors.Is(err, schema.ErrInvalid) {
			t.Errorf("case %d: err = %v", i, err)
		}
	}
	good := schema.ZTNAEvent{AppID: "app", Decision: "allow", Reason: "allow"}
	if err := good.Validate(); err != nil {
		t.Errorf("good: %v", err)
	}
}

// TestZTNAEvent_IsLegacy pins the consumer-side helper for detecting
// pre-PR-30 envelopes. Empty `Reason` is a valid wire shape during a
// rolling deploy (the Rust-side `#[serde(default)]` decodes a missing
// `rsn` key to `""`), so dashboards bucketing by `Reason` need a
// canonical way to identify legacy envelopes and fall back to the
// binary `Decision` field. Without this helper, consumers would have
// to inline a magic empty-string check at every callsite.
func TestZTNAEvent_IsLegacy(t *testing.T) {
	t.Parallel()
	legacy := schema.ZTNAEvent{AppID: "app", Decision: "allow", Reason: ""}
	if !legacy.IsLegacy() {
		t.Errorf("empty Reason must be reported as legacy")
	}
	current := schema.ZTNAEvent{AppID: "app", Decision: "allow", Reason: "allow"}
	if current.IsLegacy() {
		t.Errorf("populated Reason must NOT be reported as legacy")
	}
	// Even a deny-bucket label should be reported as non-legacy.
	deny := schema.ZTNAEvent{AppID: "app", Decision: "deny", Reason: "mfa_stale"}
	if deny.IsLegacy() {
		t.Errorf("populated Reason on a deny must NOT be reported as legacy")
	}
}

func TestSDWANEvent_Validate(t *testing.T) {
	t.Parallel()
	if err := (schema.SDWANEvent{PathID: ""}.Validate()); !errors.Is(err, schema.ErrInvalid) {
		t.Errorf("empty path_id: err = %v", err)
	}
	if err := (schema.SDWANEvent{PathID: "p"}.Validate()); err != nil {
		t.Errorf("good: %v", err)
	}
}

func TestAgentEvent_Validate(t *testing.T) {
	t.Parallel()
	bad := []schema.AgentEvent{
		{EventType: "", Platform: schema.PlatformLinux},
		{EventType: "started", Platform: "bogus"},
	}
	for i, c := range bad {
		if err := c.Validate(); !errors.Is(err, schema.ErrInvalid) {
			t.Errorf("case %d: err = %v", i, err)
		}
	}
}

// TestAgentEvent_ReasonRoundTrip locks the dedicated `rsn` diagnostic
// field's wire contract: it carries the reason under the short tag when
// set (matching the Rust `crates/sng-core/src/events.rs::AgentEvent.reason`),
// is omitted when empty so legacy consumers see no spurious key, and a
// payload lacking `rsn` still decodes (the empty "unspecified" sentinel).
func TestAgentEvent_ReasonRoundTrip(t *testing.T) {
	t.Parallel()

	withReason := schema.AgentEvent{
		DeviceID:  "d1",
		EventType: "tunnel_down",
		Reason:    "idle",
		Platform:  schema.PlatformAndroid,
	}
	b, err := msgpack.Marshal(&withReason)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var raw map[string]any
	if err := msgpack.Unmarshal(b, &raw); err != nil {
		t.Fatalf("unmarshal to map: %v", err)
	}
	if raw["rsn"] != "idle" {
		t.Errorf("reason must ride the rsn tag; got map %v", raw)
	}
	var back schema.AgentEvent
	if err := msgpack.Unmarshal(b, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back.Reason != "idle" {
		t.Errorf("reason round trip: got %q", back.Reason)
	}

	empty := schema.AgentEvent{
		DeviceID:  "d1",
		EventType: "tunnel_up",
		Platform:  schema.PlatformIOS,
	}
	eb, err := msgpack.Marshal(&empty)
	if err != nil {
		t.Fatalf("marshal empty: %v", err)
	}
	var rawEmpty map[string]any
	if err := msgpack.Unmarshal(eb, &rawEmpty); err != nil {
		t.Fatalf("unmarshal empty to map: %v", err)
	}
	if _, ok := rawEmpty["rsn"]; ok {
		t.Errorf("empty reason must be omitted (omitempty); got map %v", rawEmpty)
	}
}
