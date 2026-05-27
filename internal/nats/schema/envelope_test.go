package schema_test

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/nats/schema"
)

func sampleEnvelope(t *testing.T) schema.Envelope {
	t.Helper()
	payload, err := schema.PackPayload(schema.FlowEvent{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 1024, DstPort: 443,
		Protocol: "tcp", Verdict: schema.VerdictAllow,
		BytesIn: 1000, BytesOut: 500, DurationMs: 100,
	})
	if err != nil {
		t.Fatalf("pack payload: %v", err)
	}
	return schema.Envelope{
		SchemaVersion: schema.SchemaVersion,
		EventID:       uuid.New(),
		TenantID:      uuid.New(),
		DeviceID:      uuid.New(),
		Timestamp:     time.Now().UTC(),
		EventClass:    schema.EventClassFlow,
		Platform:      schema.PlatformLinux,
		Payload:       payload,
	}
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
		{AppID: "", Decision: "allow"},
		{AppID: "app", Decision: ""},
	}
	for i, c := range bad {
		if err := c.Validate(); !errors.Is(err, schema.ErrInvalid) {
			t.Errorf("case %d: err = %v", i, err)
		}
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
