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

func TestEnvelope_SampleRateRoundTrip(t *testing.T) {
	t.Parallel()
	env := sampleEnvelope(t)
	env.SampleRate = 0.25 // a kept-but-sampled event
	b, err := schema.Marshal(env)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got, err := schema.Unmarshal(b)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.SampleRate != 0.25 {
		t.Errorf("SampleRate round-trip = %v, want 0.25", got.SampleRate)
	}

	// SampleRate == 1.0 is the boundary of the valid (0,1] range and
	// must be accepted (a fully-sampled event explicitly stamped).
	full := sampleEnvelope(t)
	full.SampleRate = 1.0
	if _, err := schema.Marshal(full); err != nil {
		t.Errorf("SampleRate 1.0 should be valid, got %v", err)
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
		"sample > 1":    func(e *schema.Envelope) { e.SampleRate = 1.5 },
		"sample < 0":    func(e *schema.Envelope) { e.SampleRate = -0.1 },
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

// TestZTNAEvent_PostureDetailRoundTrip locks the additive `psd`
// posture-deny-cause field's wire contract against the Rust producer
// at `crates/sng-core/src/events.rs::ZtnaEvent.posture_detail`: it
// rides the short `psd` tag when set, is omitted when empty
// (`omitempty` mirrors the Rust `skip_serializing_if`), and an
// envelope lacking `psd` still decodes to the empty sentinel so a
// rolling deploy across the two languages is safe.
func TestZTNAEvent_PostureDetailRoundTrip(t *testing.T) {
	t.Parallel()

	withDetail := schema.ZTNAEvent{
		DeviceID:      "d1",
		AppID:         "wiki",
		PostureResult: "fail",
		Decision:      "deny",
		Reason:        "device_posture_insufficient",
		PostureDetail: "posture_compromised",
	}
	b, err := msgpack.Marshal(&withDetail)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var raw map[string]any
	if err := msgpack.Unmarshal(b, &raw); err != nil {
		t.Fatalf("unmarshal to map: %v", err)
	}
	if raw["psd"] != "posture_compromised" {
		t.Errorf("posture_detail must ride the psd tag; got map %v", raw)
	}
	// The stable reason bucket is unchanged.
	if raw["rsn"] != "device_posture_insufficient" {
		t.Errorf("reason bucket must stay stable; got map %v", raw)
	}
	var back schema.ZTNAEvent
	if err := msgpack.Unmarshal(b, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back.PostureDetail != "posture_compromised" {
		t.Errorf("posture_detail round trip: got %q", back.PostureDetail)
	}

	// A non-posture decision leaves the field empty → omitted, so
	// existing consumers see no new key.
	empty := schema.ZTNAEvent{
		DeviceID: "d1",
		AppID:    "wiki",
		Decision: "deny",
		Reason:   "mfa_stale",
	}
	eb, err := msgpack.Marshal(&empty)
	if err != nil {
		t.Fatalf("marshal empty: %v", err)
	}
	var rawEmpty map[string]any
	if err := msgpack.Unmarshal(eb, &rawEmpty); err != nil {
		t.Fatalf("unmarshal empty to map: %v", err)
	}
	if _, ok := rawEmpty["psd"]; ok {
		t.Errorf("empty posture_detail must be omitted (omitempty); got map %v", rawEmpty)
	}
}

func TestDLPEvent_Validate(t *testing.T) {
	t.Parallel()
	good := schema.DLPEvent{
		DestinationApp: "chatgpt",
		Action:         schema.DLPActionCoach,
		Severity:       "high",
		Confidence:     0.92,
		Findings: []schema.DLPFinding{
			{Kind: schema.DLPFindingSecret, Label: "github_token", Count: 2, MaxConfidence: 0.99, Severity: "high"},
		},
	}
	if err := good.Validate(); err != nil {
		t.Fatalf("good event rejected: %v", err)
	}
	bad := []schema.DLPEvent{
		{DestinationApp: "", Action: schema.DLPActionCoach, Severity: "high"},
		{DestinationApp: "chatgpt", Action: "nope", Severity: "high"},
		{DestinationApp: "chatgpt", Action: schema.DLPActionCoach, Severity: "extreme"},
		{DestinationApp: "chatgpt", Action: schema.DLPActionCoach, Severity: "high", Confidence: 1.5},
		{DestinationApp: "chatgpt", Action: schema.DLPActionCoach, Severity: "high", Findings: []schema.DLPFinding{
			{Kind: "bogus", Label: "x", Severity: "high"},
		}},
		{DestinationApp: "chatgpt", Action: schema.DLPActionCoach, Severity: "high", Findings: []schema.DLPFinding{
			{Kind: schema.DLPFindingPII, Label: "", Severity: "high"},
		}},
	}
	for i, c := range bad {
		if err := c.Validate(); !errors.Is(err, schema.ErrInvalid) {
			t.Errorf("bad case %d: err = %v", i, err)
		}
	}
}

// TestDLPEvent_RoundTrip locks the redacted DLP signal's wire contract:
// it packs through PackPayload (producer-side Validate), rides the
// short msgpack tags the Rust producer
// (crates/sng-core/src/events.rs::DlpEvent) emits, and the per-class
// finding summaries survive the round-trip with no raw content fields.
func TestDLPEvent_RoundTrip(t *testing.T) {
	t.Parallel()
	ev := schema.DLPEvent{
		DestinationApp: "suspected_ai_app",
		Action:         schema.DLPActionCoach,
		Severity:       "critical",
		Confidence:     0.81,
		Findings: []schema.DLPFinding{
			{Kind: schema.DLPFindingPII, Label: "ssn_us", Count: 3, MaxConfidence: 0.95, Severity: "high"},
			{Kind: schema.DLPFindingConfidential, Label: "confidential", Count: 1, MaxConfidence: 1.0, Severity: "critical"},
		},
		ScannedBytes: 4096,
		Truncated:    true,
	}
	b, err := schema.PackPayload(ev)
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	var raw map[string]any
	if err := msgpack.Unmarshal(b, &raw); err != nil {
		t.Fatalf("unmarshal to map: %v", err)
	}
	for _, k := range []string{"dst", "act", "sev", "cf", "fnd", "sb", "tr"} {
		if _, ok := raw[k]; !ok {
			t.Errorf("expected wire tag %q present; got map keys %v", k, raw)
		}
	}
	var back schema.DLPEvent
	if err := schema.UnpackPayload(b, &back); err != nil {
		t.Fatalf("unpack: %v", err)
	}
	if back.DestinationApp != ev.DestinationApp || back.Action != ev.Action ||
		back.Severity != ev.Severity || back.Confidence != ev.Confidence ||
		len(back.Findings) != 2 || back.ScannedBytes != 4096 || !back.Truncated {
		t.Errorf("round trip mismatch: %+v", back)
	}
	if back.Findings[0].Label != "ssn_us" || back.Findings[1].Kind != schema.DLPFindingConfidential {
		t.Errorf("findings round trip mismatch: %+v", back.Findings)
	}

	// Empty-findings / zero-diagnostic event omits the optional tags so
	// a destination-only signal stays compact on the wire.
	bare := schema.DLPEvent{DestinationApp: "claude", Action: schema.DLPActionMonitor, Severity: "low", Confidence: 0.2}
	bb, err := schema.PackPayload(bare)
	if err != nil {
		t.Fatalf("pack bare: %v", err)
	}
	var rawBare map[string]any
	if err := msgpack.Unmarshal(bb, &rawBare); err != nil {
		t.Fatalf("unmarshal bare: %v", err)
	}
	for _, k := range []string{"fnd", "sb", "tr"} {
		if _, ok := rawBare[k]; ok {
			t.Errorf("optional tag %q must be omitted when empty; got %v", k, rawBare)
		}
	}
}
