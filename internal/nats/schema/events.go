package schema

import (
	"encoding/json"
	"fmt"
	"net"
)

// FlowEvent is a per-flow telemetry record (5-tuple + verdict +
// counters). One of the highest-volume event classes — fields are
// chosen to fit a typical observation in <200 bytes wire size.
//
// Note: the per-flow traffic-classification decision lives on the
// parent Envelope (`Envelope.TrafficClass`), not here. Classification
// is a transport-layer / routing concern shared with DNS / HTTP /
// ZTNA events, so keeping it on the envelope gives a single source
// of truth and avoids the drift risk of two parallel fields with
// the same msgpack tag at different nesting levels.
type FlowEvent struct {
	SrcIP      string  `msgpack:"sip"`
	DstIP      string  `msgpack:"dip"`
	SrcPort    uint16  `msgpack:"spt"`
	DstPort    uint16  `msgpack:"dpt"`
	Protocol   string  `msgpack:"prt"` // tcp|udp|icmp|other
	AppID      string  `msgpack:"app,omitempty"`
	Verdict    Verdict `msgpack:"vd"`
	Score      float32 `msgpack:"sc,omitempty"`
	BytesIn    uint64  `msgpack:"bi"`
	BytesOut   uint64  `msgpack:"bo"`
	DurationMs uint32  `msgpack:"dur"`
}

// Validate enforces required-field invariants for FlowEvent.
func (f FlowEvent) Validate() error {
	if net.ParseIP(f.SrcIP) == nil {
		return fmt.Errorf("flow.src_ip %q invalid: %w", f.SrcIP, ErrInvalid)
	}
	if net.ParseIP(f.DstIP) == nil {
		return fmt.Errorf("flow.dst_ip %q invalid: %w", f.DstIP, ErrInvalid)
	}
	if f.Protocol == "" {
		return fmt.Errorf("flow.protocol is required: %w", ErrInvalid)
	}
	if !f.Verdict.IsValid() {
		return fmt.Errorf("flow.verdict %q invalid: %w", f.Verdict, ErrInvalid)
	}
	return nil
}

// DNSEvent is a per-query DNS telemetry record.
type DNSEvent struct {
	Query        string  `msgpack:"q"`
	QType        string  `msgpack:"qt"` // A|AAAA|CNAME|TXT|MX|SRV|NS|PTR|SOA|...
	ResponseCode string  `msgpack:"rc"` // NOERROR|NXDOMAIN|SERVFAIL|REFUSED|...
	Verdict      Verdict `msgpack:"vd"`
	LatencyMs    uint32  `msgpack:"lat"`
	Upstream     string  `msgpack:"up,omitempty"`
}

// Validate enforces required-field invariants for DNSEvent.
func (d DNSEvent) Validate() error {
	if d.Query == "" {
		return fmt.Errorf("dns.query is required: %w", ErrInvalid)
	}
	if d.QType == "" {
		return fmt.Errorf("dns.qtype is required: %w", ErrInvalid)
	}
	if !d.Verdict.IsValid() {
		return fmt.Errorf("dns.verdict %q invalid: %w", d.Verdict, ErrInvalid)
	}
	return nil
}

// HTTPEvent is a per-request HTTP/S telemetry record.
type HTTPEvent struct {
	Method      string  `msgpack:"m"`
	URL         string  `msgpack:"u"`
	Host        string  `msgpack:"h"`
	StatusCode  uint16  `msgpack:"sc"`
	Verdict     Verdict `msgpack:"vd"`
	TLSVersion  string  `msgpack:"tlv,omitempty"`
	SNI         string  `msgpack:"sni,omitempty"`
	ContentType string  `msgpack:"ct,omitempty"`
	Bytes       uint64  `msgpack:"b,omitempty"`
}

// Validate enforces required-field invariants for HTTPEvent.
func (h HTTPEvent) Validate() error {
	if h.Method == "" {
		return fmt.Errorf("http.method is required: %w", ErrInvalid)
	}
	if h.Host == "" {
		return fmt.Errorf("http.host is required: %w", ErrInvalid)
	}
	if !h.Verdict.IsValid() {
		return fmt.Errorf("http.verdict %q invalid: %w", h.Verdict, ErrInvalid)
	}
	return nil
}

// IPSEvent is an intrusion-prevention rule hit.
type IPSEvent struct {
	RuleID    string `msgpack:"rid"`
	Signature string `msgpack:"sig"`
	Severity  string `msgpack:"sev"` // info|low|medium|high|critical
	Action    string `msgpack:"act"` // alert|block|drop|reset
	SrcIP     string `msgpack:"sip"`
	DstIP     string `msgpack:"dip"`
	Protocol  string `msgpack:"prt"`
}

// Validate enforces required-field invariants for IPSEvent.
func (i IPSEvent) Validate() error {
	if i.RuleID == "" {
		return fmt.Errorf("ips.rule_id is required: %w", ErrInvalid)
	}
	if i.Severity == "" {
		return fmt.Errorf("ips.severity is required: %w", ErrInvalid)
	}
	if i.Action == "" {
		return fmt.Errorf("ips.action is required: %w", ErrInvalid)
	}
	return nil
}

// ZTNAEvent is a Zero-Trust Network Access decision record.
//
// The `Reason` field carries the structured, stable wire string for
// the deny / allow bucket (e.g. "mfa_stale", "device_posture_insufficient",
// "tenant_mismatch", "allow") so dashboards can break decisions down by
// cause without parsing a free-form message. It mirrors the Rust-side
// `sng_ztna::policy::ZtnaDecisionReason::as_str()` field-for-field and
// participates in the dedup fingerprint at
// `crates/sng-telemetry/src/dedup.rs::hash_ztna` — without it, two denies
// on the same (device, app) for different structural causes would collapse
// to a single wire event.
//
// # Producer / consumer wire-contract asymmetry
//
// The Rust-side counterpart at `crates/sng-core/src/events.rs::ZtnaEvent.reason`
// carries `#[serde(default)]` so a consumer decoding an envelope from a
// pre-PR-30 producer (one that doesn't yet emit `rsn`) decodes the field
// to the empty string instead of failing the whole envelope. This Go
// struct's `Reason` field decodes the same way: msgpack's default for
// `string` is `""`, and `UnpackPayload` does not call `Validate`.
//
// The `Validate` method below is a *producer-side* contract — it
// catches malformed events at the source (e.g. a control-plane emitter
// constructing a `ZTNAEvent` with an unset `Reason`). Consumers must
// NOT call `Validate` on inbound payloads from a legacy producer: an
// empty `Reason` is a valid wire shape for cross-version rolling
// deploys, and the binary `Decision` field is the source of truth for
// the allow/deny rollup. See the `IsLegacy` helper for the canonical
// way to detect a pre-PR-30 envelope on the consumer side.
type ZTNAEvent struct {
	DeviceID         string `msgpack:"did"`
	AppID            string `msgpack:"app"`
	PostureResult    string `msgpack:"pst"` // pass|fail
	Decision         string `msgpack:"dec"` // allow|deny
	Reason           string `msgpack:"rsn"` // detailed structured reason; see ZtnaDecisionReason in sng-ztna
	IdentityVerified bool   `msgpack:"iv"`
}

// IsLegacy reports whether this envelope was emitted by a pre-PR-30
// producer that didn't yet ship the `Reason` field. Dashboards that
// bucket by `Reason` should treat the empty string as a "legacy"
// sentinel and fall back to the binary `Decision` for the allow/deny
// rollup. See the `ZTNAEvent` doc comment for the full wire-contract
// asymmetry rationale.
func (z ZTNAEvent) IsLegacy() bool {
	return z.Reason == ""
}

// Validate enforces required-field invariants for ZTNAEvent on the
// *producer* side. It must NOT be called on inbound payloads from
// legacy producers — empty `Reason` is a valid wire shape during
// rolling deploys (see the `ZTNAEvent` doc comment and the Rust-side
// `#[serde(default)]` at `crates/sng-core/src/events.rs::ZtnaEvent.reason`).
// Use `IsLegacy` instead for consumer-side handling of pre-PR-30
// envelopes.
func (z ZTNAEvent) Validate() error {
	if z.AppID == "" {
		return fmt.Errorf("ztna.app_id is required: %w", ErrInvalid)
	}
	if z.Decision == "" {
		return fmt.Errorf("ztna.decision is required: %w", ErrInvalid)
	}
	if z.Reason == "" {
		return fmt.Errorf("ztna.reason is required: %w", ErrInvalid)
	}
	return nil
}

// SDWANEvent is a software-defined WAN steering decision +
// path-quality snapshot.
type SDWANEvent struct {
	PathID           string  `msgpack:"pid"`
	LatencyMs        float32 `msgpack:"lat"`
	LossPct          float32 `msgpack:"loss"`
	JitterMs         float32 `msgpack:"jit"`
	Score            float32 `msgpack:"sc"`
	SteeringDecision string  `msgpack:"sd"`
}

// Validate enforces required-field invariants for SDWANEvent.
func (s SDWANEvent) Validate() error {
	if s.PathID == "" {
		return fmt.Errorf("sdwan.path_id is required: %w", ErrInvalid)
	}
	return nil
}

// AgentEvent is an endpoint agent lifecycle / posture record.
type AgentEvent struct {
	DeviceID        string          `msgpack:"did"`
	EventType       string          `msgpack:"et"` // started|stopped|posture|error
	PostureSnapshot json.RawMessage `msgpack:"pst,omitempty"`
	Platform        Platform        `msgpack:"plt"`
}

// Validate enforces required-field invariants for AgentEvent.
func (a AgentEvent) Validate() error {
	if a.EventType == "" {
		return fmt.Errorf("agent.event_type is required: %w", ErrInvalid)
	}
	if !a.Platform.IsValid() {
		return fmt.Errorf("agent.platform %q invalid: %w", a.Platform, ErrInvalid)
	}
	return nil
}
