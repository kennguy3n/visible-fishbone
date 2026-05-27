package schema

import (
	"encoding/json"
	"fmt"
	"net"
)

// FlowEvent is a per-flow telemetry record (5-tuple + verdict +
// counters). One of the highest-volume event classes — fields are
// chosen to fit a typical observation in <200 bytes wire size.
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
type ZTNAEvent struct {
	DeviceID         string `msgpack:"did"`
	AppID            string `msgpack:"app"`
	PostureResult    string `msgpack:"pst"` // pass|fail
	Decision         string `msgpack:"dec"` // allow|deny
	IdentityVerified bool   `msgpack:"iv"`
}

// Validate enforces required-field invariants for ZTNAEvent.
func (z ZTNAEvent) Validate() error {
	if z.AppID == "" {
		return fmt.Errorf("ztna.app_id is required: %w", ErrInvalid)
	}
	if z.Decision == "" {
		return fmt.Errorf("ztna.decision is required: %w", ErrInvalid)
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
