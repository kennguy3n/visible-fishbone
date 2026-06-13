package ai

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// MISPParser parses a MISP (Malware Information Sharing Platform)
// JSON export into IOCs. MISP is the dominant open-source
// intel-sharing format among national CERTs, ISACs and
// sector-sharing communities, and its event/attribute layout is
// not something the generic JSONParser can read: indicators are
// MISP "attributes" nested inside events (and inside MISP
// "objects" within those events), keyed by MISP-specific attribute
// types (`ip-dst`, `domain|ip`, `filename|sha256`, …) rather than
// the flat `{indicator,type}` shape JSONParser expects, and each
// attribute carries a `to_ids` flag that marks whether it is meant
// for automated detection/blocking.
//
// The parser accepts the wire shapes the common MISP endpoints
// return, sniffed from the payload rather than configured:
//
//   - the events REST-search envelope `{"response":[{"Event":…}]}`,
//   - the attributes REST-search envelope
//     `{"response":{"Attribute":[…]}}`,
//   - a single event download `{"Event":{…}}`,
//   - a bare array of event envelopes `[{"Event":…}]`.
//
// Each attribute's type is decomposed into one IOC per recognised
// scalar component (so a `domain|ip` attribute yields both a domain
// and an IP IOC, and a `filename|sha256` attribute yields the hash
// and drops the filename), then normalized through NewIOC — the
// same canonicalisation/validation every other feed uses — so a
// malformed attribute is skipped, never fatal to the batch.
//
// MISP attributes carry no per-indicator confidence, so every IOC
// gets DefaultConfidence (matching the OTX parser); event-level
// attribution (the event `info`, and a threat-actor lifted from the
// event's MISP-galaxy clusters or tags) is carried onto each IOC.
type MISPParser struct {
	// Source labels produced IOCs; defaults to "misp".
	Source string
	// DefaultConfidence is applied to every produced IOC (MISP
	// exposes no per-attribute confidence). A zero here means the
	// indicators carry confidence 0 and are dropped by any
	// non-zero store/feed floor.
	DefaultConfidence float64
	// IncludeNonIDs controls whether attributes NOT flagged
	// `to_ids` are ingested. The zero value (false) is the precise
	// default: only attributes explicitly marked `to_ids:true`
	// — MISP's convention for "intended for automated
	// detection/blocking" — are turned into IOCs, so contextual
	// attributes (a referenced filename, a comment URL, a
	// sandbox-internal IP) never reach enforcement and cause a
	// false-positive block. Set true to ingest every attribute
	// regardless, for feeds that do not populate `to_ids`.
	IncludeNonIDs bool
}

// Name implements FeedParser.
func (p MISPParser) Name() string {
	if p.Source != "" {
		return p.Source
	}
	return "misp"
}

// mispAttribute is one MISP attribute (an indicator plus its
// metadata). `to_ids` is a pointer so an absent flag is
// distinguishable from an explicit false.
type mispAttribute struct {
	Type      string `json:"type"`
	Value     string `json:"value"`
	Category  string `json:"category"`
	Comment   string `json:"comment"`
	ToIDs     *bool  `json:"to_ids"`
	Timestamp string `json:"timestamp"`
}

// mispObject is a MISP object — a typed bundle of related
// attributes (e.g. a "file" object grouping a filename and its
// hashes). Only its nested attributes matter for IOC extraction.
type mispObject struct {
	Attribute []mispAttribute `json:"Attribute"`
}

// mispTag is a MISP tag (`tlp:white`, `misp-galaxy:threat-actor="APT28"`, …).
type mispTag struct {
	Name string `json:"name"`
}

// mispGalaxyCluster names a galaxy entry (a threat actor, malware
// family, …). The cluster `value` is the human-readable name.
type mispGalaxyCluster struct {
	Value string `json:"value"`
}

// mispGalaxy groups galaxy clusters by galaxy type.
type mispGalaxy struct {
	Type          string              `json:"type"`
	GalaxyCluster []mispGalaxyCluster `json:"GalaxyCluster"`
}

// mispEvent is a MISP event: its attributes (directly and inside
// objects) plus the event-level attribution lifted onto every IOC.
type mispEvent struct {
	Info      string          `json:"info"`
	Attribute []mispAttribute `json:"Attribute"`
	Object    []mispObject    `json:"Object"`
	Tag       []mispTag       `json:"Tag"`
	Galaxy    []mispGalaxy    `json:"Galaxy"`
}

// mispEventEnvelope wraps an event under the "Event" key, the shape
// used inside the events REST-search response array and a bare
// event array.
type mispEventEnvelope struct {
	Event *mispEvent `json:"Event"`
}

// Parse implements FeedParser.
func (p MISPParser) Parse(raw []byte) ([]IOC, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return nil, nil
	}
	source := p.Name()
	switch trimmed[0] {
	case '[':
		// Bare array of event envelopes.
		var envs []mispEventEnvelope
		if err := json.Unmarshal(trimmed, &envs); err != nil {
			return nil, fmt.Errorf("ai/feed: parse MISP event array: %w", err)
		}
		return p.iocsFromEnvelopes(envs, source), nil
	case '{':
		return p.parseObject(trimmed, source)
	}
	return nil, fmt.Errorf("ai/feed: parse MISP: unexpected leading token %q", trimmed[0])
}

// parseObject handles every object-rooted MISP shape: a single
// `{"Event":…}`, the events envelope `{"response":[{"Event":…}]}`,
// and the attributes envelope `{"response":{"Attribute":[…]}}`.
func (p MISPParser) parseObject(raw []byte, source string) ([]IOC, error) {
	var doc struct {
		Event    *mispEvent      `json:"Event"`
		Response json.RawMessage `json:"response"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("ai/feed: parse MISP document: %w", err)
	}
	// A single event download: {"Event": {…}}.
	if doc.Event != nil {
		return p.iocsFromEvent(*doc.Event, source), nil
	}
	resp := bytes.TrimSpace(doc.Response)
	if len(resp) == 0 {
		return nil, nil
	}
	switch resp[0] {
	case '[':
		// Events REST-search: {"response":[{"Event":…}]}.
		var envs []mispEventEnvelope
		if err := json.Unmarshal(resp, &envs); err != nil {
			return nil, fmt.Errorf("ai/feed: parse MISP response events: %w", err)
		}
		return p.iocsFromEnvelopes(envs, source), nil
	case '{':
		// Attributes REST-search: {"response":{"Attribute":[…]}}.
		var ar struct {
			Attribute []mispAttribute `json:"Attribute"`
		}
		if err := json.Unmarshal(resp, &ar); err != nil {
			return nil, fmt.Errorf("ai/feed: parse MISP response attributes: %w", err)
		}
		return p.iocsFromAttributes(ar.Attribute, mispAttribution{}, source), nil
	}
	return nil, nil
}

func (p MISPParser) iocsFromEnvelopes(envs []mispEventEnvelope, source string) []IOC {
	var out []IOC
	for _, env := range envs {
		if env.Event == nil {
			continue
		}
		out = append(out, p.iocsFromEvent(*env.Event, source)...)
	}
	return out
}

// iocsFromEvent extracts IOCs from an event's direct attributes and
// its objects' attributes, tagging each with the event attribution.
func (p MISPParser) iocsFromEvent(ev mispEvent, source string) []IOC {
	attr := mispAttribution{
		campaign: strings.TrimSpace(ev.Info),
		actor:    eventThreatActor(ev),
	}
	out := p.iocsFromAttributes(ev.Attribute, attr, source)
	for _, obj := range ev.Object {
		out = append(out, p.iocsFromAttributes(obj.Attribute, attr, source)...)
	}
	return out
}

// mispAttribution is the event-level context lifted onto every IOC.
type mispAttribution struct {
	campaign string
	actor    string
}

func (p MISPParser) iocsFromAttributes(attrs []mispAttribute, ev mispAttribution, source string) []IOC {
	var out []IOC
	for _, a := range attrs {
		// Precision gate: skip attributes not meant for automated
		// detection unless the operator opts in to ingest all.
		if !p.IncludeNonIDs && (a.ToIDs == nil || !*a.ToIDs) {
			continue
		}
		meta := IOCMeta{
			Source:      source,
			ThreatActor: ev.actor,
			Campaign:    ev.campaign,
			Confidence:  p.DefaultConfidence,
			LastSeen:    parseMISPTimestamp(a.Timestamp),
		}
		out = append(out, mispAttrIOCs(a.Type, a.Value, meta)...)
	}
	return out
}

// mispAttrIOCs decomposes one MISP attribute (type + value) into
// the IOCs it carries. A composite type (those MISP joins with a
// "|", e.g. "domain|ip", "filename|sha256", "ip-dst|port") is split
// on "|" in lockstep with the value, and each component that maps to
// a known scalar IOC type and has a value is normalized through
// NewIOC. A single-part type maps directly. Components that are not
// network/file indicators (a filename, a port, an email) simply have
// no scalar mapping and are dropped, so one generic path handles
// every MISP composite without per-type code.
func mispAttrIOCs(attrType, value string, meta IOCMeta) []IOC {
	attrType = strings.ToLower(strings.TrimSpace(attrType))
	if attrType == "" || strings.TrimSpace(value) == "" {
		return nil
	}
	typeParts := strings.Split(attrType, "|")
	valueParts := strings.Split(value, "|")
	var out []IOC
	for i, tp := range typeParts {
		iocType, ok := mispScalarType(tp)
		if !ok {
			continue
		}
		if i >= len(valueParts) {
			continue
		}
		v := strings.TrimSpace(valueParts[i])
		if v == "" {
			continue
		}
		if ioc, ok := NewIOC(iocType, v, meta); ok {
			out = append(out, ioc)
		}
	}
	return out
}

// mispScalarType maps a single (non-composite) MISP attribute type
// to an IOCType. MISP attribute types that are not directly
// enforceable network/file indicators (filename, port, email-*,
// regkey, btc, …) return false and are dropped.
func mispScalarType(t string) (IOCType, bool) {
	switch t {
	case "domain", "hostname":
		return IOCTypeDomain, true
	case "ip-dst", "ip-src", "ip":
		return IOCTypeIP, true
	case "url", "uri":
		return IOCTypeURL, true
	case "md5", "sha1", "sha256":
		return IOCTypeHash, true
	}
	return "", false
}

// eventThreatActor derives a threat-actor name from an event's MISP
// galaxies (preferred — the threat-actor galaxy cluster value) or,
// failing that, from a `misp-galaxy:threat-actor="…"` tag. Returns
// "" when the event carries no attribution.
func eventThreatActor(ev mispEvent) string {
	for _, g := range ev.Galaxy {
		if !strings.Contains(strings.ToLower(g.Type), "threat-actor") {
			continue
		}
		for _, c := range g.GalaxyCluster {
			if v := strings.TrimSpace(c.Value); v != "" {
				return v
			}
		}
	}
	// Fall back to the first threat-actor galaxy cluster of any
	// galaxy type, then to a threat-actor tag.
	for _, g := range ev.Galaxy {
		for _, c := range g.GalaxyCluster {
			if v := strings.TrimSpace(c.Value); v != "" {
				return v
			}
		}
	}
	for _, tag := range ev.Tag {
		if actor := actorFromTag(tag.Name); actor != "" {
			return actor
		}
	}
	return ""
}

// actorFromTag extracts the quoted value of a
// `misp-galaxy:threat-actor="APT28"` tag. Returns "" for any other
// tag (tlp:*, kill-chain phases, free-form tags).
func actorFromTag(name string) string {
	const marker = "threat-actor="
	i := strings.Index(strings.ToLower(name), marker)
	if i < 0 {
		return ""
	}
	v := strings.TrimSpace(name[i+len(marker):])
	v = strings.Trim(v, `"'`)
	return v
}

// parseMISPTimestamp parses a MISP attribute timestamp, a Unix-epoch
// seconds value carried as a JSON string. Returns the zero time for
// an empty or unparseable value (the field is advisory telemetry,
// not a correctness input).
func parseMISPTimestamp(s string) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}
	}
	secs, err := strconv.ParseInt(s, 10, 64)
	if err != nil || secs <= 0 {
		return time.Time{}
	}
	return time.Unix(secs, 0).UTC()
}

var _ FeedParser = MISPParser{}
