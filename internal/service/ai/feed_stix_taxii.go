package ai

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// STIXTAXIIParser parses a STIX 2.1 bundle or a TAXII 2.1
// collection envelope into IOCs. Both wire shapes carry STIX
// Domain Objects in an array — a STIX bundle under "objects" with
// a top-level "type":"bundle", a TAXII envelope under "objects"
// with "more"/"next" pagination fields — so a single parser
// handles both by reading the shared "objects" array.
//
// Only STIX `indicator` SDOs with `pattern_type` "stix" (or
// unset, which defaults to stix per the spec) are turned into
// IOCs; their `pattern` is decomposed into one IOC per
// comparison expression. Other SDO types (malware,
// threat-actor, relationship, …) are ignored — they carry
// context, not directly-enforceable indicators.
//
// STIX `confidence` is an integer 0–100; it is scaled to the
// [0,1] range the pipeline uses. `valid_until` becomes the IOC's
// ExpiresAt so a feed that ages out an indicator propagates the
// TTL end-to-end.
type STIXTAXIIParser struct {
	// Source overrides the IOC Source label; defaults to Name().
	Source string
	// DefaultConfidence is applied when an indicator omits the
	// optional `confidence` property. STIX treats absent
	// confidence as "unspecified"; we map it to a moderate
	// default so unscored-but-published indicators still enforce.
	DefaultConfidence float64
}

// stixEnvelope is the shared decode shape for a STIX bundle and a
// TAXII 2.1 envelope.
type stixEnvelope struct {
	Objects []stixObject `json:"objects"`
}

type stixObject struct {
	Type        string          `json:"type"`
	Pattern     string          `json:"pattern"`
	PatternType string          `json:"pattern_type"`
	Confidence  *int            `json:"confidence"`
	Created     string          `json:"created"`
	Modified    string          `json:"modified"`
	ValidUntil  string          `json:"valid_until"`
	Name        string          `json:"name"`
	Labels      []string        `json:"labels"`
	KillChain   json.RawMessage `json:"kill_chain_phases"`
}

// Name implements FeedParser.
func (p STIXTAXIIParser) Name() string {
	if p.Source != "" {
		return p.Source
	}
	return "stix-taxii"
}

// stixComparisonRe extracts `<object-type>:<property> = '<value>'`
// comparison expressions from a STIX pattern. It tolerates the
// quoted-property form used for hashes
// (`file:hashes.'SHA-256' = '...'`) by allowing quotes and dots in
// the property segment, and is intentionally liberal about the
// surrounding boolean/observation-operator syntax (AND/OR/[]/())
// because we only need the leaf comparisons, not the full
// expression tree.
var stixComparisonRe = regexp.MustCompile(`([a-zA-Z0-9_-]+):([a-zA-Z0-9_.'"-]+)\s*=\s*'((?:[^'\\]|\\.)*)'`)

// Parse implements FeedParser.
func (p STIXTAXIIParser) Parse(raw []byte) ([]IOC, error) {
	var env stixEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("ai/feed: parse STIX/TAXII envelope: %w", err)
	}
	source := p.Name()
	var out []IOC
	for _, obj := range env.Objects {
		if obj.Type != "indicator" {
			continue
		}
		if obj.PatternType != "" && !strings.EqualFold(obj.PatternType, "stix") {
			// A non-STIX pattern dialect (snort, yara, …) is not
			// something this parser can decompose into network
			// IOCs; skip rather than mis-parse.
			continue
		}
		conf := p.DefaultConfidence
		if obj.Confidence != nil {
			conf = float64(*obj.Confidence) / 100.0
		}
		meta := IOCMeta{
			Source:     source,
			Campaign:   obj.Name,
			Confidence: conf,
			FirstSeen:  parseSTIXTime(obj.Created),
			LastSeen:   parseSTIXTime(obj.Modified),
			ExpiresAt:  parseSTIXTime(obj.ValidUntil),
		}
		meta.ThreatActor = firstNonEmpty(obj.Labels)
		out = append(out, p.iocsFromPattern(obj.Pattern, meta)...)
	}
	return out, nil
}

// iocsFromPattern decomposes a STIX pattern into IOCs, one per
// leaf comparison the matcher recognises.
func (p STIXTAXIIParser) iocsFromPattern(pattern string, meta IOCMeta) []IOC {
	matches := stixComparisonRe.FindAllStringSubmatch(pattern, -1)
	if len(matches) == 0 {
		return nil
	}
	out := make([]IOC, 0, len(matches))
	for _, m := range matches {
		objType := strings.ToLower(m[1])
		prop := strings.ToLower(strings.Trim(m[2], `'"`))
		value := unescapeSTIX(m[3])

		var iocType IOCType
		switch objType {
		case "domain-name":
			iocType = IOCTypeDomain
		case "ipv4-addr", "ipv6-addr":
			// A STIX address object value may be a single address
			// or a CIDR range; route by shape so ranges aren't
			// dropped by the single-IP normalizer.
			iocType = ipKindForValue(value)
		case "url":
			iocType = IOCTypeURL
		case "file":
			if !strings.HasPrefix(prop, "hashes") {
				continue
			}
			iocType = IOCTypeHash
		default:
			continue
		}
		if ioc, ok := NewIOC(iocType, value, meta); ok {
			out = append(out, ioc)
		}
	}
	return out
}

// unescapeSTIX reverses the backslash escaping a STIX string
// literal may carry (`\'` and `\\`).
func unescapeSTIX(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	r := strings.NewReplacer(`\'`, `'`, `\\`, `\`)
	return r.Replace(s)
}

func parseSTIXTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t.UTC()
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t.UTC()
	}
	return time.Time{}
}

func firstNonEmpty(ss []string) string {
	for _, s := range ss {
		if strings.TrimSpace(s) != "" {
			return s
		}
	}
	return ""
}
