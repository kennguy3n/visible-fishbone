package ai

import (
	"encoding/json"
	"fmt"
	"strings"
)

// OTXParser parses the AlienVault OTX "subscribed pulses" API
// response (GET /api/v1/pulses/subscribed) into IOCs. The OTX
// model groups indicators under pulses; each pulse carries
// attribution (adversary, name, tags) that we lift onto every
// indicator it contains so a match can name the campaign and
// actor.
//
// OTX does not publish a per-indicator confidence, so every IOC
// gets DefaultConfidence — community intelligence is moderately
// trusted by default; an operator can raise or lower the floor
// per deployment. Per-indicator `expiration` (when present)
// becomes the IOC ExpiresAt.
type OTXParser struct {
	// Source labels produced IOCs; defaults to "otx".
	Source string
	// DefaultConfidence is applied to every OTX indicator (the
	// API exposes no per-indicator score). Defaults via the feed
	// config; a zero here means the indicators carry confidence
	// 0 and are dropped by any non-zero store/feed floor.
	DefaultConfidence float64
}

type otxResponse struct {
	Results []otxPulse `json:"results"`
}

type otxPulse struct {
	Name       string         `json:"name"`
	Adversary  string         `json:"adversary"`
	Tags       []string       `json:"tags"`
	Indicators []otxIndicator `json:"indicators"`
}

type otxIndicator struct {
	Indicator  string `json:"indicator"`
	Type       string `json:"type"`
	Created    string `json:"created"`
	Expiration string `json:"expiration"`
}

// Name implements FeedParser.
func (p OTXParser) Name() string {
	if p.Source != "" {
		return p.Source
	}
	return "otx"
}

// Parse implements FeedParser. It also accepts a bare pulse array
// or a single pulse object, which the indicators-export and
// single-pulse endpoints return, by sniffing the top-level JSON
// token.
func (p OTXParser) Parse(raw []byte) ([]IOC, error) {
	pulses, err := decodeOTXPulses(raw)
	if err != nil {
		return nil, err
	}
	source := p.Name()
	var out []IOC
	for _, pulse := range pulses {
		campaign := pulse.Name
		actor := pulse.Adversary
		if actor == "" {
			actor = firstNonEmpty(pulse.Tags)
		}
		for _, ind := range pulse.Indicators {
			iocType, ok := otxType(ind.Type)
			if !ok {
				continue
			}
			meta := IOCMeta{
				Source:      source,
				ThreatActor: actor,
				Campaign:    campaign,
				Confidence:  p.DefaultConfidence,
				FirstSeen:   parseSTIXTime(ind.Created),
				ExpiresAt:   parseSTIXTime(ind.Expiration),
			}
			if ioc, ok := NewIOC(iocType, ind.Indicator, meta); ok {
				out = append(out, ioc)
			}
		}
	}
	return out, nil
}

// decodeOTXPulses tolerates the three shapes OTX endpoints return:
// the paginated {"results":[...]} envelope, a bare [pulse,...]
// array, and a single pulse object.
func decodeOTXPulses(raw []byte) ([]otxPulse, error) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return nil, nil
	}
	switch trimmed[0] {
	case '{':
		// Either the results envelope or a single pulse. Decode
		// as the envelope first; if it carried no results but the
		// object had indicators, fall back to single-pulse.
		var env otxResponse
		if err := json.Unmarshal(raw, &env); err != nil {
			return nil, fmt.Errorf("ai/feed: parse OTX response: %w", err)
		}
		if len(env.Results) > 0 {
			return env.Results, nil
		}
		var single otxPulse
		if err := json.Unmarshal(raw, &single); err != nil {
			return nil, fmt.Errorf("ai/feed: parse OTX pulse: %w", err)
		}
		if len(single.Indicators) > 0 {
			return []otxPulse{single}, nil
		}
		return nil, nil
	case '[':
		var pulses []otxPulse
		if err := json.Unmarshal(raw, &pulses); err != nil {
			return nil, fmt.Errorf("ai/feed: parse OTX pulse array: %w", err)
		}
		return pulses, nil
	}
	return nil, fmt.Errorf("ai/feed: parse OTX: unexpected leading token %q", trimmed[0])
}

// otxType maps an OTX indicator type string to an IOCType. OTX
// hash subtypes that are not plain file digests (PEHASH, IMPHASH)
// are mapped to IOCTypeHash and validated by length in NewIOC —
// non-standard lengths are skipped there. Unsupported OTX types
// (CIDR, email, mutex, …) return false.
func otxType(t string) (IOCType, bool) {
	switch strings.ToLower(strings.TrimSpace(t)) {
	case "ipv4", "ipv6":
		return IOCTypeIP, true
	case "domain", "hostname":
		return IOCTypeDomain, true
	case "url", "uri":
		return IOCTypeURL, true
	case "filehash-md5", "filehash-sha1", "filehash-sha256":
		return IOCTypeHash, true
	}
	return "", false
}

var _ FeedParser = OTXParser{}
