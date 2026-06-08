package ai

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// AbuseCHProduct selects which abuse.ch feed an AbuseCHParser
// decodes. The three products ship in three different wire
// formats, so the parser dispatches on this.
type AbuseCHProduct string

const (
	// AbuseCHURLhaus is the URLhaus malware-URL CSV export
	// (https://urlhaus.abuse.ch/downloads/csv/). Yields URL IOCs.
	AbuseCHURLhaus AbuseCHProduct = "urlhaus"
	// AbuseCHMalwareBazaar is the MalwareBazaar hash CSV export
	// (https://bazaar.abuse.ch/export/csv/full/). Yields hash IOCs.
	AbuseCHMalwareBazaar AbuseCHProduct = "malwarebazaar"
	// AbuseCHFeodoTracker is the Feodo Tracker C2 IP block-list
	// JSON (https://feodotracker.abuse.ch/downloads/ipblocklist.json).
	// Yields IP IOCs.
	AbuseCHFeodoTracker AbuseCHProduct = "feodotracker"
)

// AbuseCHParser parses the three abuse.ch community feeds.
// abuse.ch data is operator-curated and high-signal, so the
// default confidence is high; it remains configurable.
//
// The CSV products (URLhaus, MalwareBazaar) ship column
// descriptions as leading `#` comment lines and quoted,
// header-less data rows, so the parser addresses columns by their
// documented fixed index. Feodo Tracker ships a JSON array.
type AbuseCHParser struct {
	// Product selects the wire format. Required.
	Product AbuseCHProduct
	// Source labels produced IOCs; defaults to "abuse.ch:<product>".
	Source string
	// DefaultConfidence is applied to every produced IOC.
	// Defaults (when zero) to 0.9 — abuse.ch feeds are curated
	// and high-trust.
	DefaultConfidence float64
}

// Name implements FeedParser.
func (p AbuseCHParser) Name() string {
	if p.Source != "" {
		return p.Source
	}
	return "abuse.ch:" + string(p.Product)
}

func (p AbuseCHParser) confidence() float64 {
	if p.DefaultConfidence == 0 {
		return 0.9
	}
	return p.DefaultConfidence
}

// Parse implements FeedParser, dispatching on Product.
func (p AbuseCHParser) Parse(raw []byte) ([]IOC, error) {
	switch p.Product {
	case AbuseCHURLhaus:
		return p.parseURLhaus(raw)
	case AbuseCHMalwareBazaar:
		return p.parseMalwareBazaar(raw)
	case AbuseCHFeodoTracker:
		return p.parseFeodoTracker(raw)
	}
	return nil, fmt.Errorf("ai/feed: abuse.ch: unknown product %q: %w", p.Product, errInvalidFeedConfig)
}

// abuseCHCSV reads an abuse.ch CSV export, stripping the leading
// `#` comment block and tolerating the space-after-comma quoting
// abuse.ch uses.
func abuseCHCSV(raw []byte) ([][]string, error) {
	r := csv.NewReader(bytes.NewReader(raw))
	r.Comment = '#'
	r.FieldsPerRecord = -1
	r.TrimLeadingSpace = true
	r.LazyQuotes = true
	rows, err := r.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("ai/feed: abuse.ch CSV: %w", err)
	}
	return rows, nil
}

// parseURLhaus extracts URL IOCs from the URLhaus CSV. Documented
// columns: 0=id, 1=dateadded, 2=url, 3=url_status, 4=last_online,
// 5=threat, 6=tags, 7=urlhaus_link, 8=reporter.
func (p AbuseCHParser) parseURLhaus(raw []byte) ([]IOC, error) {
	rows, err := abuseCHCSV(raw)
	if err != nil {
		return nil, err
	}
	source := p.Name()
	var out []IOC
	for _, row := range rows {
		if len(row) < 3 {
			continue
		}
		urlVal := strings.TrimSpace(row[2])
		meta := IOCMeta{
			Source:      source,
			Confidence:  p.confidence(),
			FirstSeen:   parseAbuseCHTime(field(row, 1)),
			LastSeen:    parseAbuseCHTime(field(row, 4)),
			Campaign:    field(row, 5), // threat (e.g. malware_download)
			ThreatActor: tagsToActor(field(row, 6)),
		}
		if ioc, ok := NewIOC(IOCTypeURL, urlVal, meta); ok {
			out = append(out, ioc)
		}
	}
	return out, nil
}

// parseMalwareBazaar extracts SHA-256 hash IOCs from the
// MalwareBazaar full CSV. Documented columns: 0=first_seen_utc,
// 1=sha256_hash, 2=md5_hash, 3=sha1_hash, 4=reporter,
// 5=file_name, 6=file_type_guess, 7=mime_type, 8=signature
// (malware family).
func (p AbuseCHParser) parseMalwareBazaar(raw []byte) ([]IOC, error) {
	rows, err := abuseCHCSV(raw)
	if err != nil {
		return nil, err
	}
	source := p.Name()
	var out []IOC
	for _, row := range rows {
		if len(row) < 2 {
			continue
		}
		sha256 := strings.TrimSpace(row[1])
		meta := IOCMeta{
			Source:     source,
			Confidence: p.confidence(),
			FirstSeen:  parseAbuseCHTime(field(row, 0)),
			Campaign:   field(row, 8), // signature / malware family
		}
		if sig := field(row, 8); sig != "" && sig != "n/a" {
			meta.ThreatActor = sig
		}
		if ioc, ok := NewIOC(IOCTypeHash, sha256, meta); ok {
			out = append(out, ioc)
		}
	}
	return out, nil
}

type feodoEntry struct {
	IPAddress  string `json:"ip_address"`
	Port       int    `json:"port"`
	Status     string `json:"status"`
	Malware    string `json:"malware"`
	FirstSeen  string `json:"first_seen"`
	LastOnline string `json:"last_online"`
}

// parseFeodoTracker extracts C2 IP IOCs from the Feodo Tracker
// JSON block-list.
func (p AbuseCHParser) parseFeodoTracker(raw []byte) ([]IOC, error) {
	var entries []feodoEntry
	if err := json.Unmarshal(bytes.TrimSpace(raw), &entries); err != nil {
		return nil, fmt.Errorf("ai/feed: parse Feodo Tracker: %w", err)
	}
	source := p.Name()
	var out []IOC
	for _, e := range entries {
		meta := IOCMeta{
			Source:      source,
			Confidence:  p.confidence(),
			ThreatActor: strings.TrimSpace(e.Malware),
			Campaign:    strings.TrimSpace(e.Malware) + " C2",
			FirstSeen:   parseAbuseCHTime(e.FirstSeen),
			LastSeen:    parseAbuseCHTime(e.LastOnline),
		}
		if ioc, ok := NewIOC(IOCTypeIP, e.IPAddress, meta); ok {
			out = append(out, ioc)
		}
	}
	return out, nil
}

func field(row []string, i int) string {
	if i < 0 || i >= len(row) {
		return ""
	}
	return strings.TrimSpace(row[i])
}

// tagsToActor turns the URLhaus comma/space-separated tag list
// (e.g. "emotet,heodo") into a single actor label (the first tag).
func tagsToActor(tags string) string {
	tags = strings.TrimSpace(tags)
	if tags == "" {
		return ""
	}
	parts := strings.FieldsFunc(tags, func(r rune) bool {
		return r == ',' || r == ' '
	})
	if len(parts) == 0 {
		return ""
	}
	return parts[0]
}

// parseAbuseCHTime parses the "2006-01-02 15:04:05" UTC timestamp
// abuse.ch CSV/JSON feeds use, falling back to RFC3339 forms.
func parseAbuseCHTime(s string) time.Time {
	s = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(s), "UTC"))
	if s == "" {
		return time.Time{}
	}
	for _, layout := range []string{
		"2006-01-02 15:04:05",
		time.RFC3339Nano,
		time.RFC3339,
	} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}

var _ FeedParser = AbuseCHParser{}
