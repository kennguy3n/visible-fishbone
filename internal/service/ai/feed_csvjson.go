package ai

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// CSVParser imports IOCs from a flat CSV export — the lingua
// franca of national-CERT and ISAC feeds. Columns are addressed
// by header name (preferred) or zero-based index, so the same
// parser handles the many slightly-different layouts CERTs ship
// without per-feed code.
//
// When TypeColumn is unset the indicator's type is inferred from
// its shape (classifyIndicator), which covers the common "one
// indicator per line, type implied" exports. A row whose
// indicator is empty or fails normalization is skipped, never
// fatal — a single malformed line must not drop a whole feed.
type CSVParser struct {
	// Source labels the produced IOCs; defaults to Name().
	Source string
	// IndicatorColumn is the header name (case-insensitive) of
	// the indicator column. Required.
	IndicatorColumn string
	// TypeColumn, ConfidenceColumn, ActorColumn, CampaignColumn
	// are optional header names. An unset TypeColumn triggers
	// shape inference; an unset ConfidenceColumn applies
	// DefaultConfidence.
	TypeColumn       string
	ConfidenceColumn string
	ActorColumn      string
	CampaignColumn   string
	// Delimiter overrides the field separator (default ',').
	Delimiter rune
	// Comment is the line-comment marker (default '#').
	Comment rune
	// HasHeader indicates the first non-comment row is a header.
	// When false, columns must be addressed by index (e.g.
	// IndicatorColumn = "0").
	HasHeader bool
	// DefaultConfidence is applied when no confidence column is
	// present or a row's confidence is unparseable.
	DefaultConfidence float64
}

// Name implements FeedParser.
func (p CSVParser) Name() string {
	if p.Source != "" {
		return p.Source
	}
	return "csv"
}

// Parse implements FeedParser.
func (p CSVParser) Parse(raw []byte) ([]IOC, error) {
	r := csv.NewReader(bytes.NewReader(raw))
	r.FieldsPerRecord = -1 // tolerate ragged rows; we index defensively
	r.TrimLeadingSpace = true
	if p.Delimiter != 0 {
		r.Comma = p.Delimiter
	}
	comment := p.Comment
	if comment == 0 {
		comment = '#'
	}
	r.Comment = comment

	rows, err := r.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("ai/feed: parse CSV: %w", err)
	}
	if len(rows) == 0 {
		return nil, nil
	}

	var header []string
	dataStart := 0
	if p.HasHeader {
		header = rows[0]
		dataStart = 1
	}
	cols, err := p.resolveColumns(header)
	if err != nil {
		return nil, err
	}

	source := p.Name()
	var out []IOC
	for _, row := range rows[dataStart:] {
		ioc, ok := p.rowToIOC(row, cols, source)
		if ok {
			out = append(out, ioc)
		}
	}
	return out, nil
}

// csvCols holds resolved zero-based column indices (-1 = absent).
type csvCols struct {
	indicator  int
	typ        int
	confidence int
	actor      int
	campaign   int
}

func (p CSVParser) resolveColumns(header []string) (csvCols, error) {
	c := csvCols{indicator: -1, typ: -1, confidence: -1, actor: -1, campaign: -1}
	resolve := func(spec string) (int, error) {
		if spec == "" {
			return -1, nil
		}
		// Header-name lookup (case-insensitive) when a header
		// exists; otherwise treat the spec as a numeric index.
		if len(header) > 0 {
			for i, h := range header {
				if strings.EqualFold(strings.TrimSpace(h), spec) {
					return i, nil
				}
			}
		}
		idx, err := strconv.Atoi(spec)
		if err != nil || idx < 0 {
			return -1, fmt.Errorf("ai/feed: CSV column %q not found in header and not a valid index: %w", spec, errInvalidFeedConfig)
		}
		return idx, nil
	}
	var err error
	if c.indicator, err = resolve(p.IndicatorColumn); err != nil {
		return c, err
	}
	if c.indicator < 0 {
		return c, fmt.Errorf("ai/feed: CSV IndicatorColumn is required: %w", errInvalidFeedConfig)
	}
	if c.typ, err = resolve(p.TypeColumn); err != nil {
		return c, err
	}
	if c.confidence, err = resolve(p.ConfidenceColumn); err != nil {
		return c, err
	}
	if c.actor, err = resolve(p.ActorColumn); err != nil {
		return c, err
	}
	if c.campaign, err = resolve(p.CampaignColumn); err != nil {
		return c, err
	}
	return c, nil
}

func (p CSVParser) rowToIOC(row []string, cols csvCols, source string) (IOC, bool) {
	get := func(idx int) string {
		if idx < 0 || idx >= len(row) {
			return ""
		}
		return strings.TrimSpace(row[idx])
	}
	indicator := get(cols.indicator)
	if indicator == "" {
		return IOC{}, false
	}
	conf := p.DefaultConfidence
	if cols.confidence >= 0 {
		if parsed, ok := parseConfidence(get(cols.confidence)); ok {
			conf = parsed
		}
	}
	meta := IOCMeta{
		Source:      source,
		ThreatActor: get(cols.actor),
		Campaign:    get(cols.campaign),
		Confidence:  conf,
	}

	if cols.typ >= 0 {
		t := IOCType(strings.ToLower(get(cols.typ)))
		if !t.Valid() {
			return IOC{}, false
		}
		return NewIOC(t, indicator, meta)
	}
	t, ok := classifyIndicator(indicator)
	if !ok {
		return IOC{}, false
	}
	return NewIOC(t, indicator, meta)
}

// JSONParser imports IOCs from a JSON array of indicator objects
// — the other common CERT/flat-file shape. Field names are
// configurable so a feed using {"ioc": "...", "category": "..."}
// reads the same as one using {"indicator": "...", "type": "..."}.
//
// The payload may be a bare array or an object wrapping the array
// under a configurable ArrayKey (e.g. {"data": [...]}); both are
// accepted so the parser fits the two dominant flat-JSON layouts.
type JSONParser struct {
	Source string
	// IndicatorKey / TypeKey / ConfidenceKey / ActorKey /
	// CampaignKey are the object field names to read. Indicator
	// defaults to "indicator", type to "type", confidence to
	// "confidence".
	IndicatorKey  string
	TypeKey       string
	ConfidenceKey string
	ActorKey      string
	CampaignKey   string
	// ArrayKey, when set, is the object field holding the
	// indicator array; unset means the payload is a bare array.
	ArrayKey string
	// DefaultConfidence applies when an object omits the
	// confidence field.
	DefaultConfidence float64
}

// Name implements FeedParser.
func (p JSONParser) Name() string {
	if p.Source != "" {
		return p.Source
	}
	return "json"
}

// Parse implements FeedParser.
func (p JSONParser) Parse(raw []byte) ([]IOC, error) {
	raw = bytes.TrimSpace(raw)
	var records []map[string]json.RawMessage
	if p.ArrayKey != "" {
		var wrapper map[string]json.RawMessage
		if err := json.Unmarshal(raw, &wrapper); err != nil {
			return nil, fmt.Errorf("ai/feed: parse JSON wrapper: %w", err)
		}
		inner, ok := wrapper[p.ArrayKey]
		if !ok {
			return nil, nil
		}
		if err := json.Unmarshal(inner, &records); err != nil {
			return nil, fmt.Errorf("ai/feed: parse JSON array %q: %w", p.ArrayKey, err)
		}
	} else if err := json.Unmarshal(raw, &records); err != nil {
		return nil, fmt.Errorf("ai/feed: parse JSON array: %w", err)
	}

	indicatorKey := orDefault(p.IndicatorKey, "indicator")
	typeKey := orDefault(p.TypeKey, "type")
	confidenceKey := orDefault(p.ConfidenceKey, "confidence")

	source := p.Name()
	var out []IOC
	for _, rec := range records {
		indicator := jsonString(rec[indicatorKey])
		if indicator == "" {
			continue
		}
		conf := p.DefaultConfidence
		if c, ok := jsonNumber(rec[confidenceKey]); ok {
			conf = normalizeConfidenceScale(c)
		}
		meta := IOCMeta{
			Source:      source,
			ThreatActor: jsonString(rec[p.ActorKey]),
			Campaign:    jsonString(rec[p.CampaignKey]),
			Confidence:  conf,
		}
		var ioc IOC
		var ok bool
		if tv := jsonString(rec[typeKey]); tv != "" {
			t := IOCType(strings.ToLower(tv))
			if !t.Valid() {
				continue
			}
			ioc, ok = NewIOC(t, indicator, meta)
		} else if t, classified := classifyIndicator(indicator); classified {
			ioc, ok = NewIOC(t, indicator, meta)
		}
		if ok {
			out = append(out, ioc)
		}
	}
	return out, nil
}

// parseConfidence reads a confidence cell that may be a 0–1 float
// or a 0–100 integer (CERT feeds use both); it normalizes onto
// [0,1]. Returns false for an unparseable value so the caller can
// fall back to the default.
func parseConfidence(s string) (float64, bool) {
	s = strings.TrimSpace(strings.TrimSuffix(s, "%"))
	if s == "" {
		return 0, false
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0, false
	}
	return normalizeConfidenceScale(v), true
}

// normalizeConfidenceScale maps a 0–100 confidence onto [0,1]
// while leaving an already-[0,1] value untouched. The heuristic:
// any value > 1 is treated as a percentage.
func normalizeConfidenceScale(v float64) float64 {
	if v > 1 {
		v /= 100.0
	}
	return clampConfidence(v)
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func jsonString(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return strings.TrimSpace(s)
	}
	return ""
}

func jsonNumber(raw json.RawMessage) (float64, bool) {
	if len(raw) == 0 {
		return 0, false
	}
	var f float64
	if err := json.Unmarshal(raw, &f); err == nil {
		return f, true
	}
	// Tolerate a numeric string ("85").
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		if v, err := strconv.ParseFloat(strings.TrimSpace(s), 64); err == nil {
			return v, true
		}
	}
	return 0, false
}

// errInvalidFeedConfig flags a misconfigured parser (bad column
// spec). It is a parser-construction error, distinct from a
// per-row skip.
var errInvalidFeedConfig = fmt.Errorf("invalid feed configuration")

// compile-time assertions that every parser satisfies FeedParser.
var (
	_ FeedParser = STIXTAXIIParser{}
	_ FeedParser = CSVParser{}
	_ FeedParser = JSONParser{}
)
