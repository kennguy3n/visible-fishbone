// Command bench/telemetry measures the events/sec the SNG telemetry
// pipeline (NATS JetStream -> ClickHouse -> S3) can sustain, plus a
// per-tenant cost model. report.go holds the report model: the JSON
// artifact persisted to results/, the human-readable markdown
// summary, and the verdict classifier the summary annotates each row
// with.
//
// Everything here is a pure transform over plain data so the report
// shape, the verdict maths, and the markdown rendering are unit-tested
// without touching a container, a socket, or /proc. Mirrors the spirit
// of bench/src/report.rs (the Rust edge harness) and Session-1's
// bench/controlplane/report.go: theoretical-vs-actual-vs-competitor
// columns and PASS/WARN/FAIL verdicts.
package main

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// ReportSchemaVersion is bumped whenever the JSON shape changes so a
// stale results/ artifact is never silently compared against a new
// one.
const ReportSchemaVersion = 1

// Verdict is the PASS/WARN/FAIL/INFO annotation attached to a measured
// metric relative to its theoretical target.
type Verdict string

const (
	// VerdictPass means the measured value met or beat the target.
	VerdictPass Verdict = "PASS"
	// VerdictWarn means the value missed the target but stayed within
	// the warn band (a soft miss worth flagging, not failing on).
	VerdictWarn Verdict = "WARN"
	// VerdictFail means the value missed the target beyond the warn
	// band.
	VerdictFail Verdict = "FAIL"
	// VerdictInfo marks a row that records a measurement with no
	// pass/fail target (e.g. an observed object size).
	VerdictInfo Verdict = "INFO"
)

// DefaultWarnBand is the fractional tolerance (10%) inside which a
// missed target is a WARN rather than a FAIL. Matches the >10%
// movement alert bar used by the Rust harness's regression detector.
const DefaultWarnBand = 0.10

// MetricRow is one measured metric and its comparison against the
// theoretical target and a competitor "industry norm". Theoretical and
// Competitor are pointers so a row can omit either when no meaningful
// reference exists; such rows render with an em dash and carry an INFO
// verdict.
type MetricRow struct {
	// Name is the human-readable metric label (e.g. "sustained ingest").
	Name string `json:"name"`
	// Unit is the measurement unit (e.g. "events/sec", "ms", "$/mo").
	Unit string `json:"unit,omitempty"`
	// Actual is the measured (or, in dry-run, modeled) value.
	Actual float64 `json:"actual"`
	// Theoretical is the design target this metric is judged against.
	Theoretical *float64 `json:"theoretical,omitempty"`
	// Competitor is a rough industry-norm figure for context only; it
	// never drives the verdict.
	Competitor *float64 `json:"competitor,omitempty"`
	// Verdict is the classification of Actual against Theoretical.
	Verdict Verdict `json:"verdict"`
	// Note carries any per-row caveat (e.g. "modeled, not measured").
	Note string `json:"note,omitempty"`
}

// Section groups related metric rows under one heading (e.g. the
// ingest-rate results, or the cost model).
type Section struct {
	// Title is the section heading.
	Title string `json:"title"`
	// Summary is an optional one-line description rendered under the
	// heading.
	Summary string `json:"summary,omitempty"`
	// Metrics are the rows rendered as the section's comparison table.
	Metrics []MetricRow `json:"metrics"`
}

// Report is the full artifact for one benchmark invocation. It is the
// JSON written to results/ and the source for the markdown summary.
type Report struct {
	// SchemaVersion is ReportSchemaVersion at the time of writing.
	SchemaVersion int `json:"schema_version"`
	// Benchmark is the subcommand that produced the report
	// (e.g. "full-pipeline").
	Benchmark string `json:"benchmark"`
	// UnixTimeSecs is the run timestamp, Unix epoch seconds.
	UnixTimeSecs int64 `json:"unix_time_secs"`
	// GitSHA is the optional commit the run was built from.
	GitSHA string `json:"git_sha,omitempty"`
	// DryRun records whether the run was a container-free dry run
	// (modeled projections + locally-measured CPU work) rather than a
	// live measurement against real NATS/ClickHouse/S3.
	DryRun bool `json:"dry_run"`
	// Sections are the result groups, rendered in order.
	Sections []Section `json:"sections"`
	// Caveats are run-wide honesty notes (assumptions, list-price
	// disclaimers) rendered as a trailing block in the markdown.
	Caveats []string `json:"caveats,omitempty"`
}

// NewReport constructs an empty report stamped with the schema version
// and the given identifying metadata.
func NewReport(benchmark string, unixTime int64, gitSHA string, dryRun bool) *Report {
	return &Report{
		SchemaVersion: ReportSchemaVersion,
		Benchmark:     benchmark,
		UnixTimeSecs:  unixTime,
		GitSHA:        gitSHA,
		DryRun:        dryRun,
	}
}

// AddSection appends a section to the report and returns the report so
// calls can be chained.
func (r *Report) AddSection(s Section) *Report {
	r.Sections = append(r.Sections, s)
	return r
}

// AddCaveat appends a run-wide honesty note.
func (r *Report) AddCaveat(note string) *Report {
	r.Caveats = append(r.Caveats, note)
	return r
}

// ToJSON serializes the report to indented JSON.
func (r *Report) ToJSON() (string, error) {
	out, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal report: %w", err)
	}
	return string(out), nil
}

// ReportFromJSON parses a report previously written by ToJSON.
func ReportFromJSON(s string) (*Report, error) {
	var r Report
	if err := json.Unmarshal([]byte(s), &r); err != nil {
		return nil, fmt.Errorf("unmarshal report: %w", err)
	}
	return &r, nil
}

// Verdicts tallies the verdicts across every section, useful for a
// headline PASS/WARN/FAIL count and for tests.
func (r *Report) Verdicts() map[Verdict]int {
	out := make(map[Verdict]int)
	for i := range r.Sections {
		for j := range r.Sections[i].Metrics {
			out[r.Sections[i].Metrics[j].Verdict]++
		}
	}
	return out
}

// ToMarkdown renders a human-readable summary with one comparison
// table per section.
func (r *Report) ToMarkdown() string {
	var b strings.Builder
	mode := "live"
	if r.DryRun {
		mode = "dry-run (modeled)"
	}
	fmt.Fprintf(&b, "## SNG telemetry pipeline benchmark — %s\n\n", r.Benchmark)
	fmt.Fprintf(&b, "- mode: **%s**\n", mode)
	fmt.Fprintf(&b, "- run (unix): `%d`\n", r.UnixTimeSecs)
	if r.GitSHA != "" {
		fmt.Fprintf(&b, "- commit: `%s`\n", r.GitSHA)
	}
	tally := r.Verdicts()
	fmt.Fprintf(&b, "- verdicts: %d PASS · %d WARN · %d FAIL · %d INFO\n\n",
		tally[VerdictPass], tally[VerdictWarn], tally[VerdictFail], tally[VerdictInfo])

	for i := range r.Sections {
		s := &r.Sections[i]
		fmt.Fprintf(&b, "### %s\n\n", s.Title)
		if s.Summary != "" {
			fmt.Fprintf(&b, "%s\n\n", s.Summary)
		}
		b.WriteString("| metric | actual | theoretical | competitor | verdict |\n")
		b.WriteString("| --- | ---: | ---: | ---: | :---: |\n")
		for j := range s.Metrics {
			m := &s.Metrics[j]
			fmt.Fprintf(&b, "| %s | %s | %s | %s | %s |\n",
				m.Name,
				fmtValue(m.Actual, m.Unit),
				fmtRef(m.Theoretical, m.Unit),
				fmtRef(m.Competitor, m.Unit),
				m.Verdict)
		}
		b.WriteString("\n")
		for j := range s.Metrics {
			if note := s.Metrics[j].Note; note != "" {
				fmt.Fprintf(&b, "> %s: %s\n", s.Metrics[j].Name, note)
			}
		}
		if hasNotes(s.Metrics) {
			b.WriteString("\n")
		}
	}

	if len(r.Caveats) > 0 {
		b.WriteString("### Caveats\n\n")
		for _, c := range r.Caveats {
			fmt.Fprintf(&b, "- %s\n", c)
		}
	}
	return b.String()
}

func hasNotes(rows []MetricRow) bool {
	for i := range rows {
		if rows[i].Note != "" {
			return true
		}
	}
	return false
}

// classify scores a measured value against a target. higherIsBetter
// selects the direction: throughput-style metrics pass when actual >=
// target; latency/cost-style metrics pass when actual <= target. The
// warn band is the fractional tolerance for a soft miss. A nil target
// yields VerdictInfo (a measurement with no pass/fail bar).
func classify(actual float64, target *float64, higherIsBetter bool, warnBand float64) Verdict {
	if target == nil {
		return VerdictInfo
	}
	t := *target
	if higherIsBetter {
		switch {
		case actual >= t:
			return VerdictPass
		case actual >= t*(1-warnBand):
			return VerdictWarn
		default:
			return VerdictFail
		}
	}
	switch {
	case actual <= t:
		return VerdictPass
	case actual <= t*(1+warnBand):
		return VerdictWarn
	default:
		return VerdictFail
	}
}

// ptr returns a pointer to v — a brevity helper for the optional
// Theoretical/Competitor reference fields.
func ptr(v float64) *float64 { return &v }

// fmtValue renders a measured value with a unit, choosing precision by
// magnitude so a table stays readable across events/sec (large) and
// dollars (small).
func fmtValue(v float64, unit string) string {
	num := humanizeFloat(v)
	if unit == "" {
		return num
	}
	return num + " " + unit
}

func fmtRef(v *float64, unit string) string {
	if v == nil {
		return "—"
	}
	return fmtValue(*v, unit)
}

// humanizeFloat picks a sensible precision: integers print without a
// fraction, values >= 1000 get grouped with thousands separators, and
// small fractions keep up to three significant decimals.
func humanizeFloat(v float64) string {
	switch {
	case v == float64(int64(v)):
		return groupThousands(fmt.Sprintf("%d", int64(v)))
	case v >= 1000:
		return groupThousands(fmt.Sprintf("%.0f", v))
	case v >= 1:
		return strings.TrimRight(strings.TrimRight(fmt.Sprintf("%.3f", v), "0"), ".")
	default:
		return strings.TrimRight(strings.TrimRight(fmt.Sprintf("%.4f", v), "0"), ".")
	}
}

// groupThousands inserts comma separators into the integer part of a
// (possibly signed) base-10 string.
func groupThousands(s string) string {
	neg := strings.HasPrefix(s, "-")
	if neg {
		s = s[1:]
	}
	n := len(s)
	if n <= 3 {
		if neg {
			return "-" + s
		}
		return s
	}
	var parts []string
	for n > 3 {
		parts = append(parts, s[n-3:n])
		n -= 3
	}
	parts = append(parts, s[:n])
	// reverse
	for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
		parts[i], parts[j] = parts[j], parts[i]
	}
	out := strings.Join(parts, ",")
	if neg {
		return "-" + out
	}
	return out
}

// sortedKeys returns the verdict keys in a stable display order. Used
// by callers that print a verdict tally deterministically.
func sortedKeys(m map[Verdict]int) []Verdict {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, string(k))
	}
	sort.Strings(ks)
	out := make([]Verdict, len(ks))
	for i, k := range ks {
		out[i] = Verdict(k)
	}
	return out
}
