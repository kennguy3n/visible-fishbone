package main

import (
	"os"
	"strconv"
	"strings"
)

// BusinessReport is the consolidated document. It is serialized to
// business-report.json and rendered to business-report.md.
type BusinessReport struct {
	GeneratedUnixSecs int64  `json:"generated_unix_secs"`
	GitSHA            string `json:"git_sha,omitempty"`
	// Live is false for synthetic/dry-run inputs (verdicts shown as N/A).
	Live        bool         `json:"live"`
	Theoretical *Theoretical `json:"theoretical"`
	// Competitors is the canonical reference dataset, carried through into
	// business-report.json. The markdown tables render from the matched figures
	// the upstream harnesses embed (rep.CompetitorComparison / cp.Competitor),
	// so editing competitors.json alone does not change rendered tables — the
	// upstream report must be regenerated.
	Competitors  *Competitors        `json:"competitors"`
	ControlPlane *ControlPlaneReport `json:"control_plane,omitempty"`
	Telemetry    []*TelemetryReport  `json:"telemetry,omitempty"`
	Edge         *EdgeReport         `json:"edge,omitempty"`
	TestSuite    *TestSuite          `json:"test_suite,omitempty"`
	// Efficacy holds the security-efficacy harness output (Section 7).
	// Unlike the throughput sections, these are real enforcement
	// decisions measured against known-bad/known-good corpora, so their
	// PASS/WARN/FAIL verdicts stand even in dry-run mode (like the
	// Criterion policy-eval numbers).
	Efficacy *EfficacyReport `json:"efficacy,omitempty"`
}

// ---------------------------------------------------------------------------
// Security-efficacy report (sng-efficacy harness, bench/efficacy)
// ---------------------------------------------------------------------------

// EfficacyReport mirrors the JSON emitted by the Rust sng-efficacy
// harness: one entry per security function (FW/SWG/ZTNA/IPS) with a
// confusion matrix and catch / false-positive rates.
type EfficacyReport struct {
	Suite          string              `json:"suite"`
	GitSHA         string              `json:"git_sha"`
	GeneratedAt    string              `json:"generated_at"`
	Host           string              `json:"host"`
	OverallVerdict string              `json:"overall_verdict"`
	Functions      []*EfficacyFunction `json:"functions"`
}

// EfficacyFunction is the per-function efficacy result.
type EfficacyFunction struct {
	Function       string  `json:"function"`
	Crate          string  `json:"crate"`
	Kind           string  `json:"kind"` // "enforcement" | "detection"
	Tested         bool    `json:"tested"`
	UntestedReason string  `json:"untested_reason,omitempty"`
	TotalCases     int     `json:"total_cases"`
	BadCases       int     `json:"bad_cases"`
	GoodCases      int     `json:"good_cases"`
	TP             int     `json:"tp"`
	FN             int     `json:"fn"`
	TN             int     `json:"tn"`
	FP             int     `json:"fp"`
	CatchRate      float64 `json:"catch_rate"`
	FalsePosRate   float64 `json:"false_positive_rate"`
	Accuracy       float64 `json:"accuracy"`
	Verdict        string  `json:"verdict"`
	Notes          string  `json:"notes,omitempty"`
	// Features describes WHAT the function does and HOW (capability
	// catalog); Throughput holds measured hot-path performance. Both are
	// optional — only DLP/ZTNA populate them today.
	Features   []EfficacyFeature    `json:"features,omitempty"`
	Throughput []EfficacyThroughput `json:"throughput,omitempty"`
}

// EfficacyFeature is one capability the function exercises, with a
// one-line mechanism description for the feature catalog.
type EfficacyFeature struct {
	Name     string `json:"name"`
	How      string `json:"how"`
	Coverage string `json:"coverage"`
}

// EfficacyThroughput is one measured hot-path performance point.
type EfficacyThroughput struct {
	Label      string   `json:"label"`
	Unit       string   `json:"unit"`
	Iterations int64    `json:"iterations"`
	PerOpNs    float64  `json:"per_op_ns"`
	OpsPerSec  float64  `json:"ops_per_sec"`
	BytesPerOp *int64   `json:"bytes_per_op,omitempty"`
	MBPerSec   *float64 `json:"mb_per_sec,omitempty"`
	// DebugBuild is true when the figure came from an unoptimized build
	// (an order of magnitude slower than release) — surfaced as a caveat.
	DebugBuild bool `json:"debug_build"`
}

// ---------------------------------------------------------------------------
// Session 4 — test-suite-report.md parser
// ---------------------------------------------------------------------------

// TestSuite holds the counts and Criterion numbers parsed out of the Session 4
// markdown report.
type TestSuite struct {
	Layers    []TestLayer    `json:"layers"`
	Criterion []CriterionRow `json:"criterion"`
}

type TestLayer struct {
	Name    string `json:"name"`
	Run     int    `json:"run"`
	Passed  int    `json:"passed"`
	Failed  int    `json:"failed"`
	Skipped int    `json:"skipped"`
}

type CriterionRow struct {
	Shape string  `json:"shape"`
	Ns    float64 `json:"ns"`
	Range string  `json:"range,omitempty"`
}

// loadTestSuite extracts the summary-table layer counts and the Criterion
// policy-eval rows from the Session 4 markdown. It is tolerant: rows that do
// not match the expected shape are skipped rather than erroring.
func loadTestSuite(path string) (*TestSuite, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	ts := &TestSuite{}
	for _, line := range strings.Split(string(b), "\n") {
		cells := tableCells(line)
		switch len(cells) {
		case 6: // | Layer | Command | Run | Passed | Failed | Skipped |
			run, e1 := strconv.Atoi(cells[2])
			pass, e2 := strconv.Atoi(cells[3])
			fail, e3 := strconv.Atoi(cells[4])
			skip, e4 := strconv.Atoi(cells[5])
			if e1 == nil && e2 == nil && e3 == nil && e4 == nil && cells[0] != "Layer" {
				ts.Layers = append(ts.Layers, TestLayer{
					Name: cells[0], Run: run, Passed: pass, Failed: fail, Skipped: skip,
				})
			}
		case 3: // | `evaluate/shape` | 12.770 ns | [range] |
			shape := strings.Trim(cells[0], "`")
			if strings.HasPrefix(shape, "evaluate/") {
				if ns, ok := parseNs(cells[1]); ok {
					ts.Criterion = append(ts.Criterion, CriterionRow{
						Shape: shape, Ns: ns, Range: cells[2],
					})
				}
			}
		}
	}
	return ts, nil
}

// tableCells splits a markdown table row into its inner cells, returning nil for
// non-table lines and separator rows (| --- | --- |).
func tableCells(line string) []string {
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, "|") || !strings.HasSuffix(line, "|") {
		return nil
	}
	parts := strings.Split(line, "|")
	parts = parts[1 : len(parts)-1] // drop the empty ends
	cells := make([]string, 0, len(parts))
	for _, p := range parts {
		cells = append(cells, strings.TrimSpace(p))
	}
	for _, c := range cells {
		if strings.Trim(c, "-: ") != "" {
			return cells
		}
	}
	return nil // separator row
}

// parseNs reads a "12.770 ns" style cell into nanoseconds.
func parseNs(cell string) (float64, bool) {
	f := strings.Fields(strings.Trim(cell, "`"))
	if len(f) < 2 || !strings.HasPrefix(f[1], "ns") {
		return 0, false
	}
	v, err := strconv.ParseFloat(f[0], 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

// ---------------------------------------------------------------------------
// Verdict helpers
// ---------------------------------------------------------------------------

const warnBand = 0.20 // within 20% of target -> WARN rather than FAIL

// grade returns PASS/WARN/FAIL comparing actual against target. When
// higherIsBetter is true (e.g. throughput) PASS means actual >= target; when
// false (e.g. latency, cost) PASS means actual <= target.
func grade(actual, target float64, higherIsBetter bool) string {
	if target <= 0 {
		return "N/A"
	}
	if higherIsBetter {
		switch {
		case actual >= target:
			return "PASS"
		case actual >= target*(1-warnBand):
			return "WARN"
		default:
			return "FAIL"
		}
	}
	switch {
	case actual <= target:
		return "PASS"
	case actual <= target*(1+warnBand):
		return "WARN"
	default:
		return "FAIL"
	}
}

// verdict renders a verdict cell, masking it to N/A in dry-run mode where the
// inputs are synthetic load-generator figures rather than enforced numbers.
func (r *BusinessReport) verdict(v string) string {
	if !r.Live {
		return "N/A (dry-run)"
	}
	return v
}

func num(f float64) string {
	// Only take the integer shortcut when f is safely within int64 range;
	// converting an out-of-range float64 to int64 is implementation-defined.
	if f > -1e15 && f < 1e15 && f == float64(int64(f)) {
		return strconv.FormatInt(int64(f), 10)
	}
	return strconv.FormatFloat(f, 'f', 2, 64)
}
