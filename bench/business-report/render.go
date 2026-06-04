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
	Live         bool                `json:"live"`
	Theoretical  *Theoretical        `json:"theoretical"`
	Competitors  *Competitors        `json:"competitors"`
	ControlPlane *ControlPlaneReport `json:"control_plane,omitempty"`
	Telemetry    []*TelemetryReport  `json:"telemetry,omitempty"`
	Edge         *EdgeReport         `json:"edge,omitempty"`
	TestSuite    *TestSuite          `json:"test_suite,omitempty"`
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
