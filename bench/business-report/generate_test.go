package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGrade(t *testing.T) {
	tests := []struct {
		actual, target float64
		higher         bool
		want           string
	}{
		{10, 8, true, "PASS"},     // throughput exceeds target
		{7, 8, true, "WARN"},      // within 20% band
		{5, 8, true, "FAIL"},      // well below
		{100, 200, false, "PASS"}, // latency below target
		{210, 200, false, "WARN"}, // within 20% above
		{300, 200, false, "FAIL"}, // well above
		{0, 0, true, "N/A"},       // zero target
		{0, 0, false, "N/A"},      // zero target
		{8, 8, true, "PASS"},      // exactly on target (higher)
		{200, 200, false, "PASS"}, // exactly on target (lower)
	}
	for _, tc := range tests {
		got := grade(tc.actual, tc.target, tc.higher)
		if got != tc.want {
			t.Errorf("grade(%g, %g, higher=%v) = %q, want %q", tc.actual, tc.target, tc.higher, got, tc.want)
		}
	}
}

func TestTableCells(t *testing.T) {
	tests := []struct {
		line string
		want int // -1 means nil
	}{
		{"| a | b | c |", 3},
		{"| --- | --- | --- |", -1},
		{"| --- | ---: | ---: |", -1},
		{"not a table", -1},
		{"| single |", 1},
	}
	for _, tc := range tests {
		cells := tableCells(tc.line)
		if tc.want < 0 {
			if cells != nil {
				t.Errorf("tableCells(%q) = %v, want nil", tc.line, cells)
			}
		} else if len(cells) != tc.want {
			t.Errorf("tableCells(%q) len = %d, want %d", tc.line, len(cells), tc.want)
		}
	}
}

func TestNumLargeValueNoOverflow(t *testing.T) {
	// Beyond int64 range: must fall back to float formatting, not take the
	// integer shortcut (which would be implementation-defined).
	got := num(1e19)
	if !strings.Contains(got, "e") && len(got) < 18 {
		t.Errorf("num(1e19) = %q, expected float formatting", got)
	}
	if num(8) != "8" || num(2.5) != "2.50" {
		t.Errorf("num regressed on normal values: %q %q", num(8), num(2.5))
	}
}

func costReport(costPerUser float64) *TelemetryReport {
	return &TelemetryReport{
		Benchmark: "cost-model",
		Sections: []TelemetrySection{{
			Title:   "Cost",
			Metrics: []TelemetryMetric{{Name: "Infra cost / user / mo", Actual: costPerUser}},
		}},
	}
}

func TestCostEnvelopeStrengthAndGap(t *testing.T) {
	theo := &Theoretical{UnitEconomics: UnitEconomics{OverallEnvelope: []float64{0.30, 1.20}}}

	inside := &BusinessReport{Theoretical: theo, Telemetry: []*TelemetryReport{costReport(0.50)}}
	if !containsSubstr(inside.strengths(), "sits inside") {
		t.Error("cost inside envelope should be reported as a strength")
	}
	if containsSubstr(inside.gaps(), "exceeds") {
		t.Error("cost inside envelope should not be flagged as a gap")
	}

	over := &BusinessReport{Theoretical: theo, Telemetry: []*TelemetryReport{costReport(5.00)}}
	if containsSubstr(over.strengths(), "sits inside") {
		t.Error("cost above envelope must NOT be claimed as inside (regression of review bug 0001)")
	}
	if !containsSubstr(over.gaps(), "exceeds") {
		t.Error("cost above envelope should be flagged as a gap")
	}
}

func containsSubstr(items []string, want string) bool {
	for _, s := range items {
		if strings.Contains(s, want) {
			return true
		}
	}
	return false
}

func TestParseNs(t *testing.T) {
	for _, tc := range []struct {
		in   string
		ok   bool
		want float64
	}{
		{"12.770 ns", true, 12.77},
		{"100 ns", true, 100},
		{"nope", false, 0},
	} {
		got, ok := parseNs(tc.in)
		if ok != tc.ok {
			t.Errorf("parseNs(%q) ok = %v, want %v", tc.in, ok, tc.ok)
		}
		if ok && got != tc.want {
			t.Errorf("parseNs(%q) = %g, want %g", tc.in, got, tc.want)
		}
	}
}

func TestLoadTestSuiteFromString(t *testing.T) {
	md := `# Report
| Layer | Command | Run | Passed | Failed | Skipped |
| --- | --- | ---: | ---: | ---: | ---: |
| Go unit | go test | 100 | 99 | 1 | 0 |
| Rust | cargo test | 200 | 200 | 0 | 0 |

## Criterion
| Shape | Time | Range |
| --- | ---: | --- |
| ` + "`evaluate/default_action`" + ` | 12.770 ns | [12.666 ns, 12.869 ns] |
`
	tmp := t.TempDir()
	p := filepath.Join(tmp, "test.md")
	os.WriteFile(p, []byte(md), 0o644)

	ts, err := loadTestSuite(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(ts.Layers) != 2 {
		t.Fatalf("layers = %d, want 2", len(ts.Layers))
	}
	if ts.Layers[0].Failed != 1 {
		t.Errorf("layer[0].Failed = %d, want 1", ts.Layers[0].Failed)
	}
	if len(ts.Criterion) != 1 {
		t.Fatalf("criterion = %d, want 1", len(ts.Criterion))
	}
	if ts.Criterion[0].Ns != 12.77 {
		t.Errorf("criterion[0].Ns = %g, want 12.77", ts.Criterion[0].Ns)
	}
}

func TestEndToEnd(t *testing.T) {
	args := []string{
		"--theoretical", "theoretical.json",
		"--competitors", "competitors.json",
		"--out-dir", t.TempDir(),
	}
	if err := run(args); err != nil {
		t.Fatal(err)
	}
}

func TestEndToEndWithDryRunInputs(t *testing.T) {
	cpReport := ControlPlaneReport{
		SchemaVersion: 1,
		DryRun:        true,
		APILatency: &cpAPILatencySection{
			Tiers: []cpAPITier{
				{TenantCount: 100, OverallP99Ms: 50, OverallRequestsPerSec: 100},
			},
		},
		PolicyCompile: &cpPolicyCompile{
			PerGraphSize: []cpCompileResult{
				{RuleCount: 100, Target: "Edge", CompileMs: 5},
			},
		},
		Theoretical: cpTheoretical{
			APIP99Ms:                200,
			PolicyCompile100RuleMs:  100,
			PolicyCompile1000RuleMs: 1000,
		},
		Competitor: cpCompetitor{
			FortinetPolicyPushP99Ms:    500,
			ZscalerTenantCRUDP99Ms:     300,
			PaloAltoPolicyCompileP99Ms: 800,
			Caveat:                     "test caveat",
		},
		Verdicts: []cpVerdict{
			{Metric: "api_p99", Status: "PASS"},
		},
	}

	tmp := t.TempDir()
	writeJSON(t, filepath.Join(tmp, "cp.json"), cpReport)

	outDir := filepath.Join(tmp, "out")
	args := []string{
		"--theoretical", "theoretical.json",
		"--competitors", "competitors.json",
		"--controlplane", filepath.Join(tmp, "cp.json"),
		"--out-dir", outDir,
	}
	if err := run(args); err != nil {
		t.Fatal(err)
	}

	md, err := os.ReadFile(filepath.Join(outDir, "business-report.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"Business Benchmark Report",
		"Executive Summary",
		"Edge Data Path",
		"Control Plane at Scale",
		"Telemetry Pipeline",
		"Policy Evaluation",
		"Unit Economics",
		"Test Suite Health",
		"Methodology",
		"N/A (dry-run)", // verdicts are masked
	} {
		if !strings.Contains(string(md), want) {
			t.Errorf("markdown missing expected section/text: %q", want)
		}
	}

	var jr BusinessReport
	jb, err := os.ReadFile(filepath.Join(outDir, "business-report.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(jb, &jr); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	if jr.Live {
		t.Error("expected Live=false for dry-run")
	}
	if jr.ControlPlane == nil {
		t.Error("expected control-plane section in JSON")
	}
}

func writeJSON(t *testing.T, path string, v any) {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
}
