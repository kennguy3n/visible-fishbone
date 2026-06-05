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

	below := &BusinessReport{Theoretical: theo, Telemetry: []*TelemetryReport{costReport(0.10)}}
	if containsSubstr(below.strengths(), "sits inside") {
		t.Error("cost below envelope must NOT be claimed as inside")
	}
	if !containsSubstr(below.gaps(), "below") {
		t.Error("cost below envelope lower bound should be flagged as a gap")
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

func TestSecurityEfficacySection(t *testing.T) {
	r := &BusinessReport{
		Efficacy: &EfficacyReport{
			Suite:          "security-efficacy",
			Host:           "test-host",
			OverallVerdict: "PASS",
			Functions: []*EfficacyFunction{
				{
					Function: "firewall", Crate: "sng-fw", Kind: "enforcement", Tested: true,
					TotalCases: 10, BadCases: 6, GoodCases: 4,
					TP: 6, FN: 0, TN: 4, FP: 0,
					CatchRate: 1.0, FalsePosRate: 0.0, Accuracy: 1.0,
					Verdict: "PASS", Notes: "real engine deny path",
				},
				{
					Function: "ips", Crate: "sng-ips", Kind: "detection", Tested: false,
					UntestedReason: "suricata binary not found on PATH",
					Verdict:        "UNTESTED",
				},
			},
		},
	}

	md := r.ToMarkdown()
	for _, want := range []string{
		"## 7. Security Efficacy",
		"Overall efficacy verdict: PASS",
		"| firewall | `sng-fw` | block-rate | 6 | 4 | 100.0% | 0.0% | 100.0% | PASS |",
		"detection-rate", // IPS row uses the detection KPI label
		"UNTESTED",
		"suricata binary not found on PATH",
		"Security efficacy", // executive-summary row
	} {
		if !strings.Contains(md, want) {
			t.Errorf("efficacy markdown missing %q", want)
		}
	}

	// A perfect tested corpus with zero false-positives is a data-backed
	// strength.
	if !containsSubstr(r.strengths(), "Security enforcement is correct end-to-end") {
		t.Error("perfect efficacy corpus should surface as a strength")
	}

	// A missed known-bad case (false negative) must NOT be claimed as a
	// strength.
	r.Efficacy.Functions[0].TP = 5
	r.Efficacy.Functions[0].FN = 1
	if containsSubstr(r.strengths(), "Security enforcement is correct end-to-end") {
		t.Error("efficacy with a false negative must not be claimed as a clean strength")
	}
}

func TestSecurityEfficacyCapabilities(t *testing.T) {
	bytesPerOp := int64(640)
	mbps := 2.5
	r := &BusinessReport{
		Efficacy: &EfficacyReport{
			Suite: "security-efficacy", Host: "h", OverallVerdict: "PASS",
			Functions: []*EfficacyFunction{
				{
					Function: "dlp", Crate: "sng-dlp", Kind: "detection", Tested: true,
					TotalCases: 2, BadCases: 1, GoodCases: 1, TP: 1, TN: 1,
					CatchRate: 1.0, FalsePosRate: 0.0, Accuracy: 1.0, Verdict: "PASS",
					Features: []EfficacyFeature{{
						Name:     "Check-digit validators",
						How:      "statutory check digit confirms each match | suppresses fakes",
						Coverage: "11 detectors",
					}},
					Throughput: []EfficacyThroughput{{
						Label: "classify", Unit: "scans/s", Iterations: 5000,
						PerOpNs: 207884, OpsPerSec: 4810,
						BytesPerOp: &bytesPerOp, MBPerSec: &mbps, DebugBuild: false,
					}},
				},
			},
		},
	}
	md := r.ToMarkdown()
	for _, want := range []string{
		"### 7.1 DLP (Data Loss Prevention) — Capabilities & Performance",
		"**What it does / how it works**",
		"| Capability | How it works | Coverage |",
		"| **Check-digit validators** |",
		// Pipe inside a feature description must be escaped so the row stays intact.
		"confirms each match \\| suppresses fakes",
		"**Performance (measured hot path)**",
		// Thousands separators + µs latency conversion + MB/s bandwidth.
		"| `classify` | 4,810 scans/s | 208 µs | 2.5 MB/s | 5,000 |",
		"release build",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("capabilities markdown missing %q\n---\n%s", want, md)
		}
	}
	// Release build must NOT carry the debug caveat.
	if strings.Contains(md, "Debug build.") {
		t.Error("release-build throughput must not render the debug caveat")
	}

	// Flip to a debug build: the caveat appears.
	r.Efficacy.Functions[0].Throughput[0].DebugBuild = true
	if !strings.Contains(r.ToMarkdown(), "Debug build.") {
		t.Error("debug-build throughput must render the debug caveat")
	}
}

func TestThroughputFormatHelpers(t *testing.T) {
	for _, tc := range []struct {
		in   float64
		want string
	}{
		{4810, "4,810"}, {1901606, "1,901,606"}, {526, "526"},
		{2.5, "2.5"}, {0.2, "0.2"}, {99.9, "99.9"},
	} {
		if got := humanFloat(tc.in); got != tc.want {
			t.Errorf("humanFloat(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
	for _, tc := range []struct {
		ns   float64
		want string
	}{
		{526, "526 ns"}, {207884, "208 µs"}, {3379422, "3.4 ms"},
	} {
		if got := perOpLatency(tc.ns); got != tc.want {
			t.Errorf("perOpLatency(%v) = %q, want %q", tc.ns, got, tc.want)
		}
	}
	if got := humanInt(50000); got != "50,000" {
		t.Errorf("humanInt(50000) = %q, want 50,000", got)
	}
	if got := mdCell("a|b\nc"); got != "a\\|b c" {
		t.Errorf("mdCell escaping = %q, want %q", got, "a\\|b c")
	}
}

func TestSecurityEfficacyMissing(t *testing.T) {
	r := &BusinessReport{}
	md := r.ToMarkdown()
	if !strings.Contains(md, "## 7. Security Efficacy") {
		t.Error("Section 7 header should render even when no efficacy report is supplied")
	}
	if !strings.Contains(md, "No efficacy report supplied") {
		t.Error("missing efficacy report should render the placeholder note")
	}
}

// TestEfficacyJSONContract locks the Go<->Rust wire contract for the
// efficacy report. The Go structs have no shared schema definition with the
// Rust `sng-efficacy` harness, so a Rust-side serde rename could silently
// break deserialization. This test feeds a payload that mirrors the *exact*
// JSON the Rust harness emits — including the renamed `crate`/`fn` keys and
// the Rust-only `targets`/`cases` objects Go must ignore — through the real
// loadEfficacy path and asserts every field the renderer relies on populates.
// If a future Rust rename drifts from this golden shape, this test fails
// instead of the report silently rendering empty cells.
func TestEfficacyJSONContract(t *testing.T) {
	// Byte-for-byte representative of `bench/efficacy` output: note `crate`
	// (Rust `crate_name`), `fn` (Rust `fn_`), and the Rust-only `targets`
	// and `cases` keys that the Go structs deliberately omit.
	const payload = `{
  "suite": "security-efficacy",
  "git_sha": "deadbee",
  "generated_at": "2026-06-04T00:00:00Z",
  "host": "ci-runner",
  "overall_verdict": "PASS",
  "functions": [
    {
      "function": "firewall",
      "crate": "sng-fw",
      "kind": "enforcement",
      "tested": true,
      "total_cases": 12,
      "bad_cases": 7,
      "good_cases": 5,
      "tp": 7,
      "fn": 0,
      "tn": 5,
      "fp": 0,
      "catch_rate": 1.0,
      "false_positive_rate": 0.0,
      "accuracy": 1.0,
      "targets": {"catch_pass": 0.99, "catch_warn": 0.9, "fp_pass": 0.02, "fp_warn": 0.05},
      "verdict": "PASS",
      "notes": "real engine deny path",
      "features": [
        {"name": "Check-digit validators", "how": "statutory check digit confirms each match", "coverage": "11 detectors"}
      ],
      "throughput": [
        {"label": "classify", "unit": "scans/s", "iterations": 5000, "per_op_ns": 207884.0, "ops_per_sec": 4810.0, "bytes_per_op": 640, "mb_per_sec": 2.5, "debug_build": false}
      ],
      "cases": [
        {"description": "deny tcp/9999", "bad": true, "expected": "deny", "actual": "deny", "correct": true}
      ]
    },
    {
      "function": "ips",
      "crate": "sng-ips",
      "kind": "detection",
      "tested": false,
      "untested_reason": "suricata binary not found on PATH",
      "verdict": "UNTESTED"
    }
  ]
}`
	path := filepath.Join(t.TempDir(), "efficacy-report.json")
	if err := os.WriteFile(path, []byte(payload), 0o644); err != nil {
		t.Fatal(err)
	}

	r, err := loadEfficacy(path)
	if err != nil {
		t.Fatalf("loadEfficacy rejected the Rust schema (contract drift?): %v", err)
	}
	if r.Suite != "security-efficacy" || r.OverallVerdict != "PASS" || r.Host != "ci-runner" {
		t.Fatalf("top-level fields not populated: %+v", r)
	}
	if len(r.Functions) != 2 {
		t.Fatalf("want 2 functions, got %d", len(r.Functions))
	}

	fw := r.Functions[0]
	// The renamed keys are the fragile part of the contract: `crate`->Crate
	// and `fn`->FN. Assert them explicitly.
	if fw.Crate != "sng-fw" {
		t.Errorf(`"crate" did not map to Crate: got %q`, fw.Crate)
	}
	if fw.FN != 0 || fw.TP != 7 || fw.TN != 5 || fw.FP != 0 {
		t.Errorf("confusion matrix mismatch: tp=%d fn=%d tn=%d fp=%d", fw.TP, fw.FN, fw.TN, fw.FP)
	}
	if fw.Function != "firewall" || fw.Kind != "enforcement" || !fw.Tested ||
		fw.CatchRate != 1.0 || fw.FalsePosRate != 0.0 || fw.Verdict != "PASS" {
		t.Errorf("firewall function fields mismatch: %+v", fw)
	}
	// New capability/throughput fields are part of the same wire contract.
	if len(fw.Features) != 1 || fw.Features[0].Name != "Check-digit validators" ||
		fw.Features[0].Coverage != "11 detectors" {
		t.Errorf("features did not deserialize: %+v", fw.Features)
	}
	if len(fw.Throughput) != 1 {
		t.Fatalf("throughput did not deserialize: %+v", fw.Throughput)
	}
	thr := fw.Throughput[0]
	if thr.Label != "classify" || thr.Unit != "scans/s" || thr.Iterations != 5000 ||
		thr.OpsPerSec != 4810.0 || thr.DebugBuild {
		t.Errorf("throughput scalar fields mismatch: %+v", thr)
	}
	if thr.BytesPerOp == nil || *thr.BytesPerOp != 640 || thr.MBPerSec == nil || *thr.MBPerSec != 2.5 {
		t.Errorf("throughput optional fields mismatch: %+v", thr)
	}

	ips := r.Functions[1]
	if ips.Tested || ips.Verdict != "UNTESTED" || ips.UntestedReason != "suricata binary not found on PATH" {
		t.Errorf("untested IPS function fields mismatch: %+v", ips)
	}

	// The whole report must still render end-to-end from the deserialized data.
	md := (&BusinessReport{Efficacy: r}).ToMarkdown()
	if !strings.Contains(md, "| firewall | `sng-fw` | block-rate | 7 | 5 | 100.0% | 0.0% | 100.0% | PASS |") {
		t.Errorf("deserialized efficacy did not render the expected firewall row:\n%s", md)
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
