package main

import (
	"strings"
	"testing"
)

// sampleReport builds a fully-populated full-suite report so the
// round-trip, markdown, and verdict tests all exercise every section.
func sampleReport() *BusinessBenchmarkReport {
	r := &BusinessBenchmarkReport{
		SchemaVersion: SchemaVersion,
		Mode:          ModeFullSuite,
		UnixTimeSecs:  1_700_000_000,
		GitSHA:        "abc123",
		DryRun:        true,
		APILatency: &APILatencySection{
			Tiers: []APILatencyTier{
				{
					TenantCount: 100, DurationSecs: 60, Concurrency: 32,
					OverallP99Ms: 90, OverallRequestsPerSec: 1200, ErrorRate: 0.001,
					Endpoints: []EndpointLatency{
						{Method: "GET", Route: "/api/v1/tenants/{tenant_id}", Count: 1000, P99Ms: 80, MaxMs: 120, RequestsPerSec: 600},
					},
				},
				{
					TenantCount: 1000, DurationSecs: 60, Concurrency: 64,
					OverallP99Ms: 150, OverallRequestsPerSec: 2400, ErrorRate: 0.002,
				},
			},
		},
		PolicyCompile: &PolicyCompileSection{
			PerGraphSize: []PolicyCompileResult{
				{RuleCount: 10, Target: "all", CompileMs: 2.5, BundleBytes: 1024},
				{RuleCount: 100, Target: "all", CompileMs: 18, BundleBytes: 8192},
				{RuleCount: 1000, Target: "all", CompileMs: 240, BundleBytes: 81920},
			},
			Concurrent: []ConcurrentCompileResult{
				{Tenants: 100, RuleCount: 100, WallMs: 320, MeanMs: 20, P99Ms: 45},
			},
		},
		PostgresScale: &PostgresScaleSection{
			TenantCount: 5000,
			RLS:         RLSOverhead{WithRLSP99Ms: 4.2, WithoutRLSP99Ms: 4.0, OverheadPct: 5},
			Pool:        PoolSaturation{PoolSize: 32, SaturationConcurrency: 40, MaxQueriesPerSec: 9000},
			Migration:   MigrationSpeed{RowCount: 5000, Statement: "ALTER TABLE tenants ADD COLUMN bench_flag bool", ElapsedMs: 42},
			RowCounts:   map[string]int64{"tenants": 5000, "sites": 15000, "devices": 50000},
		},
		Theoretical: DefaultTheoreticalTargets(),
		Competitor:  DefaultCompetitorBaselines(),
	}
	r.Grade()
	return r
}

func TestReportJSONRoundTrip(t *testing.T) {
	t.Parallel()
	orig := sampleReport()
	js, err := orig.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON: %v", err)
	}
	got, err := ReportFromJSON(js)
	if err != nil {
		t.Fatalf("ReportFromJSON: %v", err)
	}
	// Re-marshalling the parsed report must reproduce the bytes; the
	// report is pure data so the round-trip is byte-stable.
	js2, err := got.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON (2): %v", err)
	}
	if js != js2 {
		t.Fatalf("round-trip mismatch:\n--- first ---\n%s\n--- second ---\n%s", js, js2)
	}
	if got.PostgresScale == nil || got.PostgresScale.RowCounts["devices"] != 50000 {
		t.Fatalf("nested map lost in round-trip: %+v", got.PostgresScale)
	}
}

func TestReportFromJSONRejectsGarbage(t *testing.T) {
	t.Parallel()
	if _, err := ReportFromJSON("{not json"); err == nil {
		t.Fatal("expected error on malformed JSON, got nil")
	}
}

func TestGradeVerdictLogic(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		actual, target float64
		wantStatus     string
	}{
		"under target is pass":          {actual: 80, target: 100, wantStatus: StatusPass},
		"exactly at target is pass":     {actual: 100, target: 100, wantStatus: StatusPass},
		"within 20% over is warn":       {actual: 115, target: 100, wantStatus: StatusWarn},
		"at the 20% boundary is warn":   {actual: 120, target: 100, wantStatus: StatusWarn},
		"beyond 20% over is fail":       {actual: 121, target: 100, wantStatus: StatusFail},
		"way over is fail":              {actual: 500, target: 100, wantStatus: StatusFail},
		"no target defined yields pass": {actual: 500, target: 0, wantStatus: StatusPass},
	} {
		t.Run(name, func(t *testing.T) {
			status, gap := gradeAgainstTarget(tc.actual, tc.target)
			if status != tc.wantStatus {
				t.Fatalf("gradeAgainstTarget(%v,%v) = %s, want %s (gap=%q)",
					tc.actual, tc.target, status, tc.wantStatus, gap)
			}
			if gap == "" {
				t.Fatal("gap description must never be empty")
			}
		})
	}
}

func TestGradeUsesMaxTenantTier(t *testing.T) {
	t.Parallel()
	r := sampleReport()
	// The 1000-tenant tier (p99 150ms) must drive the API verdict,
	// not the 100-tenant tier (p99 90ms) — the worst tier is graded.
	// 150ms < 200ms target, so the verdict is PASS.
	var apiVerdict *Verdict
	for i := range r.Verdicts {
		if strings.HasPrefix(r.Verdicts[i].Metric, "API p99") {
			apiVerdict = &r.Verdicts[i]
		}
	}
	if apiVerdict == nil {
		t.Fatal("no API p99 verdict produced")
	}
	if !strings.Contains(apiVerdict.Metric, "1000 tenants") {
		t.Fatalf("API verdict should grade the max-tenant tier, got %q", apiVerdict.Metric)
	}
	if apiVerdict.Status != StatusPass {
		t.Fatalf("API verdict status = %s, want PASS (150ms < 200ms target)", apiVerdict.Status)
	}
	if apiVerdict.Actual != "150ms" {
		t.Fatalf("API verdict actual = %q, want 150ms", apiVerdict.Actual)
	}
}

func TestGradeOmitsMissingSections(t *testing.T) {
	t.Parallel()
	r := &BusinessBenchmarkReport{
		SchemaVersion: SchemaVersion,
		Mode:          ModePolicyCompile,
		Theoretical:   DefaultTheoreticalTargets(),
		Competitor:    DefaultCompetitorBaselines(),
		PolicyCompile: &PolicyCompileSection{
			PerGraphSize: []PolicyCompileResult{
				{RuleCount: 100, Target: "all", CompileMs: 18},
			},
		},
	}
	r.Grade()
	if len(r.Verdicts) != 1 {
		t.Fatalf("expected exactly 1 verdict (100-rule compile), got %d: %+v", len(r.Verdicts), r.Verdicts)
	}
	if r.Verdicts[0].Metric != "Policy compile (100 rules)" {
		t.Fatalf("unexpected verdict metric %q", r.Verdicts[0].Metric)
	}
}

func TestToMarkdownContainsHeadlineTableAndCaveat(t *testing.T) {
	t.Parallel()
	md := sampleReport().ToMarkdown()
	for _, want := range []string{
		"## SNG control-plane scale benchmark — full-suite",
		"| Metric | Theoretical | Actual | Fortinet | Zscaler | Palo Alto | Verdict |",
		"API p99 @ 1000 tenants",
		"Policy compile (100 rules)",
		"Postgres RLS overhead",
		"### API latency by tenant tier",
		"### Policy compile by graph size",
		"### Postgres at scale",
		"apples-to-apples",
		"dry-run",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown missing %q\n---\n%s", want, md)
		}
	}
}

func TestMarkdownRowCountsDeterministic(t *testing.T) {
	t.Parallel()
	// formatCountMap must sort keys so the markdown is stable.
	got := formatCountMap(map[string]int64{"devices": 50000, "sites": 15000, "tenants": 5000})
	want := "devices=50000, sites=15000, tenants=5000"
	if got != want {
		t.Fatalf("formatCountMap = %q, want %q", got, want)
	}
}

func TestDetectRegressions(t *testing.T) {
	t.Parallel()
	base := sampleReport()
	cur := sampleReport()
	// Bump the 1000-rule compile 30% (regression) and the 100-rule
	// compile 10% (within threshold, not flagged).
	for i := range cur.PolicyCompile.PerGraphSize {
		switch cur.PolicyCompile.PerGraphSize[i].RuleCount {
		case 1000:
			cur.PolicyCompile.PerGraphSize[i].CompileMs *= 1.30
		case 100:
			cur.PolicyCompile.PerGraphSize[i].CompileMs *= 1.10
		}
	}
	regs, err := DetectRegressions(base, cur, RegressionThreshold)
	if err != nil {
		t.Fatalf("DetectRegressions: %v", err)
	}
	if len(regs) != 1 || regs[0].Metric != "policy_compile_1000_rule_ms" {
		t.Fatalf("expected exactly the 1000-rule compile regression, got %+v", regs)
	}
}

func TestDetectRegressionsImprovementNotFlagged(t *testing.T) {
	t.Parallel()
	base := sampleReport()
	cur := sampleReport()
	// Halve every latency: a big improvement must never be a
	// regression.
	for i := range cur.APILatency.Tiers {
		cur.APILatency.Tiers[i].OverallP99Ms /= 2
	}
	for i := range cur.PolicyCompile.PerGraphSize {
		cur.PolicyCompile.PerGraphSize[i].CompileMs /= 2
	}
	cur.PostgresScale.RLS.OverheadPct /= 2
	regs, err := DetectRegressions(base, cur, RegressionThreshold)
	if err != nil {
		t.Fatalf("DetectRegressions: %v", err)
	}
	if len(regs) != 0 {
		t.Fatalf("improvement wrongly flagged as regression: %+v", regs)
	}
}

func TestDetectRegressionsModeMismatch(t *testing.T) {
	t.Parallel()
	base := sampleReport()
	cur := sampleReport()
	cur.Mode = ModeAPILatency
	if _, err := DetectRegressions(base, cur, RegressionThreshold); err == nil {
		t.Fatal("expected error on mode mismatch, got nil")
	}
}
