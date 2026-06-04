package main

import (
	"os"
	"path/filepath"
	"testing"
)

// writeReport renders a report to a temp report.json and returns its path.
func writeReport(t *testing.T, dir, name string, r *BusinessBenchmarkReport) string {
	t.Helper()
	js, err := r.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON: %v", err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(js), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

func apiReport(p99 float64) *BusinessBenchmarkReport {
	return &BusinessBenchmarkReport{
		SchemaVersion: SchemaVersion,
		Mode:          ModeAPILatency,
		APILatency: &APILatencySection{Tiers: []APILatencyTier{
			{TenantCount: 1000, OverallP99Ms: p99},
		}},
	}
}

func TestRunCompareNoRegression(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	base := writeReport(t, dir, "baseline.json", apiReport(100))
	cur := writeReport(t, dir, "current.json", apiReport(105)) // +5% < 20%

	if err := runCompare(&options{current: cur, baseline: base, threshold: RegressionThreshold}); err != nil {
		t.Fatalf("expected no regression, got: %v", err)
	}
}

func TestRunCompareDetectsRegression(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	base := writeReport(t, dir, "baseline.json", apiReport(100))
	cur := writeReport(t, dir, "current.json", apiReport(130)) // +30% > 20%

	err := runCompare(&options{current: cur, baseline: base, threshold: RegressionThreshold})
	if err == nil {
		t.Fatal("expected a regression error for a +30% p99 movement")
	}
}

func TestRunCompareRequiresBothFiles(t *testing.T) {
	t.Parallel()
	if err := runCompare(&options{current: "x.json"}); err == nil {
		t.Fatal("expected error when --baseline is missing")
	}
	if err := runCompare(&options{baseline: "x.json"}); err == nil {
		t.Fatal("expected error when --current is missing")
	}
}

func TestRunCompareRejectsModeMismatch(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	base := writeReport(t, dir, "baseline.json", apiReport(100))
	other := &BusinessBenchmarkReport{SchemaVersion: SchemaVersion, Mode: ModePolicyCompile}
	cur := writeReport(t, dir, "current.json", other)

	if err := runCompare(&options{current: cur, baseline: base, threshold: RegressionThreshold}); err == nil {
		t.Fatal("expected error comparing api-latency baseline against a policy-compile report")
	}
}

func TestParseCSVInts(t *testing.T) {
	t.Parallel()
	got, err := parseCSVInts("100, 500 ,1000,5000")
	if err != nil {
		t.Fatalf("parseCSVInts: %v", err)
	}
	want := []int{100, 500, 1000, 5000}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
	if _, err := parseCSVInts("100,-5"); err == nil {
		t.Error("expected error for a non-positive value")
	}
	if _, err := parseCSVInts(" , "); err == nil {
		t.Error("expected error for an empty list")
	}
}
