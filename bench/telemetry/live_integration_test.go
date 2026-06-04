//go:build integration

package main

import "testing"

// live_integration_test.go exercises the container-backed runners
// end-to-end. Gated behind `//go:build integration`; run with
// `go test -tags=integration -race ./bench/telemetry/`.

func liveOpts(sub string) Options {
	return Options{
		Subcommand:     sub,
		DryRun:         false,
		Seed:           1,
		Tenants:        50,
		DupRate:        0.10,
		UsersPerTenant: defaultUsersPerTenant,
		Samples:        2000,
	}
}

func assertReport(t *testing.T, r *Report, sub string) {
	t.Helper()
	if r == nil {
		t.Fatalf("%s returned nil report", sub)
	}
	if r.Benchmark != sub {
		t.Errorf("benchmark = %q, want %q", r.Benchmark, sub)
	}
	if len(r.Sections) == 0 {
		t.Errorf("%s produced no sections", sub)
	}
	js, err := r.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON: %v", err)
	}
	if _, err := ReportFromJSON(js); err != nil {
		t.Fatalf("round trip: %v", err)
	}
	if len(r.ToMarkdown()) == 0 {
		t.Errorf("%s produced empty markdown", sub)
	}
}

func TestLiveIngestRate(t *testing.T) {
	r, err := liveIngestRate(liveOpts("ingest-rate"))
	if err != nil {
		t.Fatalf("liveIngestRate: %v", err)
	}
	assertReport(t, r, "ingest-rate")
}

func TestLiveCHWriteRate(t *testing.T) {
	r, err := liveCHWriteRate(liveOpts("ch-write-rate"))
	if err != nil {
		t.Fatalf("liveCHWriteRate: %v", err)
	}
	assertReport(t, r, "ch-write-rate")
}

func TestLiveS3Archive(t *testing.T) {
	r, err := liveS3Archive(liveOpts("s3-archive-rate"))
	if err != nil {
		t.Fatalf("liveS3Archive: %v", err)
	}
	assertReport(t, r, "s3-archive-rate")
}

func TestLiveFullPipeline(t *testing.T) {
	r, err := liveFullPipeline(liveOpts("full-pipeline"))
	if err != nil {
		t.Fatalf("liveFullPipeline: %v", err)
	}
	assertReport(t, r, "full-pipeline")
}
