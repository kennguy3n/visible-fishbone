package main

import (
	"testing"
)

// smokeOpts is a small, fast dry-run configuration.
func smokeOpts(sub string) Options {
	return Options{
		Subcommand:     sub,
		DryRun:         true,
		Seed:           1,
		Tenants:        100,
		DupRate:        0.10,
		UsersPerTenant: defaultUsersPerTenant,
		Samples:        2000,
	}
}

func TestDryRunSubcommandsProduceValidReports(t *testing.T) {
	for sub, runner := range subcommands {
		t.Run(sub, func(t *testing.T) {
			r, err := runner(smokeOpts(sub))
			if err != nil {
				t.Fatalf("%s dry-run: %v", sub, err)
			}
			if r.Benchmark != sub {
				t.Errorf("benchmark = %q, want %q", r.Benchmark, sub)
			}
			if r.SchemaVersion != ReportSchemaVersion {
				t.Errorf("schema version = %d, want %d", r.SchemaVersion, ReportSchemaVersion)
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
			if md := r.ToMarkdown(); len(md) == 0 {
				t.Errorf("%s produced empty markdown", sub)
			}
		})
	}
}

func TestParseFlagsValidation(t *testing.T) {
	if _, err := parseFlags("ingest-rate", []string{"--dup-rate", "1.5"}); err == nil {
		t.Error("expected error for dup-rate >= 1")
	}
	if _, err := parseFlags("ingest-rate", []string{"--samples", "0"}); err == nil {
		t.Error("expected error for samples <= 0")
	}
	opts, err := parseFlags("ingest-rate", []string{"--dry-run", "--tenants", "500"})
	if err != nil {
		t.Fatalf("parseFlags: %v", err)
	}
	if !opts.DryRun || opts.Tenants != 500 {
		t.Fatalf("unexpected opts: %+v", opts)
	}
}
