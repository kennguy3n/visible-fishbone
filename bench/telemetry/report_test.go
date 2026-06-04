package main

import (
	"strings"
	"testing"
)

func TestReportJSONRoundTrip(t *testing.T) {
	r := NewReport("full-pipeline", 1700000000, "abc123", true)
	r.AddSection(Section{
		Title:   "Ingest",
		Summary: "modeled",
		Metrics: []MetricRow{
			{Name: "rate", Unit: "events/sec", Actual: 95000, Theoretical: ptr(100000), Competitor: ptr(50000), Verdict: VerdictWarn, Note: "soft miss"},
			{Name: "size", Unit: "B", Actual: 180, Verdict: VerdictInfo},
		},
	})
	r.AddCaveat("list price only")

	js, err := r.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON: %v", err)
	}
	got, err := ReportFromJSON(js)
	if err != nil {
		t.Fatalf("ReportFromJSON: %v", err)
	}
	if got.Benchmark != r.Benchmark || got.UnixTimeSecs != r.UnixTimeSecs ||
		got.GitSHA != r.GitSHA || got.DryRun != r.DryRun ||
		got.SchemaVersion != ReportSchemaVersion {
		t.Fatalf("header mismatch after round trip: %+v", got)
	}
	if len(got.Sections) != 1 || len(got.Sections[0].Metrics) != 2 {
		t.Fatalf("sections/metrics not preserved: %+v", got.Sections)
	}
	m0 := got.Sections[0].Metrics[0]
	if m0.Theoretical == nil || *m0.Theoretical != 100000 {
		t.Fatalf("theoretical pointer not preserved: %+v", m0)
	}
	m1 := got.Sections[0].Metrics[1]
	if m1.Theoretical != nil || m1.Competitor != nil {
		t.Fatalf("nil reference fields should stay nil: %+v", m1)
	}
	if len(got.Caveats) != 1 {
		t.Fatalf("caveats not preserved: %+v", got.Caveats)
	}
}

func TestReportMarkdownRendering(t *testing.T) {
	r := NewReport("ingest-rate", 1700000000, "", false)
	r.AddSection(Section{
		Title: "Ingest",
		Metrics: []MetricRow{
			{Name: "rate", Unit: "events/sec", Actual: 100000, Theoretical: ptr(100000), Verdict: VerdictPass},
			{Name: "lat", Unit: "ms", Actual: 250, Verdict: VerdictInfo, Note: "p99"},
		},
	})
	md := r.ToMarkdown()
	for _, want := range []string{
		"## SNG telemetry pipeline benchmark — ingest-rate",
		"mode: **live**",
		"### Ingest",
		"| metric | actual | theoretical | competitor | verdict |",
		"100,000 events/sec",
		"PASS",
		"> lat: p99",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown missing %q\n---\n%s", want, md)
		}
	}
	// A nil reference renders as an em dash.
	if !strings.Contains(md, "—") {
		t.Errorf("expected em dash for missing reference:\n%s", md)
	}
}

func TestClassify(t *testing.T) {
	cases := []struct {
		name           string
		actual         float64
		target         *float64
		higherIsBetter bool
		warn           float64
		want           Verdict
	}{
		{"nil target -> info", 5, nil, true, 0.1, VerdictInfo},
		{"higher pass", 100, ptr(100), true, 0.1, VerdictPass},
		{"higher warn", 95, ptr(100), true, 0.1, VerdictWarn},
		{"higher fail", 80, ptr(100), true, 0.1, VerdictFail},
		{"lower pass", 1.0, ptr(1.2), false, 0.1, VerdictPass},
		{"lower warn", 1.3, ptr(1.2), false, 0.1, VerdictWarn},
		{"lower fail", 2.0, ptr(1.2), false, 0.1, VerdictFail},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := classify(tc.actual, tc.target, tc.higherIsBetter, tc.warn); got != tc.want {
				t.Errorf("classify = %s, want %s", got, tc.want)
			}
		})
	}
}

func TestVerdictsTally(t *testing.T) {
	r := NewReport("x", 1, "", false)
	r.AddSection(Section{Metrics: []MetricRow{
		{Verdict: VerdictPass}, {Verdict: VerdictPass}, {Verdict: VerdictFail}, {Verdict: VerdictInfo},
	}})
	tally := r.Verdicts()
	if tally[VerdictPass] != 2 || tally[VerdictFail] != 1 || tally[VerdictInfo] != 1 {
		t.Fatalf("unexpected tally: %v", tally)
	}
	if keys := sortedKeys(tally); len(keys) != 3 {
		t.Fatalf("sortedKeys len = %d, want 3", len(keys))
	}
}

func TestGroupThousands(t *testing.T) {
	cases := map[string]string{
		"0": "0", "12": "12", "999": "999", "1000": "1,000",
		"1234567": "1,234,567", "-4096": "-4,096",
	}
	for in, want := range cases {
		if got := groupThousands(in); got != want {
			t.Errorf("groupThousands(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestHumanizeFloat(t *testing.T) {
	cases := map[float64]string{
		42:      "42",
		1500:    "1,500",
		3.19987: "3.2",
		0.305:   "0.305",
		100000:  "100,000",
	}
	for in, want := range cases {
		if got := humanizeFloat(in); got != want {
			t.Errorf("humanizeFloat(%v) = %q, want %q", in, got, want)
		}
	}
}
