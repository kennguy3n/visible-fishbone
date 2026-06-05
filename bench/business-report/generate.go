// Command business-report consolidates the Wave-1 benchmark artifacts (the Go
// control-plane scale bench, the Go telemetry pipeline bench, and the Rust edge
// bench's business-report) together with the static theoretical targets and
// competitor datasheet numbers into a single RFP-grade markdown + JSON report.
//
// It is a standalone `package main` (not wired into cmd/sng-control), mirroring
// the sibling harnesses under bench/controlplane and bench/telemetry. It owns a
// minimal copy of each upstream report's JSON shape rather than importing those
// `package main` types.
//
// Honesty model: the harnesses can only emit synthetic load-generator numbers
// without a live data path / dedicated hardware, so the tool defaults to
// dry-run mode — it surfaces every measured value but renders verdicts as
// "N/A (dry-run)" behind a prominent banner. Pass --live only when the inputs
// come from a real in-path run, in which case PASS/WARN/FAIL is computed.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "business-report:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("business-report", flag.ContinueOnError)
	var (
		controlPlanePath = fs.String("controlplane", "", "path to the control-plane scale bench report.json (Session 1)")
		telemetryPaths   = fs.String("telemetry", "", "comma-separated telemetry report .json files, or a directory of them (Session 2)")
		edgePath         = fs.String("edge", "", "path to the Rust edge business-report .json (Session 3)")
		testReportPath   = fs.String("test-report", "", "path to the Session 4 test-suite-report.md")
		efficacyPath     = fs.String("efficacy", "", "path to the sng-efficacy harness efficacy-report.json (Section 7: Security Efficacy)")
		theoreticalPath  = fs.String("theoretical", "bench/business-report/theoretical.json", "path to theoretical.json")
		competitorsPath  = fs.String("competitors", "bench/business-report/competitors.json", "path to competitors.json")
		outDir           = fs.String("out-dir", ".", "directory to write business-report.{md,json} into")
		gitSHA           = fs.String("git-sha", "", "optional git SHA stamped into the report")
		live             = fs.Bool("live", false, "treat inputs as real in-path measurements and compute PASS/WARN/FAIL verdicts (default: dry-run, verdicts shown as N/A)")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}

	theo, err := loadTheoretical(*theoreticalPath)
	if err != nil {
		return fmt.Errorf("load theoretical: %w", err)
	}
	comps, err := loadCompetitors(*competitorsPath)
	if err != nil {
		return fmt.Errorf("load competitors: %w", err)
	}

	rep := &BusinessReport{
		GeneratedUnixSecs: time.Now().Unix(),
		GitSHA:            *gitSHA,
		Live:              *live,
		Theoretical:       theo,
		Competitors:       comps,
	}

	if *controlPlanePath != "" {
		cp, err := loadControlPlane(*controlPlanePath)
		if err != nil {
			return fmt.Errorf("load control-plane report: %w", err)
		}
		rep.ControlPlane = cp
	}
	if *telemetryPaths != "" {
		tel, err := loadTelemetry(*telemetryPaths)
		if err != nil {
			return fmt.Errorf("load telemetry report(s): %w", err)
		}
		rep.Telemetry = tel
	}
	if *edgePath != "" {
		edge, err := loadEdge(*edgePath)
		if err != nil {
			return fmt.Errorf("load edge report: %w", err)
		}
		rep.Edge = edge
	}
	if *testReportPath != "" {
		ts, err := loadTestSuite(*testReportPath)
		if err != nil {
			return fmt.Errorf("load test-suite report: %w", err)
		}
		rep.TestSuite = ts
	}
	if *efficacyPath != "" {
		eff, err := loadEfficacy(*efficacyPath)
		if err != nil {
			return fmt.Errorf("load efficacy report: %w", err)
		}
		rep.Efficacy = eff
	}

	md := rep.ToMarkdown()
	jsonBytes, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal report: %w", err)
	}

	if err := os.MkdirAll(*outDir, 0o750); err != nil {
		return fmt.Errorf("mkdir out-dir: %w", err)
	}
	mdPath := filepath.Join(*outDir, "business-report.md")
	jsonPath := filepath.Join(*outDir, "business-report.json")
	if err := os.WriteFile(mdPath, []byte(md), 0o600); err != nil {
		return fmt.Errorf("write markdown: %w", err)
	}
	if err := os.WriteFile(jsonPath, jsonBytes, 0o600); err != nil {
		return fmt.Errorf("write json: %w", err)
	}
	fmt.Printf("business report written to %s and %s\n", mdPath, jsonPath)
	return nil
}
