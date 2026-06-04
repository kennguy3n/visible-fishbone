package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// usage is printed for -h and on a missing/unknown subcommand.
const usage = `controlplane-bench — SNG control-plane scale benchmark

Usage:
  controlplane-bench <subcommand> [flags]

Subcommands:
  api-latency      Mixed REST workload (60% read / 30% write / 10% heavy) per tenant tier
  policy-compile   In-process policy-graph compilation across sizes/targets/concurrency
  tenant-scale     Postgres RLS overhead, pool saturation, and online-DDL speed at scale
  full-suite       All of the above, into one report

Common flags:
  --dry-run                Synthesise the workload (no live control plane / Postgres). Self-testable on CI.
  --out DIR                Directory to write report.json + report.md (default: stdout only)
  --git-sha SHA            Record the commit under test (default: $GIT_SHA)
  --baseline FILE          Compare against a prior report.json and fail on >20% regression

api-latency / full-suite flags:
  --url URL                Control-plane base URL (required unless --dry-run)
  --tenant-tiers CSV       Tenant pre-seed tiers (default: 100,500,1000,5000)
  --concurrency N          Concurrent virtual clients (default: 32)
  --duration DUR           Measurement window per tier (default: 60s)
  --jwt-secret S           HS256 secret to mint operator JWTs
  --jwt-issuer S           Expected iss claim
  --jwt-audience S         Expected aud claim
  --api-key S              API key (alternative to JWT)

tenant-scale / full-suite flags:
  --dsn DSN                Postgres DSN with SNG migrations applied (required unless --dry-run)
  --tenants N              Tenants to seed (default: 5000)
  --pool-size N            App connection-pool size to probe (default: 32)
`

// options holds the parsed CLI flags shared across subcommands.
type options struct {
	dryRun      bool
	out         string
	gitSHA      string
	baseline    string
	url         string
	tenantTiers string
	concurrency int
	duration    time.Duration
	jwtSecret   string
	jwtIssuer   string
	jwtAudience string
	apiKey      string
	dsn         string
	tenants     int
	poolSize    int
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	mode := os.Args[1]
	switch mode {
	case "-h", "--help", "help":
		fmt.Fprint(os.Stdout, usage)
		return
	case ModeAPILatency, ModePolicyCompile, ModeTenantScale, ModeFullSuite:
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n\n%s", mode, usage)
		os.Exit(2)
	}

	opts := parseFlags(mode, os.Args[2:])
	if err := run(context.Background(), mode, opts); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func parseFlags(mode string, args []string) *options {
	fs := flag.NewFlagSet(mode, flag.ExitOnError)
	opts := &options{}
	fs.BoolVar(&opts.dryRun, "dry-run", false, "synthesise the workload (no live deps)")
	fs.StringVar(&opts.out, "out", "", "directory to write report.json + report.md")
	fs.StringVar(&opts.gitSHA, "git-sha", os.Getenv("GIT_SHA"), "commit under test")
	fs.StringVar(&opts.baseline, "baseline", "", "prior report.json to compare against")
	fs.StringVar(&opts.url, "url", "", "control-plane base URL")
	fs.StringVar(&opts.tenantTiers, "tenant-tiers", "100,500,1000,5000", "tenant pre-seed tiers (CSV)")
	fs.IntVar(&opts.concurrency, "concurrency", 32, "concurrent virtual clients")
	fs.DurationVar(&opts.duration, "duration", 60*time.Second, "measurement window per tier")
	fs.StringVar(&opts.jwtSecret, "jwt-secret", os.Getenv("SNG_JWT_SECRET"), "HS256 secret to mint operator JWTs")
	fs.StringVar(&opts.jwtIssuer, "jwt-issuer", "", "expected iss claim")
	fs.StringVar(&opts.jwtAudience, "jwt-audience", "", "expected aud claim")
	fs.StringVar(&opts.apiKey, "api-key", "", "API key (alternative to JWT)")
	fs.StringVar(&opts.dsn, "dsn", os.Getenv("SNG_BENCH_DSN"), "Postgres DSN")
	fs.IntVar(&opts.tenants, "tenants", 5000, "tenants to seed (tenant-scale)")
	fs.IntVar(&opts.poolSize, "pool-size", 32, "app connection-pool size to probe")
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	// ExitOnError handles the error path; the assignment keeps the
	// linter from flagging the unchecked return.
	_ = fs.Parse(args)
	return opts
}

func run(ctx context.Context, mode string, opts *options) error {
	report := &BusinessBenchmarkReport{
		SchemaVersion: SchemaVersion,
		Mode:          mode,
		UnixTimeSecs:  time.Now().Unix(),
		GitSHA:        opts.gitSHA,
		DryRun:        opts.dryRun,
		Theoretical:   DefaultTheoreticalTargets(),
		Competitor:    DefaultCompetitorBaselines(),
	}

	wantAPI := mode == ModeAPILatency || mode == ModeFullSuite
	wantCompile := mode == ModePolicyCompile || mode == ModeFullSuite
	wantPG := mode == ModeTenantScale || mode == ModeFullSuite

	if wantAPI {
		section, err := buildAPILatency(ctx, opts)
		if err != nil {
			return err
		}
		report.APILatency = section
	}
	if wantCompile {
		cfg := DefaultPolicyCompileConfig()
		if opts.dryRun {
			cfg = QuickPolicyCompileConfig()
		}
		section, err := RunPolicyCompileBench(cfg)
		if err != nil {
			return fmt.Errorf("policy-compile bench: %w", err)
		}
		report.PolicyCompile = section
	}
	if wantPG {
		section, err := buildPostgresScale(ctx, opts)
		if err != nil {
			return err
		}
		report.PostgresScale = section
	}

	report.Grade()

	if err := emit(report, opts.out); err != nil {
		return err
	}
	return checkRegression(report, opts.baseline)
}

func buildAPILatency(ctx context.Context, opts *options) (*APILatencySection, error) {
	tiers, err := parseCSVInts(opts.tenantTiers)
	if err != nil {
		return nil, fmt.Errorf("--tenant-tiers: %w", err)
	}
	if opts.dryRun {
		return dryRunAPILatency(tiers, opts.concurrency), nil
	}
	cfg := &APILatencyConfig{
		BaseURL:      opts.url,
		JWTSecret:    opts.jwtSecret,
		JWTIssuer:    opts.jwtIssuer,
		JWTAudience:  opts.jwtAudience,
		APIKey:       opts.apiKey,
		TenantCounts: tiers,
		Concurrency:  opts.concurrency,
		Duration:     opts.duration,
	}
	section, err := RunAPILatencyBench(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("api-latency bench: %w", err)
	}
	return section, nil
}

func buildPostgresScale(ctx context.Context, opts *options) (*PostgresScaleSection, error) {
	if opts.dryRun {
		return dryRunPostgresScale(opts.tenants, opts.poolSize), nil
	}
	cfg := DefaultPostgresScaleConfig(opts.dsn)
	cfg.TenantCount = opts.tenants
	cfg.PoolSize = opts.poolSize
	section, err := RunPostgresScaleBench(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("postgres-scale bench: %w", err)
	}
	return section, nil
}

// emit writes the report as JSON + markdown to outDir (when set) and
// always prints the markdown summary to stdout.
func emit(report *BusinessBenchmarkReport, outDir string) error {
	js, err := report.ToJSON()
	if err != nil {
		return err
	}
	md := report.ToMarkdown()

	if outDir != "" {
		if err := os.MkdirAll(outDir, 0o750); err != nil {
			return fmt.Errorf("create out dir: %w", err)
		}
		jsonPath := filepath.Join(outDir, "report.json")
		mdPath := filepath.Join(outDir, "report.md")
		if err := os.WriteFile(jsonPath, []byte(js+"\n"), 0o644); err != nil { //nolint:gosec // report artifact, not a secret
			return fmt.Errorf("write %s: %w", jsonPath, err)
		}
		if err := os.WriteFile(mdPath, []byte(md), 0o644); err != nil { //nolint:gosec // report artifact, not a secret
			return fmt.Errorf("write %s: %w", mdPath, err)
		}
		fmt.Fprintf(os.Stderr, "wrote %s and %s\n", jsonPath, mdPath)
	}
	fmt.Fprintln(os.Stdout, md)
	return nil
}

// checkRegression loads a baseline report (when provided), compares the
// current report against it, and returns a non-nil error when any
// metric regressed past RegressionThreshold — so CI fails the run.
func checkRegression(current *BusinessBenchmarkReport, baselinePath string) error {
	if baselinePath == "" {
		return nil
	}
	raw, err := os.ReadFile(baselinePath) //nolint:gosec // operator-supplied baseline path
	if err != nil {
		return fmt.Errorf("read baseline: %w", err)
	}
	baseline, err := ReportFromJSON(string(raw))
	if err != nil {
		return fmt.Errorf("parse baseline: %w", err)
	}
	regs, err := DetectRegressions(baseline, current, RegressionThreshold)
	if err != nil {
		return fmt.Errorf("compare against baseline: %w", err)
	}
	if len(regs) > 0 {
		var b strings.Builder
		fmt.Fprintf(&b, "%d metric(s) regressed past %.0f%%:\n", len(regs), RegressionThreshold*100)
		for _, r := range regs {
			fmt.Fprintf(&b, "  - %s: %.2f -> %.2f (+%.1f%%)\n",
				r.Metric, r.Previous, r.Current, r.ChangeFraction*100)
		}
		return errors.New(b.String())
	}
	return nil
}

// parseCSVInts parses a comma-separated list of positive integers.
func parseCSVInts(csv string) ([]int, error) {
	parts := strings.Split(csv, ",")
	out := make([]int, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil, fmt.Errorf("invalid integer %q: %w", p, err)
		}
		if n <= 0 {
			return nil, fmt.Errorf("value must be positive, got %d", n)
		}
		out = append(out, n)
	}
	if len(out) == 0 {
		return nil, errors.New("no values provided")
	}
	return out, nil
}
