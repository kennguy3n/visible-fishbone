// Command bench/telemetry is a standalone harness that measures the
// events/sec the SNG telemetry pipeline (NATS JetStream → ClickHouse →
// S3) can sustain, plus a per-tenant cost model. It is intentionally
// NOT wired into cmd/sng-control; it is a `package main` benchmark in
// the root module, built and run on its own.
//
// Subcommands:
//
//	ingest-rate       NATS JetStream ingest throughput + per-tenant fairness
//	dedup-throughput  in-memory LRU dedup throughput (container-free)
//	ch-write-rate     ClickHouse batch / sharded write throughput + query latency
//	s3-archive-rate   S3 cold-path archive throughput + compression
//	full-pipeline     end-to-end publish→CH→S3 + cost model
//
// Every subcommand accepts --dry-run, which runs the report pipeline
// with the container-free, CPU-bound measurements (msgpack encode
// throughput, real gzip compression ratio) plus modeled projections,
// and emits a valid JSON + markdown report. The live (testcontainer)
// measurements are compiled only under `-tags=integration`; without
// that tag the live runners return errIntegrationRequired and the CLI
// directs the user to --dry-run.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Options is the parsed command-line configuration shared by every
// subcommand. Not all fields apply to every subcommand; each runner
// reads the ones it needs.
type Options struct {
	// Subcommand is the selected benchmark mode.
	Subcommand string
	// DryRun selects the container-free modeled path.
	DryRun bool
	// Seed seeds the synthetic generator for reproducibility.
	Seed uint64
	// Tenants is the tenant-pool size (per-tenant fairness / sharding).
	Tenants int
	// Duration bounds a live measurement window.
	Duration time.Duration
	// DupRate is the synthetic duplicate fraction [0,1).
	DupRate float64
	// UsersPerTenant scales tenant cost to per-user cost.
	UsersPerTenant int
	// Samples is the CPU-bound sample count for the dry-run encode /
	// compression measurements.
	Samples int
	// OutDir, when set, is where the JSON artifact is written.
	OutDir string
	// GitSHA stamps the report with the build commit.
	GitSHA string
	// JSONOut prints the JSON report to stdout instead of markdown.
	JSONOut bool
}

// errIntegrationRequired is returned by the live runners when the
// binary was built without `-tags=integration`.
var errIntegrationRequired = errors.New(
	"live measurement requires building with -tags=integration (or use --dry-run)")

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "bench/telemetry: %v\n", err)
		os.Exit(1)
	}
}

// subcommands maps a name to the runner that produces its report.
var subcommands = map[string]func(Options) (*Report, error){
	"ingest-rate":      runIngestRate,
	"dedup-throughput": runDedupThroughput,
	"ch-write-rate":    runCHWriteRate,
	"s3-archive-rate":  runS3ArchiveRate,
	"full-pipeline":    runFullPipeline,
}

func run(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("missing subcommand; one of: %s", subcommandList())
	}
	sub := args[0]
	runner, ok := subcommands[sub]
	if !ok {
		return fmt.Errorf("unknown subcommand %q; one of: %s", sub, subcommandList())
	}

	opts, err := parseFlags(sub, args[1:])
	if err != nil {
		return err
	}

	report, err := runner(opts)
	if err != nil {
		if errors.Is(err, errIntegrationRequired) {
			return fmt.Errorf("%q: %w", sub, err)
		}
		return fmt.Errorf("%q: %w", sub, err)
	}
	return emit(report, opts)
}

func parseFlags(sub string, args []string) (Options, error) {
	fs := flag.NewFlagSet(sub, flag.ContinueOnError)
	opts := Options{Subcommand: sub}
	fs.BoolVar(&opts.DryRun, "dry-run", false, "run the modeled, container-free path")
	fs.Uint64Var(&opts.Seed, "seed", 1, "PRNG seed for reproducible generation")
	fs.IntVar(&opts.Tenants, "tenants", 1000, "tenant pool size")
	fs.DurationVar(&opts.Duration, "duration", 10*time.Second, "live measurement window")
	fs.Float64Var(&opts.DupRate, "dup-rate", 0.10, "synthetic duplicate fraction [0,1)")
	fs.IntVar(&opts.UsersPerTenant, "users-per-tenant", defaultUsersPerTenant, "seats per tenant (cost model)")
	fs.IntVar(&opts.Samples, "samples", 200_000, "CPU-bound sample count for dry-run measurements")
	fs.StringVar(&opts.OutDir, "out-dir", "", "directory to write the JSON report into")
	fs.StringVar(&opts.GitSHA, "git-sha", "", "commit SHA to stamp on the report")
	fs.BoolVar(&opts.JSONOut, "json", false, "print JSON report to stdout instead of markdown")
	if err := fs.Parse(args); err != nil {
		return Options{}, err
	}
	if opts.DupRate < 0 || opts.DupRate >= 1 {
		return Options{}, fmt.Errorf("--dup-rate must be in [0,1), got %v", opts.DupRate)
	}
	if opts.Samples <= 0 {
		return Options{}, fmt.Errorf("--samples must be > 0, got %d", opts.Samples)
	}
	return opts, nil
}

func subcommandList() string {
	// Stable order for help text.
	return "ingest-rate, dedup-throughput, ch-write-rate, s3-archive-rate, full-pipeline"
}

// emit writes the JSON artifact (if --out-dir is set) and prints either
// the markdown summary or the JSON report to stdout.
func emit(r *Report, opts Options) error {
	jsonStr, err := r.ToJSON()
	if err != nil {
		return err
	}
	if opts.OutDir != "" {
		if err := os.MkdirAll(opts.OutDir, 0o750); err != nil {
			return fmt.Errorf("create out-dir: %w", err)
		}
		name := fmt.Sprintf("%s-%d.json", r.Benchmark, r.UnixTimeSecs)
		path := filepath.Join(opts.OutDir, name)
		if err := os.WriteFile(path, []byte(jsonStr), 0o644); err != nil { //nolint:gosec // bench artifact, not a secret
			return fmt.Errorf("write report: %w", err)
		}
		fmt.Fprintf(os.Stderr, "wrote %s\n", path)
	}
	if opts.JSONOut {
		fmt.Fprintln(os.Stdout, jsonStr)
	} else {
		fmt.Fprintln(os.Stdout, r.ToMarkdown())
	}
	return nil
}

// nowUnix is overridable in tests for deterministic timestamps.
var nowUnix = func() int64 { return time.Now().Unix() }
