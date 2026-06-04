package main

import (
	"fmt"

	"github.com/kennguy3n/visible-fishbone/internal/service/telemetry/s3"
)

// pipeline_e2e.go owns the `full-pipeline` subcommand: the end-to-end
// publish→consume→dedup→normalize→ClickHouse+S3 path, plus the cost
// model that turns the run's resource consumption into a per-user
// monthly figure.
//
// The live measurement (embedded NATS + ClickHouse + MinIO containers
// wired exactly as production) lives in pipeline_e2e_live.go behind
// `//go:build integration`. The dry-run path composes the container-free
// measurements (encode throughput, real compression ratio) and feeds a
// cost model grounded in those measured per-event sizes under an
// explicit per-user event-rate assumption.

// assumedEventsPerUserPerSec is the sustained per-seat telemetry event
// rate the dry-run cost model assumes. A documented assumption (no
// ground-truth production number is available to this harness); the
// integration run replaces it with the measured saturation rate.
const assumedEventsPerUserPerSec = 5.0

// chOnDiskCompressionFactor estimates ClickHouse's on-disk size relative
// to the uncompressed msgpack wire size, reflecting the writer's LZ4
// column compression. A modeling assumption used only by the dry-run
// cost estimate; the integration run reads real system.parts bytes.
const chOnDiskCompressionFactor = 0.40

// dryRunNATSNodes / dryRunCHNodes are the modeled cluster sizes the
// dry-run cost estimate prices. The integration run can read the real
// topology; here they are conservative small-cluster defaults.
const (
	dryRunNATSNodes = 3
	dryRunCHNodes   = 2
)

func runFullPipeline(opts Options) (*Report, error) {
	if !opts.DryRun {
		return liveFullPipeline(opts)
	}
	return dryRunFullPipeline(opts)
}

func dryRunFullPipeline(opts Options) (*Report, error) {
	g := NewGenerator(GenConfig{
		Tenants:       opts.Tenants,
		Seed:          opts.Seed,
		DuplicateRate: opts.DupRate,
	})
	enc, err := MeasureEncode(g, opts.Samples)
	if err != nil {
		return nil, fmt.Errorf("measure encode: %w", err)
	}
	comp, err := MeasureArchiveCompression(g, opts.Samples)
	if err != nil {
		return nil, fmt.Errorf("measure compression: %w", err)
	}

	r := NewReport("full-pipeline", nowUnix(), opts.GitSHA, opts.DryRun)

	// End-to-end throughput / latency section (modeled).
	r.AddSection(Section{
		Title:   "End-to-end pipeline (modeled)",
		Summary: fmt.Sprintf("Tenant pool %d, %.0f%% duplicates; encode + compression measured, latency/saturation modeled.", opts.Tenants, opts.DupRate*100),
		Metrics: []MetricRow{
			{
				Name: "encode throughput", Unit: "events/sec",
				Actual: enc.EventsPerSec(), Verdict: VerdictInfo,
				Note: "single-core msgpack encode ceiling (measured)",
			},
			{
				Name: "publish→insert p99", Unit: "ms",
				Actual:      0,
				Theoretical: ptr(TargetE2ELatencyP99Ms),
				Competitor:  ptr(competitorE2ELatencyP99Ms),
				Verdict:     VerdictInfo,
				Note:        "measured only under -tags=integration",
			},
		},
	})

	// S3 compression section (measured).
	uncompPerEvent := 0.0
	if comp.Events > 0 {
		uncompPerEvent = float64(comp.Uncompressed) / float64(comp.Events)
	}
	r.AddSection(Section{
		Title: "Cold-path archive compression (measured)",
		Metrics: []MetricRow{
			{Name: "compression ratio", Unit: "x", Actual: comp.Ratio(), Verdict: VerdictInfo},
			{Name: "compressed size", Unit: "B/event", Actual: comp.AvgCompressedBytesPerEvent(), Verdict: VerdictInfo},
		},
	})

	// Cost model, grounded in the measured per-event sizes.
	usersTotal := opts.Tenants * opts.UsersPerTenant
	if opts.UsersPerTenant <= 0 {
		usersTotal = opts.Tenants
	}
	eventsPerSec := float64(usersTotal) * assumedEventsPerUserPerSec
	usage := ResourceUsage{
		DurationSecs:        1.0,
		EventsProcessed:     uint64(eventsPerSec),
		Tenants:             opts.Tenants,
		UsersPerTenant:      opts.UsersPerTenant,
		RetentionDays:       0, // model uses the writer's 60-day default
		NATSNodeCount:       dryRunNATSNodes,
		CHNodeCount:         dryRunCHNodes,
		CHDiskBytes:         uint64(eventsPerSec * enc.AvgWireBytes() * chOnDiskCompressionFactor),
		S3Objects:           uint64(eventsPerSec / float64(s3.DefaultMaxEventsPerObject)),
		S3CompressedBytes:   uint64(eventsPerSec * comp.AvgCompressedBytesPerEvent()),
		S3UncompressedBytes: uint64(eventsPerSec * uncompPerEvent),
	}
	breakdown := usage.ComputeCost(DefaultPricing())
	r.AddSection(CostSection(breakdown, TargetCostPerUserMonthUSD, competitorCostPerUserMonthUSD))

	r.AddCaveat(fmt.Sprintf("Cost model assumes %.0f telemetry events/user/sec sustained and a %d-node NATS / %d-node ClickHouse cluster; these are modeling assumptions, not measured topology.", assumedEventsPerUserPerSec, dryRunNATSNodes, dryRunCHNodes))
	r.AddCaveat(fmt.Sprintf("ClickHouse on-disk size is estimated at %.0f%% of the msgpack wire size (LZ4); the integration run reads real system.parts bytes instead.", chOnDiskCompressionFactor*100))
	r.AddCaveat("All dollar figures are AWS us-east-1 on-demand list prices and a steady-state extrapolation — an order-of-magnitude model, not a quote.")
	r.AddCaveat("Run with -tags=integration for measured end-to-end latency, saturation events/sec, dedup hit rate, and real per-object S3 sizes.")
	return r, nil
}
