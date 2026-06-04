package main

import (
	"fmt"
	"strings"

	"github.com/kennguy3n/visible-fishbone/internal/service/telemetry/clickhouse"
)

// ch_write_rate.go owns the `ch-write-rate` subcommand: ClickHouse batch
// flush throughput across batch sizes, sharded-writer scaling, and
// tenant-scoped read latency at increasing data volumes — bypassing NATS
// and writing straight to the writer.
//
// The live measurement (a real ClickHouse testcontainer driven through
// the production clickhouse.Writer / ShardedWriter / Reader) lives in
// ch_write_rate_live.go behind `//go:build integration`. The dry-run
// path here measures row serialization throughput and documents the
// design target.

func runCHWriteRate(opts Options) (*Report, error) {
	if !opts.DryRun {
		return liveCHWriteRate(opts)
	}
	return dryRunCHWriteRate(opts)
}

func dryRunCHWriteRate(opts Options) (*Report, error) {
	g := NewGenerator(GenConfig{Tenants: opts.Tenants, Seed: opts.Seed})
	enc, err := MeasureEncode(g, opts.Samples)
	if err != nil {
		return nil, fmt.Errorf("measure encode: %w", err)
	}

	r := NewReport("ch-write-rate", nowUnix(), opts.GitSHA, opts.DryRun)
	r.AddSection(Section{
		Title: "ClickHouse write path (modeled)",
		Summary: fmt.Sprintf("Batch sizes %s, shards %s, query volumes %s are measured under -tags=integration; default batch %d.",
			intsCSV(chBatchSizes), intsCSV(chShardCounts), int64sCSV(chQueryVolumes), clickhouse.DefaultBatchSize),
		Metrics: []MetricRow{
			{
				Name: "row serialization", Unit: "rows/sec",
				Actual: enc.EventsPerSec(), Verdict: VerdictInfo,
				Note: "single-core encode throughput; an upper bound on what the batch writer can be fed",
			},
			{
				Name: "avg row wire size", Unit: "B/row",
				Actual: enc.AvgWireBytes(), Verdict: VerdictInfo,
			},
			{
				Name: "batch insert target", Unit: "rows/sec",
				Actual:      0,
				Theoretical: ptr(TargetCHBatchRowsPerSec),
				Competitor:  ptr(competitorCHRowsPerSec),
				Verdict:     VerdictInfo,
				Note:        "design target (≈10× per-row INSERT VALUES); measured value requires -tags=integration",
			},
		},
	})
	r.AddCaveat("Dry-run cannot measure ClickHouse throughput or query latency; build with -tags=integration to populate batch-size, shard-scaling, and query-latency numbers against a real ClickHouse container.")
	r.AddCaveat("The \"order of magnitude faster than per-row INSERT VALUES\" claim is the writer's documented design intent (PrepareBatch native protocol); the integration run measures the actual multiple.")
	return r, nil
}

func intsCSV(xs []int) string {
	parts := make([]string, len(xs))
	for i, x := range xs {
		parts[i] = fmt.Sprintf("%d", x)
	}
	return strings.Join(parts, "/")
}

func int64sCSV(xs []int64) string {
	parts := make([]string, len(xs))
	for i, x := range xs {
		parts[i] = humanizeFloat(float64(x))
	}
	return strings.Join(parts, "/")
}
