//go:build integration

package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/kennguy3n/visible-fishbone/internal/nats/schema"
	"github.com/kennguy3n/visible-fishbone/internal/service/telemetry/clickhouse"
)

// ch_write_rate_live.go is the ClickHouse container measurement for the
// `ch-write-rate` subcommand: batch-flush throughput across batch
// sizes, sharded-writer scaling, and tenant-scoped read latency,
// driven through the production writer/reader (PrepareBatch hot path).

// chLiveRows bounds the rows written per sub-measurement so the
// container run stays inside the test timeout. Throughput is a rate, so
// a capped count still yields a representative rows/sec.
const chLiveRows = 60_000

// chLiveQueryRows is the table volume seeded before the tenant-scoped
// read-latency probe. Far below the spec's 1M/10M/100M tiers (see
// caveat) — those need a provisioned cluster, not a CI container.
const chLiveQueryRows = 50_000

// chSink is the common surface of *Writer and *ShardedWriter the
// throughput loop drives.
type chSink interface {
	EnsureSchema(context.Context) error
	Write(context.Context, schema.Envelope) error
	Stop(context.Context) error
}

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func liveCHWriteRate(opts Options) (*Report, error) {
	ctx := context.Background()
	endpoint, cleanup, err := startClickHouse(ctx)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	r := NewReport("ch-write-rate", nowUnix(), opts.GitSHA, false)

	baseCfg := clickhouse.Config{
		Endpoints:            []string{endpoint},
		Database:             "default",
		Table:                clickhouse.DefaultTable,
		FlushInterval:        100 * time.Millisecond,
		MaxBacklogMultiplier: 10_000,
		DialTimeout:          15 * time.Second,
	}

	// 1. Batch-size sweep through a single writer.
	batchSec := Section{
		Title:   "Batch-flush throughput (single writer)",
		Summary: fmt.Sprintf("%s rows per batch size through the PrepareBatch hot path.", humanizeFloat(float64(chLiveRows))),
	}
	for _, bs := range chBatchSizes {
		cfg := baseCfg
		cfg.BatchSize = bs
		w, err := clickhouse.New(ctx, cfg, quietLogger())
		if err != nil {
			return nil, fmt.Errorf("new writer (batch %d): %w", bs, err)
		}
		rate, err := measureSink(ctx, w, NewGenerator(GenConfig{Tenants: opts.Tenants, Seed: opts.Seed}), chLiveRows)
		if err != nil {
			return nil, fmt.Errorf("batch %d: %w", bs, err)
		}
		batchSec.Metrics = append(batchSec.Metrics, MetricRow{
			Name: fmt.Sprintf("batch size %d", bs), Unit: "rows/sec",
			Actual:      rate,
			Theoretical: ptr(TargetCHBatchRowsPerSec),
			Competitor:  ptr(competitorCHRowsPerSec),
			Verdict:     classify(rate, ptr(TargetCHBatchRowsPerSec), true, DefaultWarnBand),
		})
	}
	r.AddSection(batchSec)

	// 2. Sharded-writer scaling. All shards target the one container
	// node (endpoint repeated), so this isolates writer-side fan-out,
	// not backend scaling — see caveat.
	shardSec := Section{
		Title:   "Sharded-writer throughput",
		Summary: "Writer-side fan-out across N shards; all shards target the single benchmark ClickHouse node.",
	}
	for _, shards := range chShardCounts {
		cfg := baseCfg
		cfg.BatchSize = clickhouse.DefaultBatchSize
		cfg.Endpoints = repeatEndpoint(endpoint, shards)
		sw, err := clickhouse.NewShardedWriter(ctx, cfg, quietLogger())
		if err != nil {
			return nil, fmt.Errorf("new sharded writer (%d): %w", shards, err)
		}
		rate, err := measureSink(ctx, sw, NewGenerator(GenConfig{Tenants: opts.Tenants, Seed: opts.Seed}), chLiveRows)
		if err != nil {
			return nil, fmt.Errorf("shards %d: %w", shards, err)
		}
		shardSec.Metrics = append(shardSec.Metrics, MetricRow{
			Name: fmt.Sprintf("%d shard(s)", shards), Unit: "rows/sec",
			Actual: rate, Verdict: VerdictInfo,
		})
	}
	r.AddSection(shardSec)

	// 3. Tenant-scoped read latency at a (capped) seeded volume.
	qSec, err := measureCHQueryLatency(ctx, baseCfg, opts)
	if err != nil {
		return nil, err
	}
	r.AddSection(qSec)

	r.AddCaveat("All ClickHouse work targets a single containerised node; sharded-writer figures isolate writer-side fan-out, not multi-node backend scaling.")
	r.AddCaveat(fmt.Sprintf("Read latency is probed at %s seeded rows, far below the spec's 1M/10M/100M tiers — those require a provisioned cluster rather than a CI container.", humanizeFloat(float64(chLiveQueryRows))))
	r.AddCaveat("Throughput is measured end-to-end through the buffered writer (Write→async flush→Stop), i.e. real PrepareBatch inserts, not a micro-benchmark of the encode step alone.")
	return r, nil
}

// measureSink seeds the schema, writes n generated envelopes, and Stops
// (final flush), returning rows/sec over the whole window.
func measureSink(ctx context.Context, sink chSink, g *Generator, n int) (float64, error) {
	if err := sink.EnsureSchema(ctx); err != nil {
		_ = sink.Stop(ctx)
		return 0, fmt.Errorf("ensure schema: %w", err)
	}
	start := time.Now()
	for i := 0; i < n; i++ {
		if err := sink.Write(ctx, g.Next()); err != nil {
			_ = sink.Stop(ctx)
			return 0, fmt.Errorf("write: %w", err)
		}
	}
	if err := sink.Stop(ctx); err != nil {
		return 0, fmt.Errorf("stop/flush: %w", err)
	}
	elapsed := time.Since(start)
	if elapsed <= 0 {
		return 0, nil
	}
	return float64(n) / elapsed.Seconds(), nil
}

func measureCHQueryLatency(ctx context.Context, baseCfg clickhouse.Config, opts Options) (Section, error) {
	cfg := baseCfg
	cfg.BatchSize = clickhouse.DefaultBatchSize
	w, err := clickhouse.New(ctx, cfg, quietLogger())
	if err != nil {
		return Section{}, fmt.Errorf("new writer (query): %w", err)
	}
	if err := w.EnsureSchema(ctx); err != nil {
		_ = w.Stop(ctx)
		return Section{}, fmt.Errorf("ensure schema (query): %w", err)
	}
	// Recent BaseTime so retain_until is in the future and the seeded
	// rows survive the table's TTL long enough to be queried.
	g := NewGenerator(GenConfig{Tenants: opts.Tenants, Seed: opts.Seed, BaseTime: time.Now().Add(-time.Minute)})
	for i := 0; i < chLiveQueryRows; i++ {
		if err := w.Write(ctx, g.Next()); err != nil {
			_ = w.Stop(ctx)
			return Section{}, fmt.Errorf("seed write: %w", err)
		}
	}
	reader, err := w.NewReader()
	if err != nil {
		_ = w.Stop(ctx)
		return Section{}, fmt.Errorf("new reader: %w", err)
	}
	since := g.BaseTime().Add(-time.Hour)
	until := g.BaseTime().Add(48 * time.Hour)
	tenant := g.TenantID(0)

	start := time.Now()
	rows, err := reader.ListFlowEvents(ctx, tenant, since, until, 100_000)
	latency := time.Since(start)
	if err != nil {
		_ = w.Stop(ctx)
		return Section{}, fmt.Errorf("query: %w", err)
	}
	if err := w.Stop(ctx); err != nil {
		return Section{}, fmt.Errorf("stop (query): %w", err)
	}

	return Section{
		Title:   "Tenant-scoped read latency",
		Summary: fmt.Sprintf("ListFlowEvents for one tenant over a %s-row table.", humanizeFloat(float64(chLiveQueryRows))),
		Metrics: []MetricRow{
			{Name: "read latency", Unit: "ms", Actual: float64(latency.Microseconds()) / 1000.0, Verdict: VerdictInfo},
			{Name: "rows returned", Unit: "", Actual: float64(len(rows)), Verdict: VerdictInfo},
		},
	}, nil
}

func repeatEndpoint(ep string, n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = ep
	}
	return out
}
