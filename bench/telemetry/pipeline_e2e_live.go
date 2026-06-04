//go:build integration

package main

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/kennguy3n/visible-fishbone/internal/config"
	natsstreams "github.com/kennguy3n/visible-fishbone/internal/nats"
	"github.com/kennguy3n/visible-fishbone/internal/service/telemetry"
	"github.com/kennguy3n/visible-fishbone/internal/service/telemetry/clickhouse"
	"github.com/kennguy3n/visible-fishbone/internal/service/telemetry/s3"
)

// pipeline_e2e_live.go is the full NATS→consumer→dedup→normalize→
// ClickHouse+S3 measurement for the `full-pipeline` subcommand. It
// wires the production telemetry.Service to an embedded JetStream
// server, a ClickHouse container (hot path), and a MinIO container
// (cold path), then measures sustained throughput, the dedup hit rate
// under a realistic duplicate mix, and publish→queryable latency.

const (
	// e2eBulkEvents is the duplicate-laden batch used for the
	// throughput + dedup-rate measurement (capped for the timeout).
	e2eBulkEvents = 40_000
	// e2eLatencyProbes is the number of single-event publish→queryable
	// round trips sampled for the latency figure.
	e2eLatencyProbes = 20
)

func liveFullPipeline(opts Options) (*Report, error) {
	ctx := context.Background()

	nc, js, natsCleanup, err := embeddedNATS()
	if err != nil {
		return nil, err
	}
	defer natsCleanup()
	_ = nc

	chEndpoint, chCleanup, err := startClickHouse(ctx)
	if err != nil {
		return nil, err
	}
	defer chCleanup()

	s3Client, s3Cleanup, err := startMinIO(ctx)
	if err != nil {
		return nil, err
	}
	defer s3Cleanup()

	hot, err := clickhouse.New(ctx, clickhouse.Config{
		Endpoints:     []string{chEndpoint},
		Database:      "default",
		Table:         clickhouse.DefaultTable,
		FlushInterval: 200 * time.Millisecond,
		BatchSize:     clickhouse.DefaultBatchSize,
		DialTimeout:   15 * time.Second,
	}, quietLogger())
	if err != nil {
		return nil, fmt.Errorf("new hot writer: %w", err)
	}
	if err := hot.EnsureSchema(ctx); err != nil {
		_ = hot.Stop(ctx)
		return nil, fmt.Errorf("ensure schema: %w", err)
	}
	defer func() { _ = hot.Stop(ctx) }()

	const bucket = "sng-telemetry-e2e"
	if _, err := s3Client.CreateBucket(ctx, &awss3.CreateBucketInput{Bucket: aws.String(bucket)}); err != nil {
		return nil, fmt.Errorf("create bucket: %w", err)
	}
	cold, err := s3.New(s3Client, s3.Config{
		Bucket:             bucket,
		Prefix:             "telemetry-archive",
		StorageClass:       "STANDARD", // MinIO rejects STANDARD_IA; prod uses IA
		MaxEventsPerObject: s3LiveMaxEventsPerObject,
		FlushInterval:      time.Second,
	}, quietLogger())
	if err != nil {
		return nil, fmt.Errorf("new cold writer: %w", err)
	}
	defer func() { _ = cold.Stop(ctx) }()

	natsCfg := &config.NATS{
		Storage:      "memory",
		Replicas:     1,
		Partitions:   1,
		StreamPrefix: "SNG",
		DedupWindow:  2 * time.Minute,
	}
	// The telemetry service ensures its durable consumer but assumes the
	// stream already exists (created by control-plane bootstrap), so we
	// provision the canonical streams first.
	if err := natsstreams.EnsureStreams(ctx, js, natsstreams.DefaultStreams(natsCfg), 15*time.Second); err != nil {
		return nil, fmt.Errorf("ensure streams: %w", err)
	}
	svc, err := telemetry.New(js, natsCfg, telemetry.Config{}, hot, cold, quietLogger())
	if err != nil {
		return nil, fmt.Errorf("new telemetry service: %w", err)
	}
	if err := svc.Start(ctx); err != nil {
		return nil, fmt.Errorf("start service: %w", err)
	}
	defer func() { _ = svc.Stop(ctx) }()

	r := NewReport("full-pipeline", nowUnix(), opts.GitSHA, false)

	// 1. Throughput + dedup under a realistic duplicate mix.
	thru, err := measureE2EThroughput(ctx, js, svc, opts)
	if err != nil {
		return nil, err
	}
	r.AddSection(thru)

	// 2. Publish→queryable latency probes.
	lat, err := measureE2ELatency(ctx, js, hot, svc, opts)
	if err != nil {
		return nil, err
	}
	r.AddSection(lat)

	// 3. Cold-path object stats observed during the run. Stop the cold
	// writer first so its final partition is flushed and the counters
	// are exact rather than missing the last sub-FlushInterval batch
	// (Stop is guarded by sync.Once, so the deferred Stop is a no-op).
	if err := cold.Stop(ctx); err != nil {
		return nil, fmt.Errorf("stop cold writer: %w", err)
	}
	cs := cold.Stats()
	// The cold path archives an event only after it survives dedup and a
	// successful hot write — that is exactly what the service's Enriched
	// counter tracks, across both the throughput and latency phases.
	// Dividing by e2eBulkEvents would overcount by the ~DupRate
	// duplicates the consumer dropped and undercount by the latency
	// probes, so use the real archived count from the service metrics.
	final := svc.MetricsSnapshot()
	archived := final.Enriched
	var avgObj, bytesPerEvent float64
	if cs.Uploaded > 0 {
		avgObj = float64(cs.UploadBytes) / float64(cs.Uploaded)
	}
	if archived > 0 {
		bytesPerEvent = float64(cs.UploadBytes) / float64(archived)
	}
	r.AddSection(Section{
		Title: "Cold-path archive (observed during run)",
		Metrics: []MetricRow{
			{Name: "objects uploaded", Unit: "", Actual: float64(cs.Uploaded), Verdict: VerdictInfo},
			{Name: "avg object size", Unit: "B", Actual: avgObj, Verdict: VerdictInfo},
			{Name: "compressed size", Unit: "B/event", Actual: bytesPerEvent, Verdict: VerdictInfo, Note: "over events actually archived (post-dedup), not events published"},
		},
	})

	r.AddCaveat("All infrastructure is local (embedded JetStream + containerised ClickHouse/MinIO), so throughput reflects this host, not a production multi-node deployment.")
	r.AddCaveat("Latency is publish→queryable-in-ClickHouse, which includes the writer's 200ms flush interval; it is an upper bound on the hot-path insert latency, not a pure pipeline transit time.")
	r.AddCaveat("Event counts are capped to keep the run inside the test timeout; throughput and hit-rate are rates and remain representative.")
	return r, nil
}

func measureE2EThroughput(ctx context.Context, js publisher, svc *telemetry.Service, opts Options) (Section, error) {
	g := NewGenerator(GenConfig{Tenants: opts.Tenants, Seed: opts.Seed, DuplicateRate: opts.DupRate, BaseTime: time.Now().Add(-time.Minute)})
	before := svc.MetricsSnapshot()

	start := time.Now()
	for i := 0; i < e2eBulkEvents; i++ {
		env := g.Next()
		if err := publishEnvelope(ctx, js, env); err != nil {
			return Section{}, err
		}
	}

	// Wait until the service has acked everything published (each
	// delivery — unique or duplicate — is acked once processed).
	target := before.Acked + uint64(e2eBulkEvents)
	deadline := time.Now().Add(60 * time.Second)
	var snap telemetry.MetricsSnapshot
	for {
		snap = svc.MetricsSnapshot()
		if snap.Acked >= target {
			break
		}
		if time.Now().After(deadline) {
			return Section{}, fmt.Errorf("timeout draining pipeline: acked %d, want %d", snap.Acked, target)
		}
		time.Sleep(20 * time.Millisecond)
	}
	elapsed := time.Since(start)

	processed := snap.Received - before.Received
	deduped := snap.Deduplicated - before.Deduplicated
	var throughput, hitRate float64
	if elapsed > 0 {
		throughput = float64(e2eBulkEvents) / elapsed.Seconds()
	}
	if processed > 0 {
		hitRate = float64(deduped) / float64(processed)
	}

	return Section{
		Title:   "End-to-end throughput + dedup",
		Summary: fmt.Sprintf("%s events at %.0f%% duplicates across %d tenants, publish→ack through the full pipeline.", humanizeFloat(float64(e2eBulkEvents)), opts.DupRate*100, opts.Tenants),
		Metrics: []MetricRow{
			{
				Name: "saturation throughput", Unit: "events/sec",
				Actual:      throughput,
				Theoretical: ptr(TargetAggregateIngest),
				Competitor:  ptr(competitorIngestEventsPerSec),
				Verdict:     classify(throughput, ptr(TargetAggregateIngest), true, DefaultWarnBand),
			},
			{
				Name: "dedup hit rate", Unit: "",
				Actual:      hitRate,
				Theoretical: ptr(opts.DupRate),
				Verdict:     classify(hitRate, ptr(opts.DupRate), true, e2eDedupWarnBand),
				Note:        "observed duplicates / received; target is the injected duplicate rate",
			},
		},
	}, nil
}

// e2eDedupWarnBand is wider than the default because the observed hit
// rate has sampling variance around the injected rate.
const e2eDedupWarnBand = 0.30

func measureE2ELatency(ctx context.Context, js publisher, hot *clickhouse.Writer, svc *telemetry.Service, opts Options) (Section, error) {
	reader, err := hot.NewReader()
	if err != nil {
		return Section{}, fmt.Errorf("new reader: %w", err)
	}
	// Dedicated generator with NO duplicates and one tenant per probe so
	// each probe is a fresh, isolated, queryable row. Recent BaseTime so
	// the rows' retain_until is in the future (TTL keeps them).
	g := NewGenerator(GenConfig{Tenants: e2eLatencyProbes, Seed: opts.Seed + 1, BaseTime: time.Now().Add(-time.Minute)})
	since := g.BaseTime().Add(-time.Hour)
	until := g.BaseTime().Add(48 * time.Hour)

	var total, maxLatency time.Duration
	probes := 0
	for i := 0; i < e2eLatencyProbes; i++ {
		env := g.Next()
		tenant := env.TenantID
		baseline, err := reader.ListFlowEvents(ctx, tenant, since, until, 100_000)
		if err != nil {
			return Section{}, fmt.Errorf("baseline read: %w", err)
		}
		want := len(baseline) + 1

		start := time.Now()
		if err := publishEnvelope(ctx, js, env); err != nil {
			return Section{}, err
		}
		deadline := time.Now().Add(30 * time.Second)
		for {
			rows, err := reader.ListFlowEvents(ctx, tenant, since, until, 100_000)
			if err != nil {
				return Section{}, fmt.Errorf("probe read: %w", err)
			}
			if len(rows) >= want {
				break
			}
			if time.Now().After(deadline) {
				s := svc.MetricsSnapshot()
				st := hot.Stats()
				return Section{}, fmt.Errorf("probe %d: event not queryable within 30s (tenant=%s want=%d metrics{recv=%d decoded=%d dedup=%d hotfail=%d acked=%d nacked=%d} writer{flushed=%d pending=%d dropped=%d})",
					i, tenant, want, s.Received, s.Decoded, s.Deduplicated, s.HotWriteFails, s.Acked, s.Nacked, st.Flushed, st.Pending, st.DroppedRows)
			}
			time.Sleep(10 * time.Millisecond)
		}
		d := time.Since(start)
		total += d
		if d > maxLatency {
			maxLatency = d
		}
		probes++
	}

	var meanMs float64
	if probes > 0 {
		meanMs = float64(total.Microseconds()) / float64(probes) / 1000.0
	}
	return Section{
		Title:   "Publish→queryable latency",
		Summary: fmt.Sprintf("%d single-event probes through NATS→consumer→ClickHouse.", probes),
		Metrics: []MetricRow{
			{
				Name: "mean latency", Unit: "ms",
				Actual:      meanMs,
				Theoretical: ptr(TargetE2ELatencyP99Ms),
				Competitor:  ptr(competitorE2ELatencyP99Ms),
				Verdict:     classify(meanMs, ptr(TargetE2ELatencyP99Ms), false, DefaultWarnBand),
			},
			{Name: "max latency", Unit: "ms", Actual: float64(maxLatency.Microseconds()) / 1000.0, Verdict: VerdictInfo},
		},
	}, nil
}
