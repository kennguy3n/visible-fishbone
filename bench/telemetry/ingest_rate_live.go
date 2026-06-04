//go:build integration

package main

import (
	"context"
	"fmt"
	"math"
	"time"

	"github.com/google/uuid"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/kennguy3n/visible-fishbone/internal/config"
	natsstreams "github.com/kennguy3n/visible-fishbone/internal/nats"
	"github.com/kennguy3n/visible-fishbone/internal/nats/schema"
)

// ingest_rate_live.go is the container-free (embedded JetStream) live
// measurement for the `ingest-rate` subcommand: it publishes synthetic
// telemetry across a tenant pool through the production stream config
// and drains it through a JetStream pull consumer, measuring the
// sustained ingest rate, consumer lag, and per-tenant fairness.

// maxIngestEventsPerTier caps the events published per rate tier so the
// integration run stays inside the test timeout regardless of the
// nominal tier (which can be 100k+).
const maxIngestEventsPerTier = 50_000

func liveIngestRate(opts Options) (*Report, error) {
	ctx := context.Background()
	nc, js, cleanup, err := embeddedNATS()
	if err != nil {
		return nil, err
	}
	defer cleanup()
	_ = nc

	natsCfg := &config.NATS{
		Storage:      "memory",
		Replicas:     1,
		Partitions:   1,
		StreamPrefix: "SNG",
		DedupWindow:  2 * time.Minute,
	}
	specs := natsstreams.DefaultStreams(natsCfg)
	if err := natsstreams.EnsureStreams(ctx, js, specs, 15*time.Second); err != nil {
		return nil, fmt.Errorf("ensure streams: %w", err)
	}
	streamName := natsstreams.StreamName(natsCfg.StreamPrefix, natsstreams.StreamSuffixTelemetry)

	r := NewReport("ingest-rate", nowUnix(), opts.GitSHA, false)
	sec := Section{
		Title:   "JetStream ingest (embedded server)",
		Summary: fmt.Sprintf("Tenant pool %d; per-tier event count capped at %d; publish→drain through %s.", opts.Tenants, maxIngestEventsPerTier, streamName),
	}

	for _, tier := range ingestRateTiers {
		n := tier
		if n > maxIngestEventsPerTier {
			n = maxIngestEventsPerTier
		}
		res, err := measureIngestTier(ctx, js, streamName, opts, tier, n)
		if err != nil {
			return nil, fmt.Errorf("rate tier %d: %w", tier, err)
		}
		label := fmt.Sprintf("%s ev/s offered", humanizeFloat(float64(tier)))
		sec.Metrics = append(sec.Metrics,
			MetricRow{
				Name: label + " — drain rate", Unit: "events/sec",
				Actual:      res.drainRate,
				Theoretical: ptr(TargetAggregateIngest),
				Competitor:  ptr(competitorIngestEventsPerSec),
				Verdict:     classify(res.drainRate, ptr(TargetAggregateIngest), true, DefaultWarnBand),
			},
			MetricRow{
				Name: label + " — peak consumer lag", Unit: "msgs",
				Actual: float64(res.peakLag), Verdict: VerdictInfo,
			},
			MetricRow{
				Name: label + " — per-tenant fairness (CV)", Unit: "",
				Actual: res.fairnessCV, Verdict: VerdictInfo,
				Note: "coefficient of variation of per-tenant delivered counts; lower is fairer",
			},
		)
	}
	r.AddSection(sec)
	r.AddCaveat("Ingest is measured against an in-process JetStream server, so figures reflect this host's CPU/IO, not a production multi-node cluster.")
	r.AddCaveat("Per-tier event counts are capped to keep the run inside the test timeout; the drain rate is the sustained rate, not a function of the nominal tier.")
	r.AddCaveat("DLQ overflow is not force-triggered here: it requires sustained MaxDeliver failures, which a healthy consumer does not produce.")
	return r, nil
}

type ingestTierResult struct {
	drainRate  float64
	peakLag    uint64
	fairnessCV float64
}

func measureIngestTier(ctx context.Context, js jetstream.JetStream, streamName string, opts Options, tier, n int) (ingestTierResult, error) {
	// A fresh durable per tier so each tier drains from the start.
	durable := fmt.Sprintf("bench_ingest_%d", tier)
	cons, err := natsstreams.EnsureConsumer(ctx, js, natsstreams.ConsumerSpec{
		Stream:        streamName,
		Durable:       durable,
		FilterSubject: "sng.*.telemetry.>",
		AckWait:       30 * time.Second,
		MaxAckPending: 4096,
	})
	if err != nil {
		return ingestTierResult{}, err
	}

	g := NewGenerator(GenConfig{Tenants: opts.Tenants, Seed: opts.Seed})
	published := make([]schema.Envelope, n)
	for i := 0; i < n; i++ {
		published[i] = g.Next()
	}

	// Publish phase.
	for i := 0; i < n; i++ {
		env := published[i]
		subj := natsstreams.SubjectForTelemetry(env.TenantID.String(), string(env.EventClass))
		wire, err := schema.Marshal(env)
		if err != nil {
			return ingestTierResult{}, fmt.Errorf("marshal: %w", err)
		}
		if _, err := js.Publish(ctx, subj, wire); err != nil {
			return ingestTierResult{}, fmt.Errorf("publish: %w", err)
		}
	}

	// Peak lag right after publish, before draining.
	var peakLag uint64
	if info, err := cons.Info(ctx); err == nil {
		peakLag = info.NumPending
	}

	// Drain phase — this is the sustained ingest measurement.
	perTenant := make(map[uuid.UUID]int, opts.Tenants)
	drained := 0
	start := time.Now()
	for drained < n {
		batchSize := 500
		if rem := n - drained; rem < batchSize {
			batchSize = rem
		}
		batch, err := cons.Fetch(batchSize, jetstream.FetchMaxWait(5*time.Second))
		if err != nil {
			return ingestTierResult{}, fmt.Errorf("fetch: %w", err)
		}
		got := 0
		for msg := range batch.Messages() {
			env, err := schema.Unmarshal(msg.Data())
			if err != nil {
				return ingestTierResult{}, fmt.Errorf("unmarshal delivered: %w", err)
			}
			perTenant[env.TenantID]++
			if err := msg.Ack(); err != nil {
				return ingestTierResult{}, fmt.Errorf("ack: %w", err)
			}
			got++
		}
		if err := batch.Error(); err != nil {
			return ingestTierResult{}, fmt.Errorf("batch: %w", err)
		}
		if got == 0 {
			break
		}
		drained += got
	}
	elapsed := time.Since(start)

	res := ingestTierResult{peakLag: peakLag}
	if elapsed > 0 {
		res.drainRate = float64(drained) / elapsed.Seconds()
	}
	res.fairnessCV = coefficientOfVariation(perTenant)
	return res, nil
}

// coefficientOfVariation returns stddev/mean of the per-tenant delivered
// counts. 0 when fewer than two tenants received messages.
func coefficientOfVariation(counts map[uuid.UUID]int) float64 {
	if len(counts) < 2 {
		return 0
	}
	var sum, sumSq float64
	for _, c := range counts {
		sum += float64(c)
		sumSq += float64(c) * float64(c)
	}
	n := float64(len(counts))
	mean := sum / n
	if mean == 0 {
		return 0
	}
	variance := sumSq/n - mean*mean
	if variance < 0 {
		variance = 0
	}
	return math.Sqrt(variance) / mean
}
