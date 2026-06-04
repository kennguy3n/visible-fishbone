package main

import (
	"fmt"

	"github.com/kennguy3n/visible-fishbone/internal/service/telemetry"
)

// ingest_rate.go owns the `ingest-rate` subcommand: how many events/sec
// the NATS JetStream ingest path sustains before backpressure, and how
// fairly that budget is shared across tenants.
//
// The live measurement (embedded JetStream + the production consumer)
// lives in ingest_rate_live.go behind `//go:build integration`. The
// dry-run path here measures the genuinely CPU-bound part (msgpack
// encode throughput, wire size) and models the queueing behaviour from
// the token-bucket parameters the production limiter uses.

func runIngestRate(opts Options) (*Report, error) {
	if !opts.DryRun {
		return liveIngestRate(opts)
	}
	return dryRunIngestRate(opts)
}

func dryRunIngestRate(opts Options) (*Report, error) {
	g := NewGenerator(GenConfig{
		Tenants:       opts.Tenants,
		Seed:          opts.Seed,
		DuplicateRate: opts.DupRate,
	})
	enc, err := MeasureEncode(g, opts.Samples)
	if err != nil {
		return nil, fmt.Errorf("measure encode: %w", err)
	}

	// The aggregate per-tenant budget is the floor the limiter imposes:
	// Tenants × DefaultTenantRateLimit events/sec is the steady-state
	// ceiling before any tenant is rate-limited. The real consumer's
	// sustained ceiling is min(that budget, the single-consumer decode
	// throughput) — the dry-run reports the encode throughput as the
	// CPU-bound upper bound on a single core.
	perTenantBudget := float64(telemetry.DefaultTenantRateLimit)
	aggregateBudget := perTenantBudget * float64(opts.Tenants)
	encodeCeiling := enc.EventsPerSec()

	r := NewReport("ingest-rate", nowUnix(), opts.GitSHA, opts.DryRun)
	r.AddSection(Section{
		Title:   "Ingest throughput (modeled)",
		Summary: fmt.Sprintf("Tenant pool %d; per-tenant budget %.0f ev/s (token bucket, burst %d).", opts.Tenants, perTenantBudget, telemetry.DefaultTenantBurstSize),
		Metrics: []MetricRow{
			{
				Name: "single-core msgpack encode", Unit: "events/sec",
				Actual:     encodeCeiling,
				Competitor: ptr(competitorIngestEventsPerSec),
				Verdict:    VerdictInfo,
				Note:       "measured CPU-bound encode ceiling on this host; an upper bound, not the wire ingest rate",
			},
			{
				Name: "avg wire size", Unit: "B/event",
				Actual: enc.AvgWireBytes(), Verdict: VerdictInfo,
			},
			{
				Name: "per-tenant rate ceiling", Unit: "events/sec",
				Actual:      perTenantBudget,
				Theoretical: ptr(TargetPerTenantRate),
				Verdict:     classify(perTenantBudget, ptr(TargetPerTenantRate), true, DefaultWarnBand),
				Note:        "telemetry.DefaultTenantRateLimit; the limiter Naks beyond this so a noisy tenant cannot starve the rest",
			},
			{
				Name: "aggregate ingest budget", Unit: "events/sec",
				Actual:      aggregateBudget,
				Theoretical: ptr(TargetAggregateIngest),
				Verdict:     classify(aggregateBudget, ptr(TargetAggregateIngest), true, DefaultWarnBand),
				Note:        "tenants × per-tenant budget; modeled, not measured against a live broker",
			},
		},
	})
	// Aggregate token-bucket budget across the design tenant tiers. The
	// integration run sweeps the offered load steps (ingestRateTiers)
	// against a live broker; here we surface the modeled ceiling each
	// tenant tier implies so the two are directly comparable.
	tierSec := Section{
		Title:   "Design load tiers (modeled)",
		Summary: fmt.Sprintf("Aggregate token-bucket budget per tenant tier; integration sweeps offered load steps %s ev/s.", intsCSV(ingestRateTiers)),
	}
	for _, tenants := range tenantTiers {
		budget := perTenantBudget * float64(tenants)
		tierSec.Metrics = append(tierSec.Metrics, MetricRow{
			Name: fmt.Sprintf("%s tenants — aggregate budget", humanizeFloat(float64(tenants))), Unit: "events/sec",
			Actual:      budget,
			Theoretical: ptr(TargetAggregateIngest),
			Verdict:     classify(budget, ptr(TargetAggregateIngest), true, DefaultWarnBand),
		})
	}
	r.AddSection(tierSec)

	r.AddCaveat("Dry-run ingest figures are modeled from the production token-bucket parameters; run with -tags=integration for the measured JetStream sustained rate, DLQ overflow point, consumer lag, and per-tenant delivery-rate variance.")
	r.AddCaveat("The competitor ingest figure (~50k ev/s) is a rough single-broker industry order-of-magnitude, not a measured product number.")
	return r, nil
}
