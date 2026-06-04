package main

import (
	"math"
	"math/rand"
	"time"
)

// Dry-run synthesises plausible numbers so the full craft → measure →
// report pipeline runs on an unprivileged CI runner with no control
// plane and no Postgres. It is deliberately NOT random-seeded from the
// clock: a fixed seed keeps dry-run reports reproducible (useful for
// golden-file tests of the markdown/JSON), while still feeding real
// samples through the same aggregation code the live path uses.
//
// Policy-compile is pure CPU, so dry-run runs the REAL compile bench
// (see main.go) rather than synthesising it.

const dryRunSeed = 1

// dryRunAPILatency feeds synthetic per-request samples through the real
// latencyRecorder + aggregateTier code, so the dry-run exercises the
// same measurement path the live workload uses. Latency scales mildly
// with tenant count to mimic contention at scale.
func dryRunAPILatency(tenantCounts []int, concurrency int) *APILatencySection {
	rng := rand.New(rand.NewSource(dryRunSeed)) //nolint:gosec // deterministic synthetic data
	section := &APILatencySection{}
	endpoints := []struct {
		method, key string
		baseMs      float64
	}{
		{"GET", "GET /tenants/{id}", 5},
		{"GET", "GET /tenants/{id}/sites", 8},
		{"GET", "GET /tenants/{id}/devices", 9},
		{"GET", "GET /tenants/{id}/policy", 7},
		{"PATCH", "PATCH /tenants/{id}", 14},
		{"POST", "POST /tenants/{id}/sites", 18},
		{"POST", "POST /tenants/{id}/claim-tokens", 12},
		{"POST", "POST /tenants/{id}/policy/compile", 45},
		{"POST", "POST /tenants/{id}/policy/simulations", 60},
	}

	for _, count := range tenantCounts {
		// Scale factor grows ~logarithmically with tenant count so a
		// 5000-tenant tier shows a believable tail without exploding.
		scale := 1 + 0.12*math.Log10(float64(count))
		recs := make([]*latencyRecorder, 0, len(endpoints))
		const perEndpoint = 500
		for _, ep := range endpoints {
			rec := newLatencyRecorder(ep.method, ep.key)
			for i := 0; i < perEndpoint; i++ {
				// Log-normal-ish: base * scale * exp(normal tail).
				ms := ep.baseMs * scale * math.Exp(rng.NormFloat64()*0.35)
				failed := rng.Float64() < 0.002 // ~0.2% synthetic error rate
				rec.record(time.Duration(ms*float64(time.Millisecond)), failed)
			}
			recs = append(recs, rec)
		}
		// A synthetic 60s window with throughput proportional to the
		// fixed sample count keeps RPS believable.
		tier := aggregateTier(count, 60, concurrency, 60*time.Second, recs)
		section.Tiers = append(section.Tiers, tier)
	}
	return section
}

// dryRunPostgresScale synthesises a Postgres-scale section. RLS
// overhead is modelled as a small constant (RLS adds a predicate, not a
// scan), pool saturation at ~1.25x pool size, and a fast metadata-only
// ADD COLUMN.
func dryRunPostgresScale(tenantCount, poolSize int) *PostgresScaleSection {
	withoutRLS := 3.8
	withRLS := withoutRLS * 1.06 // ~6% predicate overhead
	return &PostgresScaleSection{
		TenantCount: tenantCount,
		RLS: RLSOverhead{
			WithRLSP99Ms:    withRLS,
			WithoutRLSP99Ms: withoutRLS,
			OverheadPct:     (withRLS - withoutRLS) / withoutRLS * 100,
		},
		Pool: PoolSaturation{
			PoolSize:              poolSize,
			SaturationConcurrency: poolSize * 2,
			MaxQueriesPerSec:      float64(poolSize) * 280,
		},
		Migration: MigrationSpeed{
			RowCount:  int64(tenantCount) * 3,
			Statement: "ALTER TABLE sites ADD COLUMN ... NOT NULL DEFAULT false",
			ElapsedMs: 6.5,
		},
		RowCounts: map[string]int64{
			"tenants":       int64(tenantCount),
			"sites":         int64(tenantCount) * 3,
			"policy_graphs": int64(tenantCount),
		},
		IndexSizeBytes: map[string]int64{
			"tenants_pkey": int64(tenantCount) * 32,
			"sites_pkey":   int64(tenantCount) * 96,
		},
	}
}
