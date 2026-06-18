package main

import "github.com/kennguy3n/visible-fishbone/internal/service/telemetry"

// targets.go centralises the theoretical design targets and the rough
// competitor "industry norm" figures the report compares against, so a
// reviewer can audit every number in one place.
//
// HONESTY: the design targets are drawn from ARCHITECTURE.md / docs/cost-model.md
// (JetStream as the sole bus, per-tenant token-bucket rate limiting, the
// $0.30–1.20/user/month direct-infra-cost band). The competitor figures
// are rough industry order-of-magnitude numbers for telemetry pipelines,
// NOT measured from any specific product — they exist only to give the
// reader a sense of scale and never drive a PASS/WARN/FAIL verdict.

// --- dimension tiers (the parameter points runs sweep over) ---

// ingestRateTiers are the offered events/sec load steps.
var ingestRateTiers = []int{1_000, 10_000, 50_000, 100_000}

// tenantTiers are the tenant-pool sizes used to test per-tenant fairness.
var tenantTiers = []int{100, 1_000, 5_000}

// chBatchSizes are the ClickHouse batch flush sizes benchmarked.
var chBatchSizes = []int{256, 1_024, 4_096}

// chShardCounts are the sharded-writer fan-out widths benchmarked.
var chShardCounts = []int{1, 2, 4, 8}

// chQueryVolumes are the row counts a tenant-scoped read is timed at.
var chQueryVolumes = []int64{1_000_000, 10_000_000, 100_000_000}

// --- theoretical design targets ---

// TargetPerTenantRate is the per-tenant steady-state events/sec budget
// the token-bucket limiter enforces (telemetry.DefaultTenantRateLimit).
const TargetPerTenantRate = float64(telemetry.DefaultTenantRateLimit)

// TargetAggregateIngest is the design sustained aggregate ingest target
// (events/sec) for a single control-plane consumer before backpressure.
const TargetAggregateIngest = 100_000.0

// TargetCHBatchRowsPerSec is the design ClickHouse batch-insert
// throughput target (rows/sec) — the "roughly an order of magnitude
// faster than per-row INSERT VALUES" claim, anchored at a ~20k rows/sec
// per-row baseline → ~200k rows/sec batched.
const TargetCHBatchRowsPerSec = 200_000.0

// TargetE2ELatencyP99Ms is the design publish→ClickHouse-insert p99
// latency target in milliseconds.
const TargetE2ELatencyP99Ms = 500.0

// TargetCostPerUserMonthUSD is the upper bound of the PRD's
// $0.30–1.20/user/month direct-infra-cost band; the cost model is judged
// against this ceiling.
const TargetCostPerUserMonthUSD = 1.20

// --- rough competitor / industry-norm figures (context only) ---

const competitorIngestEventsPerSec = 50_000.0
const competitorCHRowsPerSec = 100_000.0
const competitorE2ELatencyP99Ms = 1_000.0
const competitorCostPerUserMonthUSD = 2.00

// defaultUsersPerTenant is the assumed seats-per-tenant used to turn a
// per-tenant cost into a per-user cost when the caller does not override
// it. A 250-seat SME office is the modal tenant in the PRD.
const defaultUsersPerTenant = 250
