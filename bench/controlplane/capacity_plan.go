package main

// Capacity planning is an analytical model rather than a measured
// workload: it answers "what does the data plane look like at N
// tenants?" without standing up a 5,000-tenant fleet.
//
// The model itself now lives in the importable internal/capacityplan
// package so the offline bench artifact and the live capacity
// reconciler (internal/service/capacity) share one implementation —
// the recommendations an operator sees at runtime match these
// documented planning numbers to the row. This file keeps the bench's
// historical type names and the markdown renderer as thin aliases /
// forwarders over that package so the report schema and CLI output are
// unchanged.
//
// The first three sub-models mirror the three horizontal-scaling axes
// the platform exposes (Postgres pool, ClickHouse write throughput,
// NATS subject cardinality). A fourth sub-model captures the WS-4
// activity-tier telemetry sampling policy (fleet rows/s decomposed by
// active / idle / dormant cohort), and a fifth captures the control-
// plane (not data-plane) cost the dormancy work targets: how many
// tenants the periodic per-tenant sweeps visit per cycle, before vs
// after the activity-tiered SweepPlanner gating (the WS-1 dormancy
// dividend).

import (
	"fmt"
	"strings"

	"github.com/kennguy3n/visible-fishbone/internal/capacityplan"
)

// Bench-facing aliases for the shared capacity model types. Kept so the
// report struct, tests, and markdown renderer read with their original
// names while the single source of truth lives in internal/capacityplan.
type (
	CapacityPlanConfig  = capacityplan.Config
	CapacityPlanSection = capacityplan.Section
	PostgresPoolPlan    = capacityplan.PostgresPoolPlan
	ClickHouseWritePlan = capacityplan.ClickHouseWritePlan
	NATSSubjectPlan     = capacityplan.NATSSubjectPlan
	TierSamplingPlan    = capacityplan.TierSamplingPlan
	PeriodicSweepPlan   = capacityplan.PeriodicSweepPlan
)

// DefaultCapacityPlanConfig models the headline 5,000-tenant tier with
// the platform's documented default knobs.
func DefaultCapacityPlanConfig() CapacityPlanConfig { return capacityplan.DefaultConfig() }

// RunCapacityPlan evaluates the sub-models and returns the assembled
// section.
func RunCapacityPlan(cfg CapacityPlanConfig) *CapacityPlanSection { return capacityplan.Run(cfg) }

// boolPtr returns a pointer to v, for the tri-state PGBouncerMode field.
func boolPtr(v bool) *bool { return capacityplan.BoolPtr(v) }

// nextPow2 rounds n up to the next power of two, clamped to 256.
func nextPow2(n int) int { return capacityplan.NextPow2(n) }

// writeCapacityPlanMarkdown renders the capacity section.
func (r *BusinessBenchmarkReport) writeCapacityPlanMarkdown(b *strings.Builder) {
	cp := r.CapacityPlan
	fmt.Fprintf(b, "### Capacity plan @ %d tenants × %d telemetry classes\n\n",
		cp.TenantCount, len(cp.TelemetryClasses))
	fmt.Fprintf(b, "Telemetry classes: `%s`\n\n", strings.Join(cp.TelemetryClasses, "`, `"))
	if cp.DormantFraction > 0 {
		fmt.Fprintf(b, "Hibernation: %.0f%% dormant → **%.1f** effective emitting tenants (parked telemetry at the near-zero hibernated sample rate).\n\n",
			cp.DormantFraction*100, cp.EmittingTenantsEffective)
	}

	pg := cp.Postgres
	b.WriteString("**Postgres connection-pool pressure**\n\n")
	fmt.Fprintf(b, "- replicas × PG_MAX_OPEN_CONNS = %d × %d = %d app conns\n", pg.Replicas, pg.PoolSizePerReplica, pg.TotalAppConns)
	fmt.Fprintf(b, "- peak concurrent queries (Little's law): %.1f → recommended pool/replica %d\n", pg.PeakConcurrentQueries, pg.RecommendedPoolSize)
	fmt.Fprintf(b, "- PgBouncer: %v → backend conns required %d / max_connections %d (within: %v)\n", pg.PGBouncerMode, pg.BackendConnsRequired, pg.MaxConnections, pg.WithinMaxConnections)
	fmt.Fprintf(b, "- %s\n\n", pg.Note)

	ch := cp.ClickHouse
	b.WriteString("**ClickHouse write throughput**\n\n")
	fmt.Fprintf(b, "- %.1f rows/s total across %d shard(s) = %.1f rows/s/shard\n", ch.TotalRowsPerSec, ch.Shards, ch.RowsPerSecPerShard)
	fmt.Fprintf(b, "- %.2f inserts/s/shard @ batch %d (recommended: batch %d across %d shard(s))\n", ch.InsertsPerSecPerShard, ch.BatchSize, ch.RecommendedBatchSize, ch.RecommendedShards)
	if cp.DormantFraction > 0 {
		// Under hibernation the fleet-average rows/tenant averages in the
		// near-zero dormant telemetry; surface the per-active-tenant figure
		// too so an operator can size for the tenants that still write full
		// fidelity.
		fmt.Fprintf(b, "- %d rows/month (%d/tenant fleet-avg, %d/active-tenant), ~%.1f GB/month compressed hot storage\n", ch.MonthlyRows, ch.PerTenantMonthlyRows, ch.PerActiveTenantMonthlyRows, ch.HotStorageGBCompressed)
	} else {
		fmt.Fprintf(b, "- %d rows/month (%d/tenant), ~%.1f GB/month compressed hot storage\n", ch.MonthlyRows, ch.PerTenantMonthlyRows, ch.HotStorageGBCompressed)
	}
	fmt.Fprintf(b, "- %s\n\n", ch.Note)

	n := cp.NATS
	b.WriteString("**NATS subject cardinality**\n\n")
	fmt.Fprintf(b, "- %d distinct subjects across %d partition(s) = %.1f avg (busiest ~%d)\n", n.DistinctSubjects, n.Partitions, n.SubjectsPerPartitionAvg, n.SubjectsPerPartitionMax)
	fmt.Fprintf(b, "- %.1f msgs/s, %.0fh retention → ~%d bytes hot JetStream storage\n", n.MsgsPerSec, n.RetentionHours, n.StreamBytesHot)
	fmt.Fprintf(b, "- recommended NATS_PARTITIONS: %d — %s\n\n", n.RecommendedPartitions, n.Note)

	if ts := cp.TierSampling; ts != nil {
		b.WriteString("**WS-4 activity-tier telemetry sampling** (ClickHouse rows/s)\n\n")
		fmt.Fprintf(b, "- active: %d tenants → %.1f rows/s (full fidelity)\n", ts.ActiveTenants, ts.ActiveRowsPerSec)
		fmt.Fprintf(b, "- idle: %d tenants → %.1f rows/s (sampled @ %.2f×)\n", ts.IdleTenants, ts.IdleRowsPerSec, ts.IdleSampleMultiplier)
		fmt.Fprintf(b, "- dormant: %d tenants → %.1f rows/s (security-events-only)\n", ts.DormantTenants, ts.DormantRowsPerSec)
		fmt.Fprintf(b, "- fleet: %.1f rows/s sampled vs %.1f rows/s baseline (−%.1f%%); active cohort is %.1f%% of the write rate\n\n",
			ts.SampledRowsPerSec, ts.BaselineRowsPerSec, ts.ReductionPct, ts.ActiveCohortSharePct)
	}

	sw := cp.PeriodicSweep
	b.WriteString("**Periodic per-tenant sweep cost (dormancy dividend, WS-1)**\n\n")
	fmt.Fprintf(b, "- activity mix: %d active / %d idle / %d dormant (idle every %d cycles, dormant every %d)\n",
		sw.ActiveTenants, sw.IdleTenants, sw.DormantTenants, sw.IdleEvery, sw.DormantEvery)
	fmt.Fprintf(b, "- tiered jobs (`%s`)\n", strings.Join(sw.Jobs, "`, `"))
	fmt.Fprintf(b, "- per job: %d tenants/cycle (untiered) → %.1f tenants/cycle (tiered) = **%.1fx** fewer\n",
		sw.UntieredVisitsPerCyclePerJob, sw.TieredVisitsPerCyclePerJob, sw.ReductionFactor)
	fmt.Fprintf(b, "- tiered breakdown/cycle: %.1f active + %.1f idle + %.1f dormant\n",
		sw.ActiveVisitsPerCycle, sw.IdleVisitsPerCycle, sw.DormantVisitsPerCycle)
	fmt.Fprintf(b, "- tail dividend: idle **%.1fx**, dormant **%.1fx** fewer visits/cycle\n",
		sw.IdleReductionFactor, sw.DormantReductionFactor)
	fmt.Fprintf(b, "- aggregate across %d job(s): %d → %.1f tenants/cycle\n",
		sw.JobCount, sw.UntieredVisitsPerCycleTotal, sw.TieredVisitsPerCycleTotal)
	fmt.Fprintf(b, "- %s\n\n", sw.Note)
}
