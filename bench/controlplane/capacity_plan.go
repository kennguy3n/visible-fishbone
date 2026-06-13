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
)

// DefaultCapacityPlanConfig models the headline 5,000-tenant tier with
// the platform's documented default knobs.
func DefaultCapacityPlanConfig() CapacityPlanConfig { return capacityplan.DefaultConfig() }

// RunCapacityPlan evaluates the three sub-models and returns the
// assembled section.
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
	fmt.Fprintf(b, "- %d rows/month (%d/tenant), ~%.1f GB/month compressed hot storage\n", ch.MonthlyRows, ch.PerTenantMonthlyRows, ch.HotStorageGBCompressed)
	fmt.Fprintf(b, "- %s\n\n", ch.Note)

	n := cp.NATS
	b.WriteString("**NATS subject cardinality**\n\n")
	fmt.Fprintf(b, "- %d distinct subjects across %d partition(s) = %.1f avg (busiest ~%d)\n", n.DistinctSubjects, n.Partitions, n.SubjectsPerPartitionAvg, n.SubjectsPerPartitionMax)
	fmt.Fprintf(b, "- %.1f msgs/s, %.0fh retention → ~%d bytes hot JetStream storage\n", n.MsgsPerSec, n.RetentionHours, n.StreamBytesHot)
	fmt.Fprintf(b, "- recommended NATS_PARTITIONS: %d — %s\n\n", n.RecommendedPartitions, n.Note)
}
