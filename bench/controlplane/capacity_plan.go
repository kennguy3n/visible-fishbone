package main

// Capacity planning is an analytical model rather than a measured
// workload: it answers "what does the data plane look like at N
// tenants?" without standing up a 5,000-tenant fleet. It is therefore
// always deterministic and dependency-free (no Postgres, no NATS, no
// ClickHouse), which is exactly what a capacity-planning artifact wants
// — a reproducible projection an operator can re-run with different
// knobs (partition count, shard count, pool size) and diff.
//
// The three sub-models mirror the three horizontal-scaling axes the
// platform exposes:
//   - Postgres connection-pool pressure (PG_MAX_OPEN_CONNS,
//     read replicas, PgBouncer transaction pooling).
//   - ClickHouse write throughput (CLICKHOUSE_SHARDING, batch size).
//   - NATS subject cardinality (NATS_PARTITIONS fan-out).

import (
	"fmt"
	"math"
	"sort"
	"strings"
)

const secondsPerMonth = 30.0 * 24 * 3600

// classEventRate is the modelled sustained per-tenant publish rate
// (events/sec) for one telemetry class. flow dominates; control-plane
// classes (ztna, agent) are sparse. These are deliberately conservative
// steady-state averages for a mid-market tenant; an operator tunes them
// for their own traffic mix.
type classEventRate struct {
	class       string
	perTenantPS float64
}

// defaultClassRates is the canonical set of telemetry event classes the
// data plane partitions subjects by, per ARCHITECTURE.md §3.3
// (`sng.<tenant>.telemetry.<class>`), each paired with its modelled
// per-tenant rate. The NATS subject-cardinality and ClickHouse
// throughput models fan out across exactly these seven.
func defaultClassRates() []classEventRate {
	return []classEventRate{
		{"flow", 2.0},
		{"dns", 1.0},
		{"http", 1.5},
		{"ips", 0.2},
		{"ztna", 0.3},
		{"sdwan", 0.2},
		{"agent", 0.1},
	}
}

// CapacityPlanConfig parameterises the capacity model. Zero values are
// replaced with the documented defaults by withDefaults so a caller can
// pass an empty struct to model the default 5,000-tenant tier.
type CapacityPlanConfig struct {
	// TenantCount is the fleet size to model.
	TenantCount int
	// ControlPlaneReplicas is the number of sng-control pods sharing
	// the Postgres backend.
	ControlPlaneReplicas int
	// PGMaxOpenConns is PG_MAX_OPEN_CONNS — the per-replica app pool
	// ceiling.
	PGMaxOpenConns int
	// PGBouncerMode mirrors PG_PGBOUNCER_MODE: when true, a
	// transaction pooler multiplexes the app pools onto a far smaller
	// set of backend connections.
	PGBouncerMode bool
	// PGMaxConnections is the Postgres server's max_connections the
	// plan is graded against.
	PGMaxConnections int
	// ControlPlaneRPS is the aggregate control-plane API request rate
	// (policy pulls, enrolments, telemetry acks) — NOT the telemetry
	// event rate, which never touches Postgres. When 0 it is derived
	// from ControlPlaneRPSPerTenant × TenantCount so the Postgres
	// pressure scales with the fleet instead of being pinned to one
	// tier's headline number.
	ControlPlaneRPS float64
	// ControlPlaneRPSPerTenant is the per-tenant control-plane request
	// rate used to derive ControlPlaneRPS when it is not set explicitly.
	ControlPlaneRPSPerTenant float64
	// AvgQueryMs is the mean Postgres query service time used in the
	// Little's-law concurrency estimate.
	AvgQueryMs float64

	// ClickHouseShards is the CLICKHOUSE_SHARDING shard count rows are
	// hash-routed across.
	ClickHouseShards int
	// ClickHouseBatchSize is CLICKHOUSE_BATCH_SIZE (rows per insert).
	ClickHouseBatchSize int
	// BytesPerEvent is the normalized (metadata-first) uncompressed row
	// size in bytes.
	BytesPerEvent int
	// ClickHouseCompression is the columnar+zstd compression ratio used
	// to size on-disk hot storage.
	ClickHouseCompression float64
	// ClickHouseMaxBatchSize caps how large CLICKHOUSE_BATCH_SIZE may be
	// grown before sharding becomes the lever instead. Bounds insert
	// latency and writer memory.
	ClickHouseMaxBatchSize int

	// NATSPartitions is NATS_PARTITIONS — the telemetry stream fan-out.
	NATSPartitions int
	// NATSRetentionHours is the hot-stream retention window used to
	// size JetStream file storage.
	NATSRetentionHours float64
	// NATSMsgOverheadBytes is the per-message JetStream framing
	// overhead (subject + headers + index) added to BytesPerEvent.
	NATSMsgOverheadBytes int

	// classRates is the per-class per-tenant event rate. Unset uses
	// defaultClassRates.
	classRates []classEventRate
}

// DefaultCapacityPlanConfig models the headline 5,000-tenant tier with
// the platform's documented default knobs.
func DefaultCapacityPlanConfig() CapacityPlanConfig {
	return CapacityPlanConfig{
		TenantCount:          5000,
		ControlPlaneReplicas: 3,
		PGMaxOpenConns:       20,
		PGBouncerMode:        true,
		PGMaxConnections:     200,
		// ControlPlaneRPS left 0 so it derives from the per-tenant rate
		// below and scales with TenantCount (0.5 × 5000 = 2500 RPS at the
		// headline tier).
		ControlPlaneRPSPerTenant: 0.5,
		AvgQueryMs:               4.0,
		ClickHouseShards:         2,
		ClickHouseBatchSize:      1024,
		BytesPerEvent:            256,
		ClickHouseCompression:    8.0,
		ClickHouseMaxBatchSize:   65536,
		NATSPartitions:           16,
		NATSRetentionHours:       24,
		NATSMsgOverheadBytes:     64,
		classRates:               defaultClassRates(),
	}
}

// withDefaults fills any zero-valued field with its default so a
// partially-specified config (e.g. only TenantCount set) is still
// internally consistent.
func (c CapacityPlanConfig) withDefaults() CapacityPlanConfig {
	d := DefaultCapacityPlanConfig()
	if c.TenantCount <= 0 {
		c.TenantCount = d.TenantCount
	}
	if c.ControlPlaneReplicas <= 0 {
		c.ControlPlaneReplicas = d.ControlPlaneReplicas
	}
	if c.PGMaxOpenConns <= 0 {
		c.PGMaxOpenConns = d.PGMaxOpenConns
	}
	if c.PGMaxConnections <= 0 {
		c.PGMaxConnections = d.PGMaxConnections
	}
	if c.ControlPlaneRPSPerTenant <= 0 {
		c.ControlPlaneRPSPerTenant = d.ControlPlaneRPSPerTenant
	}
	if c.ControlPlaneRPS <= 0 {
		c.ControlPlaneRPS = c.ControlPlaneRPSPerTenant * float64(c.TenantCount)
	}
	if c.AvgQueryMs <= 0 {
		c.AvgQueryMs = d.AvgQueryMs
	}
	if c.ClickHouseShards <= 0 {
		c.ClickHouseShards = d.ClickHouseShards
	}
	if c.ClickHouseBatchSize <= 0 {
		c.ClickHouseBatchSize = d.ClickHouseBatchSize
	}
	if c.BytesPerEvent <= 0 {
		c.BytesPerEvent = d.BytesPerEvent
	}
	if c.ClickHouseCompression <= 0 {
		c.ClickHouseCompression = d.ClickHouseCompression
	}
	if c.ClickHouseMaxBatchSize <= 0 {
		c.ClickHouseMaxBatchSize = d.ClickHouseMaxBatchSize
	}
	if c.NATSPartitions <= 0 {
		c.NATSPartitions = d.NATSPartitions
	}
	if c.NATSRetentionHours <= 0 {
		c.NATSRetentionHours = d.NATSRetentionHours
	}
	if c.NATSMsgOverheadBytes <= 0 {
		c.NATSMsgOverheadBytes = d.NATSMsgOverheadBytes
	}
	if len(c.classRates) == 0 {
		c.classRates = d.classRates
	}
	return c
}

// totalEventsPerSec is the fleet-wide telemetry publish rate: every
// tenant emits every class at its per-class rate.
func (c CapacityPlanConfig) totalEventsPerSec() float64 {
	var perTenant float64
	for _, r := range c.classRates {
		perTenant += r.perTenantPS
	}
	return perTenant * float64(c.TenantCount)
}

// RunCapacityPlan evaluates the three sub-models and returns the
// assembled section. It never errors: the model is a pure transform
// over the config.
func RunCapacityPlan(cfg CapacityPlanConfig) *CapacityPlanSection {
	cfg = cfg.withDefaults()
	classes := make([]string, 0, len(cfg.classRates))
	for _, r := range cfg.classRates {
		classes = append(classes, r.class)
	}
	sort.Strings(classes)
	return &CapacityPlanSection{
		TenantCount:      cfg.TenantCount,
		TelemetryClasses: classes,
		Postgres:         planPostgresPool(cfg),
		ClickHouse:       planClickHouseWrite(cfg),
		NATS:             planNATSSubjects(cfg),
	}
}

// planPostgresPool models connection-pool pressure. Concurrent in-flight
// queries follow Little's law (concurrency = arrival_rate ×
// service_time); the app pool must cover that with headroom, and the
// Postgres backend must cover the app pools (directly, or via PgBouncer
// transaction multiplexing).
func planPostgresPool(cfg CapacityPlanConfig) PostgresPoolPlan {
	peakConcurrent := cfg.ControlPlaneRPS * (cfg.AvgQueryMs / 1000.0)
	const headroom = 1.5
	requiredPerReplica := int(math.Ceil(peakConcurrent * headroom / float64(cfg.ControlPlaneReplicas)))
	totalAppConns := cfg.PGMaxOpenConns * cfg.ControlPlaneReplicas

	// Without PgBouncer every app connection is a backend connection.
	// With transaction pooling the backend only needs to cover the
	// genuinely concurrent transactions (peak, with headroom).
	backendConns := totalAppConns
	if cfg.PGBouncerMode {
		backendConns = int(math.Ceil(peakConcurrent * headroom))
	}

	plan := PostgresPoolPlan{
		Replicas:              cfg.ControlPlaneReplicas,
		PoolSizePerReplica:    cfg.PGMaxOpenConns,
		TotalAppConns:         totalAppConns,
		PeakConcurrentQueries: round1(peakConcurrent),
		RecommendedPoolSize:   requiredPerReplica,
		PGBouncerMode:         cfg.PGBouncerMode,
		BackendConnsRequired:  backendConns,
		MaxConnections:        cfg.PGMaxConnections,
		WithinMaxConnections:  backendConns <= cfg.PGMaxConnections,
	}
	switch {
	case cfg.PGMaxOpenConns < requiredPerReplica:
		plan.Note = fmt.Sprintf("PG_MAX_OPEN_CONNS=%d is below the modelled per-replica peak of %d; raise it or add replicas.",
			cfg.PGMaxOpenConns, requiredPerReplica)
	case !plan.WithinMaxConnections:
		plan.Note = fmt.Sprintf("backend connections (%d) exceed max_connections (%d); enable PG_PGBOUNCER_MODE or raise max_connections.",
			backendConns, cfg.PGMaxConnections)
	default:
		plan.Note = "pool sized comfortably for the modelled load."
	}
	return plan
}

// planClickHouseWrite models the hot-path write load. Rows fan out
// across CLICKHOUSE_SHARDING shards by tenant hash; each shard's insert
// frequency is its row rate over the batch size.
//
// ClickHouse's dominant write-side failure mode is "too many parts":
// each INSERT creates a part, and a high part-creation rate starves the
// background merge scheduler. The healthy target is ≤ ~1 insert/s/shard
// (the same envelope the writer's 2s flush interval already aims for).
// The *primary* lever to hit it is a larger CLICKHOUSE_BATCH_SIZE (more
// rows per part), not more shards — sharding multiplies hardware and is
// only the right answer once a single shard's batch would have to grow
// past ClickHouseMaxBatchSize to keep up.
func planClickHouseWrite(cfg CapacityPlanConfig) ClickHouseWritePlan {
	rowsPerSec := cfg.totalEventsPerSec()
	rowsPerSecPerShard := rowsPerSec / float64(cfg.ClickHouseShards)
	insertsPerSecPerShard := rowsPerSecPerShard / float64(cfg.ClickHouseBatchSize)

	monthlyRows := rowsPerSec * secondsPerMonth
	uncompressedGBPerMonth := monthlyRows * float64(cfg.BytesPerEvent) / 1e9
	compressedGBPerMonth := uncompressedGBPerMonth / cfg.ClickHouseCompression

	plan := ClickHouseWritePlan{
		Shards:                 cfg.ClickHouseShards,
		BatchSize:              cfg.ClickHouseBatchSize,
		TotalRowsPerSec:        round1(rowsPerSec),
		RowsPerSecPerShard:     round1(rowsPerSecPerShard),
		InsertsPerSecPerShard:  round2c(insertsPerSecPerShard),
		MonthlyRows:            int64(monthlyRows),
		PerTenantMonthlyRows:   int64(monthlyRows / float64(cfg.TenantCount)),
		HotStorageGBCompressed: round1(compressedGBPerMonth),
		IngestBytesPerSec:      int64(rowsPerSec * float64(cfg.BytesPerEvent)),
		RecommendedShards:      cfg.ClickHouseShards,
		RecommendedBatchSize:   cfg.ClickHouseBatchSize,
	}

	const insertCeilingPerShard = 1.0
	if insertsPerSecPerShard <= insertCeilingPerShard {
		plan.Note = "insert frequency within the healthy ≤1/s/shard envelope."
		return plan
	}

	// Batch size needed to hold the current shard count at ≤1 insert/s.
	neededBatch := int(math.Ceil(rowsPerSecPerShard / insertCeilingPerShard))
	if neededBatch <= cfg.ClickHouseMaxBatchSize {
		plan.RecommendedBatchSize = neededBatch
		plan.Note = fmt.Sprintf("%.2f inserts/s/shard exceeds the ~1/s target; raise CLICKHOUSE_BATCH_SIZE to %d (more rows per part, same shard count).",
			insertsPerSecPerShard, neededBatch)
		return plan
	}
	// Even a max-size batch can't keep one shard under the ceiling, so
	// fan out: each shard then carries MaxBatchSize rows/insert at 1/s.
	plan.RecommendedBatchSize = cfg.ClickHouseMaxBatchSize
	plan.RecommendedShards = int(math.Ceil(rowsPerSec / (float64(cfg.ClickHouseMaxBatchSize) * insertCeilingPerShard)))
	plan.Note = fmt.Sprintf("%.2f inserts/s/shard exceeds the ~1/s target even at the max batch of %d; CLICKHOUSE_SHARDING across %d shards is required.",
		insertsPerSecPerShard, cfg.ClickHouseMaxBatchSize, plan.RecommendedShards)
	return plan
}

// planNATSSubjects models subject cardinality and JetStream storage.
// Distinct subjects = tenants × classes; they hash-distribute across
// NATS_PARTITIONS streams. FNV-1a over UUIDs spreads evenly, so the
// busiest partition runs only modestly above the mean — captured by a
// skew factor.
func planNATSSubjects(cfg CapacityPlanConfig) NATSSubjectPlan {
	distinct := cfg.TenantCount * len(cfg.classRates)
	avgPerPartition := float64(distinct) / float64(cfg.NATSPartitions)

	// Hash-balanced skew: with thousands of keys over tens of buckets
	// the busiest bucket is ~15% above the mean. Floor at the mean so a
	// single-partition layout reports no skew.
	const skew = 1.15
	maxPerPartition := int(math.Ceil(avgPerPartition * skew))
	if cfg.NATSPartitions <= 1 {
		maxPerPartition = distinct
	}

	msgsPerSec := cfg.totalEventsPerSec()
	retentionSec := cfg.NATSRetentionHours * 3600
	bytesPerMsg := float64(cfg.BytesPerEvent + cfg.NATSMsgOverheadBytes)
	streamBytesHot := int64(msgsPerSec * retentionSec * bytesPerMsg)

	plan := NATSSubjectPlan{
		Partitions:              cfg.NATSPartitions,
		DistinctSubjects:        distinct,
		SubjectsPerPartitionAvg: round1(avgPerPartition),
		SubjectsPerPartitionMax: maxPerPartition,
		MsgsPerSec:              round1(msgsPerSec),
		RetentionHours:          cfg.NATSRetentionHours,
		StreamBytesHot:          streamBytesHot,
	}
	// Keep each stream's subject filter under ~5k distinct subjects so
	// interest propagation and consumer filtering stay cheap.
	const subjectCeilingPerPartition = 5000.0
	if float64(maxPerPartition) > subjectCeilingPerPartition {
		plan.RecommendedPartitions = nextPow2(int(math.Ceil(float64(distinct) * skew / subjectCeilingPerPartition)))
		plan.Note = fmt.Sprintf("busiest partition holds ~%d subjects (>%.0f target); NATS_PARTITIONS=%d brings it under.",
			maxPerPartition, subjectCeilingPerPartition, plan.RecommendedPartitions)
	} else {
		plan.RecommendedPartitions = cfg.NATSPartitions
		plan.Note = "subject cardinality per partition within the healthy envelope."
	}
	return plan
}

// nextPow2 rounds n up to the next power of two, clamped to the
// config-validated NATS_PARTITIONS ceiling of 256. Powers of two keep
// the hash distribution even when operators step the partition count.
func nextPow2(n int) int {
	if n < 1 {
		return 1
	}
	p := 1
	for p < n && p < 256 {
		p <<= 1
	}
	if p > 256 {
		p = 256
	}
	return p
}

func round1(v float64) float64  { return math.Round(v*10) / 10 }
func round2c(v float64) float64 { return math.Round(v*100) / 100 }

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
