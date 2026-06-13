// Package capacityplan is the deterministic, dependency-free
// analytical model that projects the control plane's data-plane
// footprint at a given tenant count across the three horizontal-
// scaling axes the platform exposes:
//
//   - Postgres connection-pool pressure (PG_MAX_OPEN_CONNS,
//     read replicas, PgBouncer transaction pooling).
//   - ClickHouse write throughput (CLICKHOUSE_SHARDING, batch size).
//   - NATS subject cardinality (NATS_PARTITIONS fan-out).
//
// It answers "what does the data plane look like at N tenants?"
// without standing up a 5,000-tenant fleet, so it is always
// deterministic — a reproducible projection an operator can re-run
// with different knobs (partition count, shard count, pool size) and
// diff.
//
// The model lives in this importable package (rather than the
// bench/controlplane command that birthed it) so it has exactly one
// implementation: the offline `capacity-plan` bench artifact and the
// live capacity reconciler (internal/service/capacity) both call
// Run, guaranteeing the recommendations an operator sees at runtime
// match the documented planning numbers in docs/scaling.md to the
// row.
package capacityplan

import (
	"fmt"
	"math"
	"sort"
)

// secondsPerMonth is the month length used to project monthly row
// counts and storage from a steady-state per-second rate.
const secondsPerMonth = 30.0 * 24 * 3600

// BoolPtr returns a pointer to v, for the tri-state Config.PGBouncerMode
// field where the nil zero value means "unset — apply the documented
// default".
func BoolPtr(v bool) *bool { return &v }

// derefBool reports *p, treating a nil pointer as false.
func derefBool(p *bool) bool { return p != nil && *p }

// ClassEventRate is the modelled sustained per-tenant publish rate
// (events/sec) for one telemetry class. flow dominates; control-plane
// classes (ztna, agent) are sparse. These are deliberately conservative
// steady-state averages for a mid-market tenant; an operator tunes them
// for their own traffic mix.
type ClassEventRate struct {
	Class       string
	PerTenantPS float64
}

// DefaultClassRates is the canonical set of telemetry event classes the
// data plane partitions subjects by, per ARCHITECTURE.md §3.3
// (`sng.<tenant>.telemetry.<class>`), each paired with its modelled
// per-tenant rate. The NATS subject-cardinality and ClickHouse
// throughput models fan out across exactly these seven.
func DefaultClassRates() []ClassEventRate {
	return []ClassEventRate{
		{"flow", 2.0},
		{"dns", 1.0},
		{"http", 1.5},
		{"ips", 0.2},
		{"ztna", 0.3},
		{"sdwan", 0.2},
		{"agent", 0.1},
	}
}

// Config parameterises the capacity model. Zero values are replaced
// with the documented defaults by withDefaults so a caller can pass an
// empty struct to model the default 5,000-tenant tier.
type Config struct {
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
	// set of backend connections. It is a tri-state pointer rather than
	// a bare bool so withDefaults can tell "unset" (nil → apply the
	// default, which is enabled) apart from an explicit false — a plain
	// bool's zero value would silently disable pooling on a partial
	// config and contradict the documented default.
	PGBouncerMode *bool
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

	// MeasuredEventsPerSec is an optional live, fleet-wide telemetry
	// publish rate (events/sec) observed at runtime. When > 0 the
	// throughput models (ClickHouse rows/s, NATS msgs/s) use it in
	// place of the synthetic ClassRates × TenantCount projection, so a
	// reconciler fed real metrics sizes the write path against what the
	// fleet is actually emitting rather than a worst-case assumption.
	// It deliberately does NOT affect subject cardinality (subjects
	// exist per tenant×class regardless of how busy they are) or the
	// Postgres pressure model (driven by control-plane RPS, not
	// telemetry). Zero (the default) keeps the projection identical to
	// the offline bench model.
	MeasuredEventsPerSec float64

	// ClassRates is the per-class per-tenant event rate. Unset uses
	// DefaultClassRates.
	ClassRates []ClassEventRate
}

// DefaultConfig models the headline 5,000-tenant tier with the
// platform's documented default knobs.
func DefaultConfig() Config {
	return Config{
		TenantCount:          5000,
		ControlPlaneReplicas: 3,
		PGMaxOpenConns:       20,
		PGBouncerMode:        BoolPtr(true),
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
		ClassRates:               DefaultClassRates(),
	}
}

// withDefaults fills any zero-valued field with its default so a
// partially-specified config (e.g. only TenantCount set) is still
// internally consistent.
func (c Config) withDefaults() Config {
	d := DefaultConfig()
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
	if c.PGBouncerMode == nil {
		c.PGBouncerMode = d.PGBouncerMode
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
	if len(c.ClassRates) == 0 {
		c.ClassRates = d.ClassRates
	}
	return c
}

// modelledEventsPerSec is the synthetic fleet-wide telemetry publish
// rate: every tenant emits every class at its per-class rate.
func (c Config) modelledEventsPerSec() float64 {
	var perTenant float64
	for _, r := range c.ClassRates {
		perTenant += r.PerTenantPS
	}
	return perTenant * float64(c.TenantCount)
}

// effectiveEventsPerSec is the rate the throughput models size
// against: the live MeasuredEventsPerSec when supplied, else the
// synthetic per-class projection.
func (c Config) effectiveEventsPerSec() float64 {
	if c.MeasuredEventsPerSec > 0 {
		return c.MeasuredEventsPerSec
	}
	return c.modelledEventsPerSec()
}

// Section is the deterministic capacity projection: the data-plane
// footprint at a given tenant count across the three horizontal-
// scaling axes.
type Section struct {
	// TenantCount is the modelled fleet size.
	TenantCount int `json:"tenant_count"`
	// TelemetryClasses is the set of telemetry classes the throughput
	// and subject-cardinality models fan out across.
	TelemetryClasses []string `json:"telemetry_classes"`
	// Postgres is the connection-pool pressure projection.
	Postgres PostgresPoolPlan `json:"postgres"`
	// ClickHouse is the hot-path write-throughput projection.
	ClickHouse ClickHouseWritePlan `json:"clickhouse"`
	// NATS is the subject-cardinality + JetStream storage projection.
	NATS NATSSubjectPlan `json:"nats"`
}

// PostgresPoolPlan projects connection-pool pressure at scale.
type PostgresPoolPlan struct {
	Replicas              int     `json:"replicas"`
	PoolSizePerReplica    int     `json:"pool_size_per_replica"`
	TotalAppConns         int     `json:"total_app_conns"`
	PeakConcurrentQueries float64 `json:"peak_concurrent_queries"`
	RecommendedPoolSize   int     `json:"recommended_pool_size"`
	PGBouncerMode         bool    `json:"pgbouncer_mode"`
	BackendConnsRequired  int     `json:"backend_conns_required"`
	MaxConnections        int     `json:"max_connections"`
	WithinMaxConnections  bool    `json:"within_max_connections"`
	Note                  string  `json:"note"`
}

// ClickHouseWritePlan projects hot-path write load at scale.
type ClickHouseWritePlan struct {
	Shards                 int     `json:"shards"`
	BatchSize              int     `json:"batch_size"`
	TotalRowsPerSec        float64 `json:"total_rows_per_sec"`
	RowsPerSecPerShard     float64 `json:"rows_per_sec_per_shard"`
	InsertsPerSecPerShard  float64 `json:"inserts_per_sec_per_shard"`
	MonthlyRows            int64   `json:"monthly_rows"`
	PerTenantMonthlyRows   int64   `json:"per_tenant_monthly_rows"`
	HotStorageGBCompressed float64 `json:"hot_storage_gb_compressed"`
	IngestBytesPerSec      int64   `json:"ingest_bytes_per_sec"`
	RecommendedShards      int     `json:"recommended_shards"`
	RecommendedBatchSize   int     `json:"recommended_batch_size"`
	Note                   string  `json:"note"`
}

// NATSSubjectPlan projects subject cardinality + JetStream storage.
type NATSSubjectPlan struct {
	Partitions              int     `json:"partitions"`
	DistinctSubjects        int     `json:"distinct_subjects"`
	SubjectsPerPartitionAvg float64 `json:"subjects_per_partition_avg"`
	SubjectsPerPartitionMax int     `json:"subjects_per_partition_max"`
	MsgsPerSec              float64 `json:"msgs_per_sec"`
	RetentionHours          float64 `json:"retention_hours"`
	StreamBytesHot          int64   `json:"stream_bytes_hot"`
	RecommendedPartitions   int     `json:"recommended_partitions"`
	Note                    string  `json:"note"`
}

// Run evaluates the three sub-models and returns the assembled
// section. It never errors: the model is a pure transform over the
// config.
func Run(cfg Config) *Section {
	cfg = cfg.withDefaults()
	classes := make([]string, 0, len(cfg.ClassRates))
	for _, r := range cfg.ClassRates {
		classes = append(classes, r.Class)
	}
	sort.Strings(classes)
	return &Section{
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
func planPostgresPool(cfg Config) PostgresPoolPlan {
	peakConcurrent := cfg.ControlPlaneRPS * (cfg.AvgQueryMs / 1000.0)
	const headroom = 1.5
	requiredPerReplica := int(math.Ceil(peakConcurrent * headroom / float64(cfg.ControlPlaneReplicas)))
	totalAppConns := cfg.PGMaxOpenConns * cfg.ControlPlaneReplicas

	// cfg has been through withDefaults, so PGBouncerMode is non-nil here;
	// derefBool stays defensive in case planPostgresPool is ever called
	// on a raw config.
	pgbouncer := derefBool(cfg.PGBouncerMode)

	// Without PgBouncer every app connection is a backend connection.
	// With transaction pooling the backend only needs to cover the
	// genuinely concurrent transactions (peak, with headroom).
	backendConns := totalAppConns
	if pgbouncer {
		backendConns = int(math.Ceil(peakConcurrent * headroom))
	}

	plan := PostgresPoolPlan{
		Replicas:              cfg.ControlPlaneReplicas,
		PoolSizePerReplica:    cfg.PGMaxOpenConns,
		TotalAppConns:         totalAppConns,
		PeakConcurrentQueries: round1(peakConcurrent),
		RecommendedPoolSize:   requiredPerReplica,
		PGBouncerMode:         pgbouncer,
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
func planClickHouseWrite(cfg Config) ClickHouseWritePlan {
	rowsPerSec := cfg.effectiveEventsPerSec()
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
func planNATSSubjects(cfg Config) NATSSubjectPlan {
	distinct := cfg.TenantCount * len(cfg.ClassRates)
	avgPerPartition := float64(distinct) / float64(cfg.NATSPartitions)

	// Hash-balanced skew: with thousands of keys over tens of buckets
	// the busiest bucket is ~15% above the mean. Floor at the mean so a
	// single-partition layout reports no skew.
	const skew = 1.15
	maxPerPartition := int(math.Ceil(avgPerPartition * skew))
	if cfg.NATSPartitions <= 1 {
		maxPerPartition = distinct
	}

	msgsPerSec := cfg.effectiveEventsPerSec()
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
		plan.RecommendedPartitions = NextPow2(int(math.Ceil(float64(distinct) * skew / subjectCeilingPerPartition)))
		plan.Note = fmt.Sprintf("busiest partition holds ~%d subjects (>%.0f target); NATS_PARTITIONS=%d brings it under.",
			maxPerPartition, subjectCeilingPerPartition, plan.RecommendedPartitions)
	} else {
		plan.RecommendedPartitions = cfg.NATSPartitions
		plan.Note = "subject cardinality per partition within the healthy envelope."
	}
	return plan
}

// NextPow2 rounds n up to the next power of two, clamped to the
// config-validated NATS_PARTITIONS ceiling of 256. Powers of two keep
// the hash distribution even when operators step the partition count.
func NextPow2(n int) int {
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
