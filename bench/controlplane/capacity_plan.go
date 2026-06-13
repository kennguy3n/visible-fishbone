package main

// Capacity planning is an analytical model rather than a measured
// workload: it answers "what does the data plane look like at N
// tenants?" without standing up a 5,000-tenant fleet. It is therefore
// always deterministic and dependency-free (no Postgres, no NATS, no
// ClickHouse), which is exactly what a capacity-planning artifact wants
// — a reproducible projection an operator can re-run with different
// knobs (partition count, shard count, pool size) and diff.
//
// The first three sub-models mirror the three horizontal-scaling axes
// the platform exposes:
//   - Postgres connection-pool pressure (PG_MAX_OPEN_CONNS,
//     read replicas, PgBouncer transaction pooling).
//   - ClickHouse write throughput (CLICKHOUSE_SHARDING, batch size).
//   - NATS subject cardinality (NATS_PARTITIONS fan-out).
//
// A fourth sub-model captures the control-plane (not data-plane) cost
// the dormancy work targets: how many tenants the periodic per-tenant
// sweeps visit per cycle, before vs after the activity-tiered
// SweepPlanner gating (the WS-1 dormancy dividend).

import (
	"fmt"
	"math"
	"sort"
	"strings"

	"github.com/kennguy3n/visible-fishbone/internal/service/tenancy"
)

const secondsPerMonth = 30.0 * 24 * 3600

// boolPtr returns a pointer to v, for tri-state config fields where the
// nil zero value means "unset — apply the documented default".
func boolPtr(v bool) *bool { return &v }

// derefBool reports *p, treating a nil pointer as false.
func derefBool(p *bool) bool { return p != nil && *p }

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
//
// Of these, only "ips" and "ztna" are security-relevant (securityClass),
// so they alone form the dormant-tier write floor. "dlp" is also
// security-relevant at runtime but is intentionally NOT in this default
// set — endpoint DLP volume is modelled as negligible at the SME tier,
// and the tier-sampling tests are calibrated to the ips+ztna (0.5/tenant)
// floor. Add a "dlp" entry here (and re-baseline the dormant-floor tests)
// if DLP telemetry becomes material to the capacity projection.
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

	// classRates is the per-class per-tenant event rate. Unset uses
	// defaultClassRates.
	classRates []classEventRate

	// TierSampling models the WS-4 activity-tier-aware telemetry
	// sampling policy: the fleet is split into active / idle / dormant
	// cohorts, active tenants write full fidelity, idle tenants sample
	// at IdleSampleMultiplier, and dormant tenants write
	// security-events-only (ips / ztna / dlp). When false the model is
	// the pre-WS-4 projection (every tenant writes every class at full
	// rate), so the default output is unchanged — this is the bench
	// twin of the DEFAULT-OFF runtime gate.
	TierSampling bool
	// ActiveFraction / IdleFraction are the share of the fleet in the
	// active / idle cohorts; the remainder is dormant. Only consulted
	// when TierSampling is true. Defaults model a NoOps fleet where most
	// tenants are dormant trials (10% active, 15% idle, 75% dormant).
	//
	// They are not validated to sum to <= 1: tierTenantCounts clamps the
	// idle count so active+idle never exceeds TenantCount and derives
	// dormant as the remainder, so an over-1 sum is silently renormalised
	// (dormant collapses to 0) rather than rejected. Pass fractions that
	// sum to <= 1 for the cohort split you intend.
	//
	// A zero (or negative) value means "unset" and is replaced with the
	// default by withDefaults — consistent with every other knob in this
	// config. To model a fully-dormant fleet, pass a tiny positive
	// ActiveFraction (e.g. 0.001) rather than 0.
	ActiveFraction float64
	IdleFraction   float64
	// IdleSampleMultiplier is the keep fraction applied to an idle
	// tenant's events. Defaults to the telemetry package default (0.25).
	// Only consulted when TierSampling is true.
	IdleSampleMultiplier float64

	// --- Periodic per-tenant sweep (WS-1 dormancy dividend) ---------
	//
	// SweepActiveFraction / SweepIdleFraction / SweepDormantFraction are
	// the modelled activity mix of the fleet: the share of tenants the
	// SweepPlanner classifies active (seen < IdleAfter), idle (seen <
	// DormantAfter) and dormant (never/long-since seen). At ~5000 SME
	// tenants where most are dormant trials the tail dominates, so the
	// defaults are deliberately dormant-heavy. They need not sum to
	// exactly 1.0 — planPeriodicSweep normalises them — but the defaults
	// do. Each is a fraction in [0,1].
	SweepActiveFraction  float64
	SweepIdleFraction    float64
	SweepDormantFraction float64
	// sweepJobs is the set of periodic per-tenant sweep loops wired
	// through tenancy.TieredSweep. Unset uses defaultSweepJobs.
	sweepJobs []string
}

// defaultSweepJobs is the set of periodic per-tenant sweep loops that
// adopt the shared tenancy.TieredSweep helper (the {job} label values of
// the sweep_tenants_visited metric). The capacity model fans the
// dormancy dividend across exactly these.
func defaultSweepJobs() []string {
	return []string{
		"idp_directory_sync",
		"casb_noops_reconcile",
		"alert_feedback_tuning",
	}
}

// securityClass reports whether a telemetry class is security-relevant
// and therefore never shed by the dormant tier. Mirrors the runtime
// predicate (telemetry.isSecurityRelevantEventClass): ips / ztna / dlp.
func securityClass(class string) bool {
	switch class {
	case "ips", "ztna", "dlp":
		return true
	default:
		return false
	}
}

// Default cohort split + idle keep fraction for the tier-sampling
// model. Most tenants in a NoOps trial fleet are dormant.
const (
	defaultActiveFraction       = 0.10
	defaultIdleFraction         = 0.15
	defaultIdleSampleMultiplier = 0.25
)

// DefaultCapacityPlanConfig models the headline 5,000-tenant tier with
// the platform's documented default knobs.
func DefaultCapacityPlanConfig() CapacityPlanConfig {
	return CapacityPlanConfig{
		TenantCount:          5000,
		ControlPlaneReplicas: 3,
		PGMaxOpenConns:       20,
		PGBouncerMode:        boolPtr(true),
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
		// Dormant-heavy trial mix: most of a 5000-SME fleet are
		// long-idle trials. 8% active / 12% idle / 80% dormant.
		SweepActiveFraction:  0.08,
		SweepIdleFraction:    0.12,
		SweepDormantFraction: 0.80,
		sweepJobs:            defaultSweepJobs(),
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
	if len(c.classRates) == 0 {
		c.classRates = d.classRates
	}
	// Tier-sampling cohort knobs only matter when the policy is modelled;
	// fill them with NoOps-fleet defaults so an operator can flip
	// TierSampling on without having to specify the whole split.
	if c.TierSampling {
		if c.ActiveFraction <= 0 {
			c.ActiveFraction = defaultActiveFraction
		}
		if c.IdleFraction <= 0 {
			c.IdleFraction = defaultIdleFraction
		}
		if c.IdleSampleMultiplier <= 0 {
			c.IdleSampleMultiplier = defaultIdleSampleMultiplier
		}
	}
	// The three sweep fractions are filled as a group: if none was set
	// (all <= 0) apply the default mix; a partially-specified mix is left
	// as given and normalised by planPeriodicSweep.
	if c.SweepActiveFraction <= 0 && c.SweepIdleFraction <= 0 && c.SweepDormantFraction <= 0 {
		c.SweepActiveFraction = d.SweepActiveFraction
		c.SweepIdleFraction = d.SweepIdleFraction
		c.SweepDormantFraction = d.SweepDormantFraction
	} else {
		// A partially-specified mix may carry a stray negative weight;
		// clamp each to 0 so a single negative fraction can never produce
		// a negative tenant count (the normalisation in planPeriodicSweep
		// divides by the sum, which a negative term could otherwise skew).
		c.SweepActiveFraction = max(c.SweepActiveFraction, 0)
		c.SweepIdleFraction = max(c.SweepIdleFraction, 0)
		c.SweepDormantFraction = max(c.SweepDormantFraction, 0)
	}
	if len(c.sweepJobs) == 0 {
		c.sweepJobs = d.sweepJobs
	}
	return c
}

// perTenantEventsPerSec sums every class's per-tenant rate (the full
// per-tenant publish rate before any tier sampling).
func (c CapacityPlanConfig) perTenantEventsPerSec() float64 {
	var sum float64
	for _, r := range c.classRates {
		sum += r.perTenantPS
	}
	return sum
}

// perTenantSecurityEventsPerSec sums only the security-relevant classes
// (ips / ztna / dlp) — the floor a dormant tenant always writes.
func (c CapacityPlanConfig) perTenantSecurityEventsPerSec() float64 {
	var sum float64
	for _, r := range c.classRates {
		if securityClass(r.class) {
			sum += r.perTenantPS
		}
	}
	return sum
}

// totalEventsPerSec is the fleet-wide telemetry publish rate: every
// tenant emits every class at its per-class rate.
func (c CapacityPlanConfig) totalEventsPerSec() float64 {
	return c.perTenantEventsPerSec() * float64(c.TenantCount)
}

// tierTenantCounts splits the fleet into active / idle / dormant
// cohorts. Dormant absorbs the remainder (and any rounding slack) so
// the three always sum to TenantCount.
func (c CapacityPlanConfig) tierTenantCounts() (active, idle, dormant int) {
	active = int(math.Round(c.ActiveFraction * float64(c.TenantCount)))
	idle = int(math.Round(c.IdleFraction * float64(c.TenantCount)))
	if active > c.TenantCount {
		active = c.TenantCount
	}
	if active+idle > c.TenantCount {
		idle = c.TenantCount - active
	}
	dormant = c.TenantCount - active - idle
	return active, idle, dormant
}

// tierRowsPerSec returns each cohort's contribution to the fleet write
// rate under the tier-sampling policy: active full fidelity, idle scaled
// by the idle multiplier, dormant security-events-only.
func (c CapacityPlanConfig) tierRowsPerSec() (active, idle, dormant float64) {
	na, ni, nd := c.tierTenantCounts()
	perTenant := c.perTenantEventsPerSec()
	active = float64(na) * perTenant
	idle = float64(ni) * perTenant * c.IdleSampleMultiplier
	dormant = float64(nd) * c.perTenantSecurityEventsPerSec()
	return active, idle, dormant
}

// effectiveRowsPerSec is the fleet write rate the downstream ClickHouse
// model sizes against: the full publish rate when tier sampling is off,
// or the post-sampling cohort sum when it is on.
func (c CapacityPlanConfig) effectiveRowsPerSec() float64 {
	if !c.TierSampling {
		return c.totalEventsPerSec()
	}
	a, i, d := c.tierRowsPerSec()
	return a + i + d
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
		TierSampling:     planTierSampling(cfg),
		PeriodicSweep:    planPeriodicSweep(cfg),
	}
}

// planTierSampling projects the WS-4 cohort breakdown. Returns nil when
// the policy is not modelled (default-OFF), so the section is omitted
// from the report and the baseline projection is untouched. When on, it
// shows fleet rows/s decomposed by activity tier — the proof that write
// cost tracks the active cohort rather than the raw tenant count.
func planTierSampling(cfg CapacityPlanConfig) *TierSamplingPlan {
	if !cfg.TierSampling {
		return nil
	}
	na, ni, nd := cfg.tierTenantCounts()
	activeRows, idleRows, dormantRows := cfg.tierRowsPerSec()
	sampledTotal := activeRows + idleRows + dormantRows
	baselineTotal := cfg.totalEventsPerSec()

	var reductionPct float64
	if baselineTotal > 0 {
		reductionPct = (1 - sampledTotal/baselineTotal) * 100
	}
	var activeShare float64
	if sampledTotal > 0 {
		activeShare = activeRows / sampledTotal * 100
	}

	return &TierSamplingPlan{
		IdleSampleMultiplier: cfg.IdleSampleMultiplier,
		ActiveTenants:        na,
		IdleTenants:          ni,
		DormantTenants:       nd,
		ActiveRowsPerSec:     round1(activeRows),
		IdleRowsPerSec:       round1(idleRows),
		DormantRowsPerSec:    round1(dormantRows),
		SampledRowsPerSec:    round1(sampledTotal),
		BaselineRowsPerSec:   round1(baselineTotal),
		ReductionPct:         round1(reductionPct),
		ActiveCohortSharePct: round1(activeShare),
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
func planClickHouseWrite(cfg CapacityPlanConfig) ClickHouseWritePlan {
	// effectiveRowsPerSec applies the WS-4 tier-sampling reduction when
	// it is modelled, so every downstream projection (inserts/s, monthly
	// rows, storage) reflects the post-sampling load; with the policy
	// off it is exactly the full publish rate, leaving the baseline
	// projection unchanged.
	rowsPerSec := cfg.effectiveRowsPerSec()
	rowsPerSecPerShard := rowsPerSec / float64(cfg.ClickHouseShards)
	insertsPerSecPerShard := rowsPerSecPerShard / float64(cfg.ClickHouseBatchSize)

	monthlyRows := rowsPerSec * secondsPerMonth
	uncompressedGBPerMonth := monthlyRows * float64(cfg.BytesPerEvent) / 1e9
	compressedGBPerMonth := uncompressedGBPerMonth / cfg.ClickHouseCompression

	plan := ClickHouseWritePlan{
		Shards:                cfg.ClickHouseShards,
		BatchSize:             cfg.ClickHouseBatchSize,
		TotalRowsPerSec:       round1(rowsPerSec),
		RowsPerSecPerShard:    round1(rowsPerSecPerShard),
		InsertsPerSecPerShard: round2c(insertsPerSecPerShard),
		MonthlyRows:           int64(monthlyRows),
		// PerTenantMonthlyRows is the fleet-wide mean (total ÷
		// TenantCount). Under tier sampling it is NOT any single
		// tenant's volume — an active tenant writes far more and a
		// dormant one far less; the TierSampling section carries the
		// per-cohort breakdown. Without tier sampling every tenant
		// writes the same rate, so it is the exact per-tenant figure.
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

// planPeriodicSweep models the WS-1 dormancy dividend: how many tenants
// each periodic per-tenant sweep visits per cycle, before vs after the
// activity-tiered SweepPlanner gating, fanned across the jobs that adopt
// tenancy.TieredSweep.
//
// Fidelity: it does NOT re-derive the cadence arithmetic — it drives the
// real tenancy.DefaultPlanner().ShouldVisit over one full DormantEvery
// period and averages the per-tier visit rate, so the model and the
// shipped gate can never silently diverge. Cycle 0 is the full startup
// sweep, so it is included in the period average (every tier is visited
// on cycle 0), which is why the per-tier rates are marginally above the
// raw 1/IdleEvery and 1/DormantEvery cadences.
func planPeriodicSweep(cfg CapacityPlanConfig) PeriodicSweepPlan {
	planner := tenancy.DefaultPlanner()

	// Normalise the activity mix to fractions of the fleet.
	total := cfg.SweepActiveFraction + cfg.SweepIdleFraction + cfg.SweepDormantFraction
	if total <= 0 {
		// Degenerate config: treat everyone active (the planner's own
		// fail-safe posture — more work, never less).
		total = 1
		cfg.SweepActiveFraction = 1
	}
	activeFrac := cfg.SweepActiveFraction / total
	idleFrac := cfg.SweepIdleFraction / total
	dormantFrac := cfg.SweepDormantFraction / total

	n := float64(cfg.TenantCount)
	activeN := activeFrac * n
	idleN := idleFrac * n
	dormantN := dormantFrac * n

	// Average per-cycle visit rate per tier over one full cadence
	// period, using the real gate so this stays in lock-step with
	// production. The period is DormantEvery (the longest cadence); a
	// non-positive cadence (fail-safe planner) collapses to period 1.
	period := planner.DormantEvery
	if period <= 0 {
		period = 1
	}
	visitRate := func(tier tenancy.Tier) float64 {
		visits := 0
		for cycle := int64(0); cycle < period; cycle++ {
			if planner.ShouldVisit(tier, cycle) {
				visits++
			}
		}
		return float64(visits) / float64(period)
	}
	activeRate := visitRate(tenancy.TierActive)
	idleRate := visitRate(tenancy.TierIdle)
	dormantRate := visitRate(tenancy.TierDormant)

	activeVisits := activeN * activeRate
	idleVisits := idleN * idleRate
	dormantVisits := dormantN * dormantRate
	tieredPerJob := activeVisits + idleVisits + dormantVisits

	jobCount := len(cfg.sweepJobs)
	untieredPerJob := n // legacy fan-out visits every tenant every cycle

	plan := PeriodicSweepPlan{
		Jobs:           append([]string(nil), cfg.sweepJobs...),
		JobCount:       jobCount,
		IdleEvery:      planner.IdleEvery,
		DormantEvery:   planner.DormantEvery,
		ActiveTenants:  int(math.Round(activeN)),
		IdleTenants:    int(math.Round(idleN)),
		DormantTenants: int(math.Round(dormantN)),

		UntieredVisitsPerCyclePerJob: int(math.Round(untieredPerJob)),
		TieredVisitsPerCyclePerJob:   round1(tieredPerJob),

		ActiveVisitsPerCycle:  round1(activeVisits),
		IdleVisitsPerCycle:    round1(idleVisits),
		DormantVisitsPerCycle: round1(dormantVisits),

		UntieredVisitsPerCycleTotal: int(math.Round(untieredPerJob * float64(jobCount))),
		TieredVisitsPerCycleTotal:   round1(tieredPerJob * float64(jobCount)),
	}
	// Reduction factors: aggregate, and per-tier on the dormant tail
	// (the headline 10-100x). Guard against divide-by-zero on a
	// degenerate (all-active) mix.
	if tieredPerJob > 0 {
		plan.ReductionFactor = round1(untieredPerJob / tieredPerJob)
	}
	if idleRate > 0 {
		plan.IdleReductionFactor = round1(1 / idleRate)
	}
	if dormantRate > 0 {
		plan.DormantReductionFactor = round1(1 / dormantRate)
	}
	plan.Note = fmt.Sprintf(
		"%d job(s) tiered: %.0f tenants/cycle/job → %.1f (%.1fx); idle tail %.1fx, dormant tail %.1fx.",
		jobCount, untieredPerJob, plan.TieredVisitsPerCyclePerJob, plan.ReductionFactor,
		plan.IdleReductionFactor, plan.DormantReductionFactor)
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
