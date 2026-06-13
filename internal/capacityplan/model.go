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

	"github.com/kennguy3n/visible-fishbone/internal/service/tenancy"
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

	// --- Activity-tier telemetry sampling (WS-4) --------------------
	//
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
	// SweepJobs is the set of periodic per-tenant sweep loops wired
	// through tenancy.TieredSweep. Unset uses DefaultSweepJobs.
	SweepJobs []string
}

// DefaultSweepJobs is the set of periodic per-tenant sweep loops that
// adopt the shared tenancy.TieredSweep helper (the {job} label values of
// the sweep_tenants_visited metric). The capacity model fans the
// dormancy dividend across exactly these.
func DefaultSweepJobs() []string {
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
		// Dormant-heavy trial mix: most of a 5000-SME fleet are
		// long-idle trials. 8% active / 12% idle / 80% dormant.
		SweepActiveFraction:  0.08,
		SweepIdleFraction:    0.12,
		SweepDormantFraction: 0.80,
		SweepJobs:            DefaultSweepJobs(),
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
	if len(c.SweepJobs) == 0 {
		c.SweepJobs = d.SweepJobs
	}
	return c
}

// perTenantEventsPerSec sums every modelled telemetry class's per-tenant
// publish rate — what one full-fidelity tenant emits each second.
func (c Config) perTenantEventsPerSec() float64 {
	var sum float64
	for _, r := range c.ClassRates {
		sum += r.PerTenantPS
	}
	return sum
}

// perTenantSecurityEventsPerSec sums only the security-relevant classes
// (ips / ztna / dlp) — the floor a dormant tenant always writes.
func (c Config) perTenantSecurityEventsPerSec() float64 {
	var sum float64
	for _, r := range c.ClassRates {
		if securityClass(r.Class) {
			sum += r.PerTenantPS
		}
	}
	return sum
}

// modelledEventsPerSec is the synthetic fleet-wide telemetry publish
// rate: every tenant emits every class at its per-class rate.
func (c Config) modelledEventsPerSec() float64 {
	return c.perTenantEventsPerSec() * float64(c.TenantCount)
}

// tierTenantCounts splits the fleet into active / idle / dormant
// cohorts. Dormant absorbs the remainder (and any rounding slack) so
// the three always sum to TenantCount.
func (c Config) tierTenantCounts() (active, idle, dormant int) {
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
func (c Config) tierRowsPerSec() (active, idle, dormant float64) {
	na, ni, nd := c.tierTenantCounts()
	perTenant := c.perTenantEventsPerSec()
	active = float64(na) * perTenant
	idle = float64(ni) * perTenant * c.IdleSampleMultiplier
	dormant = float64(nd) * c.perTenantSecurityEventsPerSec()
	return active, idle, dormant
}

// effectiveEventsPerSec is the rate the throughput models size against.
// A live MeasuredEventsPerSec always wins — it already reflects whatever
// sampling production is doing. Otherwise, when the WS-4 tier-sampling
// policy is modelled the rate is the post-sampling cohort sum; with the
// policy off it is the synthetic full-fidelity per-class projection.
func (c Config) effectiveEventsPerSec() float64 {
	if c.MeasuredEventsPerSec > 0 {
		return c.MeasuredEventsPerSec
	}
	if c.TierSampling {
		a, i, d := c.tierRowsPerSec()
		return a + i + d
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
	// TierSampling is the WS-4 activity-tier sampling breakdown. Present
	// only when the policy is modelled (default-OFF), so the baseline
	// projection's JSON is byte-for-byte unchanged.
	TierSampling *TierSamplingPlan `json:"tier_sampling,omitempty"`
	// PeriodicSweep is the control-plane dormancy-dividend projection:
	// tenants-visited/cycle for the periodic per-tenant sweeps, before
	// vs after activity-tiered gating (WS-1).
	PeriodicSweep PeriodicSweepPlan `json:"periodic_sweep"`
}

// TierSamplingPlan decomposes the fleet write rate by activity tier
// under the WS-4 sampling policy: active tenants write full fidelity,
// idle tenants sample at IdleSampleMultiplier, dormant tenants write
// security-events-only. It is the metric proving dormant-tenant rows/s
// collapse and that total write cost tracks the active cohort.
type TierSamplingPlan struct {
	IdleSampleMultiplier float64 `json:"idle_sample_multiplier"`
	ActiveTenants        int     `json:"active_tenants"`
	IdleTenants          int     `json:"idle_tenants"`
	DormantTenants       int     `json:"dormant_tenants"`
	ActiveRowsPerSec     float64 `json:"active_rows_per_sec"`
	IdleRowsPerSec       float64 `json:"idle_rows_per_sec"`
	DormantRowsPerSec    float64 `json:"dormant_rows_per_sec"`
	SampledRowsPerSec    float64 `json:"sampled_rows_per_sec"`
	BaselineRowsPerSec   float64 `json:"baseline_rows_per_sec"`
	ReductionPct         float64 `json:"reduction_pct"`
	ActiveCohortSharePct float64 `json:"active_cohort_share_pct"`
}

// PeriodicSweepPlan projects the WS-1 dormancy dividend: how many
// tenants the periodic per-tenant sweeps (idp_directory_sync,
// casb_noops_reconcile, alert_feedback_tuning) visit per cycle once the
// shared tenancy.TieredSweep gates them by activity tier, versus the
// legacy every-tenant-every-cycle fan-out. The dominant avoidable
// control-plane cost at a dormant-heavy 5000-SME fleet.
type PeriodicSweepPlan struct {
	// Jobs is the set of sweep loops modelled (the {job} label values
	// of sweep_tenants_visited).
	Jobs []string `json:"jobs"`
	// JobCount is len(Jobs), surfaced for the aggregate roll-up.
	JobCount int `json:"job_count"`
	// IdleEvery / DormantEvery are the planner cadences the model used
	// (idle tenants visited every Nth cycle, dormant every Mth).
	IdleEvery    int64 `json:"idle_every"`
	DormantEvery int64 `json:"dormant_every"`
	// ActiveTenants / IdleTenants / DormantTenants is the modelled
	// activity-tier breakdown of the fleet.
	ActiveTenants  int `json:"active_tenants"`
	IdleTenants    int `json:"idle_tenants"`
	DormantTenants int `json:"dormant_tenants"`
	// UntieredVisitsPerCyclePerJob is the legacy cost: every tenant,
	// every cycle (== TenantCount).
	UntieredVisitsPerCyclePerJob int `json:"untiered_visits_per_cycle_per_job"`
	// TieredVisitsPerCyclePerJob is the steady-state cost after tiering,
	// averaged over one full cadence period.
	TieredVisitsPerCyclePerJob float64 `json:"tiered_visits_per_cycle_per_job"`
	// ActiveVisitsPerCycle / IdleVisitsPerCycle / DormantVisitsPerCycle
	// decompose the tiered per-job cost by tier.
	ActiveVisitsPerCycle  float64 `json:"active_visits_per_cycle"`
	IdleVisitsPerCycle    float64 `json:"idle_visits_per_cycle"`
	DormantVisitsPerCycle float64 `json:"dormant_visits_per_cycle"`
	// UntieredVisitsPerCycleTotal / TieredVisitsPerCycleTotal aggregate
	// across all modelled jobs.
	UntieredVisitsPerCycleTotal int     `json:"untiered_visits_per_cycle_total"`
	TieredVisitsPerCycleTotal   float64 `json:"tiered_visits_per_cycle_total"`
	// ReductionFactor is untiered/tiered per job (aggregate dividend).
	ReductionFactor float64 `json:"reduction_factor"`
	// IdleReductionFactor / DormantReductionFactor are the per-tier
	// dividends on the idle/dormant tail (the headline 10-100x).
	IdleReductionFactor    float64 `json:"idle_reduction_factor"`
	DormantReductionFactor float64 `json:"dormant_reduction_factor"`
	Note                   string  `json:"note"`
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
		TierSampling:     planTierSampling(cfg),
		PeriodicSweep:    planPeriodicSweep(cfg),
	}
}

// planTierSampling projects the WS-4 cohort breakdown. Returns nil when
// the policy is not modelled (default-OFF), so the section is omitted
// from the report and the baseline projection is untouched. When on, it
// shows fleet rows/s decomposed by activity tier — the proof that write
// cost tracks the active cohort rather than the raw tenant count.
func planTierSampling(cfg Config) *TierSamplingPlan {
	if !cfg.TierSampling {
		return nil
	}
	na, ni, nd := cfg.tierTenantCounts()
	activeRows, idleRows, dormantRows := cfg.tierRowsPerSec()
	sampledTotal := activeRows + idleRows + dormantRows
	baselineTotal := cfg.modelledEventsPerSec()

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
func planPeriodicSweep(cfg Config) PeriodicSweepPlan {
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

	jobCount := len(cfg.SweepJobs)
	untieredPerJob := n // legacy fan-out visits every tenant every cycle

	plan := PeriodicSweepPlan{
		Jobs:           append([]string(nil), cfg.SweepJobs...),
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
