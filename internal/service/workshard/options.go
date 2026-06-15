package workshard

import (
	"log/slog"
	"time"

	"github.com/google/uuid"
)

// Tunable defaults. They are sized for a 5,000-tenant no-ops SaaS: the
// per-cycle Postgres cost is a small constant (one heartbeat, one
// worker list, and up to three lease statements) regardless of tenant
// or shard count, and the cadence below keeps lease churn and query
// rate bounded no matter how many replicas run.
const (
	// DefaultShardCount is the fixed number of shards tenants hash into.
	// It only needs to exceed the maximum replica count comfortably so
	// ownership divides evenly; 1024 gives smooth balance well past any
	// realistic SME replica count while keeping the lease table tiny.
	DefaultShardCount = 1024

	// DefaultLeaseTTL is how long an acquired shard lease (and a worker
	// heartbeat) remains valid in the database before it is reclaimable.
	DefaultLeaseTTL = 20 * time.Second

	// DefaultCycleInterval is how often a worker heartbeats, recomputes
	// its shard assignment, and renews its leases. It is comfortably
	// below DefaultLeaseTTL-DefaultSafetyMargin so several renewals fall
	// inside every lease window and a transient blip does not drop work.
	DefaultCycleInterval = 5 * time.Second

	// DefaultSafetyMargin is how far before the database lease deadline a
	// worker stops treating itself as the owner locally. It absorbs
	// clock skew and processing latency: the previous owner has yielded
	// (locally) for at least this long before the database lease expires
	// and any successor can acquire, so no two workers process the same
	// tenant at once. Local validity window = LeaseTTL - SafetyMargin.
	DefaultSafetyMargin = 7 * time.Second

	// DefaultConcurrency bounds how many owned tenants a worker processes
	// in parallel per cycle (backpressure).
	DefaultConcurrency = 16

	// DefaultGCEvery runs the expired-worker sweep once every N cycles
	// (so registry cleanup is cheap and not every cycle).
	DefaultGCEvery = 12

	// DefaultGCGrace keeps an expired worker row visible this long after
	// it lapses before the sweep removes it.
	DefaultGCGrace = 60 * time.Second

	// DefaultShutdownTimeout bounds the lease-release call on shutdown.
	DefaultShutdownTimeout = 5 * time.Second
)

// Option configures a Distributor.
type Option func(*Distributor)

// WithShardCount sets the shard count. Must match across replicas
// (replicas with different counts would compute different tenant->shard
// maps); values < 1 are clamped to 1.
func WithShardCount(n int) Option { return func(d *Distributor) { d.shardCount = n } }

// WithLeaseTTL sets the database lease / heartbeat TTL.
func WithLeaseTTL(ttl time.Duration) Option { return func(d *Distributor) { d.leaseTTL = ttl } }

// WithCycleInterval sets the heartbeat/renewal cadence.
func WithCycleInterval(iv time.Duration) Option { return func(d *Distributor) { d.cycleInterval = iv } }

// WithSafetyMargin sets how far before DB lease expiry local ownership
// lapses.
func WithSafetyMargin(m time.Duration) Option { return func(d *Distributor) { d.safetyMargin = m } }

// WithConcurrency bounds per-cycle parallel tenant processing.
func WithConcurrency(n int) Option { return func(d *Distributor) { d.concurrency = n } }

// WithInstance sets the human-facing instance label recorded in the
// registry (defaults to hostname:pid).
func WithInstance(s string) Option { return func(d *Distributor) { d.instance = s } }

// WithWorkerID overrides the generated worker identity (mainly for
// tests; production uses a fresh per-process UUID).
func WithWorkerID(id uuid.UUID) Option { return func(d *Distributor) { d.workerID = id } }

// WithClock overrides the local clock used for lease-validity decisions
// (for deterministic tests). In production this is time.Now and is
// intentionally distinct from the database clock the leases expire on;
// the safety margin covers the skew between them.
func WithClock(now func() time.Time) Option { return func(d *Distributor) { d.clock = now } }

// WithLogger sets the structured logger.
func WithLogger(l *slog.Logger) Option {
	return func(d *Distributor) {
		if l != nil {
			d.logger = l
		}
	}
}

// WithWorkerGC tunes the expired-worker sweep cadence and grace period.
func WithWorkerGC(every int, grace time.Duration) Option {
	return func(d *Distributor) {
		d.gcEvery = every
		d.gcGrace = grace
	}
}
