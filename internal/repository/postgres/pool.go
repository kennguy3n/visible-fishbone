package postgres

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// DefaultReplicaHealthInterval is the cadence at which the
// ReadWritePool re-pings each replica to decide whether it stays in
// the read rotation. 10s is short enough that a replica that falls
// over (or a primary failover that re-points DNS) is evicted from
// the rotation within a couple of cycles, but long enough that the
// health probes are negligible load against the replica.
const DefaultReplicaHealthInterval = 10 * time.Second

// replicaHealthProbeTimeout bounds a single replica Ping so a
// hung TCP connection to one replica cannot stall the health loop
// (and therefore the eviction of the OTHER replicas) indefinitely.
const replicaHealthProbeTimeout = 2 * time.Second

// replica is one read-replica pool plus its current health state.
// `healthy` is an atomic so Replica() can read it on the hot path
// without taking a lock, while the background health loop flips it.
type replica struct {
	pool    *pgxpool.Pool
	healthy atomic.Bool
}

// ReadWritePool wraps a primary pgxpool.Pool and zero or more
// read-replica pools, implementing the read-write split described
// in docs/deploy.md's horizontal-scaling section:
//
//   - Primary() returns the writer pool. Every mutation and every
//     transaction that needs read-your-writes consistency uses it.
//   - Replica() returns a healthy replica chosen round-robin, or
//     the primary when no replica is configured or every replica is
//     currently unhealthy. Pure read paths (the Store's
//     withTenantRO helper) use it to offload SELECT load.
//
// A single background goroutine (started by StartHealthChecks)
// pings every replica on a bounded interval and removes unhealthy
// replicas from the rotation until they recover, so a replica that
// crashes or lags into unavailability degrades gracefully to the
// primary instead of surfacing connection errors to callers.
//
// The zero value is not usable; construct via NewReadWritePool.
// ReadWritePool is safe for concurrent use.
type ReadWritePool struct {
	primary  *pgxpool.Pool
	replicas []*replica

	// appRole / pgBouncerMode carry the RLS-enforcement posture the
	// Store needs when it opens a transaction. In PgBouncer
	// (transaction-pooling) mode the session-level SET SESSION ROLE
	// hook is skipped at connect time, so the Store issues a
	// transaction-local SET LOCAL ROLE instead; these fields let it
	// know whether and to what role.
	appRole       string
	pgBouncerMode bool

	healthInterval time.Duration
	logger         *slog.Logger

	// rr is the round-robin cursor for replica selection. Atomic so
	// Replica() is lock-free.
	rr atomic.Uint64

	// healthOnce guards StartHealthChecks so repeated calls (or a
	// call after Close) do not spawn duplicate loops.
	healthOnce sync.Once
	stopOnce   sync.Once
	cancel     context.CancelFunc
	done       chan struct{}
}

// ReadWritePoolConfig configures a ReadWritePool. Primary is
// required; everything else is optional.
type ReadWritePoolConfig struct {
	// Primary is the writer pool. Required.
	Primary *pgxpool.Pool
	// Replicas are the read-replica pools, already opened and
	// configured by the caller. May be empty (read-write split
	// disabled — Replica() returns Primary).
	Replicas []*pgxpool.Pool
	// AppRole is the runtime role the Store adopts per transaction
	// when PgBouncerMode is true (via SET LOCAL ROLE). Empty
	// disables the per-transaction role adoption.
	AppRole string
	// PgBouncerMode selects transaction-local role adoption (SET
	// LOCAL ROLE inside each tx) instead of the session-level
	// AfterConnect hook. See config.Postgres.PgBouncerMode.
	PgBouncerMode bool
	// HealthCheckInterval overrides DefaultReplicaHealthInterval.
	HealthCheckInterval time.Duration
	// Logger receives replica state-transition logs. Defaults to
	// slog.Default().
	Logger *slog.Logger
}

// NewReadWritePool assembles a ReadWritePool from already-opened
// pgxpool pools. Newly added replicas start healthy: the first
// health-check cycle confirms or evicts them. Call StartHealthChecks
// to begin the background eviction loop (production wiring does;
// tests that only exercise routing may skip it).
func NewReadWritePool(cfg ReadWritePoolConfig) *ReadWritePool {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	interval := cfg.HealthCheckInterval
	if interval <= 0 {
		interval = DefaultReplicaHealthInterval
	}
	p := &ReadWritePool{
		primary:        cfg.Primary,
		appRole:        cfg.AppRole,
		pgBouncerMode:  cfg.PgBouncerMode,
		healthInterval: interval,
		logger:         logger,
		done:           make(chan struct{}),
	}
	for _, rp := range cfg.Replicas {
		if rp == nil {
			continue
		}
		r := &replica{pool: rp}
		r.healthy.Store(true)
		p.replicas = append(p.replicas, r)
	}
	return p
}

// Primary returns the writer pool. Never nil for a pool built via
// NewReadWritePool with a non-nil Primary.
func (p *ReadWritePool) Primary() *pgxpool.Pool { return p.primary }

// Replica returns a healthy replica pool chosen round-robin, or the
// primary when no replica is configured or all replicas are
// currently unhealthy. The fallback to primary is deliberate: a
// read served by the primary is always correct, just less
// load-optimal, so a total replica outage degrades read latency
// rather than failing reads outright.
func (p *ReadWritePool) Replica() *pgxpool.Pool {
	n := len(p.replicas)
	if n == 0 {
		return p.primary
	}
	// Advance the cursor once, then scan up to n replicas starting
	// at that offset for the first healthy one. Scanning (rather
	// than retrying the same index) keeps selection fair even when
	// some replicas are evicted.
	start := p.rr.Add(1)
	for i := 0; i < n; i++ {
		r := p.replicas[(start+uint64(i))%uint64(n)]
		if r.healthy.Load() {
			return r.pool
		}
	}
	return p.primary
}

// AppRole reports the runtime role the Store should adopt per
// transaction in PgBouncer mode.
func (p *ReadWritePool) AppRole() string { return p.appRole }

// PgBouncerMode reports whether the Store must adopt AppRole via a
// transaction-local SET LOCAL ROLE (true) rather than relying on a
// session-level SET SESSION ROLE installed at connect time (false).
func (p *ReadWritePool) PgBouncerMode() bool { return p.pgBouncerMode }

// ReplicaCount returns the number of configured replicas (healthy
// or not).
func (p *ReadWritePool) ReplicaCount() int { return len(p.replicas) }

// HealthyReplicaCount returns how many replicas are currently in
// the read rotation. Useful for health endpoints and tests.
func (p *ReadWritePool) HealthyReplicaCount() int {
	c := 0
	for _, r := range p.replicas {
		if r.healthy.Load() {
			c++
		}
	}
	return c
}

// StartHealthChecks launches the background loop that keeps the
// replica rotation honest. Idempotent — only the first call spawns
// the goroutine. The loop exits when ctx is cancelled or Close is
// called. No-op when there are no replicas.
func (p *ReadWritePool) StartHealthChecks(ctx context.Context) {
	if len(p.replicas) == 0 {
		return
	}
	p.healthOnce.Do(func() {
		runCtx, cancel := context.WithCancel(ctx)
		p.cancel = cancel
		go p.healthLoop(runCtx)
	})
}

func (p *ReadWritePool) healthLoop(ctx context.Context) {
	defer close(p.done)
	t := time.NewTicker(p.healthInterval)
	defer t.Stop()
	// Probe immediately on start so a replica that was already down
	// at boot is evicted on the first cycle rather than after one
	// full interval.
	p.probeAll(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			p.probeAll(ctx)
		}
	}
}

// probeAll pings every replica and flips its healthy flag, logging
// only on state transitions so a steadily-healthy fleet stays quiet
// and a flapping replica is loud.
func (p *ReadWritePool) probeAll(ctx context.Context) {
	for _, r := range p.replicas {
		probeCtx, cancel := context.WithTimeout(ctx, replicaHealthProbeTimeout)
		err := r.pool.Ping(probeCtx)
		cancel()
		healthy := err == nil
		prev := r.healthy.Swap(healthy)
		if prev == healthy {
			continue
		}
		if healthy {
			p.logger.Info("postgres: read replica recovered, re-added to rotation",
				slog.String("host", replicaHost(r.pool)))
		} else {
			p.logger.Warn("postgres: read replica unhealthy, removed from rotation",
				slog.String("host", replicaHost(r.pool)),
				slog.Any("error", err))
		}
	}
}

// replicaHost extracts the configured host of a pool for logging.
// pgxpool exposes the parsed config; the connection-config Host is
// the most useful identifier in a multi-replica deployment.
func replicaHost(pool *pgxpool.Pool) string {
	if pool == nil {
		return ""
	}
	cfg := pool.Config()
	if cfg == nil || cfg.ConnConfig == nil {
		return ""
	}
	return cfg.ConnConfig.Host
}

// Close stops the health loop (waiting for it to exit) and closes
// the primary and every replica pool. Safe to call multiple times.
func (p *ReadWritePool) Close() {
	p.stopOnce.Do(func() {
		if p.cancel != nil {
			p.cancel()
			<-p.done
		}
		for _, r := range p.replicas {
			r.pool.Close()
		}
		if p.primary != nil {
			p.primary.Close()
		}
	})
}
