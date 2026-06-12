// Package leader provides Postgres advisory-lock based leader
// election so the control plane can be deployed as 2–3 horizontally
// scaled replicas behind a load balancer. Every replica serves API
// traffic and consumes NATS, but singleton background work
// (app-registry sync, certificate-rotation monitoring, scheduled
// compliance reviews) must run on exactly one replica at a time —
// otherwise the replicas would duplicate vendor fetches, race on
// certificate rotation, and emit duplicate scheduled reports.
//
// Election uses a session-level Postgres advisory lock
// (pg_try_advisory_lock): the lock is held for as long as the
// holding database session lives and is released automatically if
// that session dies (connection drop, replica crash, network
// partition that the server detects). This gives correct failover
// without a separate coordination service (etcd/Consul/ZooKeeper):
// Postgres is already a hard dependency, and the lock's
// session-lifetime semantics mean a crashed leader's lock is
// reclaimed by the server with no manual intervention.
//
// The elector maintains leadership on a single dedicated connection
// and exposes IsLeader plus RunIfLeader; callers wrap each singleton
// loop in RunIfLeader so it runs only while this replica is the
// leader and is torn down the moment leadership is lost.
package leader

import (
	"context"
	"errors"
	"hash/fnv"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// DefaultCheckInterval is how often the elector attempts to acquire
// leadership (when a follower) or verifies the held lock's session
// is still alive (when the leader). The spec calls for a 30s cadence
// — short enough that failover after a leader crash completes within
// a single check window, long enough that the try-lock probe is
// negligible load on the primary.
const DefaultCheckInterval = 30 * time.Second

// DefaultLockID is the advisory-lock key used for the control
// plane's singleton-workload leadership. Advisory-lock keys share a
// namespace across the whole database, so this is a fixed,
// deliberately uncommon constant ("SNGLEAD" interpreted loosely)
// chosen to avoid colliding with any other advisory lock the schema
// might take. Override via WithLockID if a deployment needs a
// distinct election domain.
const DefaultLockID int64 = 0x534E474C45414400 // "SNGLEAD\0"

// Session is a dedicated Postgres session that can hold a
// session-level advisory lock. The lock lives for the lifetime of
// the session, so the elector keeps one Session open for as long as
// it is the leader and closes it (releasing the lock) when it steps
// down. Implementations must be safe for sequential use by the
// single election goroutine; they are not required to be safe for
// concurrent use.
type Session interface {
	// TryLock attempts pg_try_advisory_lock(lockID). It returns
	// true when the lock was acquired by this session, false when
	// it is held by another session, and a non-nil error only on a
	// real failure (connection/query error).
	TryLock(ctx context.Context, lockID int64) (bool, error)
	// Unlock releases the advisory lock held by this session
	// (pg_advisory_unlock). Closing the session releases it anyway;
	// Unlock makes the release explicit and prompt.
	Unlock(ctx context.Context, lockID int64) error
	// Ping verifies the session is still alive. A non-nil result
	// means the session (and therefore the lock) can no longer be
	// trusted and leadership must be relinquished.
	Ping(ctx context.Context) error
	// Close releases the underlying connection back to its pool (or
	// closes it). After Close the Session must not be reused.
	Close(ctx context.Context)
}

// SessionOpener acquires a fresh dedicated Session. In production
// this hands out a connection from the primary pgx pool; in tests a
// fake opener simulates lock contention and connection loss.
type SessionOpener interface {
	Open(ctx context.Context) (Session, error)
}

// LeaderElector runs the election loop and tracks whether this
// process currently holds leadership. Construct with New, start the
// loop with Run (typically in its own goroutine), and gate singleton
// work with RunIfLeader.
type LeaderElector struct {
	opener   SessionOpener
	lockID   int64
	interval time.Duration
	identity string
	logger   *slog.Logger

	isLeader atomic.Bool

	mu      sync.Mutex
	session Session
	// generation increments on every leadership *acquisition* so
	// RunIfLeader can detect a flap (lost-then-regained between two
	// of its polls) and restart the wrapped job even if IsLeader
	// reads true at both polls.
	generation atomic.Uint64
	// epoch is the fencing token for the CURRENT leadership term —
	// see fencing.go. When the SessionOpener yields a session that
	// implements EpochReader (the production pgSession does, via the
	// Postgres transaction id), epoch is a globally monotonic value
	// that survives process restarts so a stale leader's token is
	// always strictly less than the live leader's. Otherwise it
	// falls back to the in-process generation counter.
	epoch atomic.Uint64

	// transitions counts leadership *acquisitions* (0 -> leader
	// edges) for the sng_leader_transitions_total metric. Nil when
	// no registerer was supplied; increments are guarded.
	transitions prometheus.Counter

	// newTicker constructs the periodic ticker that drives the
	// election loop (Run) and the job-supervision poll (RunIfLeader).
	// Production uses realTicker, a thin wrapper over time.NewTicker.
	// Tests inject a manually driven ticker via withTicker so timing
	// is deterministic rather than wall-clock dependent.
	newTicker tickerFunc
}

// tickerFunc constructs a ticker firing every d: it returns the
// tick channel and a stop function. It exists so tests can replace
// the real time.Ticker with a hand-driven channel.
type tickerFunc func(d time.Duration) (<-chan time.Time, func())

// realTicker is the production tickerFunc: a thin wrapper over
// time.NewTicker so behaviour is identical to using the ticker
// directly.
func realTicker(d time.Duration) (<-chan time.Time, func()) {
	t := time.NewTicker(d)
	return t.C, t.Stop
}

// withTicker overrides the ticker factory. It is unexported because
// it is a test-only seam; production always uses realTicker. A nil
// factory is ignored.
func withTicker(f tickerFunc) Option {
	return func(e *LeaderElector) {
		if f != nil {
			e.newTicker = f
		}
	}
}

// Option customises a LeaderElector.
type Option func(*LeaderElector)

// WithCheckInterval overrides DefaultCheckInterval. Non-positive
// values are ignored.
func WithCheckInterval(d time.Duration) Option {
	return func(e *LeaderElector) {
		if d > 0 {
			e.interval = d
		}
	}
}

// WithLockID overrides DefaultLockID, selecting a distinct election
// domain.
func WithLockID(id int64) Option {
	return func(e *LeaderElector) { e.lockID = id }
}

// WithIdentity sets a human-readable identifier for this replica
// (e.g. hostname/pod name) used in leadership log lines.
func WithIdentity(id string) Option {
	return func(e *LeaderElector) {
		if id != "" {
			e.identity = id
		}
	}
}

// WithLogger sets the logger. A nil logger falls back to
// slog.Default().
func WithLogger(l *slog.Logger) Option {
	return func(e *LeaderElector) {
		if l != nil {
			e.logger = l
		}
	}
}

// New constructs a LeaderElector over the given SessionOpener.
func New(opener SessionOpener, opts ...Option) *LeaderElector {
	e := &LeaderElector{
		opener:    opener,
		lockID:    DefaultLockID,
		interval:  DefaultCheckInterval,
		identity:  "sng-control",
		logger:    slog.Default(),
		newTicker: realTicker,
	}
	for _, opt := range opts {
		opt(e)
	}
	return e
}

// IsLeader reports whether this process currently holds leadership.
func (e *LeaderElector) IsLeader() bool { return e.isLeader.Load() }

// LockID returns the advisory-lock key this elector contends on.
func (e *LeaderElector) LockID() int64 { return e.lockID }

// Run drives the election loop until ctx is cancelled. It performs
// an immediate election attempt, then re-evaluates every interval.
// On return (ctx cancelled) it relinquishes leadership and closes
// the held session. Run blocks; call it in its own goroutine.
func (e *LeaderElector) Run(ctx context.Context) {
	// Immediate first attempt so a single-replica deployment becomes
	// leader at boot without waiting a full interval.
	e.tick(ctx)

	tickC, stop := e.newTicker(e.interval)
	defer stop()
	for {
		select {
		case <-ctx.Done():
			e.relinquish(context.WithoutCancel(ctx))
			return
		case <-tickC:
			e.tick(ctx)
		}
	}
}

// tick performs one election evaluation: when a follower it tries to
// acquire the lock; when the leader it verifies the held session is
// still alive and steps down if not.
func (e *LeaderElector) tick(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.session != nil {
		// Leader path: confirm the lock-holding session is healthy.
		if err := e.session.Ping(ctx); err != nil {
			e.logger.Warn("leader: lost connection holding advisory lock; stepping down",
				slog.String("identity", e.identity),
				slog.Any("error", err))
			e.demoteLocked(ctx)
		}
		return
	}

	// Follower path: try to acquire leadership.
	sess, err := e.opener.Open(ctx)
	if err != nil {
		e.logger.Warn("leader: open session failed; remaining follower",
			slog.String("identity", e.identity),
			slog.Any("error", err))
		return
	}
	acquired, err := sess.TryLock(ctx, e.lockID)
	if err != nil {
		e.logger.Warn("leader: advisory try-lock failed; remaining follower",
			slog.String("identity", e.identity),
			slog.Any("error", err))
		sess.Close(ctx)
		return
	}
	if !acquired {
		// Held by another replica — release the probe connection so
		// we don't tie up a pool slot while following.
		sess.Close(ctx)
		return
	}
	e.session = sess
	// Publish ordering: establish the term's generation and fencing
	// epoch BEFORE setting isLeader=true. FencingToken/HoldsToken read
	// isLeader and epoch with lock-free atomics, so if isLeader were
	// stored first a concurrent reader could observe leadership with a
	// stale epoch from the previous term (whose Valid()/HoldsToken
	// would wrongly pass on a re-acquisition). Go's atomics are
	// sequentially consistent, so storing epoch first guarantees any
	// observer that sees isLeader==true also sees this term's epoch.
	// generation is incremented first because acquireEpoch falls back
	// to generation.Load() when the session has no EpochReader.
	e.generation.Add(1)
	e.epoch.Store(e.acquireEpoch(ctx, sess))
	e.isLeader.Store(true)
	if e.transitions != nil {
		e.transitions.Inc()
	}
	e.logger.Info("leader: acquired leadership",
		slog.String("identity", e.identity),
		slog.Int64("lock_id", e.lockID),
		slog.Uint64("fencing_epoch", e.epoch.Load()))
}

// demoteLocked relinquishes leadership. Caller must hold e.mu.
func (e *LeaderElector) demoteLocked(ctx context.Context) {
	if e.session == nil {
		return
	}
	// Best-effort explicit unlock; Close releases the lock anyway by
	// ending the session, so an unlock error is non-fatal.
	_ = e.session.Unlock(ctx, e.lockID)
	e.session.Close(ctx)
	e.session = nil
	e.isLeader.Store(false)
}

// relinquish steps down (if leader) during shutdown.
func (e *LeaderElector) relinquish(ctx context.Context) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.session == nil {
		return
	}
	e.logger.Info("leader: relinquishing leadership on shutdown",
		slog.String("identity", e.identity))
	e.demoteLocked(ctx)
}

// RunIfLeader runs fn only while this replica is the leader, and
// tears it down the moment leadership is lost. It blocks until ctx
// is cancelled, so callers typically invoke it in its own goroutine:
//
//	go elector.RunIfLeader(ctx, "app-registry-sync", func(lctx context.Context) {
//	    syncer.Run(lctx, interval)
//	})
//
// fn is invoked with a context that is cancelled when leadership is
// lost (or ctx is cancelled). fn is expected to return promptly once
// its context is done. If leadership is later regained, fn is invoked
// again with a fresh context. fn must therefore be safe to start more
// than once over the elector's lifetime.
//
// Followers never invoke fn, which is the whole point: singleton
// loops stay dormant on non-leaders while those replicas keep serving
// API traffic and consuming NATS.
func (e *LeaderElector) RunIfLeader(ctx context.Context, name string, fn func(context.Context)) {
	// Poll leadership on a cadence finer than the election interval
	// so a job starts/stops promptly relative to a leadership
	// transition, without busy-spinning.
	poll := e.interval / 3
	if poll <= 0 {
		poll = time.Second
	}
	tickC, stop := e.newTicker(poll)
	defer stop()

	for {
		if ctx.Err() != nil {
			return
		}
		if !e.IsLeader() {
			select {
			case <-ctx.Done():
				return
			case <-tickC:
			}
			continue
		}

		// We are the leader: run fn with a leadership-scoped context.
		startGen := e.generation.Load()
		runCtx, cancel := context.WithCancel(ctx)
		done := make(chan struct{})
		go func() {
			defer close(done)
			e.logger.Info("leader: starting singleton job", slog.String("job", name))
			fn(runCtx)
		}()

		// Watch for leadership loss (or a flap that bumped the
		// generation) and cancel runCtx so fn unwinds.
		e.superviseJob(ctx, tickC, startGen)
		cancel()
		<-done
		e.logger.Info("leader: singleton job stopped", slog.String("job", name))
	}
}

// superviseJob blocks until leadership is lost, the generation
// changes (a lost-then-regained flap), or ctx is cancelled — any of
// which means the currently running job should be torn down.
func (e *LeaderElector) superviseJob(ctx context.Context, tickC <-chan time.Time, startGen uint64) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-tickC:
			if !e.IsLeader() || e.generation.Load() != startGen {
				return
			}
		}
	}
}

// LockIDForName derives a stable advisory-lock key from a name via
// FNV-1a, for callers that want a distinct election domain per
// logical workload without hand-picking integer keys. The result is
// masked to 63 bits so it is always a non-negative int64.
func LockIDForName(name string) int64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(name))
	return int64(h.Sum64() & 0x7FFFFFFFFFFFFFFF)
}

// ErrClosed is returned by a SessionOpener that has been shut down.
var ErrClosed = errors.New("leader: session opener closed")
