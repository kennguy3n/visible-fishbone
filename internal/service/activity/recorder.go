// Package activity records per-tenant activity into
// tenants.last_active_at — the signal the dormancy planner
// (internal/service/tenancy) buckets on to decide which tenants a
// periodic sweep must visit each cycle.
//
// The signal is written from hot paths: data-plane telemetry
// ingestion (every event durably written for a tenant) and
// authenticated control-plane requests. Those paths run at far higher
// rates than the planner needs, so Recorder debounces per tenant — at
// most one write per MinInterval — and performs the Postgres write
// asynchronously on a bounded worker. When the worker's queue is
// saturated it drops the touch rather than ever blocking a caller.
//
// Dropping or coalescing is safe: last_active_at is forward-only
// (advanced via GREATEST at the SQL level), so a missed or out-of-order
// touch only ever costs a little staleness in the activity tier, never
// correctness — and the classifier is itself conservative (it errs
// toward sweeping a tenant *more* often, never starving a sweep).
package activity

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
)

// TenantToucher is the narrow capability Recorder needs: advance a
// tenant's last_active_at to `seen`, forward-only.
// repository.TenantRepository satisfies it.
type TenantToucher interface {
	TouchLastActive(ctx context.Context, id uuid.UUID, seen time.Time) error
}

// Defaults tuned for a ~5000-tenant PoP. At one write per tenant per
// MinInterval the steady-state write rate is bounded by
// tenantCount/MinInterval — ~17 writes/s at the extreme of every
// tenant active every interval — which a single drain worker absorbs
// comfortably.
const (
	// DefaultMinInterval is the per-tenant debounce window. It must be
	// well under the planner's IdleAfter (24h) so a tenant with steady
	// traffic never drifts out of the active tier between writes.
	DefaultMinInterval = 5 * time.Minute
	// DefaultQueueSize bounds the in-flight touches buffered for the
	// drain worker. Sized for a burst of distinct tenants crossing
	// their debounce window in the same instant; beyond it, touches
	// are dropped (the next Observe re-enqueues once the worker
	// catches up).
	DefaultQueueSize = 4096
	// DefaultWriteTimeout caps each Postgres touch so a stalled write
	// cannot wedge the drain worker.
	DefaultWriteTimeout = 5 * time.Second
)

// Stats is a point-in-time snapshot of Recorder counters for
// observability (exported to metrics by the caller).
type Stats struct {
	// Enqueued is the number of touches accepted onto the drain queue.
	Enqueued uint64
	// Debounced is the number of Observe calls suppressed because the
	// tenant was touched within MinInterval.
	Debounced uint64
	// Dropped is the number of touches discarded because the drain
	// queue was full.
	Dropped uint64
	// Written is the number of touches successfully persisted.
	Written uint64
	// Failed is the number of touches whose persist returned an error
	// (excluding shutdown cancellation).
	Failed uint64
}

// Recorder debounces and asynchronously persists per-tenant activity.
// The zero value is not usable; construct with NewRecorder. Observe is
// safe for concurrent use from any number of hot-path goroutines; Run
// drives the single drain worker.
type Recorder struct {
	repo         TenantToucher
	minInterval  time.Duration
	writeTimeout time.Duration
	now          func() time.Time
	logger       *slog.Logger

	queue chan touch

	mu   sync.Mutex
	last map[uuid.UUID]time.Time // wall-clock of the last enqueued touch per tenant

	enqueued, debounced, dropped, written, failed atomic.Uint64

	// Lifecycle: Run drives the drain loop, Stop winds it down after a
	// final drain of whatever is still queued. The loop terminates only
	// when Stop closes stopCh (never on a process-scoped context), so
	// the recorder outlives rootCtx and keeps draining while the
	// telemetry consumer — which feeds Observe on its own background
	// context — is still emitting during the graceful-shutdown window.
	// doneCh is closed when Run returns so Stop can block until the
	// final drain has persisted, keeping those writes from racing
	// pool.Close(). This mirrors casb.ShadowITDiscoverer, which has the
	// identical "outlive rootCtx, drain after the consumer stops"
	// requirement.
	stopOnce sync.Once
	started  atomic.Bool
	stopCh   chan struct{}
	doneCh   chan struct{}
}

type touch struct {
	tenantID uuid.UUID
	seen     time.Time
}

// Option customises a Recorder at construction.
type Option func(*Recorder)

// WithMinInterval sets the per-tenant debounce window. Values <= 0 are
// ignored (the default is retained).
func WithMinInterval(d time.Duration) Option {
	return func(r *Recorder) {
		if d > 0 {
			r.minInterval = d
		}
	}
}

// WithQueueSize sets the drain-queue capacity. Values <= 0 are ignored.
func WithQueueSize(n int) Option {
	return func(r *Recorder) {
		if n > 0 {
			r.queue = make(chan touch, n)
		}
	}
}

// WithWriteTimeout caps each persist. Values <= 0 are ignored.
func WithWriteTimeout(d time.Duration) Option {
	return func(r *Recorder) {
		if d > 0 {
			r.writeTimeout = d
		}
	}
}

// WithClock overrides the time source (tests). A nil clock is ignored.
func WithClock(now func() time.Time) Option {
	return func(r *Recorder) {
		if now != nil {
			r.now = now
		}
	}
}

// WithLogger sets the logger. A nil logger is ignored (the default
// discards).
func WithLogger(l *slog.Logger) Option {
	return func(r *Recorder) {
		if l != nil {
			r.logger = l
		}
	}
}

// NewRecorder constructs a Recorder writing through repo. It panics if
// repo is nil — a Recorder with no backing store is always a wiring
// bug, never a runtime condition to tolerate.
func NewRecorder(repo TenantToucher, opts ...Option) *Recorder {
	if repo == nil {
		panic("activity: NewRecorder requires a non-nil TenantToucher")
	}
	r := &Recorder{
		repo:         repo,
		minInterval:  DefaultMinInterval,
		writeTimeout: DefaultWriteTimeout,
		now:          time.Now,
		logger:       slog.New(slog.NewTextHandler(noopWriter{}, nil)),
		last:         make(map[uuid.UUID]time.Time),
		stopCh:       make(chan struct{}),
		doneCh:       make(chan struct{}),
	}
	for _, o := range opts {
		o(r)
	}
	if r.queue == nil {
		r.queue = make(chan touch, DefaultQueueSize)
	}
	return r
}

// Observe records that the data plane (or an authenticated request)
// saw activity for tenantID at `seen`. It is the hot-path entry point:
// cheap, non-blocking, and safe for concurrent use. A nil Recorder or
// nil tenant is a no-op so callers need not branch on optional wiring.
//
// `seen` is the activity timestamp (e.g. the telemetry event time);
// zero is treated as now. The debounce gate keys on wall-clock so the
// write rate is bounded regardless of event-time skew, while the
// persisted value is the caller's `seen`.
func (r *Recorder) Observe(tenantID uuid.UUID, seen time.Time) {
	if r == nil || tenantID == uuid.Nil {
		return
	}
	now := r.now()
	if seen.IsZero() {
		seen = now
	}

	r.mu.Lock()
	if last, ok := r.last[tenantID]; ok && now.Sub(last) < r.minInterval {
		r.mu.Unlock()
		r.debounced.Add(1)
		return
	}
	r.mu.Unlock()

	select {
	case r.queue <- touch{tenantID: tenantID, seen: seen}:
		// Only mark the debounce window after a successful enqueue, so
		// a dropped touch (queue full) does not silence the tenant for
		// a whole MinInterval. The marker is advanced under the lock
		// guarding against a concurrent Observe regressing it.
		r.mu.Lock()
		if cur, ok := r.last[tenantID]; !ok || now.After(cur) {
			r.last[tenantID] = now
		}
		r.mu.Unlock()
		r.enqueued.Add(1)
	default:
		r.dropped.Add(1)
	}
}

// Run drains queued touches until Stop is called, persisting each
// through the repository, then performs a final drain of whatever is
// still buffered so the last window's activity is not lost. It blocks,
// so callers run it in a goroutine and pair it with Stop. Per-touch
// failures are logged (never propagated) so one bad write cannot stall
// the worker.
//
// The loop is driven solely by Stop (an internal channel), deliberately
// NOT by any process-scoped context: the telemetry consumer that feeds
// Observe runs on its own background context and is drained during
// graceful shutdown *after* rootCtx is cancelled, so binding Run to
// rootCtx would make it stop draining while observations are still
// arriving — silently dropping that last window.
//
// A second concurrent or repeat Run is a no-op: the started CAS admits
// exactly one drain loop, so the owner of doneCh is unambiguous and the
// deferred close can never run twice (a double close would panic).
func (r *Recorder) Run() {
	if !r.started.CompareAndSwap(false, true) {
		return
	}
	defer close(r.doneCh)
	for {
		select {
		case <-r.stopCh:
			r.drain()
			return
		case t := <-r.queue:
			r.write(t)
		}
	}
}

// Stop winds the drain loop down and blocks until its final drain has
// persisted, so queued touches finish before the caller proceeds to
// close the DB pool. Stop is idempotent and safe to call when Run was
// never started.
func (r *Recorder) Stop() {
	if r == nil {
		return
	}
	r.stopOnce.Do(func() { close(r.stopCh) })
	if r.started.Load() {
		<-r.doneCh
	}
}

// drain persists every touch currently buffered (a bounded amount, at
// most the queue capacity) without blocking on new arrivals, then
// returns. Called once from Run after Stop so the trailing window lands
// before shutdown completes.
func (r *Recorder) drain() {
	for {
		select {
		case t := <-r.queue:
			r.write(t)
		default:
			return
		}
	}
}

// write persists one touch on a bounded, detached deadline. Detaching
// from any process-scoped context is what lets the final drain keep
// succeeding during the shutdown window (between rootCtx cancel and the
// telemetry consumer's drain); the writeTimeout still caps a stalled
// write so the worker cannot wedge.
func (r *Recorder) write(t touch) {
	wctx, cancel := context.WithTimeout(context.Background(), r.writeTimeout)
	defer cancel()
	if err := r.repo.TouchLastActive(wctx, t.tenantID, t.seen); err != nil {
		r.failed.Add(1)
		// A touch for a tenant that has since been deleted, or any
		// transient store error, is benign here: the activity signal
		// is best-effort. Log at debug to avoid noise on the hot path.
		r.logger.Debug("activity: touch last_active failed",
			slog.String("tenant_id", t.tenantID.String()),
			slog.Any("error", err))
		return
	}
	r.written.Add(1)
}

// Stats returns a snapshot of the recorder's counters.
func (r *Recorder) Stats() Stats {
	if r == nil {
		return Stats{}
	}
	return Stats{
		Enqueued:  r.enqueued.Load(),
		Debounced: r.debounced.Load(),
		Dropped:   r.dropped.Load(),
		Written:   r.written.Load(),
		Failed:    r.failed.Load(),
	}
}

// noopWriter discards log output for the default logger.
type noopWriter struct{}

func (noopWriter) Write(p []byte) (int, error) { return len(p), nil }
