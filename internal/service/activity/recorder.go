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
	// pruneFactor sets the eviction horizon as a multiple of
	// minInterval: a tenant whose last touch is older than
	// pruneFactor*minInterval is evicted from the debounce map. It is
	// >1 so an entry is only dropped well after its debounce window
	// elapsed — never one that could still suppress a write — giving a
	// safety margin against evicting a tenant right at the boundary.
	pruneFactor = 2
)

// Source labels an activity touch by the ingress it came from, so the
// per-source coverage metric (see Recorder.Stats and the metrics
// ActivityCollector) can prove that every tenant-activity path — not
// just the data-plane telemetry stream — feeds last_active_at. Keep
// the set small and bounded: it becomes a Prometheus label dimension.
type Source string

const (
	// SourceUnknown is the fallback for a touch with no attributed
	// ingress (the bare Observe entry point). A non-trivial count here
	// flags an un-labelled writer.
	SourceUnknown Source = "unknown"
	// SourceTelemetry is the data-plane signal: a durably-written
	// telemetry event for the tenant (the highest-volume source).
	SourceTelemetry Source = "telemetry"
	// SourceAPI is an authenticated control-plane request whose
	// resolved tenant is in context (the RecordActivity middleware).
	SourceAPI Source = "api"
	// SourceEnroll is a successful device enrolment on the public
	// claim-token endpoint — an agent coming online, which bypasses the
	// authenticated chain so the middleware never sees it.
	SourceEnroll Source = "enroll"
	// SourceMobileToken is a successful mobile native-SSO token
	// exchange (a user/device session bootstrap on the public endpoint).
	SourceMobileToken Source = "mobile_token"
	// SourceMobileRefresh is a successful mobile session refresh — the
	// recurring agent check-in that keeps a device's session live.
	SourceMobileRefresh Source = "mobile_refresh"
)

// Sources lists every Source in a stable order. Callers (the metrics
// collector, tests) iterate it so a newly-added source is exported
// without further wiring.
func Sources() []Source {
	return []Source{
		SourceUnknown,
		SourceTelemetry,
		SourceAPI,
		SourceEnroll,
		SourceMobileToken,
		SourceMobileRefresh,
	}
}

// SourceStat is the per-source slice of a Stats snapshot.
type SourceStat struct {
	// Enqueued is the number of touches from this source accepted onto
	// the drain queue.
	Enqueued uint64
	// Debounced is the number of Observe calls from this source
	// suppressed because the tenant was touched within MinInterval.
	// The debounce gate keys on (tenant, wall-clock) alone, not on
	// source, so a touch here may have been coalesced with an *earlier
	// touch from a different source* for the same tenant — a non-zero
	// Debounced for a source does not imply that source's touches were
	// redundant with themselves. This is intentional: the gate bounds
	// the Postgres write rate per tenant, and TouchLastActive uses
	// GREATEST so only the latest timestamp matters regardless of which
	// source won.
	Debounced uint64
	// Dropped is the number of touches from this source discarded
	// because the drain queue was full.
	Dropped uint64
	// Written is the number of touches from this source successfully
	// persisted.
	Written uint64
	// Failed is the number of touches from this source whose persist
	// returned an error (excluding shutdown cancellation). Tracked
	// per-source so Enqueued reconciles with Written+Failed+in-flight
	// for each ingress, letting an operator spot a source whose writes
	// systematically fail rather than only seeing it in the aggregate.
	Failed uint64
}

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
	// BySource breaks the Enqueued/Debounced/Dropped/Written totals
	// down by ingress Source so the coverage metric can show each path
	// contributing. It always carries an entry for every Sources()
	// value (zero when unused).
	BySource map[Source]SourceStat
}

// sourceCounter holds the per-source atomic counters. A pointer to it
// is stored in the Recorder's fixed bySource map (built once at
// construction, never mutated afterwards) so concurrent Observe calls
// only ever do lock-free atomic increments.
type sourceCounter struct {
	enqueued  atomic.Uint64
	debounced atomic.Uint64
	dropped   atomic.Uint64
	written   atomic.Uint64
	failed    atomic.Uint64
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

	// pruneInterval is how often Run sweeps `last` to evict tenants not
	// seen within the eviction horizon (pruneFactor * minInterval),
	// bounding the map to the recently-active working set rather than
	// the all-time set of tenants. An evicted entry is one whose
	// debounce window has long elapsed, so dropping it is behaviourally
	// invisible: the next Observe re-enqueues and re-arms it.
	pruneInterval time.Duration

	enqueued, debounced, dropped, written, failed atomic.Uint64

	// bySource holds the per-ingress breakdown of the counters above.
	// Built once in NewRecorder with an entry for every Sources()
	// value and never mutated afterwards, so lookups are lock-free and
	// the per-source increments are plain atomics.
	bySource map[Source]*sourceCounter

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
	src      Source
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
		bySource:     make(map[Source]*sourceCounter, len(Sources())),
	}
	for _, s := range Sources() {
		r.bySource[s] = &sourceCounter{}
	}
	for _, o := range opts {
		o(r)
	}
	if r.queue == nil {
		r.queue = make(chan touch, DefaultQueueSize)
	}
	// Sweep the debounce map once per debounce window; entries older
	// than pruneFactor windows are evicted on each sweep.
	r.pruneInterval = r.minInterval
	return r
}

// Observe records that the data plane (or an authenticated request)
// saw activity for tenantID at `seen`, attributing it to SourceUnknown.
// It satisfies the narrow ActivityObserver interface the telemetry
// consumer and middleware depend on. Prefer From(src).Observe so the
// touch is attributed to its ingress in the coverage metric.
func (r *Recorder) Observe(tenantID uuid.UUID, seen time.Time) {
	r.observe(tenantID, seen, SourceUnknown)
}

// SourcedObserver is an ActivityObserver that attributes every touch it
// records to a fixed ingress Source. It keeps the narrow
// Observe(tenantID, seen) contract so it drops in wherever the bare
// Recorder did, while the coverage metric can break touches down by
// where they came from. Obtain one via Recorder.From.
type SourcedObserver struct {
	r   *Recorder
	src Source
}

// Observe records activity for tenantID at `seen`, tagged with the
// observer's Source. A nil underlying recorder is a no-op.
func (s SourcedObserver) Observe(tenantID uuid.UUID, seen time.Time) {
	s.r.observe(tenantID, seen, s.src)
}

// From returns an observer that attributes its touches to src. It is
// nil-safe on the receiver (the returned observer's Observe is then a
// no-op), so callers can wire it unconditionally and let a disabled
// recorder degrade to a pass-through.
func (r *Recorder) From(src Source) SourcedObserver {
	return SourcedObserver{r: r, src: src}
}

// observe is the hot-path entry point: cheap, non-blocking, and safe
// for concurrent use. A nil Recorder or nil tenant is a no-op so
// callers need not branch on optional wiring.
//
// `seen` is the activity timestamp (e.g. the telemetry event time);
// zero is treated as now. The debounce gate keys on wall-clock so the
// write rate is bounded regardless of event-time skew, while the
// persisted value is the caller's `seen`. The touch carries `src` so
// the drain worker can attribute the eventual write to its ingress.
func (r *Recorder) observe(tenantID uuid.UUID, seen time.Time, src Source) {
	if r == nil || tenantID == uuid.Nil {
		return
	}
	sc := r.counterFor(src)
	now := r.now()
	if seen.IsZero() {
		seen = now
	}

	r.mu.Lock()
	if last, ok := r.last[tenantID]; ok && now.Sub(last) < r.minInterval {
		r.mu.Unlock()
		r.debounced.Add(1)
		sc.debounced.Add(1)
		return
	}
	r.mu.Unlock()

	select {
	case r.queue <- touch{tenantID: tenantID, seen: seen, src: src}:
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
		sc.enqueued.Add(1)
	default:
		r.dropped.Add(1)
		sc.dropped.Add(1)
	}
}

// counterFor returns the per-source counter bucket for src, falling
// back to the SourceUnknown bucket for any value not registered at
// construction so an out-of-set label can never nil-panic the hot path.
func (r *Recorder) counterFor(src Source) *sourceCounter {
	if sc, ok := r.bySource[src]; ok {
		return sc
	}
	return r.bySource[SourceUnknown]
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
	prune := time.NewTicker(r.pruneInterval)
	defer prune.Stop()
	for {
		select {
		case <-r.stopCh:
			r.drain()
			return
		case t := <-r.queue:
			r.write(t)
		case <-prune.C:
			r.prune(r.now())
		}
	}
}

// prune evicts debounce-map entries for tenants not seen within the
// eviction horizon (pruneFactor * minInterval), keeping the map sized
// to the recently-active working set instead of the all-time tenant
// set. Evicting a stale entry is behaviourally invisible: its debounce
// window has already elapsed, so the next Observe for that tenant would
// pass the gate and re-enqueue regardless.
func (r *Recorder) prune(now time.Time) {
	horizon := time.Duration(pruneFactor) * r.minInterval
	r.mu.Lock()
	for id, ts := range r.last {
		if now.Sub(ts) >= horizon {
			delete(r.last, id)
		}
	}
	r.mu.Unlock()
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
		r.counterFor(t.src).failed.Add(1)
		// A touch for a tenant that has since been deleted, or any
		// transient store error, is benign here: the activity signal
		// is best-effort. Log at debug to avoid noise on the hot path.
		r.logger.Debug("activity: touch last_active failed",
			slog.String("tenant_id", t.tenantID.String()),
			slog.Any("error", err))
		return
	}
	r.written.Add(1)
	r.counterFor(t.src).written.Add(1)
}

// Stats returns a snapshot of the recorder's counters, including the
// per-source breakdown. BySource carries an entry for every Sources()
// value so a consumer can iterate it without nil checks.
func (r *Recorder) Stats() Stats {
	if r == nil {
		return Stats{}
	}
	bySource := make(map[Source]SourceStat, len(r.bySource))
	for src, sc := range r.bySource {
		bySource[src] = SourceStat{
			Enqueued:  sc.enqueued.Load(),
			Debounced: sc.debounced.Load(),
			Dropped:   sc.dropped.Load(),
			Written:   sc.written.Load(),
			Failed:    sc.failed.Load(),
		}
	}
	return Stats{
		Enqueued:  r.enqueued.Load(),
		Debounced: r.debounced.Load(),
		Dropped:   r.dropped.Load(),
		Written:   r.written.Load(),
		Failed:    r.failed.Load(),
		BySource:  bySource,
	}
}

// QueueLen returns the number of touches currently buffered in the
// drain queue. It is a saturation gauge for observability (exported by
// the metrics ActivityCollector); a nil Recorder reports 0.
func (r *Recorder) QueueLen() int {
	if r == nil {
		return 0
	}
	return len(r.queue)
}

// noopWriter discards log output for the default logger.
type noopWriter struct{}

func (noopWriter) Write(p []byte) (int, error) { return len(p), nil }
