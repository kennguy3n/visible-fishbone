package ai

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// Recompiler turns the FeedManager's frequent per-feed OnUpdate
// notifications into a rate-limited stream of policy recompilations.
//
// Without it, freshly-ingested IP / URL / hash IOCs only reach an
// enforcement bundle at the next operator-triggered Compile, leaving
// an unbounded enforcement delay (domain IOCs already enforce
// immediately via the demotion bridge). With it, every feed update
// schedules a recompile, but the recompiles are coalesced and spaced
// by at least MinInterval so N hourly feeds — all warming up at
// startup and ticking near the top of the hour — collapse into a
// single recompile rather than N back-to-back signing + redistribute
// cycles.
//
// Coalescing semantics: Trigger never blocks and never queues more
// than one pending recompile. Any number of triggers arriving while a
// recompile is running (or while waiting out MinInterval) collapse
// into exactly one follow-up recompile, so the bundle always
// converges to the latest snapshot without unbounded fan-out.
//
// Lifecycle mirrors FeedManager: Start launches the single worker
// goroutine, Stop is idempotent and waits for it to drain.
type Recompiler struct {
	recompile   func(context.Context) error
	minInterval time.Duration
	logger      *slog.Logger
	now         func() time.Time
	onResult    func(outcome string, d time.Duration)

	triggerCh chan struct{}
	stopCh    chan struct{}
	doneCh    chan struct{}
	stopOnce  sync.Once
	startOnce sync.Once
	started   atomic.Bool

	mu        sync.Mutex
	runs      int64
	errors    int64
	lastRunAt time.Time
	lastErr   string
}

const defaultRecompileMinInterval = 5 * time.Minute

// RecompilerOption configures a Recompiler.
type RecompilerOption func(*Recompiler)

// WithRecompileLogger sets the logger. Defaults to slog.Default().
func WithRecompileLogger(logger *slog.Logger) RecompilerOption {
	return func(r *Recompiler) {
		if logger != nil {
			r.logger = logger
		}
	}
}

// WithRecompileMinInterval overrides the minimum spacing between two
// recompiles. Non-positive values keep the default.
func WithRecompileMinInterval(d time.Duration) RecompilerOption {
	return func(r *Recompiler) {
		if d > 0 {
			r.minInterval = d
		}
	}
}

// WithRecompileObserver registers a callback invoked after each
// recompile attempt with the outcome ("success" or "error") and its
// duration. Used to drive metrics.
func WithRecompileObserver(fn func(outcome string, d time.Duration)) RecompilerOption {
	return func(r *Recompiler) { r.onResult = fn }
}

// withRecompileClock overrides the clock (tests).
func withRecompileClock(now func() time.Time) RecompilerOption {
	return func(r *Recompiler) {
		if now != nil {
			r.now = now
		}
	}
}

// NewRecompiler constructs a Recompiler that calls recompile to
// rebuild and redistribute policy bundles. recompile must be safe to
// call repeatedly; it is invoked from a single goroutine so it never
// runs concurrently with itself.
func NewRecompiler(recompile func(context.Context) error, opts ...RecompilerOption) *Recompiler {
	r := &Recompiler{
		recompile:   recompile,
		minInterval: defaultRecompileMinInterval,
		logger:      slog.Default(),
		now:         time.Now,
		triggerCh:   make(chan struct{}, 1),
		stopCh:      make(chan struct{}),
		doneCh:      make(chan struct{}),
	}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

// Trigger requests a recompile. It never blocks and coalesces: if a
// recompile is already pending or in flight, the call is a no-op
// beyond ensuring one more recompile runs after the current one.
func (r *Recompiler) Trigger() {
	select {
	case r.triggerCh <- struct{}{}:
	default:
	}
}

// Start launches the worker goroutine. Non-blocking and idempotent.
func (r *Recompiler) Start(ctx context.Context) {
	if r.recompile == nil {
		return
	}
	r.startOnce.Do(func() {
		r.started.Store(true)
		go r.loop(ctx)
	})
}

func (r *Recompiler) loop(ctx context.Context) {
	defer close(r.doneCh)
	for {
		select {
		case <-ctx.Done():
			return
		case <-r.stopCh:
			return
		case <-r.triggerCh:
			if !r.waitForSlot(ctx) {
				return
			}
			r.runRecompile(ctx)
		}
	}
}

// waitForSlot blocks until at least minInterval has elapsed since the
// last recompile, so bursts of triggers are spaced out. It returns
// false if the manager is shutting down.
func (r *Recompiler) waitForSlot(ctx context.Context) bool {
	r.mu.Lock()
	last := r.lastRunAt
	r.mu.Unlock()
	if last.IsZero() {
		return true
	}
	wait := r.minInterval - r.now().UTC().Sub(last)
	if wait <= 0 {
		return true
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-r.stopCh:
		return false
	case <-timer.C:
		return true
	}
}

func (r *Recompiler) runRecompile(ctx context.Context) {
	start := r.now().UTC()
	err := r.recompile(ctx)
	dur := r.now().UTC().Sub(start)

	r.mu.Lock()
	r.runs++
	r.lastRunAt = start
	if err != nil {
		r.errors++
		r.lastErr = err.Error()
	} else {
		r.lastErr = ""
	}
	r.mu.Unlock()

	outcome := "success"
	if err != nil {
		outcome = "error"
		if r.logger != nil {
			r.logger.ErrorContext(ctx, "threat-intel: auto-recompile failed", "error", err)
		}
	} else if r.logger != nil {
		r.logger.DebugContext(ctx, "threat-intel: auto-recompile complete", "duration", dur)
	}
	if r.onResult != nil {
		r.onResult(outcome, dur)
	}
}

// RecompileStats is a snapshot of the recompiler's counters.
type RecompileStats struct {
	Runs      int64
	Errors    int64
	LastRunAt time.Time
	LastErr   string
}

// Stats returns the recompiler's run counters.
func (r *Recompiler) Stats() RecompileStats {
	r.mu.Lock()
	defer r.mu.Unlock()
	return RecompileStats{
		Runs:      r.runs,
		Errors:    r.errors,
		LastRunAt: r.lastRunAt,
		LastErr:   r.lastErr,
	}
}

// Stop signals the worker to exit and waits for it. Idempotent; safe
// to call before Start (no-op wait).
func (r *Recompiler) Stop() {
	r.stopOnce.Do(func() { close(r.stopCh) })
	if r.started.Load() {
		<-r.doneCh
	}
}
