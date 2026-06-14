package ai

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
)

// InferencePool is a fair-scheduled admission layer in front of a
// single shared LLM backend. It exists for the fleet-scale problem:
// at ~5,000 tenants the platform cannot run one model instance per
// tenant, so every tenant's AI call lands on ONE pooled inference
// service (internal/service/ai.HTTPProvider). A self-hosted quantized
// model (Ternary-Bonsai-8B Q2_0, ~2–5s per 512-token reply on CPU)
// can only service a handful of requests concurrently, so an
// unbounded shared backend has two failure modes:
//
//   - Overload: a thundering herd of active tenants drives more
//     concurrent requests than the model can serve, collapsing
//     latency for everyone (or OOM-killing the server as KV-cache
//     grows with each in-flight request).
//   - Starvation: the existing per-tenant guardrail rate limit
//     (GuardrailedProvider) caps each tenant independently but does
//     NOT arbitrate the shared, scarce concurrency. One bursty tenant
//     still within its own rpm limit can fill every backend slot and
//     starve the rest of the fleet.
//
// InferencePool fixes both with a bounded global concurrency cap plus
// per-tenant FIFO queues drained round-robin: no single tenant can
// hold more than its fair turn of the backend, and no tenant is
// starved regardless of how many requests its neighbours enqueue.
// Strict tenant isolation is preserved — requests are keyed and
// queued by the tenant ID already carried on the context
// (ContextWithTenantID), and the pool never mixes one tenant's
// prompt/response with another's.
//
// The pool is a transparent LLMProvider decorator and is DEFAULT-OFF:
// when Enabled is false Complete is a direct pass-through to the inner
// provider, so an upgrade introduces no new scheduling behaviour and
// no new failure mode until an operator opts in. When the queue is
// saturated the pool returns an error (ErrPoolBusy / ErrPoolWaitTimeout)
// exactly as a busy backend's 503 would — callers already treat a
// Complete error as "LLM unavailable" and fall back to their
// deterministic template path, so saturation degrades gracefully and
// never fabricates a verdict.
type InferencePool struct {
	inner   LLMProvider
	cfg     InferencePoolConfig
	logger  *slog.Logger
	metrics *PoolMetrics

	mu       sync.Mutex
	queues   map[uuid.UUID][]*poolWaiter
	ring     []uuid.UUID // tenants with ≥1 queued waiter, in round-robin order
	ringPos  int
	inflight int
	queuedN  int
	closed   bool

	wake     chan struct{} // non-blocking dispatcher wake-up
	stop     chan struct{} // closed by Close to stop the dispatcher
	done     chan struct{} // closed when the dispatcher goroutine exits
	closedCh chan struct{} // closed by Close to release queued waiters
}

// InferencePoolConfig parameterises the shared inference pool.
type InferencePoolConfig struct {
	// Enabled gates the whole pool. DEFAULT-OFF: when false the pool
	// is a transparent pass-through to the inner provider (no
	// scheduling, no admission, no extra goroutine), so enabling it is
	// an explicit operator opt-in.
	Enabled bool
	// MaxConcurrent is the global cap on in-flight requests to the
	// shared backend. Sized to the model server's real parallelism
	// (e.g. llama-server --parallel slots), NOT the tenant count.
	// Zero ⇒ defaultPoolMaxConcurrent.
	MaxConcurrent int
	// MaxQueuePerTenant bounds how many requests a single tenant may
	// have waiting. Past this the pool sheds load for that tenant
	// (ErrPoolBusy) rather than letting one tenant grow an unbounded
	// backlog. Zero ⇒ defaultPoolMaxQueuePerTenant.
	MaxQueuePerTenant int
	// MaxWait caps how long a request may sit queued before it is
	// failed with ErrPoolWaitTimeout (so a saturated pool degrades to
	// the template path instead of pinning a request behind a long
	// queue). Zero/negative ⇒ bounded only by the caller's context.
	MaxWait time.Duration
}

const (
	defaultPoolMaxConcurrent     = 4
	defaultPoolMaxQueuePerTenant = 8
)

func (c InferencePoolConfig) normalize() InferencePoolConfig {
	if c.MaxConcurrent <= 0 {
		c.MaxConcurrent = defaultPoolMaxConcurrent
	}
	if c.MaxQueuePerTenant <= 0 {
		c.MaxQueuePerTenant = defaultPoolMaxQueuePerTenant
	}
	return c
}

// Pool admission errors. They are deliberately surfaced as ordinary
// Complete errors so callers fall back to their deterministic template
// path (graceful degradation), never a fabricated AI verdict.
var (
	// ErrPoolBusy is returned when a tenant's admission queue is full.
	ErrPoolBusy = errors.New("ai/inferencepool: tenant admission queue full")
	// ErrPoolWaitTimeout is returned when a queued request waited
	// longer than InferencePoolConfig.MaxWait.
	ErrPoolWaitTimeout = errors.New("ai/inferencepool: queue wait timeout")
	// ErrPoolClosed is returned when Complete races a Close.
	ErrPoolClosed = errors.New("ai/inferencepool: pool closed")
)

// poolWaiter is one queued request. admit is closed by the dispatcher
// when the request is granted a concurrency slot; granted records (under
// the pool mutex) that the slot was handed out so a concurrently
// cancelling caller knows it must release it.
type poolWaiter struct {
	tenant   uuid.UUID
	admit    chan struct{}
	granted  bool
	enqueued time.Time
}

// NewInferencePool wraps inner with a fair-scheduled admission pool.
// inner must not be nil. When cfg.Enabled is false the returned pool is
// a transparent pass-through and starts no goroutine. The caller owns
// the pool's lifecycle: call Close to stop the dispatcher and release
// any queued waiters.
func NewInferencePool(inner LLMProvider, cfg InferencePoolConfig, logger *slog.Logger) *InferencePool {
	if logger == nil {
		logger = slog.Default()
	}
	cfg = cfg.normalize()
	p := &InferencePool{
		inner:    inner,
		cfg:      cfg,
		logger:   logger,
		metrics:  &PoolMetrics{},
		queues:   make(map[uuid.UUID][]*poolWaiter),
		wake:     make(chan struct{}, 1),
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
		closedCh: make(chan struct{}),
	}
	if cfg.Enabled {
		go p.dispatch()
	} else {
		// No dispatcher: mark it already-done so Close need not wait.
		close(p.done)
	}
	return p
}

// Metrics returns the pool's live metrics handle.
func (p *InferencePool) Metrics() *PoolMetrics { return p.metrics }

// Config returns the normalized pool configuration.
func (p *InferencePool) Config() InferencePoolConfig { return p.cfg }

// Complete implements LLMProvider. When the pool is disabled it is a
// direct pass-through; otherwise the request is fair-queued by tenant
// and admitted under the global concurrency cap.
func (p *InferencePool) Complete(ctx context.Context, req LLMRequest) (LLMResponse, error) {
	if p == nil {
		return LLMResponse{}, errors.New("ai/inferencepool: Complete called on nil pool")
	}
	if !p.cfg.Enabled {
		return p.inner.Complete(ctx, req)
	}

	tenant := tenantIDFromContext(ctx)
	w, err := p.enqueue(tenant)
	if err != nil {
		return LLMResponse{}, err
	}

	var waitCh <-chan time.Time
	if p.cfg.MaxWait > 0 {
		t := time.NewTimer(p.cfg.MaxWait)
		defer t.Stop()
		waitCh = t.C
	}

	select {
	case <-w.admit:
		// Admitted: the dispatcher has reserved a slot; release exactly
		// once when we are done with the backend call.
		defer p.release()
		p.metrics.recordAdmitted(time.Since(w.enqueued))
		resp, cerr := p.inner.Complete(ctx, req)
		if cerr != nil {
			p.metrics.recordError()
			return LLMResponse{}, cerr
		}
		p.metrics.recordCompleted()
		return resp, nil
	case <-ctx.Done():
		return p.abandon(w, ctx.Err(), p.metrics.recordCancelled)
	case <-waitCh:
		return p.abandon(w, ErrPoolWaitTimeout, p.metrics.recordWaitTimeout)
	case <-p.closedCh:
		return p.abandon(w, ErrPoolClosed, nil)
	}
}

// abandon handles the non-admit exit paths (caller cancel, wait
// timeout, pool close). The request returns retErr to the caller
// regardless, so the supplied counter (if any) is always bumped to keep
// the cancelled/wait-timeout telemetry exact even when the dispatcher
// granted a slot in the same instant the caller gave up. In that grant
// race the waiter is no longer queued, so we release the slot to keep
// the global inflight count exact; the backend call is never made.
func (p *InferencePool) abandon(w *poolWaiter, retErr error, count func()) (LLMResponse, error) {
	if !p.withdraw(w) {
		// Granted just as we gave up: the slot is ours to release.
		p.release()
	}
	if count != nil {
		count()
	}
	return LLMResponse{}, retErr
}

// enqueue appends a waiter to its tenant's FIFO queue, shedding load
// (ErrPoolBusy) when that queue is already full.
func (p *InferencePool) enqueue(tenant uuid.UUID) (*poolWaiter, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil, ErrPoolClosed
	}
	if len(p.queues[tenant]) >= p.cfg.MaxQueuePerTenant {
		p.metrics.recordRejected()
		return nil, ErrPoolBusy
	}
	w := &poolWaiter{tenant: tenant, admit: make(chan struct{}), enqueued: time.Now()}
	if len(p.queues[tenant]) == 0 {
		p.ring = append(p.ring, tenant)
	}
	p.queues[tenant] = append(p.queues[tenant], w)
	p.queuedN++
	p.metrics.setQueued(int64(p.queuedN))
	p.notify()
	return w, nil
}

// withdraw removes a not-yet-granted waiter from its queue. It returns
// true when the waiter was withdrawn (caller owes nothing) and false
// when the dispatcher had already granted the slot (caller must
// release it).
func (p *InferencePool) withdraw(w *poolWaiter) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if w.granted {
		return false
	}
	q := p.queues[w.tenant]
	for i, x := range q {
		if x == w {
			p.queues[w.tenant] = append(q[:i], q[i+1:]...)
			p.queuedN--
			p.metrics.setQueued(int64(p.queuedN))
			if len(p.queues[w.tenant]) == 0 {
				delete(p.queues, w.tenant)
				p.removeFromRingLocked(w.tenant)
			}
			return true
		}
	}
	// Not granted and not in queue: treat as already withdrawn (e.g.
	// Close drained the queue). Caller owes nothing.
	return true
}

// dispatch is the single scheduler goroutine. It wakes on enqueue /
// release / close and grants as many slots as the concurrency cap and
// the queues allow.
func (p *InferencePool) dispatch() {
	defer close(p.done)
	for {
		select {
		case <-p.stop:
			return
		case <-p.wake:
			p.drain()
		}
	}
}

// drain grants concurrency slots round-robin until the cap is reached
// or no tenant has a waiting request.
func (p *InferencePool) drain() {
	for {
		p.mu.Lock()
		if p.closed || p.inflight >= p.cfg.MaxConcurrent {
			p.mu.Unlock()
			return
		}
		w := p.nextWaiterLocked()
		if w == nil {
			p.mu.Unlock()
			return
		}
		w.granted = true
		p.inflight++
		p.queuedN--
		p.metrics.setInflight(int64(p.inflight))
		p.metrics.setQueued(int64(p.queuedN))
		p.mu.Unlock()
		close(w.admit)
	}
}

// nextWaiterLocked pops the next waiter in round-robin tenant order.
// Must be called with p.mu held.
func (p *InferencePool) nextWaiterLocked() *poolWaiter {
	if len(p.ring) == 0 {
		return nil
	}
	if p.ringPos >= len(p.ring) {
		p.ringPos = 0
	}
	tenant := p.ring[p.ringPos]
	q := p.queues[tenant]
	w := q[0]
	p.queues[tenant] = q[1:]
	if len(p.queues[tenant]) == 0 {
		delete(p.queues, tenant)
		// Drop the tenant from the ring; keep ringPos pointing at the
		// next tenant so service order is preserved.
		p.ring = append(p.ring[:p.ringPos], p.ring[p.ringPos+1:]...)
		if len(p.ring) == 0 {
			p.ringPos = 0
		} else {
			p.ringPos %= len(p.ring)
		}
	} else {
		// Advance so the next grant goes to the next tenant in rotation.
		p.ringPos = (p.ringPos + 1) % len(p.ring)
	}
	return w
}

// removeFromRingLocked drops tenant from the round-robin ring. Must be
// called with p.mu held.
func (p *InferencePool) removeFromRingLocked(tenant uuid.UUID) {
	for i, t := range p.ring {
		if t == tenant {
			p.ring = append(p.ring[:i], p.ring[i+1:]...)
			switch {
			case len(p.ring) == 0:
				p.ringPos = 0
			case p.ringPos > i:
				p.ringPos--
			case p.ringPos >= len(p.ring):
				p.ringPos = 0
			}
			return
		}
	}
}

// release returns a concurrency slot and wakes the dispatcher to admit
// the next waiter.
func (p *InferencePool) release() {
	p.mu.Lock()
	if p.inflight > 0 {
		p.inflight--
	}
	p.metrics.setInflight(int64(p.inflight))
	p.mu.Unlock()
	p.notify()
}

// notify wakes the dispatcher without blocking (coalesced).
func (p *InferencePool) notify() {
	select {
	case p.wake <- struct{}{}:
	default:
	}
}

// Close stops the dispatcher and releases every queued waiter with
// ErrPoolClosed. It is idempotent and safe to call on a disabled pool.
// In-flight backend calls are not interrupted (they finish on their own
// context); only queued, not-yet-admitted waiters are released.
func (p *InferencePool) Close() {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	p.closed = true
	// Drop every queued waiter from the structures; they observe
	// closedCh and exit via abandon.
	p.queues = make(map[uuid.UUID][]*poolWaiter)
	p.ring = nil
	p.ringPos = 0
	p.queuedN = 0
	p.metrics.setQueued(0)
	p.mu.Unlock()

	close(p.closedCh)
	if p.cfg.Enabled {
		close(p.stop)
		<-p.done
	}
}

// PoolMetrics records the shared inference pool's behaviour. It proves
// the fleet-scale efficiency claim: a single bounded pool (not N
// per-tenant model instances) serves the whole fleet, with peak
// concurrency held at MaxConcurrent and fair admission across tenants.
// All counters are lock-free so the live LLM path stays cheap.
type PoolMetrics struct {
	admitted     atomic.Int64
	completed    atomic.Int64
	errors       atomic.Int64
	rejected     atomic.Int64
	waitTimeouts atomic.Int64
	cancelled    atomic.Int64
	totalWaitMS  atomic.Int64

	inflight     atomic.Int64
	peakInflight atomic.Int64
	queued       atomic.Int64
	peakQueued   atomic.Int64
}

func (m *PoolMetrics) recordAdmitted(wait time.Duration) {
	m.admitted.Add(1)
	m.totalWaitMS.Add(wait.Milliseconds())
}
func (m *PoolMetrics) recordCompleted()   { m.completed.Add(1) }
func (m *PoolMetrics) recordError()       { m.errors.Add(1) }
func (m *PoolMetrics) recordRejected()    { m.rejected.Add(1) }
func (m *PoolMetrics) recordWaitTimeout() { m.waitTimeouts.Add(1) }
func (m *PoolMetrics) recordCancelled()   { m.cancelled.Add(1) }

func (m *PoolMetrics) setInflight(v int64) {
	m.inflight.Store(v)
	updatePeak(&m.peakInflight, v)
}
func (m *PoolMetrics) setQueued(v int64) {
	m.queued.Store(v)
	updatePeak(&m.peakQueued, v)
}

// updatePeak raises peak to v if v is larger, via a CAS loop.
func updatePeak(peak *atomic.Int64, v int64) {
	for {
		cur := peak.Load()
		if v <= cur || peak.CompareAndSwap(cur, v) {
			return
		}
	}
}

// PoolMetricsSnapshot is a point-in-time copy of the pool counters,
// suitable for a status endpoint or structured log line.
type PoolMetricsSnapshot struct {
	Admitted     int64   `json:"admitted"`
	Completed    int64   `json:"completed"`
	Errors       int64   `json:"errors"`
	Rejected     int64   `json:"rejected_queue_full"`
	WaitTimeouts int64   `json:"wait_timeouts"`
	Cancelled    int64   `json:"cancelled"`
	Inflight     int64   `json:"inflight"`
	PeakInflight int64   `json:"peak_inflight"`
	Queued       int64   `json:"queued"`
	PeakQueued   int64   `json:"peak_queued"`
	AvgWaitMS    float64 `json:"avg_wait_ms"`
}

// Snapshot returns a consistent-enough copy of the counters for
// reporting. Counters are read independently, so a snapshot taken under
// concurrent load may mix values from adjacent instants; this is fine
// for telemetry and never used for control decisions.
func (m *PoolMetrics) Snapshot() PoolMetricsSnapshot {
	admitted := m.admitted.Load()
	var avg float64
	if admitted > 0 {
		avg = float64(m.totalWaitMS.Load()) / float64(admitted)
	}
	return PoolMetricsSnapshot{
		Admitted:     admitted,
		Completed:    m.completed.Load(),
		Errors:       m.errors.Load(),
		Rejected:     m.rejected.Load(),
		WaitTimeouts: m.waitTimeouts.Load(),
		Cancelled:    m.cancelled.Load(),
		Inflight:     m.inflight.Load(),
		PeakInflight: m.peakInflight.Load(),
		Queued:       m.queued.Load(),
		PeakQueued:   m.peakQueued.Load(),
		AvgWaitMS:    avg,
	}
}
