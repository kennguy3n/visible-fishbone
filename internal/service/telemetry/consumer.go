// Package telemetry — consumer.go implements the per-tenant
// backpressure + rate-limiting layer that sits between the
// JetStream pull-consumer (Service.loop) and the hot/cold writers.
//
// The existing Service in service.go drains SNG_TELEMETRY in
// FIFO order and dispatches each delivery synchronously. That is
// correct for a healthy cluster but breaks two contracts the
// product needs:
//
//  1. **Per-tenant fairness.** A single noisy tenant (compromised
//     edge replaying flow events at line rate, or a misconfigured
//     agent emitting a flood of posture events) would saturate
//     the consumer and starve the rest. JetStream itself has no
//     per-tenant fairness primitive — the stream subject filter
//     groups all tenants together.
//
//  2. **Bounded ClickHouse / S3 pressure.** The downstream
//     writers expose backlog counters but no inbound rate cap.
//     The consumer needs to slow down before the writer queues
//     overflow, not after.
//
// PerTenantLimiter solves both. Each tenant gets an independent
// token bucket (golang.org/x/time/rate). On dispatch, the
// consumer takes a token from the tenant's bucket. If the bucket
// is empty within the configured wait, the message is `Nak`'d
// with a delay so JetStream redelivers it after the rate budget
// refills — JetStream's MaxDeliver budget then provides the
// final back-pressure escape valve (the bad tenant's message
// eventually lands in the DLQ rather than blocking the consumer
// indefinitely).
//
// PerTenantLimiter is independent of Service so its semantics
// can be unit-tested without spinning up a JetStream. Service
// integrates it via WithPerTenantLimiter (additive — calling
// `New` without one keeps the prior unconditional dispatch
// behaviour).

package telemetry

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"golang.org/x/time/rate"
)

// DefaultTenantRateLimit is the per-tenant steady-state events-per-
// second budget applied when the operator does not configure an
// explicit per-tenant override. Sized at the upper bound a healthy
// SME tenant emits at peak (busy hour on a 250-seat office: ~500
// flow + dns + http events/sec).
const DefaultTenantRateLimit rate.Limit = 1000

// DefaultTenantBurstSize is the burst budget paired with the
// steady-state rate. Sized to absorb the spike when an edge boots
// and replays its on-disk spool — empirically 2-5 seconds worth
// of steady-state.
const DefaultTenantBurstSize = 4000

// DefaultTenantWaitBudget is how long the consumer is willing to
// block on a tenant's bucket before declaring "back-pressure" and
// asking JetStream to redeliver. Short on purpose: the consumer
// loop must not be held up by a single bad tenant, even with a
// strict per-tenant cap. The MaxDeliver budget on the consumer is
// the long-tail backstop.
const DefaultTenantWaitBudget = 50 * time.Millisecond

// DefaultNakBackoff is the redelivery delay applied when a tenant
// is being rate-limited. The bucket should refill in ~1s under
// the default rate; a 2s redelivery delay leaves headroom while
// still keeping the per-message latency under the JetStream
// AckWait (30s).
const DefaultNakBackoff = 2 * time.Second

// ErrTenantBlocked signals that a tenant has exhausted its
// per-tenant budget and the caller should Nak the message rather
// than dispatch it. Carries the tenant ID for logging.
var ErrTenantBlocked = errors.New("telemetry: tenant rate-limited")

// TenantLimit is the resolved budget for a single tenant.
// Construct via NewTenantLimit; the zero value is invalid.
type TenantLimit struct {
	// Rate is the steady-state events-per-second budget. Must
	// be > 0. rate.Inf disables limiting entirely (used for the
	// `system` / unbounded operator tenant).
	Rate rate.Limit
	// Burst is the maximum number of events the tenant can
	// dispatch in a single instant before the bucket starts
	// draining. Must be >= 1.
	Burst int
}

// NewTenantLimit constructs a TenantLimit with the given budget,
// returning an error if the inputs are out of range.
func NewTenantLimit(r rate.Limit, burst int) (TenantLimit, error) {
	if r <= 0 {
		return TenantLimit{}, fmt.Errorf("telemetry: tenant rate must be > 0, got %v", r)
	}
	if burst < 1 {
		return TenantLimit{}, fmt.Errorf("telemetry: tenant burst must be >= 1, got %d", burst)
	}
	return TenantLimit{Rate: r, Burst: burst}, nil
}

// LimitResolver returns the per-tenant budget for the given
// tenant. Implementations would typically read from the tenant
// service or a config map. A nil resolver means "every tenant
// gets the default budget" — which is the common path.
type LimitResolver interface {
	Resolve(ctx context.Context, tenantID uuid.UUID) TenantLimit
}

// StaticLimitResolver is the simplest LimitResolver — every
// tenant gets the same budget. Used by tests and by deployments
// that haven't yet wired per-tenant overrides.
type StaticLimitResolver struct{ Limit TenantLimit }

// Resolve returns the configured static limit.
func (s StaticLimitResolver) Resolve(_ context.Context, _ uuid.UUID) TenantLimit {
	return s.Limit
}

// MapLimitResolver looks up per-tenant overrides in a static map
// and falls back to a default. Safe for concurrent use.
type MapLimitResolver struct {
	mu        sync.RWMutex
	overrides map[uuid.UUID]TenantLimit
	fallback  TenantLimit
}

// NewMapLimitResolver constructs an empty resolver with the
// provided fallback. Use SetTenant to install overrides.
func NewMapLimitResolver(fallback TenantLimit) *MapLimitResolver {
	return &MapLimitResolver{
		overrides: make(map[uuid.UUID]TenantLimit),
		fallback:  fallback,
	}
}

// SetTenant installs a per-tenant override. Pass uuid.Nil to
// update the fallback.
func (m *MapLimitResolver) SetTenant(id uuid.UUID, limit TenantLimit) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if id == uuid.Nil {
		m.fallback = limit
		return
	}
	m.overrides[id] = limit
}

// Resolve returns the override for id, or the fallback when
// none exists.
func (m *MapLimitResolver) Resolve(_ context.Context, id uuid.UUID) TenantLimit {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if l, ok := m.overrides[id]; ok {
		return l
	}
	return m.fallback
}

// PerTenantLimiter holds the per-tenant token buckets. Buckets
// are created lazily on the first dispatch for a tenant and
// retained for the lifetime of the limiter — this is the right
// trade-off for SNG because the steady-state tenant set is
// bounded by the customer count (low thousands), not by event
// volume (millions/sec).
//
// Concurrent use is safe. The internal map is guarded by an
// RWMutex; the hot path (looking up an existing bucket) takes
// the read lock only.
type PerTenantLimiter struct {
	resolver LimitResolver

	mu      sync.RWMutex
	buckets map[uuid.UUID]*tenantBucket
}

// tenantBucket pairs a *rate.Limiter with its budget so the
// reservation reflects the latest budget from the resolver
// (an operator who lowers a tenant's budget should see the
// new limit applied without recreating the bucket).
type tenantBucket struct {
	mu     sync.Mutex
	cur    TenantLimit
	bucket *rate.Limiter
}

// NewPerTenantLimiter constructs a limiter that resolves
// per-tenant budgets through the provided resolver. A nil
// resolver is replaced with a StaticLimitResolver carrying
// the default budget.
func NewPerTenantLimiter(resolver LimitResolver) *PerTenantLimiter {
	if resolver == nil {
		resolver = StaticLimitResolver{Limit: TenantLimit{
			Rate:  DefaultTenantRateLimit,
			Burst: DefaultTenantBurstSize,
		}}
	}
	return &PerTenantLimiter{
		resolver: resolver,
		buckets:  make(map[uuid.UUID]*tenantBucket),
	}
}

// limit is the single-event budget-check entry point.
//
//   - Resolves the per-tenant TenantLimit (refresh-on-call so an
//     operator-changed budget propagates immediately).
//   - Returns nil immediately when the tenant's budget is rate.Inf
//     (the "unlimited" disposition for the system/operator tenant).
//   - Acquires one token from the tenant's bucket within wait;
//     on timeout returns ErrTenantBlocked so the caller can Nak.
func (l *PerTenantLimiter) limit(ctx context.Context, tenantID uuid.UUID, wait time.Duration) error {
	if tenantID == uuid.Nil {
		return fmt.Errorf("telemetry: tenant_id is required for rate limit: %w", ErrTenantBlocked)
	}
	desired := l.resolver.Resolve(ctx, tenantID)
	if desired.Rate == rate.Inf {
		return nil
	}
	bucket := l.bucketFor(tenantID, desired)
	if wait <= 0 {
		wait = DefaultTenantWaitBudget
	}
	rsv := bucket.bucket.Reserve()
	if !rsv.OK() {
		// rate.Inf or burst==0 with non-finite delay — the
		// bucket logic in rate.Limiter returns !OK when the
		// reservation can never be filled. We reject rather
		// than block indefinitely.
		return fmt.Errorf("telemetry: tenant %s reservation refused: %w", tenantID, ErrTenantBlocked)
	}
	delay := rsv.Delay()
	if delay == 0 {
		return nil
	}
	if delay > wait {
		// Bucket can't refill in time — give the token back
		// (Cancel resets the bucket as if Reserve was never
		// called) and let the caller Nak the message.
		rsv.Cancel()
		return fmt.Errorf("telemetry: tenant %s exceeded budget (delay %s > wait %s): %w", tenantID, delay, wait, ErrTenantBlocked)
	}
	select {
	case <-time.After(delay):
		return nil
	case <-ctx.Done():
		rsv.Cancel()
		return ctx.Err()
	}
}

// Allow is a non-blocking variant. Returns true when the tenant
// has at least one token available right now, false otherwise.
// Used in tests where blocking semantics are awkward.
func (l *PerTenantLimiter) Allow(ctx context.Context, tenantID uuid.UUID) bool {
	if tenantID == uuid.Nil {
		return false
	}
	desired := l.resolver.Resolve(ctx, tenantID)
	if desired.Rate == rate.Inf {
		return true
	}
	bucket := l.bucketFor(tenantID, desired)
	return bucket.bucket.Allow()
}

// Wait is the blocking variant. Returns nil when a token has been
// acquired, ErrTenantBlocked when the budget is exceeded within
// the configured wait, or ctx.Err() on cancellation.
func (l *PerTenantLimiter) Wait(ctx context.Context, tenantID uuid.UUID) error {
	return l.limit(ctx, tenantID, DefaultTenantWaitBudget)
}

// WaitWithBudget is the blocking variant with an explicit wait
// budget — exposed for callers who need to override the package
// default (typically tests).
func (l *PerTenantLimiter) WaitWithBudget(ctx context.Context, tenantID uuid.UUID, wait time.Duration) error {
	return l.limit(ctx, tenantID, wait)
}

// Snapshot returns the current per-tenant token counts. Used by
// the /metrics handler and by tests to verify rate-limit
// behaviour without inspecting internal state directly.
func (l *PerTenantLimiter) Snapshot() map[uuid.UUID]TenantLimitSnapshot {
	l.mu.RLock()
	defer l.mu.RUnlock()
	out := make(map[uuid.UUID]TenantLimitSnapshot, len(l.buckets))
	for id, b := range l.buckets {
		b.mu.Lock()
		out[id] = TenantLimitSnapshot{
			Tenant: id,
			Rate:   b.cur.Rate,
			Burst:  b.cur.Burst,
			// rate.Limiter does not expose tokens-remaining
			// directly; surface the budget so the operator
			// can reason about it.
		}
		b.mu.Unlock()
	}
	return out
}

// TenantLimitSnapshot is a read-only view of one tenant's budget.
type TenantLimitSnapshot struct {
	Tenant uuid.UUID
	Rate   rate.Limit
	Burst  int
}

// bucketFor returns (creating if necessary) the per-tenant bucket
// reflecting the resolver's current desired budget. When the
// resolver returns a different budget from the cached one, the
// limiter is reconfigured in place (SetLimit / SetBurst) so the
// next call observes the change without losing already-accumulated
// tokens.
func (l *PerTenantLimiter) bucketFor(id uuid.UUID, desired TenantLimit) *tenantBucket {
	l.mu.RLock()
	b, ok := l.buckets[id]
	l.mu.RUnlock()
	if ok {
		applyDesiredBudget(b, desired)
		return b
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	// Re-check under the write lock — another goroutine may
	// have inserted concurrently. If so, apply the desired
	// budget through the same helper the read-lock path uses,
	// otherwise an operator's just-resolved budget change can
	// be silently dropped for one request on the loser of the
	// create race.
	if b, ok := l.buckets[id]; ok {
		applyDesiredBudget(b, desired)
		return b
	}
	b = &tenantBucket{
		cur:    desired,
		bucket: rate.NewLimiter(desired.Rate, desired.Burst),
	}
	l.buckets[id] = b
	return b
}

// applyDesiredBudget reconciles a cached bucket with the
// resolver's latest desired budget — used by both the read-lock
// and write-lock paths in bucketFor so the create-race loser
// applies the same SetLimit / SetBurst the read-lock path would.
// The bucket's own mutex is taken inside; callers must NOT hold
// any lock that bucketFor itself uses.
func applyDesiredBudget(b *tenantBucket, desired TenantLimit) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.cur.Rate != desired.Rate {
		b.bucket.SetLimit(desired.Rate)
		b.cur.Rate = desired.Rate
	}
	if b.cur.Burst != desired.Burst {
		b.bucket.SetBurst(desired.Burst)
		b.cur.Burst = desired.Burst
	}
}
