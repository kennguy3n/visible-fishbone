package metering

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"golang.org/x/time/rate"
)

// GuardrailBudgetGate adapts a *BudgetEnforcer onto the narrow
// BudgetGate interface the AI guardrails declare (see
// internal/service/ai/guardrails.go). It is the single seam where the
// generic per-meter budget check is specialised to the LLM-token meter
// the guardrails gate on before every completion. Kept here (rather
// than in cmd/sng-control) so it is unit-tested alongside the enforcer
// and reused by any future caller.
type GuardrailBudgetGate struct {
	enforcer *BudgetEnforcer
}

// NewGuardrailBudgetGate wraps an enforcer for use as an AI BudgetGate.
func NewGuardrailBudgetGate(enforcer *BudgetEnforcer) *GuardrailBudgetGate {
	return &GuardrailBudgetGate{enforcer: enforcer}
}

// CheckLLMTokenBudget returns a non-nil error (wrapping
// ErrBudgetExceeded) only when spending estimatedTokens would breach
// the tenant's hard LLM-token budget; a soft-limit crossing is allowed
// (and alerted inside the enforcer). A nil enforcer is treated as "no
// budgeting configured" and always allows.
func (g *GuardrailBudgetGate) CheckLLMTokenBudget(ctx context.Context, tenantID uuid.UUID, estimatedTokens int64) error {
	if g == nil || g.enforcer == nil {
		return nil
	}
	_, err := g.enforcer.CheckBudget(ctx, MeterLLMTokensUsed, tenantID, estimatedTokens)
	return err
}

// GuardrailUsageRecorder adapts a *MeteringService onto the AI
// UsageRecorder interface, metering a completed LLM call's token count
// and the call itself. Both meter writes are attempted; a combined
// error is returned (the guardrails log it and never surface it to the
// caller, so metering can never break the live LLM path).
type GuardrailUsageRecorder struct {
	svc *MeteringService
}

// NewGuardrailUsageRecorder wraps a MeteringService for use as an AI
// UsageRecorder.
func NewGuardrailUsageRecorder(svc *MeteringService) *GuardrailUsageRecorder {
	return &GuardrailUsageRecorder{svc: svc}
}

// RecordLLMUsage meters `tokens` against llm_tokens_used and `calls`
// against llm_calls. A nil service is a no-op.
func (r *GuardrailUsageRecorder) RecordLLMUsage(ctx context.Context, tenantID uuid.UUID, tokens, calls int64) error {
	if r == nil || r.svc == nil {
		return nil
	}
	tokenErr := r.svc.Record(ctx, tenantID, MeterLLMTokensUsed, tokens)
	callErr := r.svc.Record(ctx, tenantID, MeterLLMCalls, calls)
	return errors.Join(tokenErr, callErr)
}

// --- ClickHouse row-write rate limiting -----------------------------------
//
// ClickHouse row writes are SNG's dominant write-amplification cost
// driver (see cost-model.md): one flow can fan out to several telemetry
// rows, and a single noisy tenant — a compromised edge replaying flow
// events, or a mis-tuned agent re-emitting posture on every packet — can
// drive a row-write flood that both inflates that tenant's ClickHouse
// bill and threatens the shared hot tier for every other tenant. The
// telemetry consumer's PerTenantLimiter caps *event* throughput, but a
// single event can still expand to many rows downstream, so the row
// write itself needs its own per-tenant cap measured in the unit that
// actually costs money: rows.
//
// ClickHouseRowLimiter is that cap. It is a per-tenant token bucket
// (golang.org/x/time/rate) where one token == one row, so the bucket
// directly bounds a tenant's sustained rows/sec while letting a burst
// (an edge flushing its on-disk spool) through up to the burst budget.
// It is real-time and lock-free on the hot path (an existing tenant's
// bucket is read under an RWMutex read lock; only first-touch creation
// takes the write lock). Buckets are retained for the limiter's
// lifetime — the steady-state tenant set is bounded by the customer
// count (low thousands), not by row volume (millions/sec) — so the
// memory cost is a few thousand small structs, not a per-row
// allocation.
//
// It lives here, beside the other metering adapters, because it is the
// seam that specialises the generic per-tenant budget notion onto the
// ClickHouse-rows meter: the hot-path writer calls AllowN/WaitN before
// persisting a batch, and the admitted volume is exactly what
// MeterClickHouseRowsWritten (and therefore the cost projection)
// accounts for.

const (
	// DefaultClickHouseRowRateLimit is the per-tenant steady-state
	// ClickHouse rows-per-second budget applied when an operator has
	// not configured an explicit override. Sized at the upper bound a
	// healthy SME tenant sustains: ~500 events/sec at peak (busy hour
	// on a 250-seat office) fanning out to ~4 telemetry rows each.
	DefaultClickHouseRowRateLimit rate.Limit = 2000
	// DefaultClickHouseRowBurst is the burst budget paired with the
	// steady-state rate. Sized to absorb an edge flushing its on-disk
	// spool on reconnect (a few seconds of steady-state) and to exceed
	// any single hot-writer flush batch, so a legitimate batch is never
	// larger than the bucket can admit in one shot.
	DefaultClickHouseRowBurst = 20000
)

// ErrRowLimitExceeded signals that admitting the requested rows would
// breach the tenant's ClickHouse row-write budget right now; the caller
// should shed or defer the write (e.g. Nak the delivery) rather than
// persist it. Carries no tenant ID so it stays a comparable sentinel;
// callers log the tenant from their own context.
var ErrRowLimitExceeded = errors.New("metering: clickhouse row-write rate limit exceeded")

// RowLimit is the resolved ClickHouse row-write budget for one tenant.
// Construct via NewRowLimit; the zero value is invalid. Rate is in
// rows/sec, Burst in rows. A Rate of rate.Inf disables limiting for the
// tenant (used for the system/operator tenant).
type RowLimit struct {
	Rate  rate.Limit
	Burst int
}

// NewRowLimit constructs a RowLimit, validating the inputs. Pass
// rate.Inf with any Burst >= 1 for an unlimited tenant.
func NewRowLimit(r rate.Limit, burst int) (RowLimit, error) {
	if r <= 0 {
		return RowLimit{}, fmt.Errorf("metering: row rate must be > 0, got %v", r)
	}
	if burst < 1 {
		return RowLimit{}, fmt.Errorf("metering: row burst must be >= 1, got %d", burst)
	}
	return RowLimit{Rate: r, Burst: burst}, nil
}

// RowLimitResolver returns the per-tenant ClickHouse row-write budget.
// Implementations typically read from the tenant/tier service or a
// config map; a nil resolver means "every tenant gets the default
// budget", which is the common path.
//
// HOT-PATH CONTRACT: ResolveRowLimit is called by AllowN/WaitN once per
// admitted event on the telemetry hot path (millions/sec aggregate), so
// it MUST be cheap and non-blocking — an in-memory lookup, never a
// synchronous DB/RPC call. The shipped StaticRowLimitResolver is a field
// read, and bucketFor only rebuilds a tenant's bucket when the resolved
// budget actually changes, so a resolver that wants live, per-tenant
// budgets must serve them from a cache it refreshes out-of-band (e.g. a
// background sync off the tenant/tier service), not by doing I/O here.
type RowLimitResolver interface {
	ResolveRowLimit(ctx context.Context, tenantID uuid.UUID) RowLimit
}

// StaticRowLimitResolver gives every tenant the same budget.
type StaticRowLimitResolver struct{ Limit RowLimit }

// ResolveRowLimit returns the configured static limit.
func (s StaticRowLimitResolver) ResolveRowLimit(context.Context, uuid.UUID) RowLimit {
	return s.Limit
}

func defaultRowLimit() RowLimit {
	return RowLimit{Rate: DefaultClickHouseRowRateLimit, Burst: DefaultClickHouseRowBurst}
}

// RowLimitFromConfig builds a per-tenant RowLimit from operator-supplied
// values, falling back to the package default for any field <= 0. This
// keeps the default budget defined in exactly one place (the
// DefaultClickHouseRow* constants) so config plumbing never duplicates —
// and therefore never drifts from — it.
func RowLimitFromConfig(perSec float64, burst int) RowLimit {
	rl := defaultRowLimit()
	if perSec > 0 {
		rl.Rate = rate.Limit(perSec)
	}
	if burst > 0 {
		rl.Burst = burst
	}
	return rl
}

// ClickHouseRowLimiter holds the per-tenant row-write token buckets.
// Safe for concurrent use: the bucket map is guarded by an RWMutex and
// the hot path (an existing bucket) takes only the read lock.
type ClickHouseRowLimiter struct {
	resolver RowLimitResolver
	now      func() time.Time

	mu      sync.RWMutex
	buckets map[uuid.UUID]*rowBucket
}

// rowBucket pairs a *rate.Limiter with the budget it was built for, so
// the limiter is rebuilt in place when an operator changes the tenant's
// budget rather than serving a stale rate forever.
type rowBucket struct {
	mu     sync.Mutex
	cur    RowLimit
	bucket *rate.Limiter
}

// RowLimiterOption customises a ClickHouseRowLimiter.
type RowLimiterOption func(*ClickHouseRowLimiter)

// withRowLimiterClock overrides the wall clock; test-only. It governs
// the explicit-time API only — AllowN drives the bucket through
// rate.Limiter's AllowN(now, n) and budget refresh uses SetLimitAt /
// SetBurstAt(now, ...) — so a pinned clock makes the non-blocking path
// fully deterministic. WaitN is the deliberate exception: golang.org/x/
// time/rate exposes no explicit-time WaitN (it must compute a delay and
// sleep against the real monotonic clock), so WaitN always uses the real
// clock regardless of this option. Tests that pin the clock must assert
// over AllowN; WaitN tests should assert on context cancellation /
// completion, not on pinned-clock token math.
func withRowLimiterClock(now func() time.Time) RowLimiterOption {
	return func(l *ClickHouseRowLimiter) {
		if now != nil {
			l.now = now
		}
	}
}

// NewClickHouseRowLimiter constructs a limiter resolving per-tenant
// budgets through resolver. A nil resolver gives every tenant the
// default budget.
func NewClickHouseRowLimiter(resolver RowLimitResolver, opts ...RowLimiterOption) *ClickHouseRowLimiter {
	if resolver == nil {
		resolver = StaticRowLimitResolver{Limit: defaultRowLimit()}
	}
	l := &ClickHouseRowLimiter{
		resolver: resolver,
		now:      time.Now,
		buckets:  make(map[uuid.UUID]*rowBucket),
	}
	for _, opt := range opts {
		opt(l)
	}
	return l
}

// bucketFor returns the tenant's bucket, creating it on first touch.
// Budget refresh and token consumption are done together under the
// bucket's own mutex by refreshLocked/allowN, so this only handles the
// map lookup-or-create (guarded by l.mu).
func (l *ClickHouseRowLimiter) bucketFor(id uuid.UUID, desired RowLimit) *rowBucket {
	l.mu.RLock()
	b, ok := l.buckets[id]
	l.mu.RUnlock()
	if ok {
		return b
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if b, ok = l.buckets[id]; !ok {
		b = &rowBucket{cur: desired, bucket: rate.NewLimiter(desired.Rate, desired.Burst)}
		l.buckets[id] = b
	}
	return b
}

// refreshLocked rebuilds the limiter's rate and burst in place when the
// operator changed the tenant's budget, so a lowered cap takes effect on
// the next call without dropping the tenant's accumulated tokens (and
// without touching any other tenant's bucket). The caller MUST hold
// b.mu: SetLimitAt and SetBurstAt are two calls, and only holding b.mu
// across both — and across the token op that follows (see allowN) —
// keeps a concurrent reader from observing a half-applied limiter (new
// rate, old burst). `now` is passed in so the refresh and the token op
// share a single clock instant.
func (b *rowBucket) refreshLocked(now time.Time, desired RowLimit) {
	if b.cur == desired {
		return
	}
	b.cur = desired
	b.bucket.SetLimitAt(now, desired.Rate)
	b.bucket.SetBurstAt(now, desired.Burst)
}

// allowN refreshes the budget and consumes `rows` tokens atomically
// under b.mu, so the non-blocking hot path can never see a half-applied
// (new rate, old burst) limiter mid-reconfigure. b.mu is per-tenant and
// a tenant is pinned to one partition, so it is uncontended in practice;
// the extra hold around the already-internally-locked rate.Limiter call
// costs nothing on the common path and closes the reconfigure window.
func (b *rowBucket) allowN(now time.Time, desired RowLimit, rows int) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.refreshLocked(now, desired)
	return b.bucket.AllowN(now, rows)
}

// AllowN reports whether the tenant may write `rows` ClickHouse rows
// right now, consuming that many tokens when it returns true. It never
// blocks. A non-positive row count is a no-op that always allows; a nil
// tenant is rejected. A tenant whose budget is rate.Inf is always
// allowed. When the budget is finite and exhausted (or `rows` exceeds
// the burst and so can never be admitted in one shot) it returns false
// and consumes nothing, so the caller can shed or defer the write.
func (l *ClickHouseRowLimiter) AllowN(ctx context.Context, tenantID uuid.UUID, rows int64) bool {
	if l == nil || rows <= 0 {
		return true
	}
	if tenantID == uuid.Nil {
		return false
	}
	desired := l.resolver.ResolveRowLimit(ctx, tenantID)
	if desired.Rate == rate.Inf {
		return true
	}
	// A batch larger than the burst can never be admitted by the token
	// bucket; reject it here rather than letting rate.Limiter panic on
	// an n that exceeds the burst.
	if rows > int64(desired.Burst) {
		return false
	}
	b := l.bucketFor(tenantID, desired)
	return b.allowN(l.now(), desired, int(rows))
}

// WaitN blocks until the tenant has accrued enough budget to write
// `rows` ClickHouse rows, then consumes it — applying smooth
// back-pressure to a writer rather than shedding. It returns when the
// tokens are reserved, or early with ctx.Err() if the context is
// cancelled first. A non-positive row count is a no-op; a nil tenant is
// rejected; a rate.Inf tenant returns immediately. `rows` exceeding the
// burst returns ErrRowLimitExceeded (it can never be satisfied), so the
// caller splits the batch rather than blocking forever.
//
// Unlike AllowN, WaitN always uses the real monotonic clock, not the
// withRowLimiterClock test clock: rate.Limiter has no explicit-time
// WaitN (it sleeps for the computed delay), so a pinned clock cannot
// drive it. In production l.now is time.Now, so the two stay consistent.
//
// The budget refresh runs under b.mu before the (blocking) reservation
// so the two SetXAt calls are applied atomically; WaitN cannot hold b.mu
// across its sleep, but a budget change concurrent with an in-flight
// WaitN is an operator-rare event and self-corrects on the next call.
func (l *ClickHouseRowLimiter) WaitN(ctx context.Context, tenantID uuid.UUID, rows int64) error {
	if l == nil || rows <= 0 {
		return nil
	}
	if tenantID == uuid.Nil {
		return fmt.Errorf("metering: tenant id required for row rate limit: %w", ErrRowLimitExceeded)
	}
	desired := l.resolver.ResolveRowLimit(ctx, tenantID)
	if desired.Rate == rate.Inf {
		return nil
	}
	if rows > int64(desired.Burst) {
		return fmt.Errorf("metering: batch of %d rows exceeds tenant burst %d: %w", rows, desired.Burst, ErrRowLimitExceeded)
	}
	b := l.bucketFor(tenantID, desired)
	b.mu.Lock()
	b.refreshLocked(l.now(), desired)
	b.mu.Unlock()
	return b.bucket.WaitN(ctx, int(rows))
}

// RowLimitSnapshot is a read-only view of one tenant's row-write budget,
// for the /metrics surface and tests.
type RowLimitSnapshot struct {
	Tenant uuid.UUID
	Rate   rate.Limit
	Burst  int
}

// Snapshot returns the current per-tenant budgets. Nil receiver yields
// nil so an optional limiter can be snapshotted without a nil check.
func (l *ClickHouseRowLimiter) Snapshot() map[uuid.UUID]RowLimitSnapshot {
	if l == nil {
		return nil
	}
	l.mu.RLock()
	defer l.mu.RUnlock()
	out := make(map[uuid.UUID]RowLimitSnapshot, len(l.buckets))
	for id, b := range l.buckets {
		b.mu.Lock()
		out[id] = RowLimitSnapshot{Tenant: id, Rate: b.cur.Rate, Burst: b.cur.Burst}
		b.mu.Unlock()
	}
	return out
}
