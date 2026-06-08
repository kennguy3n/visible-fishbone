package middleware

import (
	"context"
	"log/slog"
	"math"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/config"
	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// TenantTierResolver resolves a tenant's billing tier so the
// per-tenant rate limiter can pick the matching request budget. It is
// satisfied by a thin adapter over the tenant repository; the
// interface keeps this middleware decoupled from storage and trivially
// fakeable in tests.
type TenantTierResolver interface {
	// ResolveTier returns the tenant's current tier. An error is
	// treated as "tier unknown": the limiter falls back to the
	// standard budget rather than failing the request open or closed
	// on a transient lookup error.
	ResolveTier(ctx context.Context, tenantID uuid.UUID) (repository.TenantTier, error)
}

// TenantRateLimiter is a per-tenant token-bucket limiter. Each tenant
// gets a bucket whose capacity is its tier's per-minute allowance and
// whose refill rate spreads that allowance evenly across the minute,
// so a tenant may burst up to a full minute's budget and then settles
// to the steady rate. Buckets are created on demand and pruned by a
// background goroutine after IdleTTL of inactivity, bounding the map
// under a churn of one-shot tenants across the 5K-tenant fleet.
//
// It is intended to run AFTER the auth middleware (so the resolved
// tenant identity is in context) and is keyed on the tenant UUID, not
// the source IP — a single tenant spread across many IPs still shares
// one budget, and many tenants behind one IP each get their own.
type TenantRateLimiter struct {
	cfg      config.TenantRateLimit
	resolver TenantTierResolver
	logger   *slog.Logger
	now      func() time.Time

	mu      sync.Mutex
	buckets map[uuid.UUID]*tenantBucket
	stop    chan struct{}
	stopped chan struct{}
}

// tenantBucket is one tenant's token bucket plus a cached view of the
// tenant's tier (refreshed at most once per TierTTL).
type tenantBucket struct {
	tokens   float64
	capacity float64
	refill   float64 // tokens per second
	last     time.Time
	tier     repository.TenantTier
	tierAt   time.Time
	lastSeen time.Time
}

// rateDecision is the outcome of a single bucket consult.
type rateDecision struct {
	allowed    bool
	limit      int
	remaining  int
	resetEpoch int64 // unix seconds at which the bucket is fully refilled
	retryAfter int   // seconds until the next token (only when !allowed)
}

// NewTenantRateLimiter constructs a per-tenant limiter and starts its
// cleanup goroutine. resolver may be nil, in which case every tenant
// is treated as the standard tier. logger may be nil (logging is then
// suppressed). Caller is responsible for invoking Close on shutdown.
func NewTenantRateLimiter(cfg config.TenantRateLimit, resolver TenantTierResolver, logger *slog.Logger) *TenantRateLimiter {
	l := &TenantRateLimiter{
		cfg:      cfg,
		resolver: resolver,
		logger:   logger,
		now:      time.Now,
		buckets:  make(map[uuid.UUID]*tenantBucket),
		stop:     make(chan struct{}),
		stopped:  make(chan struct{}),
	}
	go l.cleanupLoop()
	return l
}

// Close stops the cleanup goroutine. Idempotent.
func (l *TenantRateLimiter) Close() {
	select {
	case <-l.stop:
	default:
		close(l.stop)
		<-l.stopped
	}
}

// Middleware returns the HTTP middleware. When disabled, or when the
// request carries no resolved tenant (e.g. a platform-admin token with
// no tenant claim, or a public route), it is a pass-through — those
// requests are still covered by the outer per-IP limiter.
func (l *TenantRateLimiter) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !l.cfg.Enabled {
				next.ServeHTTP(w, r)
				return
			}
			tid := TenantIDFromContext(r.Context())
			if tid == uuid.Nil {
				next.ServeHTTP(w, r)
				return
			}
			d := l.consult(r.Context(), tid)
			h := w.Header()
			h.Set("X-RateLimit-Limit", strconv.Itoa(d.limit))
			h.Set("X-RateLimit-Remaining", strconv.Itoa(d.remaining))
			h.Set("X-RateLimit-Reset", strconv.FormatInt(d.resetEpoch, 10))
			if !d.allowed {
				h.Set("Retry-After", strconv.Itoa(d.retryAfter))
				h.Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusTooManyRequests)
				_, _ = w.Write([]byte(`{"error":{"code":"tenant_rate_limited","message":"tenant request rate limit exceeded"}}`))
				if l.logger != nil {
					l.logger.Warn("tenant rate limit exceeded",
						slog.String("tenant_id", tid.String()),
						slog.Int("limit_per_min", d.limit),
						slog.Int("retry_after_s", d.retryAfter),
						slog.String("method", r.Method),
						slog.String("path", r.URL.Path),
					)
				}
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// consult refills and consumes a token from the tenant's bucket,
// returning the decision plus the header values.
func (l *TenantRateLimiter) consult(ctx context.Context, tenantID uuid.UUID) rateDecision {
	now := l.now()
	tier := l.resolveTier(ctx, tenantID, now)
	capacity := float64(l.limitForTier(tier))

	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.buckets[tenantID]
	if !ok {
		b = &tenantBucket{
			tokens: capacity,
			last:   now,
			tier:   tier,
			tierAt: now,
		}
		l.buckets[tenantID] = b
	}
	// Refresh the tier (and thus the bucket geometry) at most once per
	// TierTTL so an upgrade/downgrade takes effect without a per-request
	// tenant lookup.
	if now.Sub(b.tierAt) >= l.cfg.TierTTL {
		b.tier = tier
		b.tierAt = now
	}
	b.capacity = float64(l.limitForTier(b.tier))
	// Refill rate: a full minute's budget spread evenly across 60s.
	b.refill = b.capacity / 60.0

	// Refill based on elapsed wall-clock time, then clamp to capacity.
	elapsed := now.Sub(b.last).Seconds()
	if elapsed > 0 {
		b.tokens = math.Min(b.capacity, b.tokens+elapsed*b.refill)
		b.last = now
	}
	b.lastSeen = now

	d := rateDecision{limit: int(b.capacity)}
	if b.tokens >= 1 {
		b.tokens--
		d.allowed = true
	}
	if b.tokens < 0 {
		b.tokens = 0
	}
	d.remaining = int(math.Floor(b.tokens))
	// Reset: seconds until the bucket is fully replenished.
	var secondsToFull float64
	if b.refill > 0 {
		secondsToFull = (b.capacity - b.tokens) / b.refill
	}
	d.resetEpoch = now.Add(time.Duration(secondsToFull * float64(time.Second))).Unix()
	if !d.allowed {
		// Seconds until at least one whole token is available.
		need := 1 - b.tokens
		secs := 1
		if b.refill > 0 {
			secs = int(math.Ceil(need / b.refill))
		}
		if secs < 1 {
			secs = 1
		}
		d.retryAfter = secs
	}
	return d
}

// resolveTier looks up the tenant's tier via the resolver, falling
// back to the standard tier when no resolver is configured or the
// lookup errors. The result is cached on the bucket (see consult), so
// this only performs work on bucket creation and at TierTTL refreshes;
// here it is consulted unconditionally but the bucket decides whether
// to adopt the value.
func (l *TenantRateLimiter) resolveTier(ctx context.Context, tenantID uuid.UUID, now time.Time) repository.TenantTier {
	if l.resolver == nil {
		return repository.TenantTierStarter
	}
	// Fast path: reuse the cached tier when it is still fresh, avoiding
	// a resolver call on every request.
	l.mu.Lock()
	if b, ok := l.buckets[tenantID]; ok && now.Sub(b.tierAt) < l.cfg.TierTTL {
		cached := b.tier
		l.mu.Unlock()
		return cached
	}
	l.mu.Unlock()

	// Deliberately call the resolver WITHOUT holding the mutex: it does a
	// DB round-trip, and holding the lock across it would serialize every
	// tenant's rate-limit check behind one tenant's lookup — a far worse
	// failure mode on a 5K-tenant fleet than the alternative. The cost is
	// that the first concurrent burst for a cold (or TTL-expired) tenant
	// may issue a few redundant lookups before one goroutine caches the
	// tier; since ResolveTier is a read-only, idempotent Get that is an
	// acceptable trade for low lock contention.
	tier, err := l.resolver.ResolveTier(ctx, tenantID)
	if err != nil {
		if l.logger != nil {
			l.logger.Warn("tenant tier resolve failed; using standard budget",
				slog.String("tenant_id", tenantID.String()),
				slog.String("error", err.Error()),
			)
		}
		return repository.TenantTierStarter
	}
	return tier
}

// limitForTier maps a tenant tier to its per-minute request budget.
// The starter tier is "standard"; professional and enterprise are
// "premium". An unrecognised tier falls back to the standard budget
// (fail-safe: never grant more than the lowest budget for an unknown
// tier).
func (l *TenantRateLimiter) limitForTier(tier repository.TenantTier) int {
	switch tier {
	case repository.TenantTierProfessional, repository.TenantTierEnterprise:
		return l.cfg.PremiumPerMinute
	default:
		return l.cfg.StandardPerMinute
	}
}

// cleanupLoop prunes idle tenant buckets.
func (l *TenantRateLimiter) cleanupLoop() {
	defer close(l.stopped)
	interval := l.cfg.CleanupInterval
	if interval <= 0 {
		interval = time.Minute
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-l.stop:
			return
		case <-t.C:
			l.evictIdle()
		}
	}
}

func (l *TenantRateLimiter) evictIdle() {
	ttl := l.cfg.IdleTTL
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	cutoff := l.now().Add(-ttl)
	l.mu.Lock()
	defer l.mu.Unlock()
	for k, b := range l.buckets {
		if b.lastSeen.Before(cutoff) {
			delete(l.buckets, k)
		}
	}
}
