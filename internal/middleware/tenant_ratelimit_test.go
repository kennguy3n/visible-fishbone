package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/config"
	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// fakeTierResolver is a static, call-counting TenantTierResolver.
type fakeTierResolver struct {
	tier  repository.TenantTier
	err   error
	calls int
}

func (f *fakeTierResolver) ResolveTier(_ context.Context, _ uuid.UUID) (repository.TenantTier, error) {
	f.calls++
	return f.tier, f.err
}

func testTenantRLConfig() config.TenantRateLimit {
	return config.TenantRateLimit{
		Enabled:           true,
		StandardPerMinute: 100,
		PremiumPerMinute:  500,
		TierTTL:           time.Minute,
		CleanupInterval:   time.Hour, // disable background churn in tests
		IdleTTL:           10 * time.Minute,
	}
}

// newTestClock returns a controllable clock and a setter advancing it.
func newTestClock(start time.Time) (func() time.Time, func(time.Duration)) {
	cur := start
	return func() time.Time { return cur }, func(d time.Duration) { cur = cur.Add(d) }
}

func tenantReq(tid uuid.UUID) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/things", nil)
	return req.WithContext(WithTenantIDForTest(req.Context(), tid))
}

func TestTenantRateLimiter_BurstThenDeny(t *testing.T) {
	t.Parallel()
	cfg := testTenantRLConfig()
	cfg.StandardPerMinute = 3
	clock, _ := newTestClock(time.Unix(1_700_000_000, 0))

	l := NewTenantRateLimiter(cfg, &fakeTierResolver{tier: repository.TenantTierStarter}, nil)
	l.now = clock
	defer l.Close()

	tid := uuid.New()
	h := l.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Capacity = 3: three immediate requests pass, the fourth is shed.
	for i := 0; i < 3; i++ {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, tenantReq(tid))
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d: status = %d, want 200", i+1, rec.Code)
		}
		if got := rec.Header().Get("X-RateLimit-Limit"); got != "3" {
			t.Errorf("request %d: X-RateLimit-Limit = %q, want 3", i+1, got)
		}
		wantRemaining := strconv.Itoa(2 - i)
		if got := rec.Header().Get("X-RateLimit-Remaining"); got != wantRemaining {
			t.Errorf("request %d: X-RateLimit-Remaining = %q, want %q", i+1, got, wantRemaining)
		}
	}

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, tenantReq(tid))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("4th request: status = %d, want 429", rec.Code)
	}
	if got := rec.Header().Get("Retry-After"); got == "" {
		t.Error("4th request: missing Retry-After header")
	}
	if got := rec.Header().Get("X-RateLimit-Remaining"); got != "0" {
		t.Errorf("4th request: X-RateLimit-Remaining = %q, want 0", got)
	}
}

func TestTenantRateLimiter_RefillsOverTime(t *testing.T) {
	t.Parallel()
	cfg := testTenantRLConfig()
	cfg.StandardPerMinute = 60 // 1 token/sec refill
	clock, advance := newTestClock(time.Unix(1_700_000_000, 0))

	l := NewTenantRateLimiter(cfg, &fakeTierResolver{tier: repository.TenantTierStarter}, nil)
	l.now = clock
	defer l.Close()

	tid := uuid.New()
	h := l.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Drain the full 60-token bucket.
	for i := 0; i < 60; i++ {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, tenantReq(tid))
		if rec.Code != http.StatusOK {
			t.Fatalf("drain %d: status = %d", i, rec.Code)
		}
	}
	// Empty now → denied.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, tenantReq(tid))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("post-drain: status = %d, want 429", rec.Code)
	}
	// After 2s, refill restores 2 tokens (1/sec).
	advance(2 * time.Second)
	for i := 0; i < 2; i++ {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, tenantReq(tid))
		if rec.Code != http.StatusOK {
			t.Fatalf("refilled %d: status = %d, want 200", i, rec.Code)
		}
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, tenantReq(tid))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("after refilled budget: status = %d, want 429", rec.Code)
	}
}

func TestTenantRateLimiter_PremiumTierHigherBudget(t *testing.T) {
	t.Parallel()
	cfg := testTenantRLConfig()
	cfg.StandardPerMinute = 2
	cfg.PremiumPerMinute = 5
	clock, _ := newTestClock(time.Unix(1_700_000_000, 0))

	l := NewTenantRateLimiter(cfg, &fakeTierResolver{tier: repository.TenantTierEnterprise}, nil)
	l.now = clock
	defer l.Close()

	tid := uuid.New()
	h := l.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Enterprise → premium budget of 5.
	for i := 0; i < 5; i++ {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, tenantReq(tid))
		if rec.Code != http.StatusOK {
			t.Fatalf("premium request %d: status = %d", i+1, rec.Code)
		}
		if got := rec.Header().Get("X-RateLimit-Limit"); got != "5" {
			t.Errorf("X-RateLimit-Limit = %q, want 5", got)
		}
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, tenantReq(tid))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("6th premium request: status = %d, want 429", rec.Code)
	}
}

func TestTenantRateLimiter_PerTenantIsolation(t *testing.T) {
	t.Parallel()
	cfg := testTenantRLConfig()
	cfg.StandardPerMinute = 1
	clock, _ := newTestClock(time.Unix(1_700_000_000, 0))

	l := NewTenantRateLimiter(cfg, &fakeTierResolver{tier: repository.TenantTierStarter}, nil)
	l.now = clock
	defer l.Close()

	h := l.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	a, b := uuid.New(), uuid.New()
	// Exhaust tenant A.
	recA := httptest.NewRecorder()
	h.ServeHTTP(recA, tenantReq(a))
	recA = httptest.NewRecorder()
	h.ServeHTTP(recA, tenantReq(a))
	if recA.Code != http.StatusTooManyRequests {
		t.Fatalf("tenant A 2nd: status = %d, want 429", recA.Code)
	}
	// Tenant B is unaffected by A's exhaustion.
	recB := httptest.NewRecorder()
	h.ServeHTTP(recB, tenantReq(b))
	if recB.Code != http.StatusOK {
		t.Fatalf("tenant B 1st: status = %d, want 200 (isolation broken)", recB.Code)
	}
}

func TestTenantRateLimiter_DisabledIsPassThrough(t *testing.T) {
	t.Parallel()
	cfg := testTenantRLConfig()
	cfg.Enabled = false
	cfg.StandardPerMinute = 1

	l := NewTenantRateLimiter(cfg, &fakeTierResolver{tier: repository.TenantTierStarter}, nil)
	defer l.Close()

	tid := uuid.New()
	h := l.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	for i := 0; i < 10; i++ {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, tenantReq(tid))
		if rec.Code != http.StatusOK {
			t.Fatalf("disabled request %d: status = %d, want 200", i, rec.Code)
		}
		if rec.Header().Get("X-RateLimit-Limit") != "" {
			t.Error("disabled limiter should not set rate-limit headers")
		}
	}
}

func TestTenantRateLimiter_NoTenantIsPassThrough(t *testing.T) {
	t.Parallel()
	cfg := testTenantRLConfig()
	cfg.StandardPerMinute = 1

	l := NewTenantRateLimiter(cfg, &fakeTierResolver{tier: repository.TenantTierStarter}, nil)
	defer l.Close()

	h := l.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	// No tenant in context (e.g. platform-admin token) → never limited.
	for i := 0; i < 5; i++ {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/things", nil)
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("no-tenant request %d: status = %d, want 200", i, rec.Code)
		}
	}
}

func TestTenantRateLimiter_TierCachedWithinTTL(t *testing.T) {
	t.Parallel()
	cfg := testTenantRLConfig()
	cfg.StandardPerMinute = 100
	cfg.TierTTL = time.Minute
	clock, advance := newTestClock(time.Unix(1_700_000_000, 0))

	resolver := &fakeTierResolver{tier: repository.TenantTierStarter}
	l := NewTenantRateLimiter(cfg, resolver, nil)
	l.now = clock
	defer l.Close()

	tid := uuid.New()
	h := l.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	for i := 0; i < 5; i++ {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, tenantReq(tid))
	}
	if resolver.calls != 1 {
		t.Fatalf("resolver called %d times within TTL, want 1 (tier not cached)", resolver.calls)
	}
	// Past the TTL the tier is re-resolved.
	advance(2 * time.Minute)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, tenantReq(tid))
	if resolver.calls != 2 {
		t.Fatalf("resolver called %d times after TTL, want 2 (tier not refreshed)", resolver.calls)
	}
}

func TestTenantRateLimiter_ResolverErrorFallsBackToStandard(t *testing.T) {
	t.Parallel()
	cfg := testTenantRLConfig()
	cfg.StandardPerMinute = 2
	cfg.PremiumPerMinute = 500
	clock, _ := newTestClock(time.Unix(1_700_000_000, 0))

	// Resolver always errors → limiter must use the standard budget.
	l := NewTenantRateLimiter(cfg, &fakeTierResolver{err: context.DeadlineExceeded}, nil)
	l.now = clock
	defer l.Close()

	tid := uuid.New()
	h := l.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	for i := 0; i < 2; i++ {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, tenantReq(tid))
		if rec.Code != http.StatusOK {
			t.Fatalf("fallback request %d: status = %d", i+1, rec.Code)
		}
		if got := rec.Header().Get("X-RateLimit-Limit"); got != "2" {
			t.Errorf("X-RateLimit-Limit = %q, want 2 (standard fallback)", got)
		}
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, tenantReq(tid))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("3rd request: status = %d, want 429", rec.Code)
	}
}

func TestTenantRateLimiter_EvictIdle(t *testing.T) {
	t.Parallel()
	cfg := testTenantRLConfig()
	cfg.IdleTTL = time.Minute
	clock, advance := newTestClock(time.Unix(1_700_000_000, 0))

	l := NewTenantRateLimiter(cfg, &fakeTierResolver{tier: repository.TenantTierStarter}, nil)
	l.now = clock
	defer l.Close()

	tid := uuid.New()
	h := l.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, tenantReq(tid))

	l.mu.Lock()
	n := len(l.buckets)
	l.mu.Unlock()
	if n != 1 {
		t.Fatalf("bucket count = %d, want 1", n)
	}

	advance(2 * time.Minute)
	l.evictIdle()

	l.mu.Lock()
	n = len(l.buckets)
	l.mu.Unlock()
	if n != 0 {
		t.Fatalf("bucket count after evict = %d, want 0", n)
	}
}
