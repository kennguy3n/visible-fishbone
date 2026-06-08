package middleware_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/config"
	"github.com/kennguy3n/visible-fishbone/internal/middleware"
)

// authWithGuard builds the Auth middleware fronted by an AttemptLimiter
// with the given threshold/cooldown, returning the handler and guard.
func authWithGuard(t *testing.T, keys middleware.APIKeyLookup, maxFailures int, cooldown time.Duration) (http.Handler, *middleware.AttemptLimiter) {
	t.Helper()
	guard, err := middleware.NewAttemptLimiter(middleware.AttemptLimiterConfig{
		MaxFailures:     maxFailures,
		Cooldown:        cooldown,
		CleanupInterval: time.Hour,
		IdleTTL:         10 * time.Minute,
	})
	if err != nil {
		t.Fatalf("NewAttemptLimiter: %v", err)
	}
	cfg := &config.Auth{APIKeyHeader: "X-SNG-API-Key"}
	h := middleware.Auth(cfg, keys, middleware.WithBruteForceGuard(guard, discardLogger()))(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }),
	)
	return h, guard
}

func TestAuthBruteForce_LocksOutAfterFailedAPIKeys(t *testing.T) {
	t.Parallel()
	keys := stubAPIKeys{err: middleware.ErrAPIKeyNotFound}
	h, guard := authWithGuard(t, keys, 5, 30*time.Second)
	defer guard.Close()

	send := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/things", nil)
		req.RemoteAddr = "203.0.113.50:1111"
		req.Header.Set("X-SNG-API-Key", "wrong-key")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	// Five invalid keys are each rejected with 401 (unauthorized), not
	// yet locked out.
	for i := 0; i < 5; i++ {
		rec := send()
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: status = %d, want 401", i+1, rec.Code)
		}
	}
	// The 6th request from the same IP is now in cooldown → 429 with
	// Retry-After, regardless of the (still invalid) credential.
	rec := send()
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("post-threshold: status = %d, want 429", rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Error("429 response missing Retry-After header")
	}
}

func TestAuthBruteForce_OtherIPUnaffected(t *testing.T) {
	t.Parallel()
	keys := stubAPIKeys{err: middleware.ErrAPIKeyNotFound}
	h, guard := authWithGuard(t, keys, 3, 30*time.Second)
	defer guard.Close()

	attacker := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/things", nil)
		req.RemoteAddr = "203.0.113.60:2222"
		req.Header.Set("X-SNG-API-Key", "wrong-key")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	for i := 0; i < 3; i++ {
		attacker()
	}
	if rec := attacker(); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("attacker not locked out: status = %d", rec.Code)
	}

	// A different IP presenting the same bad key still gets a normal
	// 401 — the lockout is per-IP, not global.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/things", nil)
	req.RemoteAddr = "203.0.113.61:3333"
	req.Header.Set("X-SNG-API-Key", "wrong-key")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unrelated IP: status = %d, want 401 (lockout leaked across IPs)", rec.Code)
	}
}

func TestAuthBruteForce_SuccessResetsCounter(t *testing.T) {
	t.Parallel()
	tid := uuid.New()
	// A lookup that fails for "wrong-key" and succeeds for "good-key".
	keys := toggleAPIKeys{good: "good-key", info: middleware.APIKeyInfo{ID: "k-1", TenantID: tid, Subject: "bot"}}
	h, guard := authWithGuard(t, keys, 5, 30*time.Second)
	defer guard.Close()

	const ip = "203.0.113.70:4444"
	bad := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/things", nil)
		req.RemoteAddr = ip
		req.Header.Set("X-SNG-API-Key", "wrong-key")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	good := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/things", nil)
		req.RemoteAddr = ip
		req.Header.Set("X-SNG-API-Key", "good-key")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	// Four failures (under threshold), then a success resets the count.
	for i := 0; i < 4; i++ {
		bad()
	}
	if rec := good(); rec.Code != http.StatusOK {
		t.Fatalf("valid key: status = %d, want 200", rec.Code)
	}
	// Four more failures must NOT lock out — the counter restarted.
	for i := 0; i < 4; i++ {
		if rec := bad(); rec.Code != http.StatusUnauthorized {
			t.Fatalf("post-reset failure %d: status = %d, want 401", i+1, rec.Code)
		}
	}
}

// toggleAPIKeys resolves only the configured good key; everything else
// is ErrAPIKeyNotFound.
type toggleAPIKeys struct {
	good string
	info middleware.APIKeyInfo
}

func (s toggleAPIKeys) Lookup(_ context.Context, key string) (middleware.APIKeyInfo, error) {
	if key == s.good {
		return s.info, nil
	}
	return middleware.APIKeyInfo{}, middleware.ErrAPIKeyNotFound
}
