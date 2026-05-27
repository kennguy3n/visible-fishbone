package middleware_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/config"
	"github.com/kennguy3n/visible-fishbone/internal/middleware"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

func TestRequestID_PreservesProvided(t *testing.T) {
	t.Parallel()
	provided := "00000000-0000-0000-0000-000000000abc"
	h := middleware.RequestID()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if id := middleware.RequestIDFromContext(r.Context()); id != provided {
			t.Errorf("context id = %q, want %q", id, provided)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(middleware.RequestIDHeader, provided)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if got := rec.Header().Get(middleware.RequestIDHeader); got != provided {
		t.Errorf("response header = %q", got)
	}
}

func TestRequestID_GeneratesWhenMissing(t *testing.T) {
	t.Parallel()
	h := middleware.RequestID()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if got := rec.Header().Get(middleware.RequestIDHeader); got == "" {
		t.Error("no request id generated")
	}
}

func TestRecovery_TurnsPanicInto500(t *testing.T) {
	t.Parallel()
	h := middleware.Recovery(discardLogger())(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		panic("boom")
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d", rec.Code)
	}
}

func TestLogging_RecordsStatus(t *testing.T) {
	t.Parallel()
	buf := &bytes.Buffer{}
	logger := slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	h := middleware.Logging(logger)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
		_, _ = w.Write([]byte("hi"))
	}))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/x", nil))
	if !bytes.Contains(buf.Bytes(), []byte("status=418")) {
		t.Errorf("log missing status: %s", buf.String())
	}
}

func TestCORS_AllowsConfiguredOrigin(t *testing.T) {
	t.Parallel()
	cfg := &config.CORS{AllowedOrigins: []string{"https://app.example"}, AllowedMethods: []string{"GET"}, AllowedHeaders: []string{"Authorization"}, MaxAge: 60 * time.Second}
	h := middleware.CORS(cfg)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Origin", "https://app.example")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "https://app.example" {
		t.Errorf("allow-origin = %q", got)
	}
}

func TestCORS_OptionsShortCircuits(t *testing.T) {
	t.Parallel()
	cfg := &config.CORS{AllowedOrigins: []string{"*"}, AllowedMethods: []string{"GET"}, AllowedHeaders: []string{"Authorization"}, MaxAge: time.Minute}
	called := false
	h := middleware.CORS(cfg)(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) { called = true }))
	req := httptest.NewRequest(http.MethodOptions, "/", nil)
	req.Header.Set("Origin", "https://anything.example")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if called {
		t.Error("downstream handler invoked on preflight")
	}
	if rec.Code != http.StatusNoContent {
		t.Errorf("status = %d", rec.Code)
	}
}

func TestCORS_DisallowsUnknownOrigin(t *testing.T) {
	t.Parallel()
	cfg := &config.CORS{AllowedOrigins: []string{"https://app.example"}}
	h := middleware.CORS(cfg)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Origin", "https://attacker.example")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("unexpected allow-origin = %q", got)
	}
}

func TestRateLimit_BurstThenDeny(t *testing.T) {
	t.Parallel()
	cfg := &config.RateLimit{
		Enabled: true, Rate: 1, Burst: 2,
		CleanupInterval: time.Hour, IdleTTL: time.Hour,
	}
	rl, err := middleware.NewRateLimiter(cfg)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	defer rl.Close()

	h := rl.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	for i := 0; i < 2; i++ {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("burst %d: status = %d", i, rec.Code)
		}
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("3rd call: status = %d, want 429", rec.Code)
	}
}

func TestRateLimit_TrustedProxyXFF(t *testing.T) {
	t.Parallel()
	cfg := &config.RateLimit{
		Enabled: true, Rate: 1, Burst: 1,
		CleanupInterval: time.Hour, IdleTTL: time.Hour,
		TrustedProxies: "10.0.0.0/8",
	}
	rl, err := middleware.NewRateLimiter(cfg)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	defer rl.Close()

	h := rl.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))

	for _, client := range []string{"1.2.3.4", "5.6.7.8"} {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "10.0.0.5:1234"
		req.Header.Set("X-Forwarded-For", client)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("client %s: status = %d", client, rec.Code)
		}
	}
}

type stubAPIKeys struct {
	info middleware.APIKeyInfo
	err  error
}

func (s stubAPIKeys) Lookup(_ context.Context, _ string) (middleware.APIKeyInfo, error) {
	return s.info, s.err
}

func TestAuth_APIKey(t *testing.T) {
	t.Parallel()
	tid := uuid.New()
	keys := stubAPIKeys{info: middleware.APIKeyInfo{ID: "k-1", TenantID: tid, Subject: "ci-bot"}}
	cfg := &config.Auth{APIKeyHeader: "X-SNG-API-Key"}
	h := middleware.Auth(cfg, keys)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if id := middleware.APIKeyIDFromContext(r.Context()); id != "k-1" {
			t.Errorf("api key id = %q", id)
		}
		if got := middleware.TenantIDFromContext(r.Context()); got != tid {
			t.Errorf("tenant id = %v", got)
		}
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-SNG-API-Key", "secret")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestAuth_APIKey_Invalid(t *testing.T) {
	t.Parallel()
	keys := stubAPIKeys{err: errors.New("no")}
	cfg := &config.Auth{APIKeyHeader: "X-SNG-API-Key"}
	h := middleware.Auth(cfg, keys)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("downstream invoked")
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-SNG-API-Key", "bogus")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d", rec.Code)
	}
}

func TestAuth_JWT(t *testing.T) {
	t.Parallel()
	secret := []byte("supersecret")
	uid := uuid.New()
	tid := uuid.New()
	claims := jwt.MapClaims{
		"iss":       "sng-control",
		"aud":       "sng-control",
		"sub":       uid.String(),
		"tenant_id": tid.String(),
		"exp":       time.Now().Add(time.Hour).Unix(),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := tok.SignedString(secret)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	cfg := &config.Auth{JWTSecret: string(secret), JWTIssuer: "sng-control", JWTAudience: "sng-control"}
	h := middleware.Auth(cfg, nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := middleware.UserIDFromContext(r.Context()); got != uid {
			t.Errorf("user_id = %v", got)
		}
		if got := middleware.TenantIDFromContext(r.Context()); got != tid {
			t.Errorf("tenant_id = %v", got)
		}
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+signed)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
}

func TestAuth_JWT_Invalid(t *testing.T) {
	t.Parallel()
	cfg := &config.Auth{JWTSecret: "secret", JWTIssuer: "iss", JWTAudience: "aud"}
	h := middleware.Auth(cfg, nil)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("downstream invoked")
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer not-a-jwt")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d", rec.Code)
	}
}

func TestAuth_MissingCredentials(t *testing.T) {
	t.Parallel()
	cfg := &config.Auth{JWTSecret: "x", APIKeyHeader: "X-SNG-API-Key"}
	h := middleware.Auth(cfg, nil)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("downstream invoked")
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d", rec.Code)
	}
}

func TestRequireTenant_Match(t *testing.T) {
	t.Parallel()
	tid := uuid.New()
	mux := http.NewServeMux()
	mux.Handle("GET /api/v1/tenants/{tenant_id}", middleware.RequireTenant("tenant_id")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := middleware.TenantIDFromContext(r.Context())
		_ = json.NewEncoder(w).Encode(map[string]string{"id": got.String()})
	})))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/"+tid.String(), nil)
	// Simulate the auth layer having bound the same tenant.
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
}

func TestRequireTenant_Mismatch(t *testing.T) {
	t.Parallel()
	pathTenant := uuid.New()
	authTenant := uuid.New()
	// Use the public Auth middleware (API-key path) to bind the
	// auth tenant — that's what RequireTenant compares against.
	keys := stubAPIKeys{info: middleware.APIKeyInfo{ID: "k", TenantID: authTenant}}
	cfg := &config.Auth{APIKeyHeader: "X-SNG-API-Key"}

	mux := http.NewServeMux()
	mux.Handle("GET /api/v1/tenants/{tenant_id}",
		middleware.Auth(cfg, keys)(
			middleware.RequireTenant("tenant_id")(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				t.Error("handler should not run on mismatch")
				w.WriteHeader(http.StatusOK)
			}))))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/"+pathTenant.String(), nil)
	req.Header.Set("X-SNG-API-Key", "secret")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
}
