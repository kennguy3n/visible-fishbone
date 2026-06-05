//go:build !production

// Every test in this file mints an HS256 (HMAC) mobile session JWT and
// drives it through middleware.Auth, exercising the device-revocation
// re-check that only runs once a Bearer token has been verified. That
// verification path is compiled out of production builds (the stub in
// auth_hmac_prod.go refuses every Bearer token), so these tests are
// constrained to non-production builds to match the code they cover.
package middleware_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/config"
	"github.com/kennguy3n/visible-fishbone/internal/middleware"
)

// fakeDeviceStatus is a programmable middleware.MobileDeviceStatusResolver
// that records how it was called.
type fakeDeviceStatus struct {
	err       error
	calls     int
	gotTenant uuid.UUID
	gotKey    string
}

func (f *fakeDeviceStatus) MobileSessionAllowed(_ context.Context, tenantID uuid.UUID, deviceKey string) error {
	f.calls++
	f.gotTenant = tenantID
	f.gotKey = deviceKey
	return f.err
}

// mintSessionJWT signs an HS256 token with the standard claims plus the
// optional device-bound mobile claims, mirroring OIDCService.mintSession.
func mintSessionJWT(t *testing.T, secret []byte, tenantID uuid.UUID, tokenType, deviceKey string) string {
	t.Helper()
	claims := jwt.MapClaims{
		"iss":       "sng-control",
		"aud":       "sng-control",
		"sub":       uuid.New().String(),
		"tenant_id": tenantID.String(),
		"exp":       time.Now().Add(time.Hour).Unix(),
	}
	if tokenType != "" {
		claims["token_type"] = tokenType
	}
	if deviceKey != "" {
		claims["device_key"] = deviceKey
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := tok.SignedString(secret)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return signed
}

func authCfg(secret string) *config.Auth {
	return &config.Auth{JWTSecret: secret, JWTIssuer: "sng-control", JWTAudience: "sng-control"}
}

// TestAuth_MobileDeviceRevoked_Returns403 verifies that a mobile
// session JWT bound to a revoked device is refused with 403 across the
// auth middleware, regardless of which endpoint it targets.
func TestAuth_MobileDeviceRevoked_Returns403(t *testing.T) {
	t.Parallel()
	secret := []byte("supersecret")
	tid := uuid.New()
	const key = "ZGV2aWNlLWtleQ=="
	signed := mintSessionJWT(t, secret, tid, "mobile", key)

	resolver := &fakeDeviceStatus{err: middleware.ErrMobileDeviceRevoked}
	handlerRan := false
	h := middleware.Auth(authCfg(string(secret)), nil, middleware.WithMobileDeviceStatus(resolver))(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			handlerRan = true
			w.WriteHeader(http.StatusOK)
		}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/"+tid.String()+"/devices", nil)
	req.Header.Set("Authorization", "Bearer "+signed)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if handlerRan {
		t.Error("handler ran despite revoked device")
	}
	if resolver.calls != 1 {
		t.Errorf("resolver calls = %d, want 1", resolver.calls)
	}
	if resolver.gotTenant != tid || resolver.gotKey != key {
		t.Errorf("resolver got (%s, %q), want (%s, %q)", resolver.gotTenant, resolver.gotKey, tid, key)
	}
	var body struct {
		Error struct{ Code string } `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body.Error.Code != "device_revoked" {
		t.Errorf("error code = %q, want device_revoked", body.Error.Code)
	}
}

// TestAuth_MobileDeviceActive_PassesThrough verifies an active device's
// session proceeds and the resolver is consulted with the token's
// tenant + device key.
func TestAuth_MobileDeviceActive_PassesThrough(t *testing.T) {
	t.Parallel()
	secret := []byte("supersecret")
	tid := uuid.New()
	const key = "YWN0aXZlLWtleQ=="
	signed := mintSessionJWT(t, secret, tid, "mobile", key)

	resolver := &fakeDeviceStatus{err: nil}
	handlerRan := false
	h := middleware.Auth(authCfg(string(secret)), nil, middleware.WithMobileDeviceStatus(resolver))(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			handlerRan = true
			w.WriteHeader(http.StatusOK)
		}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/x", nil)
	req.Header.Set("Authorization", "Bearer "+signed)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if !handlerRan {
		t.Error("handler did not run for active device")
	}
	if resolver.calls != 1 {
		t.Errorf("resolver calls = %d, want 1", resolver.calls)
	}
}

// TestAuth_MobileDeviceStatus_FailsOpenOnInfraError verifies that a
// non-revocation (infrastructure) error from the resolver does NOT
// block the request: the token is already cryptographically valid and
// the sensitive self-service endpoints re-check at the service layer.
func TestAuth_MobileDeviceStatus_FailsOpenOnInfraError(t *testing.T) {
	t.Parallel()
	secret := []byte("supersecret")
	tid := uuid.New()
	signed := mintSessionJWT(t, secret, tid, "mobile", "a2V5")

	resolver := &fakeDeviceStatus{err: errors.New("db unavailable")}
	handlerRan := false
	h := middleware.Auth(authCfg(string(secret)), nil, middleware.WithMobileDeviceStatus(resolver))(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			handlerRan = true
			w.WriteHeader(http.StatusOK)
		}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/x", nil)
	req.Header.Set("Authorization", "Bearer "+signed)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("fail-open expected 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	if !handlerRan {
		t.Error("handler did not run on fail-open path")
	}
	if resolver.calls != 1 {
		t.Errorf("resolver calls = %d, want 1", resolver.calls)
	}
}

// TestAuth_NonMobileToken_SkipsRevocationCheck verifies the resolver is
// NOT consulted for operator-console tokens (no mobile claims), so the
// per-request device lookup only burdens mobile sessions.
func TestAuth_NonMobileToken_SkipsRevocationCheck(t *testing.T) {
	t.Parallel()
	secret := []byte("supersecret")
	tid := uuid.New()
	// Operator token: no token_type / device_key claims.
	signed := mintSessionJWT(t, secret, tid, "", "")

	resolver := &fakeDeviceStatus{err: middleware.ErrMobileDeviceRevoked}
	h := middleware.Auth(authCfg(string(secret)), nil, middleware.WithMobileDeviceStatus(resolver))(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/x", nil)
	req.Header.Set("Authorization", "Bearer "+signed)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if resolver.calls != 0 {
		t.Errorf("resolver consulted for non-mobile token (calls=%d)", resolver.calls)
	}
}

// TestAuth_NonMobileTokenType_WithDeviceKey_SkipsCheck verifies the
// IsMobile() gate: a token that carries a device_key but whose
// token_type is not "mobile" must not trigger the revocation lookup.
func TestAuth_NonMobileTokenType_WithDeviceKey_SkipsCheck(t *testing.T) {
	t.Parallel()
	secret := []byte("supersecret")
	tid := uuid.New()
	signed := mintSessionJWT(t, secret, tid, "operator", "c29tZS1rZXk=")

	resolver := &fakeDeviceStatus{err: middleware.ErrMobileDeviceRevoked}
	h := middleware.Auth(authCfg(string(secret)), nil, middleware.WithMobileDeviceStatus(resolver))(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/x", nil)
	req.Header.Set("Authorization", "Bearer "+signed)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if resolver.calls != 0 {
		t.Errorf("resolver consulted for non-mobile token_type (calls=%d)", resolver.calls)
	}
}

// TestAuth_NoResolver_MobileTokenPasses verifies backward compatibility:
// when no resolver option is supplied, a mobile token is accepted with
// no device lookup (previous behaviour).
func TestAuth_NoResolver_MobileTokenPasses(t *testing.T) {
	t.Parallel()
	secret := []byte("supersecret")
	tid := uuid.New()
	signed := mintSessionJWT(t, secret, tid, "mobile", "a2V5")

	handlerRan := false
	h := middleware.Auth(authCfg(string(secret)), nil)(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			handlerRan = true
			w.WriteHeader(http.StatusOK)
		}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/x", nil)
	req.Header.Set("Authorization", "Bearer "+signed)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK || !handlerRan {
		t.Fatalf("status = %d, ran = %v", rec.Code, handlerRan)
	}
}
