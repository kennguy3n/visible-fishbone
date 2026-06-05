//go:build !production

package middleware_test

import (
	"bytes"
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

// The tests in this file mint HS256 (HMAC) operator JWTs and expect
// middleware.Auth to verify them. That verification path only exists
// in non-production builds (auth_hmac.go, //go:build !production); a
// production build links the refusing stub in auth_hmac_prod.go, so
// these tests must not compile under -tags production. The build-tag
// independent middleware behaviour (API-key auth, CORS, rate limiting,
// recovery, request-id, logging, tenant matching) stays in
// middleware_test.go so it keeps running in both build flavours.

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

func TestLogging_CapturesUserIDFromJWT(t *testing.T) {
	t.Parallel()
	buf := &bytes.Buffer{}
	logger := slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelInfo}))

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
	h := middleware.Logging(logger)(
		middleware.Auth(cfg, nil)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})))

	req := httptest.NewRequest(http.MethodGet, "/secure", nil)
	req.Header.Set("Authorization", "Bearer "+signed)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	if !bytes.Contains(buf.Bytes(), []byte("user_id="+uid.String())) {
		t.Errorf("log missing user_id %s, got: %s", uid, buf.String())
	}
	if !bytes.Contains(buf.Bytes(), []byte("tenant_id="+tid.String())) {
		t.Errorf("log missing tenant_id %s, got: %s", tid, buf.String())
	}
}
