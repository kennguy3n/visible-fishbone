package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestLivenessOK(t *testing.T) {
	h := NewHealth(0)
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	h.Liveness(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type = %q", ct)
	}
	var body livenessResponse
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Status != "ok" {
		t.Errorf("status = %q, want ok", body.Status)
	}
	if body.Uptime == "" {
		t.Error("uptime should not be empty")
	}
}

func TestLivenessMethodNotAllowed(t *testing.T) {
	h := NewHealth(0)
	req := httptest.NewRequest(http.MethodPost, "/healthz", nil)
	rec := httptest.NewRecorder()
	h.Liveness(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rec.Code)
	}
	if allow := rec.Header().Get("Allow"); allow == "" {
		t.Error("Allow header missing")
	}
}

func TestReadinessAllOK(t *testing.T) {
	h := NewHealth(100 * time.Millisecond)
	h.Register("postgres", PingerFunc(func(ctx context.Context) error { return nil }))
	h.Register("nats", PingerFunc(func(ctx context.Context) error { return nil }))

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()
	h.Readiness(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var body readinessResponse
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Status != "ready" {
		t.Errorf("status = %q", body.Status)
	}
	if len(body.Checks) != 2 {
		t.Errorf("checks = %d, want 2", len(body.Checks))
	}
	for name, r := range body.Checks {
		if r.Status != "ok" {
			t.Errorf("%s status = %q", name, r.Status)
		}
	}
}

func TestReadinessOneDown(t *testing.T) {
	h := NewHealth(100 * time.Millisecond)
	h.Register("postgres", PingerFunc(func(ctx context.Context) error { return nil }))
	h.Register("nats", PingerFunc(func(ctx context.Context) error { return errors.New("connection refused") }))

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()
	h.Readiness(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
	var body readinessResponse
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Status != "not_ready" {
		t.Errorf("status = %q", body.Status)
	}
	if body.Checks["nats"].Status != "error" {
		t.Errorf("nats status = %q", body.Checks["nats"].Status)
	}
	if body.Checks["nats"].Error == "" {
		t.Error("nats error should be populated")
	}
}

func TestReadinessTimeout(t *testing.T) {
	h := NewHealth(20 * time.Millisecond)
	h.Register("slow", PingerFunc(func(ctx context.Context) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
			return nil
		}
	}))

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()
	h.Readiness(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}

func TestReadinessNoDeps(t *testing.T) {
	// No registered dependencies => trivially ready.
	h := NewHealth(0)
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()
	h.Readiness(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

func TestRegisterIgnoresInvalid(t *testing.T) {
	h := NewHealth(0)
	h.Register("", PingerFunc(func(ctx context.Context) error { return nil }))
	h.Register("nilpinger", nil)
	if _, err := h.Dependency(""); err == nil {
		t.Error("empty name should not register")
	}
	if _, err := h.Dependency("nilpinger"); err == nil {
		t.Error("nil pinger should not register")
	}
}

func TestRegisterReplaces(t *testing.T) {
	h := NewHealth(0)
	h.Register("dep", PingerFunc(func(ctx context.Context) error { return errors.New("first") }))
	h.Register("dep", PingerFunc(func(ctx context.Context) error { return nil }))
	p, err := h.Dependency("dep")
	if err != nil {
		t.Fatalf("Dependency: %v", err)
	}
	if perr := p.Ping(context.Background()); perr != nil {
		t.Errorf("expected replaced pinger to succeed, got %v", perr)
	}
}

func TestDependencyUnregistered(t *testing.T) {
	h := NewHealth(0)
	if _, err := h.Dependency("missing"); !errors.Is(err, ErrUnregistered) {
		t.Errorf("expected ErrUnregistered, got %v", err)
	}
}

func TestReadinessHEAD(t *testing.T) {
	h := NewHealth(0)
	req := httptest.NewRequest(http.MethodHead, "/readyz", nil)
	rec := httptest.NewRecorder()
	h.Readiness(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("HEAD status = %d, want 200", rec.Code)
	}
}
