package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestMintTokenClaims(t *testing.T) {
	t.Parallel()
	cfg := &APILatencyConfig{JWTSecret: "secret", JWTIssuer: "sng-control", JWTAudience: "sng-control"}
	signed, err := mintToken(cfg, "tenant-123")
	if err != nil {
		t.Fatalf("mintToken: %v", err)
	}
	tok, err := jwt.Parse(signed, func(_ *jwt.Token) (any, error) { return []byte("secret"), nil })
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	claims, ok := tok.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatalf("claims type %T", tok.Claims)
	}
	if claims["iss"] != "sng-control" || claims["aud"] != "sng-control" {
		t.Fatalf("iss/aud not set: %v", claims)
	}
	if claims["tenant_id"] != "tenant-123" {
		t.Fatalf("tenant_id claim = %v, want tenant-123", claims["tenant_id"])
	}
}

func TestMintTokenOmitsEmptyClaims(t *testing.T) {
	t.Parallel()
	cfg := &APILatencyConfig{JWTSecret: "secret"}
	signed, err := mintToken(cfg, "")
	if err != nil {
		t.Fatalf("mintToken: %v", err)
	}
	tok, _ := jwt.Parse(signed, func(_ *jwt.Token) (any, error) { return []byte("secret"), nil })
	claims := tok.Claims.(jwt.MapClaims)
	if _, ok := claims["iss"]; ok {
		t.Error("iss should be omitted when issuer is empty")
	}
	if _, ok := claims["tenant_id"]; ok {
		t.Error("tenant_id should be omitted for a platform-operator token")
	}
}

func TestBuildWorkloadOpsMix(t *testing.T) {
	t.Parallel()
	ops := buildWorkloadOps()
	if len(ops) != 100 {
		t.Fatalf("expected 100 weighted ops, got %d", len(ops))
	}
	var reads, writes, heavy int
	for _, op := range ops {
		switch {
		case op.method == http.MethodGet:
			reads++
		case strings.Contains(op.key, "policy/compile"), strings.Contains(op.key, "simulations"):
			heavy++
		default:
			writes++
		}
	}
	if reads != 60 || writes != 30 || heavy != 10 {
		t.Fatalf("mix = reads:%d writes:%d heavy:%d, want 60/30/10", reads, writes, heavy)
	}
}

func TestIsError(t *testing.T) {
	t.Parallel()
	for status, want := range map[int]bool{200: false, 201: false, 299: false, 300: true, 404: true, 500: true, 0: true} {
		if got := isError(status); got != want {
			t.Errorf("isError(%d) = %v, want %v", status, got, want)
		}
	}
}

func TestAPIKeyAuthHeader(t *testing.T) {
	t.Parallel()
	cfg := &APILatencyConfig{APIKey: "k-123", APIKeyHeader: "X-SNG-API-Key"}
	c := newAPIClient(cfg)
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://x/", nil)
	if err := c.authHeader(req, "t1"); err != nil {
		t.Fatalf("authHeader: %v", err)
	}
	if req.Header.Get("X-SNG-API-Key") != "k-123" {
		t.Fatalf("api key header not set: %q", req.Header.Get("X-SNG-API-Key"))
	}
}

func TestAuthHeaderErrorsWithoutCredential(t *testing.T) {
	t.Parallel()
	c := newAPIClient(&APILatencyConfig{})
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://x/", nil)
	if err := c.authHeader(req, "t1"); err == nil {
		t.Fatal("expected error when neither JWT secret nor API key is set")
	}
}

// fakeControlPlane is a minimal stand-in implementing only the routes
// the seeder and workload touch, so the workload driver can be tested
// end-to-end (auth, request shapes, recording) without the full server.
type fakeControlPlane struct {
	mu        sync.Mutex
	tenantSeq int
	siteSeq   int
	hits      map[string]int
}

func newFakeControlPlane() *fakeControlPlane {
	return &fakeControlPlane{hits: map[string]int{}}
}

func (f *fakeControlPlane) handler(t *testing.T) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/tenants", func(w http.ResponseWriter, r *http.Request) {
		f.requireAuth(t, w, r)
		f.mu.Lock()
		f.tenantSeq++
		id := "tenant-" + itoa(f.tenantSeq)
		f.mu.Unlock()
		writeJSON(w, http.StatusCreated, map[string]string{"id": id})
	})
	mux.HandleFunc("POST /api/v1/tenants/{id}/sites", func(w http.ResponseWriter, r *http.Request) {
		f.requireAuth(t, w, r)
		f.count("sites")
		f.mu.Lock()
		f.siteSeq++
		id := "site-" + itoa(f.siteSeq)
		f.mu.Unlock()
		writeJSON(w, http.StatusCreated, map[string]string{"id": id})
	})
	mux.HandleFunc("PUT /api/v1/tenants/{id}/policy", func(w http.ResponseWriter, r *http.Request) {
		f.requireAuth(t, w, r)
		f.count("policy-put")
		w.WriteHeader(http.StatusCreated)
	})
	mux.HandleFunc("GET /api/v1/tenants/{id}", func(w http.ResponseWriter, r *http.Request) {
		f.requireAuth(t, w, r)
		f.count("get-tenant")
		writeJSON(w, http.StatusOK, map[string]string{"id": r.PathValue("id")})
	})
	mux.HandleFunc("GET /api/v1/tenants/{id}/sites", func(w http.ResponseWriter, r *http.Request) {
		f.requireAuth(t, w, r)
		writeJSON(w, http.StatusOK, []any{})
	})
	mux.HandleFunc("GET /api/v1/tenants/{id}/devices", func(w http.ResponseWriter, r *http.Request) {
		f.requireAuth(t, w, r)
		writeJSON(w, http.StatusOK, []any{})
	})
	mux.HandleFunc("GET /api/v1/tenants/{id}/policy", func(w http.ResponseWriter, r *http.Request) {
		f.requireAuth(t, w, r)
		writeJSON(w, http.StatusOK, map[string]any{"rules": []any{}})
	})
	mux.HandleFunc("PATCH /api/v1/tenants/{id}", func(w http.ResponseWriter, r *http.Request) {
		f.requireAuth(t, w, r)
		writeJSON(w, http.StatusOK, map[string]string{"id": r.PathValue("id")})
	})
	mux.HandleFunc("POST /api/v1/tenants/{id}/claim-tokens", func(w http.ResponseWriter, r *http.Request) {
		f.requireAuth(t, w, r)
		writeJSON(w, http.StatusCreated, map[string]string{"token": "claim-xyz"})
	})
	mux.HandleFunc("POST /api/v1/tenants/{id}/policy/compile", func(w http.ResponseWriter, r *http.Request) {
		f.requireAuth(t, w, r)
		f.count("compile")
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	})
	mux.HandleFunc("POST /api/v1/tenants/{id}/policy/simulations", func(w http.ResponseWriter, r *http.Request) {
		f.requireAuth(t, w, r)
		f.count("simulate")
		writeJSON(w, http.StatusOK, map[string]any{"changed": 0})
	})
	return mux
}

func (f *fakeControlPlane) requireAuth(t *testing.T, w http.ResponseWriter, r *http.Request) {
	t.Helper()
	if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
		w.WriteHeader(http.StatusUnauthorized)
		t.Errorf("%s %s missing bearer token", r.Method, r.URL.Path)
	}
}

func (f *fakeControlPlane) count(key string) {
	f.mu.Lock()
	f.hits[key]++
	f.mu.Unlock()
}

func writeJSON(w http.ResponseWriter, code int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(body)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

func TestSeedTenantsHitsExpectedRoutes(t *testing.T) {
	t.Parallel()
	fake := newFakeControlPlane()
	srv := httptest.NewServer(fake.handler(t))
	defer srv.Close()

	cfg := &APILatencyConfig{BaseURL: srv.URL, JWTSecret: "s"}
	c := newAPIClient(cfg)
	tenants, err := c.seedTenants(context.Background(), 4)
	if err != nil {
		t.Fatalf("seedTenants: %v", err)
	}
	if len(tenants) != 4 {
		t.Fatalf("seeded %d tenants, want 4", len(tenants))
	}
	for _, tn := range tenants {
		if len(tn.SiteIDs) != 3 {
			t.Fatalf("tenant %s has %d sites, want 3", tn.ID, len(tn.SiteIDs))
		}
	}
	if fake.hits["sites"] != 12 {
		t.Fatalf("expected 12 site creates (4x3), got %d", fake.hits["sites"])
	}
	if fake.hits["policy-put"] != 4 {
		t.Fatalf("expected 4 policy seeds, got %d", fake.hits["policy-put"])
	}
}

func TestRunTierRecordsAndAggregates(t *testing.T) {
	t.Parallel()
	fake := newFakeControlPlane()
	srv := httptest.NewServer(fake.handler(t))
	defer srv.Close()

	cfg := &APILatencyConfig{BaseURL: srv.URL, JWTSecret: "s", Concurrency: 4, Duration: 300 * time.Millisecond}
	c := newAPIClient(cfg)
	tenants := []seededTenant{{ID: "tenant-1"}, {ID: "tenant-2"}}
	tier := c.runTier(context.Background(), 1000, tenants)

	if tier.TenantCount != 1000 {
		t.Fatalf("tier.TenantCount = %d, want 1000", tier.TenantCount)
	}
	if len(tier.Endpoints) == 0 {
		t.Fatal("no per-endpoint results recorded")
	}
	if tier.OverallRequestsPerSec <= 0 {
		t.Fatalf("RPS should be positive, got %f", tier.OverallRequestsPerSec)
	}
	// All fake routes return 2xx, so the error rate must be ~0.
	if tier.ErrorRate != 0 {
		t.Fatalf("error rate = %f, want 0 (all fake routes 2xx)", tier.ErrorRate)
	}
}

func TestRunAPILatencyBenchRequiresURL(t *testing.T) {
	t.Parallel()
	_, err := RunAPILatencyBench(context.Background(), &APILatencyConfig{TenantCounts: []int{1}})
	if err == nil {
		t.Fatal("expected error when BaseURL is empty")
	}
}
