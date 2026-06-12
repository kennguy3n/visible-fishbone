package handler_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/config"
	"github.com/kennguy3n/visible-fishbone/internal/handler"
	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
	"github.com/kennguy3n/visible-fishbone/internal/service/rollout"
)

// newRolloutTestRouter builds a router with only the rollout handler
// wired over an in-memory repo, plus a JWT for the seeded tenant/user.
func newRolloutTestRouter(t *testing.T, opts ...handler.RolloutOption) (http.Handler, uuid.UUID, uuid.UUID, string) {
	t.Helper()
	store := memory.NewStore()
	tenantID := uuid.New()
	if _, err := memory.NewTenantRepository(store).Create(t.Context(),
		repository.Tenant{
			ID: tenantID, Name: "T", Slug: "t-rollout",
			Status: repository.TenantStatusActive, Tier: repository.TenantTierStarter,
		}); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	userID := uuid.New()

	svc, err := rollout.New(memory.NewCapabilityRolloutRepository())
	if err != nil {
		t.Fatalf("new rollout service: %v", err)
	}

	jwtSecret := "test-jwt-secret-key"
	cfg := &config.Config{
		Auth: config.Auth{
			JWTSecret:    jwtSecret,
			JWTIssuer:    "sng-control",
			JWTAudience:  "sng-control",
			APIKeyHeader: "X-SNG-API-Key",
		},
	}
	router := handler.NewRouter(handler.RouterDeps{
		Config:  cfg,
		Rollout: handler.NewRolloutHandler(svc, opts...),
	})

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss":       "sng-control",
		"aud":       "sng-control",
		"sub":       userID.String(),
		"tenant_id": tenantID.String(),
		"iat":       time.Now().Unix(),
		"exp":       time.Now().Add(5 * time.Minute).Unix(),
	})
	signed, err := token.SignedString([]byte(jwtSecret))
	if err != nil {
		t.Fatalf("sign jwt: %v", err)
	}
	return router, tenantID, userID, signed
}

func TestRolloutHandler_ListDefaultsAllOff(t *testing.T) {
	t.Parallel()
	router, tenantID, _, token := newRolloutTestRouter(t)
	base := "/api/v1/tenants/" + tenantID.String() + "/rollout"

	rec := doJSON(t, router, http.MethodGet, base, token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("list: want 200, got %d — %s", rec.Code, rec.Body.String())
	}
	var listed struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &listed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(listed.Items) != len(rollout.AllCapabilities()) {
		t.Fatalf("list len = %d, want %d", len(listed.Items), len(rollout.AllCapabilities()))
	}
	for _, item := range listed.Items {
		if item["state"] != "off" {
			t.Fatalf("default state = %v, want off", item["state"])
		}
		if item["enforces"] != false || item["evaluates"] != false {
			t.Fatalf("off must neither enforce nor evaluate: %v", item)
		}
		// A never-transitioned default carries no timestamps.
		if _, ok := item["created_at"]; ok {
			t.Fatalf("default record must omit created_at: %v", item)
		}
	}
}

func TestRolloutHandler_TransitionProgression(t *testing.T) {
	t.Parallel()
	router, tenantID, userID, token := newRolloutTestRouter(t)
	base := "/api/v1/tenants/" + tenantID.String() + "/rollout/clamav_swg"

	// off -> monitor.
	rec := doJSON(t, router, http.MethodPost, base+"/transition", token, map[string]any{
		"to": "monitor", "reason": "begin staged rollout",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("advance to monitor: want 200, got %d — %s", rec.Code, rec.Body.String())
	}
	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got["state"] != "monitor" || got["evaluates"] != true || got["enforces"] != false {
		t.Fatalf("monitor semantics wrong: %v", got)
	}
	if got["updated_by"] != userID.String() {
		t.Fatalf("updated_by = %v, want %s", got["updated_by"], userID)
	}

	// monitor -> enforce.
	rec = doJSON(t, router, http.MethodPost, base+"/transition", token, map[string]any{"to": "enforce"})
	if rec.Code != http.StatusOK {
		t.Fatalf("advance to enforce: want 200, got %d — %s", rec.Code, rec.Body.String())
	}

	// GET reflects the enforce state.
	rec = doJSON(t, router, http.MethodGet, base, token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("get: want 200, got %d", rec.Code)
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal get: %v", err)
	}
	if got["state"] != "enforce" || got["enforces"] != true {
		t.Fatalf("enforce semantics wrong: %v", got)
	}
}

func TestRolloutHandler_RejectsSkipWithoutAllowSkip(t *testing.T) {
	t.Parallel()
	router, tenantID, _, token := newRolloutTestRouter(t)
	base := "/api/v1/tenants/" + tenantID.String() + "/rollout/noops_autoenforce/transition"

	// off -> enforce without allow_skip is a 400.
	rec := doJSON(t, router, http.MethodPost, base, token, map[string]any{"to": "enforce"})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("skip without flag: want 400, got %d — %s", rec.Code, rec.Body.String())
	}

	// With allow_skip it succeeds.
	rec = doJSON(t, router, http.MethodPost, base, token, map[string]any{"to": "enforce", "allow_skip": true})
	if rec.Code != http.StatusOK {
		t.Fatalf("skip with flag: want 200, got %d — %s", rec.Code, rec.Body.String())
	}
}

func TestRolloutHandler_InvalidInputs(t *testing.T) {
	t.Parallel()
	router, tenantID, _, token := newRolloutTestRouter(t)

	// Unknown capability in the path -> 400.
	rec := doJSON(t, router, http.MethodGet,
		"/api/v1/tenants/"+tenantID.String()+"/rollout/bogus", token, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad capability: want 400, got %d", rec.Code)
	}

	// Unknown target state -> 400.
	rec = doJSON(t, router, http.MethodPost,
		"/api/v1/tenants/"+tenantID.String()+"/rollout/clamav_swg/transition", token,
		map[string]any{"to": "bogus"})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad state: want 400, got %d", rec.Code)
	}
}

func TestRolloutHandler_TenantIsolation(t *testing.T) {
	t.Parallel()
	router, _, _, token := newRolloutTestRouter(t)

	// The token is bound to the seeded tenant; a path for a DIFFERENT
	// tenant must be refused (not silently served the caller's data).
	other := uuid.New()
	rec := doJSON(t, router, http.MethodGet,
		"/api/v1/tenants/"+other.String()+"/rollout", token, nil)
	if rec.Code == http.StatusOK {
		t.Fatalf("cross-tenant read returned 200; want a 4xx tenant-scope rejection")
	}
}

// stubRolloutAuthz is a scripted RolloutAuthorizer: it grants permission
// only when present in `granted` (and records the permissions queried).
type stubRolloutAuthz struct {
	granted map[string]bool
	err     error
	queried []string
}

func (s *stubRolloutAuthz) HasPermission(_ context.Context, _ uuid.UUID, permission string) (bool, error) {
	s.queried = append(s.queried, permission)
	if s.err != nil {
		return false, s.err
	}
	return s.granted[permission], nil
}

// With an authorizer wired, a caller lacking the permission is refused
// 403 on both the read and the transition — a transition flips a security
// control's enforcement posture, so it must be admin-gated.
func TestRolloutHandler_RBACDeniesWithoutPermission(t *testing.T) {
	t.Parallel()
	authz := &stubRolloutAuthz{granted: map[string]bool{}}
	router, tenantID, _, token := newRolloutTestRouter(t, handler.WithRolloutAuthorizer(authz))

	rec := doJSON(t, router, http.MethodGet, "/api/v1/tenants/"+tenantID.String()+"/rollout", token, nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("list without rollout:read: want 403, got %d — %s", rec.Code, rec.Body.String())
	}

	rec = doJSON(t, router, http.MethodPost,
		"/api/v1/tenants/"+tenantID.String()+"/rollout/clamav_swg/transition", token,
		map[string]any{"to": "monitor"})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("transition without rollout:write: want 403, got %d — %s", rec.Code, rec.Body.String())
	}
}

// With the permission granted, the same calls succeed and the handler
// queried the write permission for the transition (not the read one).
func TestRolloutHandler_RBACAllowsWithPermission(t *testing.T) {
	t.Parallel()
	authz := &stubRolloutAuthz{granted: map[string]bool{
		"rollout:read":  true,
		"rollout:write": true,
	}}
	router, tenantID, _, token := newRolloutTestRouter(t, handler.WithRolloutAuthorizer(authz))

	rec := doJSON(t, router, http.MethodGet, "/api/v1/tenants/"+tenantID.String()+"/rollout", token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("list with rollout:read: want 200, got %d — %s", rec.Code, rec.Body.String())
	}

	rec = doJSON(t, router, http.MethodPost,
		"/api/v1/tenants/"+tenantID.String()+"/rollout/clamav_swg/transition", token,
		map[string]any{"to": "monitor"})
	if rec.Code != http.StatusOK {
		t.Fatalf("transition with rollout:write: want 200, got %d — %s", rec.Code, rec.Body.String())
	}

	var sawWrite bool
	for _, p := range authz.queried {
		if p == "rollout:write" {
			sawWrite = true
		}
	}
	if !sawWrite {
		t.Fatalf("transition must check rollout:write; queried=%v", authz.queried)
	}
}
