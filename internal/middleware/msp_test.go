package middleware_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/middleware"
)

// stubMSPAuthz lets each test pin a deterministic outcome for the
// RequireMSPScope authorizer.
type stubMSPAuthz struct {
	allow     bool
	err       error
	gotUser   uuid.UUID
	gotMSP    uuid.UUID
	gotPerm   string
	callCount int
}

func (s *stubMSPAuthz) AuthorizeMSP(_ context.Context, userID, mspID uuid.UUID, perm string) (bool, error) {
	s.callCount++
	s.gotUser = userID
	s.gotMSP = mspID
	s.gotPerm = perm
	return s.allow, s.err
}

func TestRequireMSP_StampsContext(t *testing.T) {
	t.Parallel()
	mspID := uuid.New()
	mux := http.NewServeMux()
	mux.Handle("GET /api/v1/msps/{msp_id}", middleware.RequireMSP("msp_id")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := middleware.MSPIDFromContext(r.Context())
		if got != mspID {
			t.Errorf("ctx msp_id = %v, want %v", got, mspID)
		}
		w.WriteHeader(http.StatusNoContent)
	})))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/msps/"+mspID.String(), nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Errorf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
}

func TestRequireMSP_RejectsBadUUID(t *testing.T) {
	t.Parallel()
	mux := http.NewServeMux()
	mux.Handle("GET /api/v1/msps/{msp_id}", middleware.RequireMSP("msp_id")(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Fatal("handler should not be reached")
	})))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/msps/not-a-uuid", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d", rec.Code)
	}
}

func TestRequireMSPScope_DeniesUnauthenticated(t *testing.T) {
	t.Parallel()
	mspID := uuid.New()
	authz := &stubMSPAuthz{allow: true}
	mux := http.NewServeMux()
	mux.Handle("GET /api/v1/msps/{msp_id}/tenants",
		middleware.RequireMSPScope(authz, "tenants:read", "msp_id")(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
			t.Fatal("handler should not be reached")
		})))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/msps/"+mspID.String()+"/tenants", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d", rec.Code)
	}
	if authz.callCount != 0 {
		t.Fatal("authorizer must not be called for unauthenticated requests")
	}
}

func TestRequireMSPScope_DeniesWhenAuthorizerSaysNo(t *testing.T) {
	t.Parallel()
	mspID := uuid.New()
	userID := uuid.New()
	authz := &stubMSPAuthz{allow: false}

	mux := http.NewServeMux()
	mux.Handle("GET /api/v1/msps/{msp_id}/tenants",
		middleware.RequireMSPScope(authz, "tenants:read", "msp_id")(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
			t.Fatal("handler must not run on deny")
		})))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/msps/"+mspID.String()+"/tenants", nil)
	// Simulate the auth middleware having bound a user id.
	req = req.WithContext(middleware.WithUserIDForTest(req.Context(), userID))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	if authz.gotUser != userID || authz.gotMSP != mspID || authz.gotPerm != "tenants:read" {
		t.Fatalf("authorizer called with user=%v msp=%v perm=%q", authz.gotUser, authz.gotMSP, authz.gotPerm)
	}
}

func TestRequireMSPScope_AllowsAndStampsContext(t *testing.T) {
	t.Parallel()
	mspID := uuid.New()
	userID := uuid.New()
	authz := &stubMSPAuthz{allow: true}

	mux := http.NewServeMux()
	called := false
	mux.Handle("GET /api/v1/msps/{msp_id}/tenants",
		middleware.RequireMSPScope(authz, "tenants:read", "msp_id")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
			if got := middleware.MSPIDFromContext(r.Context()); got != mspID {
				t.Errorf("ctx msp_id = %v, want %v", got, mspID)
			}
			w.WriteHeader(http.StatusOK)
		})))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/msps/"+mspID.String()+"/tenants", nil)
	req = req.WithContext(middleware.WithUserIDForTest(req.Context(), userID))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !called {
		t.Errorf("status = %d called=%v body=%s", rec.Code, called, rec.Body.String())
	}
}

func TestRequireMSPScope_AuthorizerErrorIs500(t *testing.T) {
	t.Parallel()
	mspID := uuid.New()
	userID := uuid.New()
	authz := &stubMSPAuthz{err: errors.New("boom")}

	mux := http.NewServeMux()
	mux.Handle("GET /api/v1/msps/{msp_id}/tenants",
		middleware.RequireMSPScope(authz, "tenants:read", "msp_id")(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
			t.Fatal("handler must not run on error")
		})))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/msps/"+mspID.String()+"/tenants", nil)
	req = req.WithContext(middleware.WithUserIDForTest(req.Context(), userID))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d", rec.Code)
	}
}
