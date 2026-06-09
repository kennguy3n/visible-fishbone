package handler_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/handler"
	"github.com/kennguy3n/visible-fishbone/internal/middleware"
	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
	"github.com/kennguy3n/visible-fishbone/internal/service/audit"
)

// auditMux wires an AuditHandler over a memory-backed audit service
// and the given platform authorizer. A nil authorizer leaves the
// admin route unregistered (mirroring production wiring).
func auditMux(t *testing.T, authz handler.PlatformAuthorizer) (*http.ServeMux, *memory.AuditLogRepository, repository.Tenant) {
	t.Helper()
	s := memory.NewStore()
	tn, err := memory.NewTenantRepository(s).Create(context.Background(), repository.Tenant{
		Name: "T", Slug: "t", Status: repository.TenantStatusActive, Tier: repository.TenantTierStarter,
	})
	if err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	repo := memory.NewAuditLogRepository(s)
	mux := http.NewServeMux()
	handler.NewAuditHandler(audit.New(repo), authz).Register(mux)
	return mux, repo, tn
}

// TestAuditHandler_AdminListGlobal verifies that, for an authorized
// platform operator, the admin endpoint returns only platform-scoped
// (tenant_id IS NULL) rows, renders their tenant_id as JSON null, and
// never leaks tenant-scoped rows.
func TestAuditHandler_AdminListGlobal(t *testing.T) {
	mux, repo, tn := auditMux(t, platformAuthz{allow: true})
	ctx := context.Background()

	// One tenant-scoped row (must NOT appear in the global list).
	if _, err := repo.Append(ctx, tn.ID, repository.AuditEntry{
		Action: "tenant.thing", ResourceType: "thing",
	}); err != nil {
		t.Fatalf("append tenant: %v", err)
	}
	// Two platform-scoped rows, one carrying an operator actor.
	operator := uuid.New()
	if _, err := repo.AppendGlobal(ctx, repository.AuditEntry{
		ActorID: &operator, Action: "app_registry.created", ResourceType: "app_registry",
	}); err != nil {
		t.Fatalf("append global (operator): %v", err)
	}
	if _, err := repo.AppendGlobal(ctx, repository.AuditEntry{
		Action: "app.synced", ResourceType: "app_registry",
	}); err != nil {
		t.Fatalf("append global (sync): %v", err)
	}

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, authedReq(httptest.NewRequest(http.MethodGet, "/api/v1/admin/audit-log", nil)))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}

	var resp struct {
		Items []struct {
			TenantID     *string `json:"tenant_id"`
			ActorID      *string `json:"actor_id"`
			Action       string  `json:"action"`
			ResourceType string  `json:"resource_type"`
		} `json:"items"`
		NextCursor string `json:"next_cursor"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v; body=%s", err, rec.Body.String())
	}
	if len(resp.Items) != 2 {
		t.Fatalf("items = %d, want 2 (global only); body=%s", len(resp.Items), rec.Body.String())
	}
	var sawOperator bool
	for _, it := range resp.Items {
		if it.TenantID != nil {
			t.Errorf("global row tenant_id = %q, want null", *it.TenantID)
		}
		if it.ResourceType != "app_registry" {
			t.Errorf("resource_type = %q, want app_registry", it.ResourceType)
		}
		if it.Action == "app_registry.created" && it.ActorID != nil && *it.ActorID == operator.String() {
			sawOperator = true
		}
	}
	if !sawOperator {
		t.Errorf("expected the operator-attributed global row to carry actor_id %s", operator)
	}

	// The tenant-scoped endpoint must still render tenant_id (the
	// pointer change must not drop it for owned rows). It is not
	// platform-gated; MountTenantScoped handles its auth.
	rec2 := httptest.NewRecorder()
	mux.ServeHTTP(rec2, authedReq(httptest.NewRequest(http.MethodGet, "/api/v1/tenants/"+tn.ID.String()+"/audit-log", nil)))
	if rec2.Code != http.StatusOK {
		t.Fatalf("tenant status = %d, want 200; body=%s", rec2.Code, rec2.Body.String())
	}
	var tresp struct {
		Items []struct {
			TenantID *string `json:"tenant_id"`
		} `json:"items"`
	}
	if err := json.Unmarshal(rec2.Body.Bytes(), &tresp); err != nil {
		t.Fatalf("decode tenant: %v", err)
	}
	if len(tresp.Items) != 1 {
		t.Fatalf("tenant items = %d, want 1 (global rows must not leak)", len(tresp.Items))
	}
	if tresp.Items[0].TenantID == nil || *tresp.Items[0].TenantID != tn.ID.String() {
		t.Errorf("tenant row tenant_id = %v, want %s", tresp.Items[0].TenantID, tn.ID)
	}
}

// TestAuditHandler_AdminListGlobalRejectsBadFilter checks the shared
// query parser surfaces a 400 on a malformed actor_id (after the
// platform gate is passed).
func TestAuditHandler_AdminListGlobalRejectsBadFilter(t *testing.T) {
	mux, _, _ := auditMux(t, platformAuthz{allow: true})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, authedReq(httptest.NewRequest(http.MethodGet, "/api/v1/admin/audit-log?actor_id=not-a-uuid", nil)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
}

// TestAuditHandler_AdminListGlobalAuthz exercises the platform-auth
// gate: missing identity → 401, denied grant → 403, tenant-bound
// credential → 403, and a nil authorizer → route unregistered (404).
func TestAuditHandler_AdminListGlobalAuthz(t *testing.T) {
	const path = "/api/v1/admin/audit-log"

	t.Run("unauthenticated", func(t *testing.T) {
		mux, _, _ := auditMux(t, platformAuthz{allow: true})
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401; body=%s", rec.Code, rec.Body.String())
		}
	})

	t.Run("grant denied", func(t *testing.T) {
		mux, _, _ := auditMux(t, platformAuthz{allow: false})
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, authedReq(httptest.NewRequest(http.MethodGet, path, nil)))
		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403; body=%s", rec.Code, rec.Body.String())
		}
	})

	t.Run("tenant-bound credential refused", func(t *testing.T) {
		mux, _, _ := auditMux(t, platformAuthz{allow: true})
		req := httptest.NewRequest(http.MethodGet, path, nil)
		ctx := middleware.WithUserIDForTest(req.Context(), uuid.New())
		ctx = middleware.WithTenantIDForTest(ctx, uuid.New())
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req.WithContext(ctx))
		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403; body=%s", rec.Code, rec.Body.String())
		}
	})

	t.Run("nil authorizer leaves route unregistered", func(t *testing.T) {
		mux, _, _ := auditMux(t, nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, authedReq(httptest.NewRequest(http.MethodGet, path, nil)))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404; body=%s", rec.Code, rec.Body.String())
		}
	})
}
