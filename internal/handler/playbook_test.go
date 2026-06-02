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
	"github.com/kennguy3n/visible-fishbone/internal/service/playbook"
	"github.com/kennguy3n/visible-fishbone/internal/service/playbook/executors"
)

type stubPublisher struct{}

func (s *stubPublisher) Publish(_ context.Context, _ string, _ []byte) error { return nil }

func newPlaybookTestRouter(t *testing.T) (http.Handler, uuid.UUID, string) {
	t.Helper()
	store := memory.NewStore()
	tenantID := uuid.New()
	if _, err := memory.NewTenantRepository(store).Create(context.Background(),
		repository.Tenant{
			ID: tenantID, Name: "T", Slug: "t-playbook",
			Status: repository.TenantStatusActive, Tier: repository.TenantTierStarter,
		}); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	userID := uuid.New()

	pub := &stubPublisher{}
	engine := playbook.NewEngine(
		memory.NewPlaybookRepository(store),
		memory.NewPlaybookExecutionRepository(store),
		pub,
		nil,
	)
	reg := executors.NewRegistry(pub)
	engine.SetExecutors(reg)

	approvalSvc := playbook.NewApprovalService(
		memory.NewPlaybookApprovalRepository(store),
		memory.NewPlaybookExecutionRepository(store),
		nil,
	)

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
		Config:   cfg,
		Playbook: handler.NewPlaybookHandler(engine, approvalSvc),
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
	return router, tenantID, signed
}

func TestPlaybookHandler_CRUD(t *testing.T) {
	t.Parallel()
	router, tenantID, token := newPlaybookTestRouter(t)
	path := "/api/v1/tenants/" + tenantID.String() + "/playbooks"

	// CREATE
	stepsJSON, _ := json.Marshal([]map[string]any{
		{"order": 1, "type": "notify", "config": map[string]string{"message": "test", "target": "ops"}, "timeout_seconds": 30},
	})
	rec := doJSON(t, router, http.MethodPost, path, token, map[string]any{
		"name":              "test-playbook",
		"description":       "A test playbook",
		"trigger_condition": "brute_force",
		"steps":             json.RawMessage(stepsJSON),
		"enabled":           true,
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: expected 201, got %d: %s", rec.Code, rec.Body.String())
	}

	var pb map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &pb)
	pbID := pb["id"].(string)

	// GET
	rec = doJSON(t, router, http.MethodGet, path+"/"+pbID, token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("get: expected 200, got %d", rec.Code)
	}

	// LIST
	rec = doJSON(t, router, http.MethodGet, path, token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("list: expected 200, got %d", rec.Code)
	}

	// UPDATE
	rec = doJSON(t, router, http.MethodPut, path+"/"+pbID, token, map[string]any{
		"name": "updated-playbook",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("update: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	// DELETE
	rec = doJSON(t, router, http.MethodDelete, path+"/"+pbID, token, nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete: expected 204, got %d", rec.Code)
	}
}

func TestPlaybookHandler_DryRun(t *testing.T) {
	t.Parallel()
	router, tenantID, token := newPlaybookTestRouter(t)
	path := "/api/v1/tenants/" + tenantID.String() + "/playbooks"

	stepsJSON, _ := json.Marshal([]map[string]any{
		{"order": 1, "type": "notify", "config": map[string]string{"message": "test"}, "timeout_seconds": 30},
	})
	rec := doJSON(t, router, http.MethodPost, path, token, map[string]any{
		"name":              "dry-run-playbook",
		"trigger_condition": "brute_force",
		"steps":             json.RawMessage(stepsJSON),
		"enabled":           true,
	})
	var pb map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &pb)
	pbID := pb["id"].(string)

	rec = doJSON(t, router, http.MethodPost, path+"/"+pbID+"/dry-run", token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("dry-run: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestPlaybookHandler_Executions(t *testing.T) {
	t.Parallel()
	router, tenantID, token := newPlaybookTestRouter(t)
	path := "/api/v1/tenants/" + tenantID.String() + "/playbooks"

	rec := doJSON(t, router, http.MethodGet, path+"/executions", token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("list executions: expected 200, got %d", rec.Code)
	}
}

func TestPlaybookHandler_Approvals(t *testing.T) {
	t.Parallel()
	router, tenantID, token := newPlaybookTestRouter(t)
	path := "/api/v1/tenants/" + tenantID.String() + "/playbooks"

	rec := doJSON(t, router, http.MethodGet, path+"/approvals/pending", token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("list pending approvals: expected 200, got %d", rec.Code)
	}
}
