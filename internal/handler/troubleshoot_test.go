package handler_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/handler"
	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
	"github.com/kennguy3n/visible-fishbone/internal/service/troubleshoot"
)

func newTestTroubleshootHandler(t *testing.T) (*handler.TroubleshootHandler, uuid.UUID) {
	t.Helper()
	store := memory.NewStore()
	tenantRepo := memory.NewTenantRepository(store)
	tenant, err := tenantRepo.Create(t.Context(), repository.Tenant{
		Name: "test-tenant",
		Slug: "test-" + uuid.New().String()[:8],
	})
	if err != nil {
		t.Fatal(err)
	}

	kbRepo := memory.NewKBEntryRepository(store)
	sessRepo := memory.NewTroubleshootSessionRepository(store)

	kbSvc := troubleshoot.NewKBService(kbRepo)
	engine := troubleshoot.NewDiagnosticEngine(nil)
	assistant := troubleshoot.NewAssistant(nil, kbSvc, engine)
	sessSvc := troubleshoot.NewSessionService(sessRepo, assistant, nil)

	h := handler.NewTroubleshootHandler(sessSvc, kbSvc, engine)
	return h, tenant.ID
}

func TestTroubleshootHandler_KB_CRUD(t *testing.T) {
	h, tenantID := newTestTroubleshootHandler(t)

	mux := http.NewServeMux()
	h.Register(mux)

	// Create
	body, _ := json.Marshal(map[string]any{
		"category": "connectivity",
		"title":    "Test Article",
		"content":  "Test content",
		"tags":     []string{"test"},
	})
	req := httptest.NewRequest("POST", "/api/v1/tenants/"+tenantID.String()+"/troubleshoot/kb", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	var created map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	entryID := created["id"].(string)

	// Get
	req = httptest.NewRequest("GET", "/api/v1/tenants/"+tenantID.String()+"/troubleshoot/kb/"+entryID, nil)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 on GET, got %d: %s", w.Code, w.Body.String())
	}

	// List
	req = httptest.NewRequest("GET", "/api/v1/tenants/"+tenantID.String()+"/troubleshoot/kb", nil)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 on list, got %d: %s", w.Code, w.Body.String())
	}

	// Update
	updateBody, _ := json.Marshal(map[string]any{
		"title": "Updated Title",
	})
	req = httptest.NewRequest("PUT", "/api/v1/tenants/"+tenantID.String()+"/troubleshoot/kb/"+entryID, bytes.NewReader(updateBody))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 on PUT, got %d: %s", w.Code, w.Body.String())
	}

	// Delete
	req = httptest.NewRequest("DELETE", "/api/v1/tenants/"+tenantID.String()+"/troubleshoot/kb/"+entryID, nil)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204 on DELETE, got %d: %s", w.Code, w.Body.String())
	}
}

func TestTroubleshootHandler_Session(t *testing.T) {
	h, tenantID := newTestTroubleshootHandler(t)

	mux := http.NewServeMux()
	h.Register(mux)

	// Start session
	body, _ := json.Marshal(map[string]any{
		"issue": "VPN connectivity problem",
	})
	req := httptest.NewRequest("POST", "/api/v1/tenants/"+tenantID.String()+"/troubleshoot/sessions", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	var sess map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &sess); err != nil {
		t.Fatal(err)
	}
	sessID := sess["id"].(string)

	// Get session
	req = httptest.NewRequest("GET", "/api/v1/tenants/"+tenantID.String()+"/troubleshoot/sessions/"+sessID, nil)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Send message
	msgBody, _ := json.Marshal(map[string]any{
		"content": "What should I check first?",
	})
	req = httptest.NewRequest("POST", "/api/v1/tenants/"+tenantID.String()+"/troubleshoot/sessions/"+sessID+"/messages", bytes.NewReader(msgBody))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Resolve session
	req = httptest.NewRequest("POST", "/api/v1/tenants/"+tenantID.String()+"/troubleshoot/sessions/"+sessID+"/resolve", nil)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestTroubleshootHandler_Diagnostics(t *testing.T) {
	h, tenantID := newTestTroubleshootHandler(t)

	mux := http.NewServeMux()
	h.Register(mux)

	// Run all diagnostics
	req := httptest.NewRequest("POST", "/api/v1/tenants/"+tenantID.String()+"/troubleshoot/diagnostics/run", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}
