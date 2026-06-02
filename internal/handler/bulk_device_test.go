package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
	"github.com/kennguy3n/visible-fishbone/internal/service/identity"
)

func newBulkDeviceTestSetup(t *testing.T) (*BulkDeviceHandler, *memory.Store, uuid.UUID) {
	t.Helper()
	store := memory.NewStore()
	tenantID := uuid.New()
	_, err := memory.NewTenantRepository(store).Create(context.Background(), repository.Tenant{
		ID:   tenantID,
		Name: "bulk-test",
		Slug: "bulk",
	})
	if err != nil {
		t.Fatal(err)
	}
	svc := identity.NewBulkDeviceService(
		memory.NewDeviceRepository(store),
		memory.NewClaimTokenRepository(store),
		memory.NewDeviceEnrollmentRepository(store),
		nil,
	)
	h := NewBulkDeviceHandler(svc, nil)
	return h, store, tenantID
}

func TestBulkDevice_Enroll(t *testing.T) {
	t.Parallel()
	h, _, tenantID := newBulkDeviceTestSetup(t)
	tid := tenantID.String()

	body, _ := json.Marshal(BulkEnrollHTTPRequest{Count: 3})
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/tenants/"+tid+"/devices/bulk/enroll",
		bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("tenant_id", tid)
	rec := httptest.NewRecorder()
	h.bulkEnroll(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body = %s", rec.Code, rec.Body.String())
	}

	var resp map[string]json.RawMessage
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, ok := resp["tokens"]; !ok {
		t.Error("expected tokens in response")
	}
}

func TestBulkDevice_Enroll_InvalidCount(t *testing.T) {
	t.Parallel()
	h, _, tenantID := newBulkDeviceTestSetup(t)
	tid := tenantID.String()

	body, _ := json.Marshal(BulkEnrollHTTPRequest{Count: 0})
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/tenants/"+tid+"/devices/bulk/enroll",
		bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("tenant_id", tid)
	rec := httptest.NewRecorder()
	h.bulkEnroll(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestBulkDevice_Revoke(t *testing.T) {
	t.Parallel()
	h, store, tenantID := newBulkDeviceTestSetup(t)
	tid := tenantID.String()

	enrollRepo := memory.NewDeviceEnrollmentRepository(store)
	deviceID := uuid.New()
	_, err := enrollRepo.CreateEnrollment(context.Background(), tenantID, repository.DeviceEnrollment{
		DeviceID: deviceID,
		Status:   repository.EnrollmentStatusActive,
	})
	if err != nil {
		t.Fatal(err)
	}

	body, _ := json.Marshal(BulkRevokeHTTPRequest{DeviceIDs: []uuid.UUID{deviceID}})
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/tenants/"+tid+"/devices/bulk/revoke",
		bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("tenant_id", tid)
	rec := httptest.NewRecorder()
	h.bulkRevoke(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", rec.Code, rec.Body.String())
	}
}

func TestBulkDevice_ImportCSV(t *testing.T) {
	t.Parallel()
	h, _, tenantID := newBulkDeviceTestSetup(t)
	tid := tenantID.String()

	csv := "device_id,name,platform,status,created_at\nabc,dev1,linux,active,2025-01-01T00:00:00Z\n"
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/tenants/"+tid+"/devices/import",
		strings.NewReader(csv))
	req.SetPathValue("tenant_id", tid)
	rec := httptest.NewRecorder()
	h.importCSV(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", rec.Code, rec.Body.String())
	}
}

func TestBulkDevice_ExportCSV(t *testing.T) {
	t.Parallel()
	h, _, tenantID := newBulkDeviceTestSetup(t)
	tid := tenantID.String()

	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/tenants/"+tid+"/devices/export", nil)
	req.SetPathValue("tenant_id", tid)
	rec := httptest.NewRecorder()
	h.exportCSV(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "text/csv" {
		t.Errorf("content-type = %q, want text/csv", ct)
	}
}
