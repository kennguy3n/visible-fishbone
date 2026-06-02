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
	devRepo := memory.NewDeviceRepository(store)
	h := NewBulkDeviceHandler(svc, devRepo, nil)
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

func TestBulkDevice_Enroll_NegativeTTL(t *testing.T) {
	t.Parallel()
	h, _, tenantID := newBulkDeviceTestSetup(t)
	tid := tenantID.String()

	body, _ := json.Marshal(BulkEnrollHTTPRequest{Count: 1, TTL: "-24h"})
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/tenants/"+tid+"/devices/bulk/enroll",
		bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("tenant_id", tid)
	rec := httptest.NewRecorder()
	h.bulkEnroll(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for negative ttl", rec.Code)
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
	h, store, tenantID := newBulkDeviceTestSetup(t)
	tid := tenantID.String()

	csv := "device_id,name,platform,status,created_at\n" +
		"abc,dev1,linux,active,2025-01-01T00:00:00Z\n" +
		"def,dev2,windows,pending,2025-01-02T00:00:00Z\n"
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/tenants/"+tid+"/devices/import",
		strings.NewReader(csv))
	req.SetPathValue("tenant_id", tid)
	rec := httptest.NewRecorder()
	h.importCSV(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", rec.Code, rec.Body.String())
	}
	var result identity.BulkResult
	if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if result.Total != 2 || result.Succeeded != 2 || result.Failed != 0 {
		t.Errorf("result = %+v, want total=2 succeeded=2 failed=0", result)
	}
	// Imported rows must actually be persisted as devices.
	page, err := memory.NewDeviceRepository(store).List(
		context.Background(), tenantID, repository.DeviceListFilter{}, repository.Page{Limit: 50})
	if err != nil {
		t.Fatalf("list devices: %v", err)
	}
	if len(page.Items) != 2 {
		t.Errorf("persisted devices = %d, want 2", len(page.Items))
	}
}

func TestBulkDevice_ImportCSV_InvalidPlatformIsolated(t *testing.T) {
	t.Parallel()
	h, store, tenantID := newBulkDeviceTestSetup(t)
	tid := tenantID.String()

	csv := "device_id,name,platform,status,created_at\n" +
		"abc,dev1,linux,active,2025-01-01T00:00:00Z\n" +
		"def,dev2,plan9,active,2025-01-02T00:00:00Z\n"
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/tenants/"+tid+"/devices/import",
		strings.NewReader(csv))
	req.SetPathValue("tenant_id", tid)
	rec := httptest.NewRecorder()
	h.importCSV(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", rec.Code, rec.Body.String())
	}
	var result identity.BulkResult
	if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if result.Succeeded != 1 || result.Failed != 1 {
		t.Errorf("result = %+v, want succeeded=1 failed=1", result)
	}
	page, err := memory.NewDeviceRepository(store).List(
		context.Background(), tenantID, repository.DeviceListFilter{}, repository.Page{Limit: 50})
	if err != nil {
		t.Fatalf("list devices: %v", err)
	}
	if len(page.Items) != 1 {
		t.Errorf("persisted devices = %d, want 1 (bad row isolated)", len(page.Items))
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
