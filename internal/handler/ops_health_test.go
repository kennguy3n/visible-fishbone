package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
)

func newOpsHealthTestSetup(t *testing.T) (*OpsHealthHandler, uuid.UUID) {
	t.Helper()
	store := memory.NewStore()
	tenantID := uuid.New()
	_, err := memory.NewTenantRepository(store).Create(context.Background(), repository.Tenant{
		ID:   tenantID,
		Name: "test",
		Slug: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	snapRepo := memory.NewOpsHealthSnapshotRepository(store)
	h := NewOpsHealthHandler(snapRepo, nil)
	return h, tenantID
}

func TestOpsHealth_RecordAndGet(t *testing.T) {
	t.Parallel()
	h, tenantID := newOpsHealthTestSetup(t)
	tid := tenantID.String()

	// Record a snapshot.
	body, _ := json.Marshal(OpsHealthRecordRequest{
		HealthScore:     85,
		ComponentScores: json.RawMessage(`{"telemetry":90,"policy":80}`),
	})
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/tenants/"+tid+"/ops/health",
		bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("tenant_id", tid)
	rec := httptest.NewRecorder()
	h.record(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("record: status = %d, want 201; body = %s", rec.Code, rec.Body.String())
	}

	// Get latest.
	req = httptest.NewRequest(http.MethodGet,
		"/api/v1/tenants/"+tid+"/ops/health", nil)
	req.SetPathValue("tenant_id", tid)
	rec = httptest.NewRecorder()
	h.getLatest(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("get: status = %d, want 200; body = %s", rec.Code, rec.Body.String())
	}

	var dto OpsHealthSnapshotDTO
	if err := json.NewDecoder(rec.Body).Decode(&dto); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if dto.HealthScore != 85 {
		t.Errorf("score = %d, want 85", dto.HealthScore)
	}
}

func TestOpsHealth_History(t *testing.T) {
	t.Parallel()
	h, tenantID := newOpsHealthTestSetup(t)
	tid := tenantID.String()

	for i := range 2 {
		body, _ := json.Marshal(OpsHealthRecordRequest{
			HealthScore:     50 + i*10,
			ComponentScores: json.RawMessage(`{}`),
		})
		req := httptest.NewRequest(http.MethodPost,
			"/api/v1/tenants/"+tid+"/ops/health",
			bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.SetPathValue("tenant_id", tid)
		rec := httptest.NewRecorder()
		h.record(rec, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("record %d: status = %d", i, rec.Code)
		}
	}

	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/tenants/"+tid+"/ops/health/history", nil)
	req.SetPathValue("tenant_id", tid)
	rec := httptest.NewRecorder()
	h.history(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("history: status = %d", rec.Code)
	}

	var resp OpsHealthHistoryResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Snapshots) != 2 {
		t.Errorf("snapshots = %d, want 2", len(resp.Snapshots))
	}
}

func TestOpsHealth_History_CappedAtMax(t *testing.T) {
	t.Parallel()
	store := memory.NewStore()
	tenantID := uuid.New()
	if _, err := memory.NewTenantRepository(store).Create(context.Background(), repository.Tenant{
		ID: tenantID, Name: "cap", Slug: "cap",
	}); err != nil {
		t.Fatal(err)
	}
	repo := memory.NewOpsHealthSnapshotRepository(store)
	ctx := context.Background()
	// Record more snapshots than the cap; ListHistory must return at
	// most MaxOpsHealthHistory rows so a high-frequency tenant cannot
	// blow up an unpaginated response.
	for i := 0; i < repository.MaxOpsHealthHistory+5; i++ {
		if _, err := repo.Create(ctx, tenantID, repository.OpsHealthSnapshot{
			HealthScore:     50,
			ComponentScores: json.RawMessage(`{}`),
		}); err != nil {
			t.Fatalf("create %d: %v", i, err)
		}
	}
	snaps, err := repo.ListHistory(ctx, tenantID, time.Now().UTC().AddDate(0, 0, -30))
	if err != nil {
		t.Fatalf("list history: %v", err)
	}
	if len(snaps) != repository.MaxOpsHealthHistory {
		t.Errorf("snapshots = %d, want %d (capped)", len(snaps), repository.MaxOpsHealthHistory)
	}
}

func TestOpsHealth_InvalidScore(t *testing.T) {
	t.Parallel()
	h, tenantID := newOpsHealthTestSetup(t)
	tid := tenantID.String()

	body, _ := json.Marshal(OpsHealthRecordRequest{
		HealthScore:     150,
		ComponentScores: json.RawMessage(`{}`),
	})
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/tenants/"+tid+"/ops/health",
		bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("tenant_id", tid)
	rec := httptest.NewRecorder()
	h.record(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestOpsHealth_NullComponentScoresRejected(t *testing.T) {
	t.Parallel()
	h, tenantID := newOpsHealthTestSetup(t)
	tid := tenantID.String()

	// A literal JSON `null` has len 4, so it must be rejected by the
	// explicit null check rather than slipping past len()==0.
	body, _ := json.Marshal(OpsHealthRecordRequest{
		HealthScore:     50,
		ComponentScores: json.RawMessage(`null`),
	})
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/tenants/"+tid+"/ops/health",
		bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("tenant_id", tid)
	rec := httptest.NewRecorder()
	h.record(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for null component_scores; body = %s", rec.Code, rec.Body.String())
	}
}

func TestOpsHealth_GetLatest_NoData(t *testing.T) {
	t.Parallel()
	h, tenantID := newOpsHealthTestSetup(t)
	tid := tenantID.String()

	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/tenants/"+tid+"/ops/health", nil)
	req.SetPathValue("tenant_id", tid)
	rec := httptest.NewRecorder()
	h.getLatest(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 when no snapshots exist", rec.Code)
	}
}
