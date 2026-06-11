package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
	"github.com/kennguy3n/visible-fishbone/internal/service/tenant"
)

// newTestMigrationHandler wires a TenantMigrationHandler against the
// in-memory repositories with only the Region plane wired (the PoP /
// keys / telemetry / object planes are nil — logged no-ops — which is a
// valid production posture for a single-region-backend deployment). It
// seeds a tenant with the given region so the source region is set.
func newTestMigrationHandler(t *testing.T, region string) (*TenantMigrationHandler, repository.Tenant, repository.TenantRepository) {
	t.Helper()
	store := memory.NewStore()
	tenantRepo := memory.NewTenantRepository(store)
	migRepo := memory.NewTenantMigrationRepository(store)
	audit := memory.NewAuditLogRepository(store)
	svc := tenant.New(tenantRepo, audit, nil)
	seed, err := svc.Create(context.Background(), repository.Tenant{
		Name:   "Acme",
		Slug:   "acme",
		Region: region,
		Tier:   repository.TenantTierStarter,
	})
	if err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	migrator, err := tenant.NewRegionMigrator(migRepo, tenantRepo, audit,
		tenant.MigrationPlanes{Region: tenant.NewRegionColumnPlane(tenantRepo)}, nil)
	if err != nil {
		t.Fatalf("new migrator: %v", err)
	}
	return NewTenantMigrationHandler(migrator), seed, tenantRepo
}

func postMigrate(t *testing.T, h *TenantMigrationHandler, id, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/tenants/"+id+"/migrate-region", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("tenant_id", id)
	rec := httptest.NewRecorder()
	h.start(rec, req)
	return rec
}

func getMigrationStatus(t *testing.T, h *TenantMigrationHandler, id string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/tenants/"+id+"/migration-status", nil)
	req.SetPathValue("tenant_id", id)
	rec := httptest.NewRecorder()
	h.status(rec, req)
	return rec
}

// TestMigrateRegion_HappyPath drives a full migration to completion and
// asserts the authoritative tenants.region column flipped.
func TestMigrateRegion_HappyPath(t *testing.T) {
	t.Parallel()
	h, seed, tenantRepo := newTestMigrationHandler(t, "us-east-1")

	rec := postMigrate(t, h, seed.ID.String(), `{"target_region":"eu-west-1"}`)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp MigrationResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.State != repository.MigrationStateCompleted {
		t.Errorf("state = %q, want %q", resp.State, repository.MigrationStateCompleted)
	}
	if resp.SourceRegion != "us-east-1" || resp.TargetRegion != "eu-west-1" {
		t.Errorf("regions = %q -> %q, want us-east-1 -> eu-west-1", resp.SourceRegion, resp.TargetRegion)
	}
	if resp.DualRead {
		t.Errorf("dual_read = true, want false on a completed migration")
	}
	got, err := tenantRepo.Get(context.Background(), seed.ID)
	if err != nil {
		t.Fatalf("get tenant: %v", err)
	}
	if got.Region != "eu-west-1" {
		t.Errorf("tenant region = %q, want eu-west-1 (region must commit)", got.Region)
	}
}

// TestMigrateRegion_AsyncDrive verifies the control-plane async posture
// (EnableAsyncDrive): the POST returns 202 with a PENDING record
// (dual_read armed, region not yet flipped) without blocking on the
// pipeline, and once the background drive is drained the status endpoint
// reports completion and the authoritative tenant region column has
// flipped.
func TestMigrateRegion_AsyncDrive(t *testing.T) {
	t.Parallel()
	store := memory.NewStore()
	tenantRepo := memory.NewTenantRepository(store)
	migRepo := memory.NewTenantMigrationRepository(store)
	audit := memory.NewAuditLogRepository(store)
	svc := tenant.New(tenantRepo, audit, nil)
	seed, err := svc.Create(context.Background(), repository.Tenant{
		Name:   "Acme",
		Slug:   "acme-async",
		Region: "us-east-1",
		Tier:   repository.TenantTierStarter,
	})
	if err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	migrator, err := tenant.NewRegionMigrator(migRepo, tenantRepo, audit,
		tenant.MigrationPlanes{Region: tenant.NewRegionColumnPlane(tenantRepo)}, nil)
	if err != nil {
		t.Fatalf("new migrator: %v", err)
	}
	migrator.EnableAsyncDrive()
	h := NewTenantMigrationHandler(migrator)

	rec := postMigrate(t, h, seed.ID.String(), `{"target_region":"eu-west-1"}`)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp MigrationResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// Async contract: the POST returns the pending record without waiting
	// for the pipeline to run.
	if resp.State != repository.MigrationStatePending {
		t.Fatalf("async start state = %q, want pending", resp.State)
	}
	if !resp.DualRead {
		t.Errorf("dual_read should be armed on the pending record")
	}

	// Drain the background drive (as graceful shutdown does), then the
	// status endpoint reports the terminal completed record.
	drainCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	migrator.Shutdown(drainCtx)

	statusRec := getMigrationStatus(t, h, seed.ID.String())
	if statusRec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", statusRec.Code, statusRec.Body.String())
	}
	var status MigrationResponse
	if err := json.NewDecoder(statusRec.Body).Decode(&status); err != nil {
		t.Fatalf("decode status: %v", err)
	}
	if status.State != repository.MigrationStateCompleted {
		t.Fatalf("after drain state = %q, want completed", status.State)
	}
	if status.DualRead {
		t.Errorf("dual_read should be cleared on completion")
	}
	got, err := tenantRepo.Get(context.Background(), seed.ID)
	if err != nil {
		t.Fatalf("get tenant: %v", err)
	}
	if got.Region != "eu-west-1" {
		t.Errorf("tenant region = %q, want eu-west-1 (region must commit)", got.Region)
	}
}

// TestMigrateRegion_MissingTargetRegion asserts a 400 when the body has
// no target_region.
func TestMigrateRegion_MissingTargetRegion(t *testing.T) {
	t.Parallel()
	h, seed, _ := newTestMigrationHandler(t, "us-east-1")

	rec := postMigrate(t, h, seed.ID.String(), `{}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
}

// TestMigrateRegion_SourceRegionUnset asserts a 422 when the tenant has
// no residency region to migrate from.
func TestMigrateRegion_SourceRegionUnset(t *testing.T) {
	t.Parallel()
	h, seed, _ := newTestMigrationHandler(t, "")

	rec := postMigrate(t, h, seed.ID.String(), `{"target_region":"eu-west-1"}`)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var env ErrorEnvelope
	if err := json.NewDecoder(rec.Body).Decode(&env); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if env.Error.Code != "source_region_unset" {
		t.Errorf("code = %q, want source_region_unset", env.Error.Code)
	}
}

// TestMigrationStatus_NotFound asserts a 404 when no migration exists
// for the tenant yet.
func TestMigrationStatus_NotFound(t *testing.T) {
	t.Parallel()
	h, seed, _ := newTestMigrationHandler(t, "us-east-1")

	rec := getMigrationStatus(t, h, seed.ID.String())
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
}

// TestMigrationStatus_AfterCompletion asserts the status endpoint
// returns the terminal record once a migration has run.
func TestMigrationStatus_AfterCompletion(t *testing.T) {
	t.Parallel()
	h, seed, _ := newTestMigrationHandler(t, "us-east-1")

	if rec := postMigrate(t, h, seed.ID.String(), `{"target_region":"eu-west-1"}`); rec.Code != http.StatusAccepted {
		t.Fatalf("start status = %d, body = %s", rec.Code, rec.Body.String())
	}
	rec := getMigrationStatus(t, h, seed.ID.String())
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp MigrationResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.State != repository.MigrationStateCompleted {
		t.Errorf("state = %q, want %q", resp.State, repository.MigrationStateCompleted)
	}
}
