package identity_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
	"github.com/kennguy3n/visible-fishbone/internal/service/identity"
)

func setupBulkTest(t *testing.T) (*identity.BulkDeviceService, *memory.Store, uuid.UUID) {
	t.Helper()
	store := memory.NewStore()
	tenantID := uuid.New()
	_, err := memory.NewTenantRepository(store).Create(context.Background(), repository.Tenant{
		ID:   tenantID,
		Name: "bulk-test",
		Slug: "bulk-test",
	})
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	devices := memory.NewDeviceRepository(store)
	tokens := memory.NewClaimTokenRepository(store)
	enrolls := memory.NewDeviceEnrollmentRepository(store)
	svc := identity.NewBulkDeviceService(devices, tokens, enrolls, nil)
	return svc, store, tenantID
}

func TestBulkDevice_GenerateTokens(t *testing.T) {
	svc, _, tenantID := setupBulkTest(t)
	ctx := context.Background()

	result, tokens, err := svc.BulkGenerateTokens(ctx, tenantID, 5, time.Hour)
	if err != nil {
		t.Fatalf("generate tokens: %v", err)
	}
	if result.Total != 5 {
		t.Errorf("total = %d, want 5", result.Total)
	}
	if result.Succeeded != 5 {
		t.Errorf("succeeded = %d, want 5", result.Succeeded)
	}
	if len(tokens) != 5 {
		t.Errorf("tokens = %d, want 5", len(tokens))
	}
}

func TestBulkDevice_GenerateTokens_ExceedsLimit(t *testing.T) {
	svc, _, tenantID := setupBulkTest(t)
	ctx := context.Background()

	_, _, err := svc.BulkGenerateTokens(ctx, tenantID, identity.MaxBulkDevices+1, time.Hour)
	if err == nil {
		t.Fatal("expected error for exceeding max")
	}
}

func TestBulkDevice_GenerateTokens_Zero(t *testing.T) {
	svc, _, tenantID := setupBulkTest(t)
	ctx := context.Background()

	_, _, err := svc.BulkGenerateTokens(ctx, tenantID, 0, time.Hour)
	if err == nil {
		t.Fatal("expected error for zero count")
	}
}

func TestBulkDevice_Revoke(t *testing.T) {
	svc, store, tenantID := setupBulkTest(t)
	ctx := context.Background()

	// Create enrollments to revoke.
	enrollRepo := memory.NewDeviceEnrollmentRepository(store)
	ids := make([]uuid.UUID, 3)
	for i := range ids {
		ids[i] = uuid.New()
		_, err := enrollRepo.CreateEnrollment(ctx, tenantID, repository.DeviceEnrollment{
			DeviceID: ids[i],
			Status:   repository.EnrollmentStatusActive,
		})
		if err != nil {
			t.Fatalf("create enrollment %d: %v", i, err)
		}
	}

	result, err := svc.BulkRevoke(ctx, tenantID, ids)
	if err != nil {
		t.Fatalf("bulk revoke: %v", err)
	}
	if result.Succeeded != 3 {
		t.Errorf("succeeded = %d, want 3", result.Succeeded)
	}
	if result.Failed != 0 {
		t.Errorf("failed = %d, want 0", result.Failed)
	}
}

func TestBulkDevice_Revoke_PartialFailure(t *testing.T) {
	svc, store, tenantID := setupBulkTest(t)
	ctx := context.Background()

	realID := uuid.New()
	enrollRepo := memory.NewDeviceEnrollmentRepository(store)
	_, err := enrollRepo.CreateEnrollment(ctx, tenantID, repository.DeviceEnrollment{
		DeviceID: realID,
		Status:   repository.EnrollmentStatusActive,
	})
	if err != nil {
		t.Fatalf("create enrollment: %v", err)
	}

	fakeID := uuid.New()
	result, err := svc.BulkRevoke(ctx, tenantID, []uuid.UUID{realID, fakeID})
	if err != nil {
		t.Fatalf("bulk revoke: %v", err)
	}
	if result.Succeeded != 1 {
		t.Errorf("succeeded = %d, want 1", result.Succeeded)
	}
	if result.Failed != 1 {
		t.Errorf("failed = %d, want 1", result.Failed)
	}
}

func TestBulkDevice_ExportCSV(t *testing.T) {
	svc, _, tenantID := setupBulkTest(t)
	ctx := context.Background()

	devices := []repository.Device{
		{ID: uuid.New(), TenantID: tenantID, Name: "d1", Platform: "linux", Status: "active", CreatedAt: time.Now().UTC()},
		{ID: uuid.New(), TenantID: tenantID, Name: "d2", Platform: "windows", Status: "active", CreatedAt: time.Now().UTC()},
		{ID: uuid.New(), TenantID: uuid.New(), Name: "other", Platform: "macos", Status: "active", CreatedAt: time.Now().UTC()},
	}

	data, err := svc.ExportCSV(ctx, tenantID, devices)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 3 { // header + 2 tenant devices
		t.Errorf("lines = %d, want 3", len(lines))
	}
}

func TestBulkDevice_ImportCSV(t *testing.T) {
	svc, store, tenantID := setupBulkTest(t)
	ctx := context.Background()

	csv := "device_id,name,platform,status,created_at\n" +
		"abc-123,dev1,linux,active,2025-01-01T00:00:00Z\n" +
		"def-456,dev2,windows,active,2025-01-02T00:00:00Z\n"

	result, err := svc.ImportCSV(ctx, tenantID, strings.NewReader(csv))
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if result.Total != 2 || result.Succeeded != 2 || result.Failed != 0 {
		t.Errorf("result = %+v, want total=2 succeeded=2 failed=0", result)
	}
	// Rows must be persisted as devices for the tenant.
	page, err := memory.NewDeviceRepository(store).List(
		ctx, tenantID, repository.DeviceListFilter{}, repository.Page{Limit: 50})
	if err != nil {
		t.Fatalf("list devices: %v", err)
	}
	if len(page.Items) != 2 {
		t.Errorf("persisted devices = %d, want 2", len(page.Items))
	}
}

func TestBulkDevice_ImportCSV_InvalidPlatformIsolated(t *testing.T) {
	svc, store, tenantID := setupBulkTest(t)
	ctx := context.Background()

	csv := "device_id,name,platform,status,created_at\n" +
		"abc-123,dev1,linux,active,2025-01-01T00:00:00Z\n" +
		"def-456,dev2,plan9,active,2025-01-02T00:00:00Z\n"

	result, err := svc.ImportCSV(ctx, tenantID, strings.NewReader(csv))
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if result.Succeeded != 1 || result.Failed != 1 {
		t.Errorf("result = %+v, want succeeded=1 failed=1", result)
	}
	if len(result.Errors) != 1 {
		t.Errorf("errors = %v, want 1 entry", result.Errors)
	}
	page, err := memory.NewDeviceRepository(store).List(
		ctx, tenantID, repository.DeviceListFilter{}, repository.Page{Limit: 50})
	if err != nil {
		t.Fatalf("list devices: %v", err)
	}
	if len(page.Items) != 1 {
		t.Errorf("persisted devices = %d, want 1 (bad row isolated)", len(page.Items))
	}
}

func TestBulkDevice_ImportCSV_MalformedRowReported(t *testing.T) {
	svc, store, tenantID := setupBulkTest(t)
	ctx := context.Background()

	// Second data row has only 3 columns and cannot be parsed.
	csv := "device_id,name,platform,status,created_at\n" +
		"abc-123,dev1,linux,active,2025-01-01T00:00:00Z\n" +
		"def-456,dev2,windows\n"

	result, err := svc.ImportCSV(ctx, tenantID, strings.NewReader(csv))
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	// The malformed row must be counted, not silently dropped.
	if result.Total != 2 || result.Succeeded != 1 || result.Failed != 1 {
		t.Errorf("result = %+v, want total=2 succeeded=1 failed=1", result)
	}
	if len(result.Errors) != 1 {
		t.Fatalf("errors = %v, want 1 entry", result.Errors)
	}
	if !strings.Contains(result.Errors[0], "row 2") {
		t.Errorf("error %q should reference the malformed row 2", result.Errors[0])
	}
	page, err := memory.NewDeviceRepository(store).List(
		ctx, tenantID, repository.DeviceListFilter{}, repository.Page{Limit: 50})
	if err != nil {
		t.Fatalf("list devices: %v", err)
	}
	if len(page.Items) != 1 {
		t.Errorf("persisted devices = %d, want 1 (malformed row not persisted)", len(page.Items))
	}
}

func TestBulkDevice_ImportCSV_Empty(t *testing.T) {
	svc, _, tenantID := setupBulkTest(t)
	result, err := svc.ImportCSV(context.Background(), tenantID, strings.NewReader("header\n"))
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if result.Total != 0 || result.Succeeded != 0 {
		t.Errorf("result = %+v, want empty", result)
	}
}
