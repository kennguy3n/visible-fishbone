package identity_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/middleware"
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
	audit := memory.NewAuditLogRepository(store)
	svc := identity.NewBulkDeviceService(devices, tokens, enrolls, audit, nil)
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

// certRevokeFailRepo wraps a real enrollment repository but forces
// RevokeAllCertificates to fail, so we can assert BulkRevoke's
// fail-closed handling of a partially-revoked device.
type certRevokeFailRepo struct {
	repository.DeviceEnrollmentRepository
	err error
}

func (r certRevokeFailRepo) RevokeAllCertificates(_ context.Context, _ uuid.UUID, _ uuid.UUID, _ time.Time) error {
	return r.err
}

// pgLikeEnrollRepo mimics the Postgres enrollment store's guarded
// transition (`UPDATE ... WHERE status != 'revoked'` returns
// ErrNotFound for an already-revoked enrollment), plus a toggleable
// certificate-revocation failure, so we can exercise BulkRevoke's
// retry/heal path that the in-memory store cannot reproduce.
type pgLikeEnrollRepo struct {
	repository.DeviceEnrollmentRepository
	exists    map[uuid.UUID]bool
	revoked   map[uuid.UUID]bool
	certFail  bool
	certCalls map[uuid.UUID]int
}

func (r *pgLikeEnrollRepo) UpdateEnrollmentStatus(_ context.Context, _ uuid.UUID, did uuid.UUID, status repository.EnrollmentStatus) error {
	if !r.exists[did] {
		return repository.ErrNotFound
	}
	if status == repository.EnrollmentStatusRevoked && r.revoked[did] {
		return repository.ErrNotFound // guarded transition: no row matches
	}
	if status == repository.EnrollmentStatusRevoked {
		r.revoked[did] = true
	}
	return nil
}

func (r *pgLikeEnrollRepo) GetEnrollmentAnyStatus(_ context.Context, tid uuid.UUID, did uuid.UUID) (repository.DeviceEnrollment, error) {
	if !r.exists[did] {
		return repository.DeviceEnrollment{}, repository.ErrNotFound
	}
	st := repository.EnrollmentStatusActive
	if r.revoked[did] {
		st = repository.EnrollmentStatusRevoked
	}
	return repository.DeviceEnrollment{DeviceID: did, TenantID: tid, Status: st}, nil
}

func (r *pgLikeEnrollRepo) RevokeAllCertificates(_ context.Context, _ uuid.UUID, did uuid.UUID, _ time.Time) error {
	r.certCalls[did]++
	if r.certFail {
		return errors.New("ca unreachable")
	}
	return nil
}

func TestBulkDevice_Revoke_RetryHealsHalfRevoked(t *testing.T) {
	store := memory.NewStore()
	tenantID := uuid.New()
	ctx := context.Background()
	if _, err := memory.NewTenantRepository(store).Create(ctx, repository.Tenant{
		ID: tenantID, Name: "heal", Slug: "heal",
	}); err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	did := uuid.New()
	enrolls := &pgLikeEnrollRepo{
		exists:    map[uuid.UUID]bool{did: true},
		revoked:   map[uuid.UUID]bool{},
		certFail:  true,
		certCalls: map[uuid.UUID]int{},
	}
	svc := identity.NewBulkDeviceService(
		memory.NewDeviceRepository(store),
		memory.NewClaimTokenRepository(store),
		enrolls, memory.NewAuditLogRepository(store), nil)

	// First attempt: enrollment flips to revoked but cert revocation
	// fails, leaving the device half-revoked and reported as Failed.
	r1, err := svc.BulkRevoke(ctx, tenantID, []uuid.UUID{did})
	if err != nil {
		t.Fatalf("bulk revoke (1): %v", err)
	}
	if r1.Succeeded != 0 || r1.Failed != 1 {
		t.Fatalf("attempt 1: succeeded=%d failed=%d, want 0/1", r1.Succeeded, r1.Failed)
	}
	if !enrolls.revoked[did] {
		t.Fatal("attempt 1: enrollment should be revoked")
	}
	if enrolls.certCalls[did] != 1 {
		t.Fatalf("attempt 1: cert revoke calls=%d, want 1", enrolls.certCalls[did])
	}

	// CA recovers. A retry must heal the half-revoked device by
	// re-running certificate revocation even though the guarded
	// enrollment update now reports ErrNotFound (already revoked).
	enrolls.certFail = false
	r2, err := svc.BulkRevoke(ctx, tenantID, []uuid.UUID{did})
	if err != nil {
		t.Fatalf("bulk revoke (2): %v", err)
	}
	if r2.Succeeded != 1 || r2.Failed != 0 {
		t.Errorf("attempt 2: succeeded=%d failed=%d, want 1/0 (retry should heal)", r2.Succeeded, r2.Failed)
	}
	if enrolls.certCalls[did] != 2 {
		t.Errorf("attempt 2: cert revoke calls=%d, want 2 (must be retried)", enrolls.certCalls[did])
	}
}

func TestBulkDevice_Revoke_CertFailureCountsAsFailed(t *testing.T) {
	store := memory.NewStore()
	tenantID := uuid.New()
	if _, err := memory.NewTenantRepository(store).Create(context.Background(), repository.Tenant{
		ID: tenantID, Name: "cert-fail", Slug: "cert-fail",
	}); err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	ctx := context.Background()

	realEnroll := memory.NewDeviceEnrollmentRepository(store)
	deviceID := uuid.New()
	if _, err := realEnroll.CreateEnrollment(ctx, tenantID, repository.DeviceEnrollment{
		DeviceID: deviceID,
		Status:   repository.EnrollmentStatusActive,
	}); err != nil {
		t.Fatalf("create enrollment: %v", err)
	}

	enrolls := certRevokeFailRepo{
		DeviceEnrollmentRepository: realEnroll,
		err:                        errors.New("ca unreachable"),
	}
	audit := memory.NewAuditLogRepository(store)
	svc := identity.NewBulkDeviceService(
		memory.NewDeviceRepository(store),
		memory.NewClaimTokenRepository(store),
		enrolls, audit, nil)

	result, err := svc.BulkRevoke(ctx, tenantID, []uuid.UUID{deviceID})
	if err != nil {
		t.Fatalf("bulk revoke: %v", err)
	}
	// Fail closed: the enrollment was revoked but its certificates were
	// not, so the device must NOT count as a clean success.
	if result.Succeeded != 0 {
		t.Errorf("succeeded = %d, want 0 when cert revocation fails", result.Succeeded)
	}
	if result.Failed != 1 {
		t.Errorf("failed = %d, want 1 when cert revocation fails", result.Failed)
	}
	if len(result.Errors) != 1 || !strings.Contains(result.Errors[0], "certificate revocation failed") {
		t.Errorf("errors = %v, want one mentioning certificate revocation", result.Errors)
	}
	// The enrollment transition that did occur must still be audited.
	entries, err := audit.List(ctx, tenantID,
		repository.AuditFilter{Action: "device.enrollment.revoked"},
		repository.Page{Limit: 10})
	if err != nil {
		t.Fatalf("list audit: %v", err)
	}
	if len(entries.Items) != 1 {
		t.Errorf("audit entries = %d, want 1 (enrollment revocation is still recorded)", len(entries.Items))
	}
}

func TestBulkDevice_Revoke_EmitsAuditTrail(t *testing.T) {
	svc, store, tenantID := setupBulkTest(t)
	ctx := context.Background()

	enrollRepo := memory.NewDeviceEnrollmentRepository(store)
	ids := make([]uuid.UUID, 2)
	for i := range ids {
		ids[i] = uuid.New()
		if _, err := enrollRepo.CreateEnrollment(ctx, tenantID, repository.DeviceEnrollment{
			DeviceID: ids[i],
			Status:   repository.EnrollmentStatusActive,
		}); err != nil {
			t.Fatalf("create enrollment %d: %v", i, err)
		}
	}

	if _, err := svc.BulkRevoke(ctx, tenantID, ids); err != nil {
		t.Fatalf("bulk revoke: %v", err)
	}

	// Each successful revocation must leave an audit entry, matching the
	// single-device RevokeDevice path so compliance reporting is complete.
	auditRepo := memory.NewAuditLogRepository(store)
	entries, err := auditRepo.List(ctx, tenantID,
		repository.AuditFilter{Action: "device.enrollment.revoked"},
		repository.Page{Limit: 100})
	if err != nil {
		t.Fatalf("list audit: %v", err)
	}
	if len(entries.Items) != len(ids) {
		t.Fatalf("audit entries = %d, want %d", len(entries.Items), len(ids))
	}
	for _, e := range entries.Items {
		if e.ResourceType != "device_enrollment" {
			t.Errorf("resource type = %q, want device_enrollment", e.ResourceType)
		}
		if e.ResourceID == nil {
			t.Error("audit entry missing resource id")
		}
	}
}

func TestBulkDevice_Revoke_AuditCarriesActorID(t *testing.T) {
	svc, store, tenantID := setupBulkTest(t)
	actor := uuid.New()
	ctx := middleware.WithUserIDForTest(context.Background(), actor)

	enrollRepo := memory.NewDeviceEnrollmentRepository(store)
	deviceID := uuid.New()
	if _, err := enrollRepo.CreateEnrollment(ctx, tenantID, repository.DeviceEnrollment{
		DeviceID: deviceID,
		Status:   repository.EnrollmentStatusActive,
	}); err != nil {
		t.Fatalf("create enrollment: %v", err)
	}

	if _, err := svc.BulkRevoke(ctx, tenantID, []uuid.UUID{deviceID}); err != nil {
		t.Fatalf("bulk revoke: %v", err)
	}

	// The human initiator must be attributed on the audit entry's
	// ActorID column, not just buried in details, so compliance
	// queries can trace who triggered the bulk operation.
	auditRepo := memory.NewAuditLogRepository(store)
	entries, err := auditRepo.List(ctx, tenantID,
		repository.AuditFilter{Action: "device.enrollment.revoked"},
		repository.Page{Limit: 10})
	if err != nil {
		t.Fatalf("list audit: %v", err)
	}
	if len(entries.Items) != 1 {
		t.Fatalf("audit entries = %d, want 1", len(entries.Items))
	}
	got := entries.Items[0]
	if got.ActorID == nil || *got.ActorID != actor {
		t.Errorf("ActorID = %v, want %v", got.ActorID, actor)
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

func TestBulkDevice_ImportCSV_EmptyStatusDefaultsToPending(t *testing.T) {
	svc, store, tenantID := setupBulkTest(t)
	ctx := context.Background()

	// status column left blank must not persist an empty, non-enum status.
	csv := "device_id,name,platform,status,created_at\n" +
		"abc-123,dev1,linux,,2025-01-01T00:00:00Z\n"

	result, err := svc.ImportCSV(ctx, tenantID, strings.NewReader(csv))
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if result.Succeeded != 1 || result.Failed != 0 {
		t.Fatalf("result = %+v, want succeeded=1 failed=0", result)
	}
	page, err := memory.NewDeviceRepository(store).List(
		ctx, tenantID, repository.DeviceListFilter{}, repository.Page{Limit: 50})
	if err != nil {
		t.Fatalf("list devices: %v", err)
	}
	if len(page.Items) != 1 {
		t.Fatalf("persisted devices = %d, want 1", len(page.Items))
	}
	if got := page.Items[0].Status; got != repository.DeviceStatusPending {
		t.Errorf("status = %q, want %q", got, repository.DeviceStatusPending)
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
