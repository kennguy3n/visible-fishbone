package identity_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/service/identity"
)

func TestCertMonitor_HealthSummary(t *testing.T) {
	svc := identity.NewCertMonitorService(nil, nil, nil)
	now := time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)
	svc.SetNowFunc(func() time.Time { return now })

	tenantID := uuid.New()
	revoked := now.Add(-time.Hour)
	certs := []repository.DeviceCertificate{
		{ID: uuid.New(), DeviceID: uuid.New(), TenantID: tenantID, ExpiresAt: now.AddDate(0, 6, 0)},                      // healthy
		{ID: uuid.New(), DeviceID: uuid.New(), TenantID: tenantID, ExpiresAt: now.Add(15 * 24 * time.Hour)},              // expiring soon (within 30d)
		{ID: uuid.New(), DeviceID: uuid.New(), TenantID: tenantID, ExpiresAt: now.Add(-24 * time.Hour)},                  // expired
		{ID: uuid.New(), DeviceID: uuid.New(), TenantID: tenantID, ExpiresAt: now.AddDate(1, 0, 0), RevokedAt: &revoked}, // revoked
		{ID: uuid.New(), DeviceID: uuid.New(), TenantID: uuid.New(), ExpiresAt: now.AddDate(0, 1, 0)},                    // different tenant
	}

	summary := svc.HealthSummary(context.Background(), tenantID, certs)
	if summary.Total != 4 {
		t.Errorf("total = %d, want 4", summary.Total)
	}
	if summary.Healthy != 1 {
		t.Errorf("healthy = %d, want 1", summary.Healthy)
	}
	if summary.ExpiringSoon != 1 {
		t.Errorf("expiring_soon = %d, want 1", summary.ExpiringSoon)
	}
	if summary.Expired != 1 {
		t.Errorf("expired = %d, want 1", summary.Expired)
	}
	if summary.Revoked != 1 {
		t.Errorf("revoked = %d, want 1", summary.Revoked)
	}
}

func TestCertMonitor_FindExpiring(t *testing.T) {
	svc := identity.NewCertMonitorService(nil, nil, nil)
	now := time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)
	svc.SetNowFunc(func() time.Time { return now })

	tenantID := uuid.New()
	certs := []repository.DeviceCertificate{
		{ID: uuid.New(), DeviceID: uuid.New(), TenantID: tenantID, Serial: "A", ExpiresAt: now.Add(10 * 24 * time.Hour)},
		{ID: uuid.New(), DeviceID: uuid.New(), TenantID: tenantID, Serial: "B", ExpiresAt: now.AddDate(0, 6, 0)},
		{ID: uuid.New(), DeviceID: uuid.New(), TenantID: tenantID, Serial: "C", ExpiresAt: now.Add(-24 * time.Hour)},
	}

	expiring := svc.FindExpiring(context.Background(), tenantID, certs)
	if len(expiring) != 2 {
		t.Fatalf("expiring = %d, want 2 (one within threshold, one expired)", len(expiring))
	}
}

func TestCertMonitor_FindExpiring_IgnoresRevoked(t *testing.T) {
	svc := identity.NewCertMonitorService(nil, nil, nil)
	now := time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)
	svc.SetNowFunc(func() time.Time { return now })

	tenantID := uuid.New()
	revoked := now.Add(-time.Hour)
	certs := []repository.DeviceCertificate{
		{ID: uuid.New(), DeviceID: uuid.New(), TenantID: tenantID, ExpiresAt: now.Add(5 * 24 * time.Hour), RevokedAt: &revoked},
	}
	expiring := svc.FindExpiring(context.Background(), tenantID, certs)
	if len(expiring) != 0 {
		t.Errorf("revoked cert should not be in expiring list, got %d", len(expiring))
	}
}

func TestCertMonitor_CheckRenewalStatus(t *testing.T) {
	svc := identity.NewCertMonitorService(nil, nil, nil)
	now := time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)
	svc.SetNowFunc(func() time.Time { return now })

	tenantID := uuid.New()
	deviceID := uuid.New()
	lastIssued := now.Add(-48 * time.Hour)

	enrollment := repository.DeviceEnrollment{
		DeviceID:         deviceID,
		TenantID:         tenantID,
		Status:           repository.EnrollmentStatusActive,
		LastCertIssuedAt: &lastIssued,
	}

	// Cert expiring in 10 days (within 30-day threshold) + a renewed cert.
	certs := []repository.DeviceCertificate{
		{ID: uuid.New(), DeviceID: deviceID, TenantID: tenantID, ExpiresAt: now.Add(10 * 24 * time.Hour), IssuedAt: lastIssued.Add(-30 * 24 * time.Hour)},
		{ID: uuid.New(), DeviceID: deviceID, TenantID: tenantID, ExpiresAt: now.Add(365 * 24 * time.Hour), IssuedAt: lastIssued},
	}

	status := svc.CheckRenewalStatus(enrollment, certs)
	if !status.Triggered {
		t.Error("expected triggered")
	}
	if !status.RenewedAfter {
		t.Error("expected renewed after trigger")
	}
}

func TestCertMonitor_CustomThreshold(t *testing.T) {
	svc := identity.NewCertMonitorService(nil, nil, nil)
	now := time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)
	svc.SetNowFunc(func() time.Time { return now })
	svc.SetThreshold(7 * 24 * time.Hour) // 7-day window

	tenantID := uuid.New()
	certs := []repository.DeviceCertificate{
		{ID: uuid.New(), DeviceID: uuid.New(), TenantID: tenantID, ExpiresAt: now.Add(15 * 24 * time.Hour)},
	}

	summary := svc.HealthSummary(context.Background(), tenantID, certs)
	if summary.Healthy != 1 {
		t.Error("cert 15d out should be healthy with 7d threshold")
	}
	if summary.ExpiringSoon != 0 {
		t.Errorf("expiring_soon = %d, want 0", summary.ExpiringSoon)
	}
}
