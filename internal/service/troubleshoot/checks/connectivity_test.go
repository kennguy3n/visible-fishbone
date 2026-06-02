package checks_test

import (
	"context"
	"testing"
	"time"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
	"github.com/kennguy3n/visible-fishbone/internal/service/troubleshoot/checks"
)

func seedTenantForChecks(t *testing.T, store *memory.Store) repository.Tenant {
	t.Helper()
	repo := memory.NewTenantRepository(store)
	tenant, err := repo.Create(context.Background(), repository.Tenant{
		Name: "check-tenant",
		Slug: "check-" + time.Now().Format("150405"),
	})
	if err != nil {
		t.Fatal(err)
	}
	return tenant
}

func TestConnectivityCheck_NoDevices(t *testing.T) {
	store := memory.NewStore()
	tenant := seedTenantForChecks(t, store)
	deviceRepo := memory.NewDeviceRepository(store)
	check := checks.NewConnectivityCheck(deviceRepo, 5*time.Minute)

	result := check.Run(context.Background(), tenant.ID)
	if result.Status != checks.DiagnosticPass {
		t.Fatalf("expected pass with no devices, got %s", result.Status)
	}
}

func TestConnectivityCheck_HealthyDevice(t *testing.T) {
	store := memory.NewStore()
	tenant := seedTenantForChecks(t, store)
	deviceRepo := memory.NewDeviceRepository(store)

	now := time.Now().UTC()
	_, err := deviceRepo.Create(context.Background(), tenant.ID, repository.Device{
		Name:       "healthy",
		Platform:   "linux",
		LastSeenAt: &now,
	})
	if err != nil {
		t.Fatal(err)
	}

	check := checks.NewConnectivityCheck(deviceRepo, 5*time.Minute)
	result := check.Run(context.Background(), tenant.ID)
	if result.Status != checks.DiagnosticPass {
		t.Fatalf("expected pass, got %s: %s", result.Status, result.Message)
	}
}

func TestConnectivityCheck_StaleDevice(t *testing.T) {
	store := memory.NewStore()
	tenant := seedTenantForChecks(t, store)
	deviceRepo := memory.NewDeviceRepository(store)

	stale := time.Now().UTC().Add(-10 * time.Minute)
	_, err := deviceRepo.Create(context.Background(), tenant.ID, repository.Device{
		Name:       "stale",
		Platform:   "linux",
		LastSeenAt: &stale,
	})
	if err != nil {
		t.Fatal(err)
	}

	check := checks.NewConnectivityCheck(deviceRepo, 5*time.Minute)
	result := check.Run(context.Background(), tenant.ID)
	if result.Status == checks.DiagnosticPass {
		t.Fatal("expected non-pass for stale device")
	}
}
