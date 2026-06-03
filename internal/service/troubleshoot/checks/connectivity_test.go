package checks_test

import (
	"context"
	"encoding/json"
	"fmt"
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

// TestConnectivityCheck_PaginatesBeyondOnePage seeds more devices than
// repository.MaxPageLimit (200) to prove the check walks every page
// rather than only evaluating the first one.
func TestConnectivityCheck_PaginatesBeyondOnePage(t *testing.T) {
	store := memory.NewStore()
	tenant := seedTenantForChecks(t, store)
	deviceRepo := memory.NewDeviceRepository(store)

	const total = repository.MaxPageLimit + 50 // 250 > one page
	stale := time.Now().UTC().Add(-10 * time.Minute)
	for i := 0; i < total; i++ {
		_, err := deviceRepo.Create(context.Background(), tenant.ID, repository.Device{
			Name:       fmt.Sprintf("dev-%d", i),
			Platform:   "linux",
			LastSeenAt: &stale,
		})
		if err != nil {
			t.Fatal(err)
		}
	}

	check := checks.NewConnectivityCheck(deviceRepo, 5*time.Minute)
	result := check.Run(context.Background(), tenant.ID)

	var details struct {
		TotalDevices int `json:"total_devices"`
		StaleDevices int `json:"stale_devices"`
	}
	if err := json.Unmarshal(result.Details, &details); err != nil {
		t.Fatalf("unmarshal details: %v", err)
	}
	if details.TotalDevices != total {
		t.Fatalf("expected all %d devices evaluated, got total_devices=%d", total, details.TotalDevices)
	}
	if details.StaleDevices != total {
		t.Fatalf("expected all %d devices counted stale, got stale_devices=%d", total, details.StaleDevices)
	}
	if result.Status != checks.DiagnosticFail {
		t.Fatalf("expected fail when every device is stale, got %s", result.Status)
	}
}
