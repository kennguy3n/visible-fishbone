package troubleshoot_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
	"github.com/kennguy3n/visible-fishbone/internal/service/troubleshoot"
	"github.com/kennguy3n/visible-fishbone/internal/service/troubleshoot/checks"
)

func TestDiagnosticEngine_RunAll(t *testing.T) {
	store := memory.NewStore()
	tenantID := seedTenant(t, store)
	deviceRepo := memory.NewDeviceRepository(store)

	// Seed a device with a recent heartbeat.
	now := time.Now().UTC()
	_, err := deviceRepo.Create(context.Background(), tenantID, repository.Device{
		Name:       "test-device",
		Platform:   "linux",
		LastSeenAt: &now,
	})
	if err != nil {
		t.Fatal(err)
	}

	connCheck := checks.NewConnectivityCheck(deviceRepo, 5*time.Minute)
	perfCheck := checks.NewPerformanceCheck(deviceRepo, 10*time.Minute)

	engine := troubleshoot.NewDiagnosticEngine([]checks.DiagnosticCheck{connCheck, perfCheck})

	results := engine.RunAll(context.Background(), tenantID)
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}

	for _, r := range results {
		if r.Status != troubleshoot.DiagnosticPass {
			t.Errorf("expected pass for %s, got %s: %s", r.CheckName, r.Status, r.Message)
		}
	}
}

func TestDiagnosticEngine_RunCheck(t *testing.T) {
	store := memory.NewStore()
	tenantID := seedTenant(t, store)
	deviceRepo := memory.NewDeviceRepository(store)

	connCheck := checks.NewConnectivityCheck(deviceRepo, 5*time.Minute)
	engine := troubleshoot.NewDiagnosticEngine([]checks.DiagnosticCheck{connCheck})

	result, err := engine.RunCheck(context.Background(), tenantID, "connectivity")
	if err != nil {
		t.Fatal(err)
	}
	if result.CheckName != "connectivity" {
		t.Fatalf("expected check name 'connectivity', got %q", result.CheckName)
	}
}

func TestDiagnosticEngine_UnknownCheck(t *testing.T) {
	engine := troubleshoot.NewDiagnosticEngine(nil)
	_, err := engine.RunCheck(context.Background(), uuid.New(), "nonexistent")
	if err == nil {
		t.Fatal("expected error for unknown check")
	}
}

func TestDiagnosticEngine_StaleDevice(t *testing.T) {
	store := memory.NewStore()
	tenantID := seedTenant(t, store)
	deviceRepo := memory.NewDeviceRepository(store)

	staleTime := time.Now().UTC().Add(-10 * time.Minute)
	_, err := deviceRepo.Create(context.Background(), tenantID, repository.Device{
		Name:       "stale-device",
		Platform:   "linux",
		LastSeenAt: &staleTime,
	})
	if err != nil {
		t.Fatal(err)
	}

	connCheck := checks.NewConnectivityCheck(deviceRepo, 5*time.Minute)
	engine := troubleshoot.NewDiagnosticEngine([]checks.DiagnosticCheck{connCheck})

	result, err := engine.RunCheck(context.Background(), tenantID, "connectivity")
	if err != nil {
		t.Fatal(err)
	}
	if result.Status == troubleshoot.DiagnosticPass {
		t.Fatal("expected non-pass status for stale device")
	}
}
