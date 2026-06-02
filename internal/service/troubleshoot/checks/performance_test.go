package checks_test

import (
	"context"
	"testing"
	"time"

	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
	"github.com/kennguy3n/visible-fishbone/internal/service/troubleshoot/checks"
)

func TestPerformanceCheck_NoDevices(t *testing.T) {
	store := memory.NewStore()
	tenant := seedTenantForChecks(t, store)
	deviceRepo := memory.NewDeviceRepository(store)
	check := checks.NewPerformanceCheck(deviceRepo, 10*time.Minute)

	result := check.Run(context.Background(), tenant.ID)
	if result.Status != checks.DiagnosticPass {
		t.Fatalf("expected pass with no devices, got %s: %s", result.Status, result.Message)
	}
}
