package checks_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
	"github.com/kennguy3n/visible-fishbone/internal/service/troubleshoot/checks"
)

func TestCertHealthCheck_NoEnrollments(t *testing.T) {
	store := memory.NewStore()
	tenant := seedTenantForChecks(t, store)
	enrollRepo := memory.NewDeviceEnrollmentRepository(store)
	check := checks.NewCertHealthCheck(enrollRepo, 30*24*time.Hour)

	result := check.Run(context.Background(), tenant.ID)
	if result.Status != checks.DiagnosticPass {
		t.Fatalf("expected pass with no enrollments, got %s: %s", result.Status, result.Message)
	}

	_ = uuid.New() // satisfy import
}
