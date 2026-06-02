package checks_test

import (
	"context"
	"testing"

	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
	"github.com/kennguy3n/visible-fishbone/internal/service/troubleshoot/checks"
)

func TestIntegrationHealthCheck_NoConnectors(t *testing.T) {
	store := memory.NewStore()
	tenant := seedTenantForChecks(t, store)
	connRepo := memory.NewIntegrationConnectorRepository(store)
	check := checks.NewIntegrationHealthCheck(connRepo)

	result := check.Run(context.Background(), tenant.ID)
	if result.Status != checks.DiagnosticPass {
		t.Fatalf("expected pass with no connectors, got %s: %s", result.Status, result.Message)
	}
}
