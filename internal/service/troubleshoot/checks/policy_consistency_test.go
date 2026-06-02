package checks_test

import (
	"context"
	"testing"

	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
	"github.com/kennguy3n/visible-fishbone/internal/service/troubleshoot/checks"
)

func TestPolicyConsistencyCheck_NoPolicies(t *testing.T) {
	store := memory.NewStore()
	tenant := seedTenantForChecks(t, store)
	policyRepo := memory.NewPolicyRepository(store)
	check := checks.NewPolicyConsistencyCheck(policyRepo)

	result := check.Run(context.Background(), tenant.ID)
	if result.Status != checks.DiagnosticPass {
		t.Fatalf("expected pass with no policies, got %s: %s", result.Status, result.Message)
	}
}
