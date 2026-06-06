package residency_test

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
	"github.com/kennguy3n/visible-fishbone/internal/service/residency"
)

func resolver(region residency.Region, err error) residency.RegionResolverFunc {
	return func(ctx context.Context, _ uuid.UUID) (residency.Region, error) {
		return region, err
	}
}

func TestServiceCheckAllowsMatchingRegion(t *testing.T) {
	audit := memory.NewResidencyAuditRepository(memory.NewStore())
	svc := residency.NewService(resolver("ap-southeast-1", nil), audit, nil)
	tenantID := uuid.New()

	if err := svc.Check(context.Background(), tenantID, residency.PlaneTelemetry, "AP-Southeast-1 "); err != nil {
		t.Fatalf("matching region (normalized) should be allowed, got %v", err)
	}
	entries, err := audit.List(context.Background(), tenantID, 0)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("allowed write must not record an audit entry, got %d", len(entries))
	}
}

func TestServiceCheckUnconfiguredTenantAllowsAnyRegion(t *testing.T) {
	svc := residency.NewService(resolver("", nil), nil, nil)
	if err := svc.Check(context.Background(), uuid.New(), residency.PlaneColdStorage, "eu-central-1"); err != nil {
		t.Fatalf("tenant without a designated region is unconstrained, got %v", err)
	}
}

func TestServiceCheckRejectsCrossRegionAndRecords(t *testing.T) {
	audit := memory.NewResidencyAuditRepository(memory.NewStore())
	svc := residency.NewService(resolver("eu-central-1", nil), audit, nil)
	tenantID := uuid.New()

	err := svc.Check(context.Background(), tenantID, residency.PlaneColdStorage, "us-east-1")
	if !errors.Is(err, residency.ErrResidencyViolation) {
		t.Fatalf("cross-region write must be rejected, got %v", err)
	}
	entries, listErr := audit.List(context.Background(), tenantID, 0)
	if listErr != nil {
		t.Fatalf("List: %v", listErr)
	}
	if len(entries) != 1 {
		t.Fatalf("rejection must record exactly one audit entry, got %d", len(entries))
	}
	got := entries[0]
	if got.Plane != string(residency.PlaneColdStorage) ||
		got.DesignatedRegion != "eu-central-1" || got.AttemptedRegion != "us-east-1" {
		t.Fatalf("unexpected audit entry: %+v", got)
	}
	if got.Detail == "" {
		t.Fatal("audit entry should capture the violation detail")
	}
}

func TestServiceCheckUnknownTargetRegionIsFailClosed(t *testing.T) {
	audit := memory.NewResidencyAuditRepository(memory.NewStore())
	svc := residency.NewService(resolver("ap-southeast-1", nil), audit, nil)
	tenantID := uuid.New()

	if err := svc.Check(context.Background(), tenantID, residency.PlaneTelemetry, ""); !errors.Is(err, residency.ErrResidencyViolation) {
		t.Fatalf("unknown target region must be rejected fail-closed, got %v", err)
	}
	entries, _ := audit.List(context.Background(), tenantID, 0)
	if len(entries) != 1 {
		t.Fatalf("expected one recorded rejection, got %d", len(entries))
	}
}

func TestServiceCheckResolverErrorIsFailClosed(t *testing.T) {
	sentinel := errors.New("tenant lookup failed")
	svc := residency.NewService(resolver("", sentinel), nil, nil)
	err := svc.Check(context.Background(), uuid.New(), residency.PlaneTelemetry, "ap-southeast-1")
	if !errors.Is(err, sentinel) {
		t.Fatalf("resolver error must propagate (fail-closed), got %v", err)
	}
}

func TestServiceRecordSurvivesNilAudit(t *testing.T) {
	// A rejection with no audit sink configured must still return the
	// violation (and not panic).
	svc := residency.NewService(resolver("eu-central-1", nil), nil, nil)
	if err := svc.Check(context.Background(), uuid.New(), residency.PlaneTelemetry, "us-east-1"); !errors.Is(err, residency.ErrResidencyViolation) {
		t.Fatalf("expected violation with nil audit sink, got %v", err)
	}
}

func TestGuardBindsPlaneAndSinkRegion(t *testing.T) {
	audit := memory.NewResidencyAuditRepository(memory.NewStore())
	svc := residency.NewService(resolver("ap-southeast-1", nil), audit, nil)
	tenantID := uuid.New()

	allow := residency.NewGuard(svc, residency.PlaneColdStorage, "ap-southeast-1")
	if err := allow.Check(context.Background(), tenantID); err != nil {
		t.Fatalf("guard whose sink region matches designation should allow, got %v", err)
	}

	deny := residency.NewGuard(svc, residency.PlaneColdStorage, "eu-central-1")
	if err := deny.Check(context.Background(), tenantID); !errors.Is(err, residency.ErrResidencyViolation) {
		t.Fatalf("guard whose sink region differs should deny, got %v", err)
	}
}

// Ensure the memory audit repo satisfies the interface the service
// depends on (compile-time guard mirrored as a runtime no-op).
var _ repository.ResidencyAuditRepository = (*memory.ResidencyAuditRepository)(nil)
