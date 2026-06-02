package compliance_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
	"github.com/kennguy3n/visible-fishbone/internal/service/compliance"
)

func newTestService() (*compliance.ReportService, *memory.Store) {
	store := memory.NewStore()
	repo := memory.NewComplianceReportRepository(store)
	svc := compliance.NewReportService(repo, nil)
	return svc, store
}

func TestGenerate_AllFrameworks(t *testing.T) {
	svc, _ := newTestService()
	ctx := context.Background()
	tenantID := uuid.New()

	frameworks := []compliance.ComplianceFramework{
		compliance.FrameworkPCIDSS,
		compliance.FrameworkHIPAA,
		compliance.FrameworkSOC2,
		compliance.FrameworkISO27001,
	}

	for _, fw := range frameworks {
		report, err := svc.Generate(ctx, tenantID, fw, compliance.EnforcedPolicies{
			DLP:     true,
			Browser: true,
			CASB:    true,
			Policy:  true,
		})
		if err != nil {
			t.Fatalf("Generate(%s): %v", fw, err)
		}
		if report.Framework != fw {
			t.Errorf("expected framework %s, got %s", fw, report.Framework)
		}
		if report.TenantID != tenantID {
			t.Error("tenant ID mismatch")
		}
		if report.Score < 0 || report.Score > report.MaxScore {
			t.Errorf("score %f out of range [0, %f]", report.Score, report.MaxScore)
		}
		if len(report.Controls) == 0 {
			t.Error("expected non-empty controls")
		}
		if len(report.EvidencePack) == 0 {
			t.Error("expected non-empty evidence pack")
		}
	}
}

func TestGenerate_InvalidFramework(t *testing.T) {
	svc, _ := newTestService()
	ctx := context.Background()
	_, err := svc.Generate(ctx, uuid.New(), "INVALID", compliance.EnforcedPolicies{})
	if err != repository.ErrInvalidArgument {
		t.Errorf("expected ErrInvalidArgument, got %v", err)
	}
}

func TestGenerate_NoPolicies_ZeroScore(t *testing.T) {
	svc, _ := newTestService()
	ctx := context.Background()
	report, err := svc.Generate(ctx, uuid.New(), compliance.FrameworkPCIDSS, compliance.EnforcedPolicies{})
	if err != nil {
		t.Fatal(err)
	}
	if report.Score != 0 {
		t.Errorf("expected score 0 with no policies, got %f", report.Score)
	}
	for _, c := range report.Controls {
		if c.Status != compliance.ControlUnmet {
			t.Errorf("control %s should be unmet, got %s", c.ControlID, c.Status)
		}
	}
}

func TestGenerate_AllPolicies_PositiveScore(t *testing.T) {
	svc, _ := newTestService()
	ctx := context.Background()
	report, err := svc.Generate(ctx, uuid.New(), compliance.FrameworkPCIDSS, compliance.EnforcedPolicies{
		DLP:           true,
		Browser:       true,
		CASB:          true,
		Policy:        true,
		AccessControl: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Score == 0 {
		t.Error("expected positive score with all policies enforced")
	}
	if report.Score != report.MaxScore {
		t.Errorf("expected full score %f with all policies, got %f", report.MaxScore, report.Score)
	}
}

func TestGet_NotFound(t *testing.T) {
	svc, _ := newTestService()
	ctx := context.Background()
	_, err := svc.Get(ctx, uuid.New(), uuid.New())
	if err != repository.ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestList_Empty(t *testing.T) {
	svc, _ := newTestService()
	ctx := context.Background()
	result, err := svc.List(ctx, uuid.New(), repository.Page{})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Items) != 0 {
		t.Errorf("expected empty list, got %d items", len(result.Items))
	}
}

func TestList_ReturnsGenerated(t *testing.T) {
	svc, _ := newTestService()
	ctx := context.Background()
	tenantID := uuid.New()
	_, err := svc.Generate(ctx, tenantID, compliance.FrameworkSOC2, compliance.EnforcedPolicies{DLP: true})
	if err != nil {
		t.Fatal(err)
	}
	result, err := svc.List(ctx, tenantID, repository.Page{})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Items) != 1 {
		t.Errorf("expected 1 item, got %d", len(result.Items))
	}
}

func TestGetEvidence_ValidJSON(t *testing.T) {
	svc, _ := newTestService()
	ctx := context.Background()
	tenantID := uuid.New()
	report, err := svc.Generate(ctx, tenantID, compliance.FrameworkHIPAA, compliance.EnforcedPolicies{CASB: true})
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := svc.GetEvidence(ctx, tenantID, report.ID)
	if err != nil {
		t.Fatal(err)
	}
	var pack compliance.EvidencePack
	if err := json.Unmarshal(evidence, &pack); err != nil {
		t.Fatalf("evidence pack is not valid JSON: %v", err)
	}
	if pack.Framework != compliance.FrameworkHIPAA {
		t.Errorf("expected HIPAA framework, got %s", pack.Framework)
	}
}

func TestGenerate_TenantIsolation(t *testing.T) {
	svc, _ := newTestService()
	ctx := context.Background()
	tenant1 := uuid.New()
	tenant2 := uuid.New()

	_, err := svc.Generate(ctx, tenant1, compliance.FrameworkSOC2, compliance.EnforcedPolicies{DLP: true})
	if err != nil {
		t.Fatal(err)
	}

	result, err := svc.List(ctx, tenant2, repository.Page{})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Items) != 0 {
		t.Errorf("tenant2 should see 0 reports, got %d", len(result.Items))
	}
}
