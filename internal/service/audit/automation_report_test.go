package audit_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/service/audit"
)

func TestAutomationReport_Generate(t *testing.T) {
	svc := audit.NewAutomationReportService(nil)
	tenantID := uuid.New()
	from := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	to := time.Date(2025, 1, 31, 23, 59, 59, 0, time.UTC)

	actions := []audit.AutomationAction{
		{ID: uuid.New(), TenantID: tenantID, ActionType: "playbook_execution", Outcome: "success", Timestamp: from.AddDate(0, 0, 1)},
		{ID: uuid.New(), TenantID: tenantID, ActionType: "ai_suggestion", Outcome: "success", Timestamp: from.AddDate(0, 0, 2)},
		{ID: uuid.New(), TenantID: tenantID, ActionType: "cert_rotation", Outcome: "failure", Timestamp: from.AddDate(0, 0, 3)},
		{ID: uuid.New(), TenantID: tenantID, ActionType: "policy_auto_review", Outcome: "success", Timestamp: from.AddDate(0, 0, 4)},
		{ID: uuid.New(), TenantID: uuid.New(), ActionType: "playbook_execution", Outcome: "success", Timestamp: from.AddDate(0, 0, 5)}, // other tenant
	}
	svc.AddStaticActions(actions)

	report, err := svc.GenerateReport(context.Background(), tenantID, from, to)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if report.TenantID != tenantID {
		t.Error("wrong tenant_id")
	}
	if len(report.Actions) != 4 {
		t.Errorf("actions = %d, want 4", len(report.Actions))
	}
	if report.Summary.TotalActions != 4 {
		t.Errorf("total = %d, want 4", report.Summary.TotalActions)
	}
	if report.Summary.PlaybookExecutions != 1 {
		t.Errorf("playbook = %d, want 1", report.Summary.PlaybookExecutions)
	}
	if report.Summary.AISuggestions != 1 {
		t.Errorf("ai = %d, want 1", report.Summary.AISuggestions)
	}
	if report.Summary.CertRotations != 1 {
		t.Errorf("cert = %d, want 1", report.Summary.CertRotations)
	}
	if report.Summary.PolicyAutoReviews != 1 {
		t.Errorf("review = %d, want 1", report.Summary.PolicyAutoReviews)
	}
	if report.Summary.SuccessRate != 75 {
		t.Errorf("success_rate = %f, want 75", report.Summary.SuccessRate)
	}
}

func TestAutomationReport_TimeFiltering(t *testing.T) {
	svc := audit.NewAutomationReportService(nil)
	tenantID := uuid.New()
	from := time.Date(2025, 1, 10, 0, 0, 0, 0, time.UTC)
	to := time.Date(2025, 1, 20, 0, 0, 0, 0, time.UTC)

	actions := []audit.AutomationAction{
		{ID: uuid.New(), TenantID: tenantID, ActionType: "playbook_execution", Outcome: "success", Timestamp: time.Date(2025, 1, 5, 0, 0, 0, 0, time.UTC)},  // before
		{ID: uuid.New(), TenantID: tenantID, ActionType: "cert_rotation", Outcome: "success", Timestamp: time.Date(2025, 1, 15, 0, 0, 0, 0, time.UTC)},       // in range
		{ID: uuid.New(), TenantID: tenantID, ActionType: "ai_suggestion", Outcome: "success", Timestamp: time.Date(2025, 1, 25, 0, 0, 0, 0, time.UTC)},       // after
	}
	svc.AddStaticActions(actions)

	report, err := svc.GenerateReport(context.Background(), tenantID, from, to)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if len(report.Actions) != 1 {
		t.Errorf("actions = %d, want 1 (only in-range)", len(report.Actions))
	}
}

func TestAutomationReport_ExportJSON(t *testing.T) {
	svc := audit.NewAutomationReportService(nil)
	tenantID := uuid.New()
	from := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	to := time.Date(2025, 1, 31, 0, 0, 0, 0, time.UTC)

	actions := []audit.AutomationAction{
		{ID: uuid.New(), TenantID: tenantID, ActionType: "cert_rotation", Outcome: "success", Timestamp: from.AddDate(0, 0, 1)},
	}
	svc.AddStaticActions(actions)

	report, err := svc.GenerateReport(context.Background(), tenantID, from, to)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	data, err := svc.ExportJSON(report)
	if err != nil {
		t.Fatalf("export: %v", err)
	}

	var parsed audit.AutomationReport
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if parsed.TenantID != tenantID {
		t.Error("round-trip tenant_id mismatch")
	}
}

func TestAutomationReport_EmptyActions(t *testing.T) {
	svc := audit.NewAutomationReportService(nil)
	tenantID := uuid.New()
	from := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	to := time.Date(2025, 1, 31, 0, 0, 0, 0, time.UTC)

	report, err := svc.GenerateReport(context.Background(), tenantID, from, to)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if report.Summary.TotalActions != 0 {
		t.Errorf("total = %d, want 0", report.Summary.TotalActions)
	}
	if report.Summary.SuccessRate != 0 {
		t.Errorf("success_rate = %f, want 0", report.Summary.SuccessRate)
	}
}
