package ai

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestReportEngine_Generate_TemplateOnly(t *testing.T) {
	t.Parallel()
	engine := NewReportEngine(nil)
	input := PostureInput{
		TenantID: uuid.New(),
		Period: ReportPeriod{
			Start: time.Now().Add(-7 * 24 * time.Hour),
			End:   time.Now(),
			Label: "weekly",
		},
		AlertsBySeverity: map[string]int{
			"critical": 2,
			"high":     5,
			"medium":   10,
			"low":      20,
		},
		ResolvedAlerts:   15,
		PrevPeriodAlerts: 30,
		TopThreats: []ThreatEntry{
			{Kind: "brute_force", Count: 8},
			{Kind: "anomaly", Count: 5},
		},
		TotalPolicies:  20,
		ActivePolicies: 18,
		TotalVerdicts:  1000,
		DenyVerdicts:   50,
	}

	report, err := engine.Generate(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if report.AIGenerated {
		t.Fatal("template-only mode: ai_generated must be false")
	}
	if report.TenantID != input.TenantID {
		t.Fatal("tenant_id mismatch")
	}
	if report.Overview.TotalAlerts != 37 {
		t.Fatalf("expected 37 total alerts, got %d", report.Overview.TotalAlerts)
	}
	if report.Overview.AlertsBySeverity["critical"] != 2 {
		t.Fatalf("expected 2 critical alerts, got %d", report.Overview.AlertsBySeverity["critical"])
	}
	if report.Overview.Trend != "degrading" {
		t.Fatalf("expected degrading trend, got %s", report.Overview.Trend)
	}
	if len(report.Recommendations) == 0 {
		t.Fatal("expected recommendations")
	}
}

func TestReportEngine_Generate_WithLLM(t *testing.T) {
	t.Parallel()
	llm := &reportStubLLM{text: "Executive summary from AI.", modelID: "gpt-4"}
	engine := NewReportEngine(llm)
	input := PostureInput{
		TenantID: uuid.New(),
		Period: ReportPeriod{
			Start: time.Now().Add(-7 * 24 * time.Hour),
			End:   time.Now(),
			Label: "weekly",
		},
		AlertsBySeverity: map[string]int{"high": 3},
		TotalPolicies:    10,
		ActivePolicies:   10,
	}

	report, err := engine.Generate(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !report.AIGenerated {
		t.Fatal("expected ai_generated=true with LLM")
	}
	if report.Summary != "Executive summary from AI." {
		t.Fatalf("expected LLM summary, got %q", report.Summary)
	}
	if report.ModelID != "gpt-4" {
		t.Fatalf("expected model_id gpt-4, got %q", report.ModelID)
	}
}

func TestReportEngine_TrendAnalysis(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name      string
		current   int
		previous  int
		wantDir   string
	}{
		{"stable-zero", 0, 0, "stable"},
		{"degrading-from-zero", 10, 0, "degrading"},
		{"improving", 5, 20, "improving"},
		{"stable-close", 10, 10, "stable"},
		{"degrading", 50, 20, "degrading"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir, _ := computeTrend(tc.current, tc.previous)
			if dir != tc.wantDir {
				t.Errorf("computeTrend(%d, %d) direction = %s, want %s",
					tc.current, tc.previous, dir, tc.wantDir)
			}
		})
	}
}

func TestReportEngine_PolicyCoverage(t *testing.T) {
	t.Parallel()
	engine := NewReportEngine(nil)
	input := PostureInput{
		TenantID: uuid.New(),
		Period: ReportPeriod{
			Start: time.Now().Add(-30 * 24 * time.Hour),
			End:   time.Now(),
			Label: "monthly",
		},
		AlertsBySeverity: map[string]int{},
		TotalPolicies:    10,
		ActivePolicies:   5,
	}

	report, err := engine.Generate(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if report.PolicyHealth.CoveragePct != 50 {
		t.Fatalf("expected 50%% coverage, got %.1f%%", report.PolicyHealth.CoveragePct)
	}
	foundCoverageRec := false
	for _, r := range report.Recommendations {
		if len(r) > 0 {
			foundCoverageRec = true
		}
	}
	if !foundCoverageRec {
		t.Fatal("expected coverage recommendation")
	}
}

// --- test stubs ---

type reportStubLLM struct {
	text    string
	modelID string
	err     error
}

func (s *reportStubLLM) Complete(_ context.Context, _ LLMRequest) (LLMResponse, error) {
	if s.err != nil {
		return LLMResponse{}, s.err
	}
	return LLMResponse{Text: s.text, ModelID: s.modelID, TokenCount: 80}, nil
}
