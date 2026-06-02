package ai

import (
	"strings"
	"testing"
)

func TestRenderTemplate_NoEvents(t *testing.T) {
	t.Parallel()
	data := TemplateData{
		TenantID:       "test-tenant",
		TimeRangeLabel: "2024-01-01T00:00:00Z to 2024-01-02T00:00:00Z",
	}
	s := RenderTemplate(data)
	if s.AIGenerated {
		t.Fatal("template output must have ai_generated=false")
	}
	if !strings.Contains(s.Text, "test-tenant") {
		t.Fatalf("expected tenant ID in text, got: %s", s.Text)
	}
	if len(s.KeyFindings) != 1 || !strings.Contains(s.KeyFindings[0], "No significant events") {
		t.Fatalf("expected 'No significant events' finding, got: %v", s.KeyFindings)
	}
	if len(s.RecommendedActions) != 1 || !strings.Contains(s.RecommendedActions[0], "No immediate action") {
		t.Fatalf("expected 'No immediate action' action, got: %v", s.RecommendedActions)
	}
}

func TestRenderTemplate_WithAlerts(t *testing.T) {
	t.Parallel()
	data := TemplateData{
		TenantID:       "tenant-1",
		AlertCount:     5,
		TopAlertKinds:  []string{"brute_force", "port_scan"},
		BaselineCount:  2,
		TopDimensions:  []string{"login_rate"},
		VerdictCount:   10,
		DenyCount:      3,
		AllowCount:     7,
		TimeRangeLabel: "last 24h",
	}
	s := RenderTemplate(data)
	if s.AIGenerated {
		t.Fatal("template output must have ai_generated=false")
	}
	if len(s.KeyFindings) < 3 {
		t.Fatalf("expected at least 3 findings, got %d: %v", len(s.KeyFindings), s.KeyFindings)
	}
	if !strings.Contains(s.KeyFindings[0], "5 alert(s)") {
		t.Fatalf("expected alert count, got: %s", s.KeyFindings[0])
	}
	if !strings.Contains(s.KeyFindings[0], "brute_force") {
		t.Fatalf("expected top alert kind, got: %s", s.KeyFindings[0])
	}
	if !strings.Contains(s.KeyFindings[1], "2 baseline deviation") {
		t.Fatalf("expected baseline count, got: %s", s.KeyFindings[1])
	}
	if !strings.Contains(s.KeyFindings[2], "10 policy verdict") {
		t.Fatalf("expected verdict count, got: %s", s.KeyFindings[2])
	}
	if len(s.RecommendedActions) < 3 {
		t.Fatalf("expected at least 3 actions, got %d", len(s.RecommendedActions))
	}
}

func TestRenderTemplate_AIGeneratedAlwaysFalse(t *testing.T) {
	t.Parallel()
	cases := []TemplateData{
		{TenantID: "t1", TimeRangeLabel: "x"},
		{TenantID: "t2", AlertCount: 1, TimeRangeLabel: "x"},
		{TenantID: "t3", VerdictCount: 5, DenyCount: 5, TimeRangeLabel: "x"},
	}
	for _, data := range cases {
		s := RenderTemplate(data)
		if s.AIGenerated {
			t.Fatalf("expected ai_generated=false for data: %+v", data)
		}
	}
}
