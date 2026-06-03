package ai

import (
	"encoding/json"
	"testing"
)

func TestBuiltinTemplates(t *testing.T) {
	t.Parallel()
	templates := BuiltinTemplates()
	if len(templates) != 4 {
		t.Fatalf("expected 4 templates, got %d", len(templates))
	}

	names := map[string]bool{}
	for _, tmpl := range templates {
		if tmpl.Name == "" {
			t.Fatal("template name must not be empty")
		}
		if names[tmpl.Name] {
			t.Fatalf("duplicate template name: %s", tmpl.Name)
		}
		names[tmpl.Name] = true

		if tmpl.Category == "" {
			t.Fatalf("template %s: category must not be empty", tmpl.Name)
		}
		if tmpl.TitleTemplate == "" {
			t.Fatalf("template %s: title_template must not be empty", tmpl.Name)
		}
		if tmpl.Action == "" {
			t.Fatalf("template %s: action must not be empty", tmpl.Name)
		}
		if len(tmpl.RequiredContext) == 0 {
			t.Fatalf("template %s: required_context must not be empty", tmpl.Name)
		}
	}
}

func TestApplyTemplate_RemoveUnused(t *testing.T) {
	t.Parallel()
	tmpl := removeUnusedRuleTemplate()
	ruleRaw := json.RawMessage(`{"id":"r1","verb":"allow"}`)

	suggestion := ApplyTemplate(tmpl, "r1", 90, ruleRaw)
	if suggestion.Category != SuggestionCategoryUnused {
		t.Fatalf("expected category=unused, got %s", suggestion.Category)
	}
	if suggestion.Confidence != 0.95 {
		t.Fatalf("expected confidence=0.95 for 90 days, got %f", suggestion.Confidence)
	}
	if suggestion.Change.Action != "remove" {
		t.Fatalf("expected action=remove, got %s", suggestion.Change.Action)
	}
	if suggestion.Risk.Level != RiskLevelLow {
		t.Fatalf("expected risk=low, got %s", suggestion.Risk.Level)
	}
}

func TestApplyTemplate_NarrowScope(t *testing.T) {
	t.Parallel()
	tmpl := narrowSourceScopeTemplate()
	ruleRaw := json.RawMessage(`{"id":"r2","verb":"allow"}`)

	suggestion := ApplyTemplate(tmpl, "r2", 30, ruleRaw)
	if suggestion.Category != SuggestionCategoryOverlyPermissive {
		t.Fatalf("expected category=overly_permissive, got %s", suggestion.Category)
	}
	if suggestion.Change.Action != "modify" {
		t.Fatalf("expected action=modify, got %s", suggestion.Change.Action)
	}
	if suggestion.Risk.Level != RiskLevelMedium {
		t.Fatalf("expected risk=medium, got %s", suggestion.Risk.Level)
	}
}

func TestApplyTemplate_TimeRestriction(t *testing.T) {
	t.Parallel()
	tmpl := addTimeRestrictionTemplate()
	ruleRaw := json.RawMessage(`{"id":"r3","verb":"allow"}`)

	suggestion := ApplyTemplate(tmpl, "r3", 30, ruleRaw)
	if suggestion.Change.Action != "modify" {
		t.Fatalf("expected action=modify, got %s", suggestion.Change.Action)
	}
}

func TestApplyTemplate_EnableLogging(t *testing.T) {
	t.Parallel()
	tmpl := enableLoggingTemplate()
	ruleRaw := json.RawMessage(`{"id":"r4","verb":"allow"}`)

	suggestion := ApplyTemplate(tmpl, "r4", 30, ruleRaw)
	if suggestion.Category != SuggestionCategoryDenyLog {
		t.Fatalf("expected category=deny_log, got %s", suggestion.Category)
	}
	if suggestion.Confidence != 0.95 {
		t.Fatalf("expected confidence=0.95 for enable_logging, got %f", suggestion.Confidence)
	}
	if suggestion.Change.Action != "add_logging" {
		t.Fatalf("expected action=add_logging, got %s", suggestion.Change.Action)
	}
	if suggestion.Risk.Level != RiskLevelLow {
		t.Fatalf("expected risk=low, got %s", suggestion.Risk.Level)
	}
}

func TestTemplateConfidence(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		tmpl     SuggestionTemplate
		days     int
		expected float64
	}{
		{"unused_30", removeUnusedRuleTemplate(), 30, 0.7},
		{"unused_60", removeUnusedRuleTemplate(), 60, 0.85},
		{"unused_90", removeUnusedRuleTemplate(), 90, 0.95},
		{"logging", enableLoggingTemplate(), 30, 0.95},
		{"narrow", narrowSourceScopeTemplate(), 30, 0.6},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := templateConfidence(tt.tmpl, tt.days)
			if got != tt.expected {
				t.Fatalf("expected %f, got %f", tt.expected, got)
			}
		})
	}
}
