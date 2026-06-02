package ai

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/google/uuid"
)

func TestTighteningService_UnusedRules(t *testing.T) {
	t.Parallel()
	svc := NewTighteningService(nil, nil)

	report, err := svc.Analyze(context.Background(), AnalyzeInput{
		TenantID: uuid.New(),
		Rules: []json.RawMessage{
			json.RawMessage(`{"id":"r1","verb":"allow","domain":"ngfw"}`),
			json.RawMessage(`{"id":"r2","verb":"deny","domain":"ngfw"}`),
		},
		HitCounts: map[string]int64{
			"r1": 0,
			"r2": 100,
		},
		WindowDays: 30,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, rec := range report.Recommendations {
		if rec.RuleID == "r1" && rec.Category == SuggestionCategoryUnused {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected unused recommendation for r1")
	}
	if report.RulesAnalyzed != 2 {
		t.Fatalf("expected 2 rules analyzed, got %d", report.RulesAnalyzed)
	}
}

func TestTighteningService_ShadowedRules(t *testing.T) {
	t.Parallel()
	svc := NewTighteningService(nil, nil)

	report, err := svc.Analyze(context.Background(), AnalyzeInput{
		TenantID: uuid.New(),
		Rules: []json.RawMessage{
			json.RawMessage(`{"id":"broad","verb":"allow","domain":"ngfw"}`),
			json.RawMessage(`{"id":"narrow","verb":"allow","domain":"ngfw","subject_refs":["admin"]}`),
		},
		HitCounts: map[string]int64{
			"broad":  500,
			"narrow": 10,
		},
		WindowDays: 30,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, rec := range report.Recommendations {
		if rec.RuleID == "narrow" && rec.Category == SuggestionCategoryShadowed {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected shadowed recommendation for narrow rule")
	}
}

func TestTighteningService_OverlyPermissiveRules(t *testing.T) {
	t.Parallel()
	svc := NewTighteningService(nil, nil)

	report, err := svc.Analyze(context.Background(), AnalyzeInput{
		TenantID: uuid.New(),
		Rules: []json.RawMessage{
			json.RawMessage(`{"id":"r-permissive","verb":"allow","domain":"swg"}`),
		},
		HitCounts: map[string]int64{"r-permissive": 200},
		WindowDays: 30,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, rec := range report.Recommendations {
		if rec.RuleID == "r-permissive" && rec.Category == SuggestionCategoryOverlyPermissive {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected overly_permissive recommendation")
	}
}

func TestTighteningService_DefaultWindowDays(t *testing.T) {
	t.Parallel()
	svc := NewTighteningService(nil, nil)

	report, err := svc.Analyze(context.Background(), AnalyzeInput{
		TenantID: uuid.New(),
		Rules: []json.RawMessage{
			json.RawMessage(`{"id":"r1","verb":"allow","domain":"ngfw"}`),
		},
		HitCounts:  map[string]int64{"r1": 0},
		WindowDays: 0,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if report.AnalysisWindow != 30 {
		t.Fatalf("expected default window=30, got %d", report.AnalysisWindow)
	}
}
