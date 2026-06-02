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

func hasShadowed(recs []TighteningRecommendation, ruleID string) bool {
	for _, rec := range recs {
		if rec.RuleID == ruleID && rec.Category == SuggestionCategoryShadowed {
			return true
		}
	}
	return false
}

// A higher-priority rule restricted via the structured "subjects" field is
// NOT a catch-all, so lower-priority rules must not be flagged as shadowed.
func TestTighteningService_ShadowedRules_SubjectsRestrictedHigherIsNotCatchAll(t *testing.T) {
	t.Parallel()
	svc := NewTighteningService(nil, nil)

	report, err := svc.Analyze(context.Background(), AnalyzeInput{
		TenantID: uuid.New(),
		Rules: []json.RawMessage{
			json.RawMessage(`{"id":"higher","verb":"allow","domain":"ngfw","subjects":[{"type":"group","id":"admin"}]}`),
			json.RawMessage(`{"id":"lower","verb":"allow","domain":"ngfw","subject_refs":["ops"]}`),
		},
		HitCounts:  map[string]int64{"higher": 500, "lower": 10},
		WindowDays: 30,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hasShadowed(report.Recommendations, "lower") {
		t.Fatal("higher rule restricted by subjects must not shadow lower rule")
	}
}

// A lower-priority rule restricted only via "subjects" is still shadowed by a
// genuine catch-all higher-priority rule.
func TestTighteningService_ShadowedRules_SubjectsRestrictedLowerIsShadowed(t *testing.T) {
	t.Parallel()
	svc := NewTighteningService(nil, nil)

	report, err := svc.Analyze(context.Background(), AnalyzeInput{
		TenantID: uuid.New(),
		Rules: []json.RawMessage{
			json.RawMessage(`{"id":"broad","verb":"allow","domain":"ngfw"}`),
			json.RawMessage(`{"id":"narrow","verb":"allow","domain":"ngfw","subjects":[{"type":"group","id":"admin"}]}`),
		},
		HitCounts:  map[string]int64{"broad": 500, "narrow": 10},
		WindowDays: 30,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasShadowed(report.Recommendations, "narrow") {
		t.Fatal("expected shadowed recommendation for subjects-restricted narrow rule")
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
		HitCounts:  map[string]int64{"r-permissive": 200},
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
