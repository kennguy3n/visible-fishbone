package ai

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
)

func TestPolicySuggestService_UnusedRule(t *testing.T) {
	t.Parallel()
	store := memory.NewStore()
	repo := memory.NewAISuggestionRepository(store)
	svc := NewPolicySuggestService(nil, nil, repo, nil)

	tenantID := uuid.New()
	rules := []json.RawMessage{
		json.RawMessage(`{"id":"rule-1","verb":"allow","domain":"ngfw"}`),
	}
	hitCounts := map[string]int64{"rule-1": 0}

	suggestions, err := svc.AnalyzeAndSuggest(context.Background(), tenantID, rules, hitCounts, 30)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(suggestions) == 0 {
		t.Fatal("expected at least one suggestion for unused rule")
	}
	if suggestions[0].Category != SuggestionCategoryUnused {
		t.Fatalf("expected category=unused, got %s", suggestions[0].Category)
	}
	if suggestions[0].Confidence <= 0 {
		t.Fatal("expected positive confidence")
	}

	listed, err := repo.List(context.Background(), tenantID, nil, repository.Page{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(listed.Items) != len(suggestions) {
		t.Fatalf("expected %d persisted suggestions, got %d", len(suggestions), len(listed.Items))
	}
}

func TestPolicySuggestService_OverlyPermissiveRule(t *testing.T) {
	t.Parallel()
	store := memory.NewStore()
	repo := memory.NewAISuggestionRepository(store)
	svc := NewPolicySuggestService(nil, nil, repo, nil)

	tenantID := uuid.New()
	rules := []json.RawMessage{
		json.RawMessage(`{"id":"rule-broad","verb":"allow","domain":"ngfw"}`),
	}
	hitCounts := map[string]int64{"rule-broad": 100}

	suggestions, err := svc.AnalyzeAndSuggest(context.Background(), tenantID, rules, hitCounts, 30)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := false
	for _, s := range suggestions {
		if s.Category == SuggestionCategoryOverlyPermissive {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected overly_permissive suggestion for rule with no subjects")
	}
}

func TestPolicySuggestService_NoSuggestionsForActiveNarrowRules(t *testing.T) {
	t.Parallel()
	store := memory.NewStore()
	repo := memory.NewAISuggestionRepository(store)
	svc := NewPolicySuggestService(nil, nil, repo, nil)

	tenantID := uuid.New()
	rules := []json.RawMessage{
		json.RawMessage(`{"id":"rule-narrow","verb":"allow","domain":"ngfw","subject_refs":["admin-group"]}`),
	}
	hitCounts := map[string]int64{"rule-narrow": 500}

	suggestions, err := svc.AnalyzeAndSuggest(context.Background(), tenantID, rules, hitCounts, 30)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(suggestions) != 0 {
		t.Fatalf("expected no suggestions for active narrow rules, got %d", len(suggestions))
	}
}

func TestPolicySuggestService_ConfidenceIncreasesWithWindowDays(t *testing.T) {
	t.Parallel()
	store := memory.NewStore()
	repo := memory.NewAISuggestionRepository(store)
	svc := NewPolicySuggestService(nil, nil, repo, nil)

	tenantID := uuid.New()
	rules := []json.RawMessage{
		json.RawMessage(`{"id":"rule-test","verb":"allow","domain":"ngfw"}`),
	}
	hitCounts := map[string]int64{"rule-test": 0}

	s30, _ := svc.AnalyzeAndSuggest(context.Background(), tenantID, rules, hitCounts, 30)

	store2 := memory.NewStore()
	repo2 := memory.NewAISuggestionRepository(store2)
	svc2 := NewPolicySuggestService(nil, nil, repo2, nil)
	s90, _ := svc2.AnalyzeAndSuggest(context.Background(), tenantID, rules, hitCounts, 90)

	if len(s30) == 0 || len(s90) == 0 {
		t.Fatal("expected suggestions for both windows")
	}

	var conf30, conf90 float64
	for _, s := range s30 {
		if s.Category == SuggestionCategoryUnused {
			conf30 = s.Confidence
			break
		}
	}
	for _, s := range s90 {
		if s.Category == SuggestionCategoryUnused {
			conf90 = s.Confidence
			break
		}
	}
	if conf90 <= conf30 {
		t.Fatalf("expected 90-day confidence (%f) > 30-day confidence (%f)", conf90, conf30)
	}
}
