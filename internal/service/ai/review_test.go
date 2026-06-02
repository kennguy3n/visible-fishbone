package ai

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
)

func seedSuggestion(t *testing.T, repo repository.AISuggestionRepository, tenantID uuid.UUID) repository.AISuggestion {
	t.Helper()
	s, err := repo.Create(context.Background(), tenantID, repository.AISuggestion{
		RuleID:         "test-rule",
		Category:       "unused",
		SuggestionJSON: json.RawMessage(`{"action":"remove"}`),
		Confidence:     0.85,
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	return s
}

func TestReviewService_ApproveSuggestion(t *testing.T) {
	t.Parallel()
	store := memory.NewStore()
	repo := memory.NewAISuggestionRepository(store)
	svc := NewReviewService(repo, nil)

	tenantID := uuid.New()
	s := seedSuggestion(t, repo, tenantID)
	reviewerID := uuid.New()

	updated, err := svc.ApproveSuggestion(context.Background(), tenantID, s.ID, reviewerID, "looks good")
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	if updated.Status != repository.AISuggestionStatusApproved {
		t.Fatalf("expected approved, got %s", updated.Status)
	}
	if updated.ReviewerID == nil || *updated.ReviewerID != reviewerID {
		t.Fatal("expected reviewer_id to be set")
	}
}

func TestReviewService_RejectSuggestion(t *testing.T) {
	t.Parallel()
	store := memory.NewStore()
	repo := memory.NewAISuggestionRepository(store)
	svc := NewReviewService(repo, nil)

	tenantID := uuid.New()
	s := seedSuggestion(t, repo, tenantID)
	reviewerID := uuid.New()

	updated, err := svc.RejectSuggestion(context.Background(), tenantID, s.ID, reviewerID, "not needed")
	if err != nil {
		t.Fatalf("reject: %v", err)
	}
	if updated.Status != repository.AISuggestionStatusRejected {
		t.Fatalf("expected rejected, got %s", updated.Status)
	}
}

func TestReviewService_InvalidTransition(t *testing.T) {
	t.Parallel()
	store := memory.NewStore()
	repo := memory.NewAISuggestionRepository(store)
	svc := NewReviewService(repo, nil)

	tenantID := uuid.New()
	s := seedSuggestion(t, repo, tenantID)
	reviewerID := uuid.New()

	if _, err := svc.RejectSuggestion(context.Background(), tenantID, s.ID, reviewerID, "no"); err != nil {
		t.Fatalf("reject: %v", err)
	}

	_, err := svc.ApproveSuggestion(context.Background(), tenantID, s.ID, reviewerID, "wait")
	if err == nil {
		t.Fatal("expected error for rejected -> approved transition")
	}
	if !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("expected ErrInvalidTransition, got: %v", err)
	}
}

func TestReviewService_ApprovedToApplied(t *testing.T) {
	t.Parallel()
	store := memory.NewStore()
	repo := memory.NewAISuggestionRepository(store)
	svc := NewReviewService(repo, nil)

	tenantID := uuid.New()
	s := seedSuggestion(t, repo, tenantID)
	reviewerID := uuid.New()

	if _, err := svc.ApproveSuggestion(context.Background(), tenantID, s.ID, reviewerID, "looks good"); err != nil {
		t.Fatalf("approve: %v", err)
	}

	updated, err := svc.ApplySuggestion(context.Background(), tenantID, s.ID)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if updated.Status != repository.AISuggestionStatusApplied {
		t.Fatalf("expected applied, got %s", updated.Status)
	}
	// Apply carries no reviewer/feedback; the attribution recorded at
	// approve time must be preserved, not cleared.
	if updated.ReviewerID == nil || *updated.ReviewerID != reviewerID {
		t.Fatalf("reviewer_id not preserved across apply: got %v", updated.ReviewerID)
	}
	if updated.Feedback == nil || *updated.Feedback != "looks good" {
		t.Fatalf("feedback not preserved across apply: got %v", updated.Feedback)
	}
}

func TestReviewService_RollbackApplied(t *testing.T) {
	t.Parallel()
	store := memory.NewStore()
	repo := memory.NewAISuggestionRepository(store)
	svc := NewReviewService(repo, nil)

	tenantID := uuid.New()
	s := seedSuggestion(t, repo, tenantID)
	reviewerID := uuid.New()

	if _, err := svc.ApproveSuggestion(context.Background(), tenantID, s.ID, reviewerID, ""); err != nil {
		t.Fatalf("approve: %v", err)
	}
	if _, err := svc.ApplySuggestion(context.Background(), tenantID, s.ID); err != nil {
		t.Fatalf("apply: %v", err)
	}

	updated, err := svc.RollbackSuggestion(context.Background(), tenantID, s.ID)
	if err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if updated.Status != repository.AISuggestionStatusRolledBack {
		t.Fatalf("expected rolled_back, got %s", updated.Status)
	}
}

func TestReviewService_ListSuggestions(t *testing.T) {
	t.Parallel()
	store := memory.NewStore()
	repo := memory.NewAISuggestionRepository(store)
	svc := NewReviewService(repo, nil)

	tenantID := uuid.New()
	seedSuggestion(t, repo, tenantID)
	seedSuggestion(t, repo, tenantID)

	result, err := svc.ListSuggestions(context.Background(), tenantID, nil, repository.Page{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(result.Items) != 2 {
		t.Fatalf("expected 2 suggestions, got %d", len(result.Items))
	}
}

func TestReviewService_ListSuggestionsWithStatusFilter(t *testing.T) {
	t.Parallel()
	store := memory.NewStore()
	repo := memory.NewAISuggestionRepository(store)
	svc := NewReviewService(repo, nil)

	tenantID := uuid.New()
	s := seedSuggestion(t, repo, tenantID)
	seedSuggestion(t, repo, tenantID)

	reviewerID := uuid.New()
	if _, err := svc.ApproveSuggestion(context.Background(), tenantID, s.ID, reviewerID, ""); err != nil {
		t.Fatalf("approve: %v", err)
	}

	pending := "pending"
	result, err := svc.ListSuggestions(context.Background(), tenantID, &pending, repository.Page{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(result.Items) != 1 {
		t.Fatalf("expected 1 pending suggestion, got %d", len(result.Items))
	}
}

func TestBuildAuditEntry(t *testing.T) {
	t.Parallel()
	reviewerID := uuid.New()
	fb := "test feedback"
	s := repository.AISuggestion{
		ID:         uuid.New(),
		TenantID:   uuid.New(),
		ReviewerID: &reviewerID,
		Feedback:   &fb,
	}
	entry := BuildAuditEntry(s, SuggestionStatusApproved)
	if entry.SuggestionID != s.ID {
		t.Fatal("suggestion_id mismatch")
	}
	if entry.Feedback != fb {
		t.Fatal("feedback mismatch")
	}
	data := MarshalAuditJSON(entry)
	if len(data) == 0 {
		t.Fatal("expected non-empty audit JSON")
	}
}
