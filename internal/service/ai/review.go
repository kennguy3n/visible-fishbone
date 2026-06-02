package ai

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// ReviewService manages the operator approve/reject/modify workflow
// for AI-generated suggestions. Approved suggestions enter the
// canary rollout pipeline; rejected suggestions are stored as
// negative signal for future model improvement.
type ReviewService struct {
	repo   repository.AISuggestionRepository
	logger *slog.Logger
}

// NewReviewService constructs a ReviewService.
func NewReviewService(repo repository.AISuggestionRepository, logger *slog.Logger) *ReviewService {
	if logger == nil {
		logger = slog.Default()
	}
	return &ReviewService{repo: repo, logger: logger}
}

// Errors surfaced by the review workflow.
var (
	ErrInvalidTransition = errors.New("ai: invalid status transition")
	ErrAlreadyReviewed   = errors.New("ai: suggestion already reviewed")
)

// validTransitions defines the allowed status transitions.
var validTransitions = map[SuggestionStatus][]SuggestionStatus{
	SuggestionStatusPending:  {SuggestionStatusApproved, SuggestionStatusRejected},
	SuggestionStatusApproved: {SuggestionStatusApplied, SuggestionStatusRolledBack},
	SuggestionStatusApplied:  {SuggestionStatusRolledBack},
}

func isValidTransition(from, to SuggestionStatus) bool {
	targets, ok := validTransitions[from]
	if !ok {
		return false
	}
	for _, t := range targets {
		if t == to {
			return true
		}
	}
	return false
}

// ListSuggestions lists suggestions for a tenant with optional
// status filter.
func (s *ReviewService) ListSuggestions(
	ctx context.Context,
	tenantID uuid.UUID,
	status *string,
	page repository.Page,
) (repository.PageResult[repository.AISuggestion], error) {
	return s.repo.List(ctx, tenantID, status, page)
}

// GetSuggestion returns a single suggestion by ID.
func (s *ReviewService) GetSuggestion(
	ctx context.Context,
	tenantID, id uuid.UUID,
) (repository.AISuggestion, error) {
	return s.repo.Get(ctx, tenantID, id)
}

// ApproveSuggestion marks a suggestion as approved by the reviewer.
func (s *ReviewService) ApproveSuggestion(
	ctx context.Context,
	tenantID, id uuid.UUID,
	reviewerID uuid.UUID,
	feedback string,
) (repository.AISuggestion, error) {
	return s.transition(ctx, tenantID, id, SuggestionStatusApproved, &reviewerID, feedback)
}

// RejectSuggestion marks a suggestion as rejected by the reviewer.
func (s *ReviewService) RejectSuggestion(
	ctx context.Context,
	tenantID, id uuid.UUID,
	reviewerID uuid.UUID,
	feedback string,
) (repository.AISuggestion, error) {
	return s.transition(ctx, tenantID, id, SuggestionStatusRejected, &reviewerID, feedback)
}

// ApplySuggestion marks an approved suggestion as applied (entered
// canary/active pipeline).
func (s *ReviewService) ApplySuggestion(
	ctx context.Context,
	tenantID, id uuid.UUID,
) (repository.AISuggestion, error) {
	return s.transition(ctx, tenantID, id, SuggestionStatusApplied, nil, "")
}

// RollbackSuggestion marks a suggestion as rolled back.
func (s *ReviewService) RollbackSuggestion(
	ctx context.Context,
	tenantID, id uuid.UUID,
) (repository.AISuggestion, error) {
	return s.transition(ctx, tenantID, id, SuggestionStatusRolledBack, nil, "")
}

func (s *ReviewService) transition(
	ctx context.Context,
	tenantID, id uuid.UUID,
	newStatus SuggestionStatus,
	reviewerID *uuid.UUID,
	feedback string,
) (repository.AISuggestion, error) {
	existing, err := s.repo.Get(ctx, tenantID, id)
	if err != nil {
		return repository.AISuggestion{}, err
	}

	currentStatus := SuggestionStatus(existing.Status)
	if !isValidTransition(currentStatus, newStatus) {
		return repository.AISuggestion{}, fmt.Errorf("%w: %s -> %s", ErrInvalidTransition, currentStatus, newStatus)
	}

	var fbPtr *string
	if feedback != "" {
		fbPtr = &feedback
	}
	if err := s.repo.UpdateStatus(ctx, tenantID, id, string(newStatus), reviewerID, fbPtr); err != nil {
		return repository.AISuggestion{}, fmt.Errorf("update status: %w", err)
	}

	updated, err := s.repo.Get(ctx, tenantID, id)
	if err != nil {
		return repository.AISuggestion{}, fmt.Errorf("get after update: %w", err)
	}

	s.logger.Info("suggestion status changed",
		slog.String("tenant_id", tenantID.String()),
		slog.String("suggestion_id", id.String()),
		slog.String("from", string(currentStatus)),
		slog.String("to", string(newStatus)),
	)

	return updated, nil
}

// AuditEntry records a review decision for audit trail purposes.
type AuditEntry struct {
	SuggestionID uuid.UUID        `json:"suggestion_id"`
	TenantID     uuid.UUID        `json:"tenant_id"`
	ReviewerID   *uuid.UUID       `json:"reviewer_id,omitempty"`
	Action       SuggestionStatus `json:"action"`
	Feedback     string           `json:"feedback,omitempty"`
	Timestamp    time.Time        `json:"timestamp"`
}

// BuildAuditEntry constructs an audit entry from a review decision.
func BuildAuditEntry(suggestion repository.AISuggestion, action SuggestionStatus) AuditEntry {
	entry := AuditEntry{
		SuggestionID: suggestion.ID,
		TenantID:     suggestion.TenantID,
		ReviewerID:   suggestion.ReviewerID,
		Action:       action,
		Timestamp:    time.Now().UTC(),
	}
	if suggestion.Feedback != nil {
		entry.Feedback = *suggestion.Feedback
	}
	return entry
}

// MarshalAuditJSON serialises an audit entry for the audit log.
func MarshalAuditJSON(entry AuditEntry) json.RawMessage {
	b, _ := json.Marshal(entry)
	return b
}
