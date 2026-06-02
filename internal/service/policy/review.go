package policy

import (
	"context"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// DefaultReviewInterval is the default number of days between
// policy reviews when no custom interval is configured.
const DefaultReviewInterval = 90

// DefaultExpiryThreshold is the lookahead for flagging upcoming
// policy expiries.
const DefaultExpiryThreshold = 7 * 24 * time.Hour

// ReviewSchedule is a service-layer type for a scheduled policy review.
type ReviewSchedule struct {
	PolicyID           uuid.UUID
	TenantID           uuid.UUID
	ReviewIntervalDays int
	LastReviewedAt     *time.Time
	NextReviewAt       *time.Time
}

// StalePolicy identifies a policy that has not been reviewed within
// the configured review window.
type StalePolicy struct {
	PolicyID       uuid.UUID
	TenantID       uuid.UUID
	LastReviewedAt *time.Time
	DaysOverdue    int
}

// PolicyExpiry represents a time-bounded policy rule that will
// auto-disable after its expiry date.
type PolicyExpiry struct {
	PolicyID  uuid.UUID
	TenantID  uuid.UUID
	ExpiresAt time.Time
	Expired   bool
}

// ReviewEvent is emitted for downstream notification consumption.
type ReviewEvent struct {
	Type     string    `json:"type"`
	TenantID uuid.UUID `json:"tenant_id"`
	PolicyID uuid.UUID `json:"policy_id"`
	Message  string    `json:"message"`
	At       time.Time `json:"at"`
}

// ReviewEventSink consumes review events for downstream processing.
type ReviewEventSink interface {
	Emit(ctx context.Context, event ReviewEvent) error
}

// noopSink discards events — used when no real sink is provided.
type noopSink struct{}

func (noopSink) Emit(context.Context, ReviewEvent) error { return nil }

// ReviewService manages periodic policy review scheduling, stale
// detection, and expiry support.
type ReviewService struct {
	schedules repository.PolicyReviewScheduleRepository
	logger    *slog.Logger
	nowFunc   func() time.Time
	sink      ReviewEventSink
}

// NewReviewService returns a ready-to-use review scheduler.
func NewReviewService(
	schedules repository.PolicyReviewScheduleRepository,
	logger *slog.Logger,
) *ReviewService {
	if logger == nil {
		logger = slog.Default()
	}
	return &ReviewService{
		schedules: schedules,
		logger:    logger,
		nowFunc:   func() time.Time { return time.Now().UTC() },
		sink:      noopSink{},
	}
}

// SetEventSink configures the downstream event consumer.
func (s *ReviewService) SetEventSink(sink ReviewEventSink) {
	if sink != nil {
		s.sink = sink
	}
}

// SetNowFunc overrides the clock for deterministic tests.
func (s *ReviewService) SetNowFunc(fn func() time.Time) {
	if fn != nil {
		s.nowFunc = fn
	}
}

// ScheduleReview creates or retrieves a review schedule for a policy.
func (s *ReviewService) ScheduleReview(
	ctx context.Context,
	tenantID, policyID uuid.UUID,
	intervalDays int,
) (repository.PolicyReviewSchedule, error) {
	if intervalDays <= 0 {
		intervalDays = DefaultReviewInterval
	}
	now := s.nowFunc()
	nextReview := now.AddDate(0, 0, intervalDays)
	sched := repository.PolicyReviewSchedule{
		PolicyID:           policyID,
		ReviewIntervalDays: intervalDays,
		NextReviewAt:       &nextReview,
	}
	created, err := s.schedules.Create(ctx, tenantID, sched)
	if err != nil {
		return repository.PolicyReviewSchedule{}, err
	}
	return created, nil
}

// GetSchedule retrieves the review schedule for a given policy.
func (s *ReviewService) GetSchedule(
	ctx context.Context,
	tenantID, policyID uuid.UUID,
) (repository.PolicyReviewSchedule, error) {
	return s.schedules.Get(ctx, tenantID, policyID)
}

// MarkReviewed records that a policy has been reviewed and advances
// the next review date.
func (s *ReviewService) MarkReviewed(
	ctx context.Context,
	tenantID, policyID uuid.UUID,
) error {
	now := s.nowFunc()
	if err := s.schedules.UpdateLastReviewed(ctx, tenantID, policyID, now); err != nil {
		return err
	}
	_ = s.sink.Emit(ctx, ReviewEvent{
		Type:     "policy.review.completed",
		TenantID: tenantID,
		PolicyID: policyID,
		Message:  "policy review completed",
		At:       now,
	})
	return nil
}

// FindStalePolicies returns policies whose next review is overdue.
func (s *ReviewService) FindStalePolicies(
	ctx context.Context,
	limit int,
) ([]StalePolicy, error) {
	if limit <= 0 {
		limit = 100
	}
	now := s.nowFunc()
	due, err := s.schedules.ListDue(ctx, now, limit)
	if err != nil {
		return nil, err
	}
	var stale []StalePolicy
	for _, d := range due {
		daysOverdue := 0
		if d.NextReviewAt != nil {
			daysOverdue = int(now.Sub(*d.NextReviewAt).Hours() / 24)
		}
		stale = append(stale, StalePolicy{
			PolicyID:       d.PolicyID,
			TenantID:       d.TenantID,
			LastReviewedAt: d.LastReviewedAt,
			DaysOverdue:    daysOverdue,
		})
	}
	return stale, nil
}

// CheckAndNotify finds stale policies and emits review-due events.
func (s *ReviewService) CheckAndNotify(ctx context.Context) (int, error) {
	stale, err := s.FindStalePolicies(ctx, 500)
	if err != nil {
		return 0, err
	}
	now := s.nowFunc()
	emitted := 0
	for _, sp := range stale {
		if err := s.sink.Emit(ctx, ReviewEvent{
			Type:     "policy.review.due",
			TenantID: sp.TenantID,
			PolicyID: sp.PolicyID,
			Message:  "policy review is overdue",
			At:       now,
		}); err != nil {
			s.logger.Error("review: failed to emit event",
				slog.Any("error", err),
				slog.String("policyID", sp.PolicyID.String()))
			continue
		}
		emitted++
	}
	return emitted, nil
}

// CheckExpiry evaluates a policy's expiry status.
func (s *ReviewService) CheckExpiry(expiresAt time.Time) PolicyExpiry {
	now := s.nowFunc()
	return PolicyExpiry{
		ExpiresAt: expiresAt,
		Expired:   now.After(expiresAt),
	}
}
