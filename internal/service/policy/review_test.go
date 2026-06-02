package policy_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
	"github.com/kennguy3n/visible-fishbone/internal/service/policy"
)

// collectingSink records emitted events for assertions.
type collectingSink struct {
	mu     sync.Mutex
	events []policy.ReviewEvent
}

func (s *collectingSink) Emit(_ context.Context, e policy.ReviewEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, e)
	return nil
}

func (s *collectingSink) Events() []policy.ReviewEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]policy.ReviewEvent, len(s.events))
	copy(out, s.events)
	return out
}

func setupReviewTest(t *testing.T) (*policy.ReviewService, *memory.Store, uuid.UUID) {
	t.Helper()
	store := memory.NewStore()
	tenantID := uuid.New()
	_, err := memory.NewTenantRepository(store).Create(context.Background(), repository.Tenant{
		ID:   tenantID,
		Name: "test-tenant",
		Slug: "test",
	})
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	schedRepo := memory.NewPolicyReviewScheduleRepository(store)
	svc := policy.NewReviewService(schedRepo, nil)
	return svc, store, tenantID
}

func TestReviewService_ScheduleAndGet(t *testing.T) {
	svc, _, tenantID := setupReviewTest(t)
	ctx := context.Background()
	policyID := uuid.New()

	sched, err := svc.ScheduleReview(ctx, tenantID, policyID, 30)
	if err != nil {
		t.Fatalf("schedule: %v", err)
	}
	if sched.ReviewIntervalDays != 30 {
		t.Errorf("interval = %d, want 30", sched.ReviewIntervalDays)
	}
	if sched.NextReviewAt == nil {
		t.Fatal("next_review_at is nil")
	}

	got, err := svc.GetSchedule(ctx, tenantID, policyID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.PolicyID != policyID {
		t.Errorf("policy_id = %v, want %v", got.PolicyID, policyID)
	}
}

func TestReviewService_DefaultInterval(t *testing.T) {
	svc, _, tenantID := setupReviewTest(t)
	ctx := context.Background()
	policyID := uuid.New()

	sched, err := svc.ScheduleReview(ctx, tenantID, policyID, 0)
	if err != nil {
		t.Fatalf("schedule: %v", err)
	}
	if sched.ReviewIntervalDays != policy.DefaultReviewInterval {
		t.Errorf("interval = %d, want %d", sched.ReviewIntervalDays, policy.DefaultReviewInterval)
	}
}

func TestReviewService_DuplicateSchedule(t *testing.T) {
	svc, _, tenantID := setupReviewTest(t)
	ctx := context.Background()
	policyID := uuid.New()

	if _, err := svc.ScheduleReview(ctx, tenantID, policyID, 30); err != nil {
		t.Fatalf("first schedule: %v", err)
	}
	_, err := svc.ScheduleReview(ctx, tenantID, policyID, 60)
	if err == nil {
		t.Fatal("expected conflict error for duplicate schedule")
	}
}

func TestReviewService_MarkReviewed(t *testing.T) {
	svc, _, tenantID := setupReviewTest(t)
	ctx := context.Background()
	policyID := uuid.New()

	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	svc.SetNowFunc(func() time.Time { return now })

	if _, err := svc.ScheduleReview(ctx, tenantID, policyID, 30); err != nil {
		t.Fatalf("schedule: %v", err)
	}

	sink := &collectingSink{}
	svc.SetEventSink(sink)

	reviewTime := now.AddDate(0, 0, 5)
	svc.SetNowFunc(func() time.Time { return reviewTime })
	if err := svc.MarkReviewed(ctx, tenantID, policyID); err != nil {
		t.Fatalf("mark reviewed: %v", err)
	}

	got, err := svc.GetSchedule(ctx, tenantID, policyID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.LastReviewedAt == nil {
		t.Fatal("last_reviewed_at is nil after mark")
	}
	if got.NextReviewAt == nil {
		t.Fatal("next_review_at is nil after mark")
	}
	expectedNext := reviewTime.AddDate(0, 0, 30)
	if !got.NextReviewAt.Equal(expectedNext) {
		t.Errorf("next_review = %v, want %v", *got.NextReviewAt, expectedNext)
	}

	events := sink.Events()
	if len(events) != 1 {
		t.Fatalf("events = %d, want 1", len(events))
	}
	if events[0].Type != "policy.review.completed" {
		t.Errorf("event type = %q, want policy.review.completed", events[0].Type)
	}
}

func TestReviewService_FindStalePolicies(t *testing.T) {
	svc, _, tenantID := setupReviewTest(t)
	ctx := context.Background()

	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	svc.SetNowFunc(func() time.Time { return now })

	p1 := uuid.New()
	p2 := uuid.New()
	if _, err := svc.ScheduleReview(ctx, tenantID, p1, 10); err != nil {
		t.Fatalf("schedule p1: %v", err)
	}
	if _, err := svc.ScheduleReview(ctx, tenantID, p2, 60); err != nil {
		t.Fatalf("schedule p2: %v", err)
	}

	// Advance past p1's due date but not p2's.
	future := now.AddDate(0, 0, 15)
	svc.SetNowFunc(func() time.Time { return future })

	stale, err := svc.FindStalePolicies(ctx, 100)
	if err != nil {
		t.Fatalf("find stale: %v", err)
	}
	if len(stale) != 1 {
		t.Fatalf("stale = %d, want 1", len(stale))
	}
	if stale[0].PolicyID != p1 {
		t.Errorf("stale policy = %v, want %v", stale[0].PolicyID, p1)
	}
	if stale[0].DaysOverdue < 4 {
		t.Errorf("days overdue = %d, want >= 4", stale[0].DaysOverdue)
	}
}

func TestReviewService_CheckAndNotify(t *testing.T) {
	svc, _, tenantID := setupReviewTest(t)
	ctx := context.Background()

	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	svc.SetNowFunc(func() time.Time { return now })

	policyID := uuid.New()
	if _, err := svc.ScheduleReview(ctx, tenantID, policyID, 5); err != nil {
		t.Fatalf("schedule: %v", err)
	}

	sink := &collectingSink{}
	svc.SetEventSink(sink)

	// Move past the review date.
	svc.SetNowFunc(func() time.Time { return now.AddDate(0, 0, 10) })
	n, err := svc.CheckAndNotify(ctx)
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if n != 1 {
		t.Errorf("notified = %d, want 1", n)
	}
	events := sink.Events()
	if len(events) != 1 {
		t.Fatalf("events = %d, want 1", len(events))
	}
	if events[0].Type != "policy.review.due" {
		t.Errorf("event type = %q", events[0].Type)
	}
}

func TestReviewService_CheckExpiry(t *testing.T) {
	svc, _, _ := setupReviewTest(t)
	now := time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)
	svc.SetNowFunc(func() time.Time { return now })

	future := now.AddDate(0, 0, 10)
	result := svc.CheckExpiry(future)
	if result.Expired {
		t.Error("policy should not be expired yet")
	}

	past := now.AddDate(0, 0, -5)
	result = svc.CheckExpiry(past)
	if !result.Expired {
		t.Error("policy should be expired")
	}
}
