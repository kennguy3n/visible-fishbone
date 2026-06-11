// Package memory_test — dlp_review_test pins the write-time validation
// and tenant-isolation contract for the DLPReviewRepository so the
// memory store stays a faithful double for the Postgres CHECK
// constraints and RLS policy in migration 060.
package memory_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
	"github.com/kennguy3n/visible-fishbone/internal/service/dlpreview"
)

func pendingEvent(tenant uuid.UUID, at time.Time) dlpreview.ReviewEvent {
	return dlpreview.ReviewEvent{
		ID:             uuid.New(),
		TenantID:       tenant,
		Signal:         "ai_app_upload",
		DestinationApp: "chatgpt",
		Severity:       dlpreview.SeverityHigh,
		Confidence:     0.9,
		State:          dlpreview.StatePending,
		Findings:       []dlpreview.FindingAggregate{},
		CreatedAt:      at,
	}
}

func TestDLPReviewRepository_Enqueue_RejectsInvalid(t *testing.T) {
	t.Parallel()
	repo := memory.NewDLPReviewRepository()
	tenant := uuid.New()
	now := time.Now().UTC()

	cases := map[string]func(*dlpreview.ReviewEvent){
		"nil id":            func(e *dlpreview.ReviewEvent) { e.ID = uuid.Nil },
		"tenant mismatch":   func(e *dlpreview.ReviewEvent) { e.TenantID = uuid.New() },
		"empty signal":      func(e *dlpreview.ReviewEvent) { e.Signal = "" },
		"empty destination": func(e *dlpreview.ReviewEvent) { e.DestinationApp = "" },
		"bad severity":      func(e *dlpreview.ReviewEvent) { e.Severity = "nope" },
		"confidence range":  func(e *dlpreview.ReviewEvent) { e.Confidence = 2 },
		"non-pending state": func(e *dlpreview.ReviewEvent) { e.State = dlpreview.StateApproved },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			ev := pendingEvent(tenant, now)
			mutate(&ev)
			if _, err := repo.Enqueue(context.Background(), tenant, ev); !errors.Is(err, repository.ErrInvalidArgument) {
				t.Fatalf("err = %v, want ErrInvalidArgument", err)
			}
		})
	}
}

func TestDLPReviewRepository_Enqueue_DuplicateIDConflicts(t *testing.T) {
	t.Parallel()
	repo := memory.NewDLPReviewRepository()
	tenant := uuid.New()
	ev := pendingEvent(tenant, time.Now().UTC())
	if _, err := repo.Enqueue(context.Background(), tenant, ev); err != nil {
		t.Fatalf("first enqueue: %v", err)
	}
	if _, err := repo.Enqueue(context.Background(), tenant, ev); !errors.Is(err, repository.ErrConflict) {
		t.Fatalf("duplicate enqueue err = %v, want ErrConflict", err)
	}
}

func TestDLPReviewRepository_Transition_Rules(t *testing.T) {
	t.Parallel()
	repo := memory.NewDLPReviewRepository()
	tenant := uuid.New()
	ev := pendingEvent(tenant, time.Now().UTC())
	if _, err := repo.Enqueue(context.Background(), tenant, ev); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	// Non-terminal target is rejected.
	if _, err := repo.Transition(context.Background(), tenant, ev.ID, dlpreview.StatePending, "r", time.Now()); !errors.Is(err, repository.ErrInvalidArgument) {
		t.Fatalf("transition to pending err = %v, want ErrInvalidArgument", err)
	}
	// Empty actor is rejected.
	if _, err := repo.Transition(context.Background(), tenant, ev.ID, dlpreview.StateApproved, "", time.Now()); !errors.Is(err, repository.ErrInvalidArgument) {
		t.Fatalf("empty actor err = %v, want ErrInvalidArgument", err)
	}
	// Cross-tenant transition is ErrNotFound.
	if _, err := repo.Transition(context.Background(), uuid.New(), ev.ID, dlpreview.StateApproved, "r", time.Now()); !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("cross-tenant transition err = %v, want ErrNotFound", err)
	}
	// Happy path.
	decidedAt := time.Now().UTC()
	got, err := repo.Transition(context.Background(), tenant, ev.ID, dlpreview.StateApproved, "reviewer", decidedAt)
	if err != nil {
		t.Fatalf("transition: %v", err)
	}
	if got.State != dlpreview.StateApproved || got.DecidedBy == nil || *got.DecidedBy != "reviewer" {
		t.Fatalf("unexpected transition result: %+v", got)
	}
	// Second decision conflicts.
	if _, err := repo.Transition(context.Background(), tenant, ev.ID, dlpreview.StateBlocked, "r2", time.Now()); !errors.Is(err, repository.ErrConflict) {
		t.Fatalf("second transition err = %v, want ErrConflict", err)
	}
}

func TestDLPReviewRepository_Summary_TenantScopedAndWindowed(t *testing.T) {
	t.Parallel()
	repo := memory.NewDLPReviewRepository()
	tenantA, tenantB := uuid.New(), uuid.New()
	base := time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC)

	// Two recent events for A, one old (should be excluded by window).
	recentA1 := pendingEvent(tenantA, base)
	recentA2 := pendingEvent(tenantA, base.Add(time.Minute))
	oldA := pendingEvent(tenantA, base.Add(-48*time.Hour))
	// One for B that must never bleed into A's summary.
	forB := pendingEvent(tenantB, base)

	for _, ev := range []dlpreview.ReviewEvent{recentA1, recentA2, oldA} {
		if _, err := repo.Enqueue(context.Background(), tenantA, ev); err != nil {
			t.Fatalf("enqueue A: %v", err)
		}
	}
	if _, err := repo.Enqueue(context.Background(), tenantB, forB); err != nil {
		t.Fatalf("enqueue B: %v", err)
	}

	since := base.Add(-time.Hour)
	sum, err := repo.Summary(context.Background(), tenantA, since)
	if err != nil {
		t.Fatalf("Summary: %v", err)
	}
	if sum.Total != 2 {
		t.Fatalf("total = %d, want 2 (old + cross-tenant excluded)", sum.Total)
	}
	if sum.Pending != 2 || sum.PendingByApp["chatgpt"] != 2 {
		t.Fatalf("pending = %d, byApp = %+v", sum.Pending, sum.PendingByApp)
	}
}

func TestDLPReviewRepository_List_DefaultLimit(t *testing.T) {
	t.Parallel()
	repo := memory.NewDLPReviewRepository()
	tenant := uuid.New()
	base := time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC)
	for i := 0; i < 150; i++ {
		ev := pendingEvent(tenant, base.Add(time.Duration(i)*time.Second))
		if _, err := repo.Enqueue(context.Background(), tenant, ev); err != nil {
			t.Fatalf("enqueue: %v", err)
		}
	}
	got, err := repo.List(context.Background(), tenant, dlpreview.ListFilter{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 100 {
		t.Fatalf("list len = %d, want default cap 100", len(got))
	}
	// Newest first.
	if !got[0].CreatedAt.After(got[1].CreatedAt) {
		t.Fatal("expected newest-first ordering")
	}
}
