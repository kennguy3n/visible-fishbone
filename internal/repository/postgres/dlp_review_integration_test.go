//go:build integration

package postgres_test

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/postgres"
	"github.com/kennguy3n/visible-fishbone/internal/service/dlpreview"
)

// TestDLPReviewQueue_Integration exercises the Postgres-backed review
// queue against a real container: the state machine, RLS tenant
// isolation, the redacted-evidence round-trip, and the digest
// aggregation. Run with `go test -tags integration ./...`.
func TestDLPReviewQueue_Integration(t *testing.T) {
	t.Parallel()
	store, cleanup := startPostgres(t)
	t.Cleanup(cleanup)

	repo := postgres.NewDLPReviewRepository(store)
	tnt := mustTenant(t, store.NewTenantRepository())

	newEvent := func(app string, sev dlpreview.Severity, at time.Time) dlpreview.ReviewEvent {
		return dlpreview.ReviewEvent{
			ID:             uuid.New(),
			TenantID:       tnt.ID,
			Signal:         "ai_app_upload",
			DestinationApp: app,
			Severity:       sev,
			Confidence:     0.92,
			State:          dlpreview.StatePending,
			Findings: []dlpreview.FindingAggregate{
				{Kind: dlpreview.FindingSecret, Label: "github_token", Count: 1, MaxConfidence: 1, Severity: dlpreview.SeverityHigh},
			},
			CreatedAt: at,
		}
	}

	t.Run("EnqueueAndRoundTrip", func(t *testing.T) {
		ev := newEvent("chatgpt", dlpreview.SeverityHigh, time.Now().UTC())
		stored, err := repo.Enqueue(bgCtx(), tnt.ID, ev)
		if err != nil {
			t.Fatalf("enqueue: %v", err)
		}
		if stored.State != dlpreview.StatePending || stored.DecidedAt != nil {
			t.Fatalf("unexpected stored event: %+v", stored)
		}
		got, err := repo.Get(bgCtx(), tnt.ID, ev.ID)
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		if len(got.Findings) != 1 || got.Findings[0].Label != "github_token" {
			t.Fatalf("evidence did not round-trip: %+v", got.Findings)
		}
	})

	t.Run("TransitionAtomicity", func(t *testing.T) {
		ev := newEvent("claude", dlpreview.SeverityCritical, time.Now().UTC())
		if _, err := repo.Enqueue(bgCtx(), tnt.ID, ev); err != nil {
			t.Fatalf("enqueue: %v", err)
		}
		if _, err := repo.Transition(bgCtx(), tnt.ID, ev.ID, dlpreview.StateApproved, "reviewer", time.Now().UTC()); err != nil {
			t.Fatalf("transition: %v", err)
		}
		// Second decision must conflict, not silently overwrite.
		if _, err := repo.Transition(bgCtx(), tnt.ID, ev.ID, dlpreview.StateBlocked, "other", time.Now().UTC()); !errors.Is(err, repository.ErrConflict) {
			t.Fatalf("double decision err = %v, want ErrConflict", err)
		}
		// Unknown id is ErrNotFound.
		if _, err := repo.Transition(bgCtx(), tnt.ID, uuid.New(), dlpreview.StateApproved, "x", time.Now().UTC()); !errors.Is(err, repository.ErrNotFound) {
			t.Fatalf("unknown transition err = %v, want ErrNotFound", err)
		}
	})

	t.Run("RLSTenantIsolation", func(t *testing.T) {
		other := mustTenant(t, store.NewTenantRepository())
		ev := newEvent("gemini", dlpreview.SeverityMedium, time.Now().UTC())
		if _, err := repo.Enqueue(bgCtx(), tnt.ID, ev); err != nil {
			t.Fatalf("enqueue: %v", err)
		}
		// The other tenant cannot see or decide this event — RLS scopes
		// the row out, so it reads as not found.
		if _, err := repo.Get(bgCtx(), other.ID, ev.ID); !errors.Is(err, repository.ErrNotFound) {
			t.Fatalf("cross-tenant get err = %v, want ErrNotFound", err)
		}
		if _, err := repo.Transition(bgCtx(), other.ID, ev.ID, dlpreview.StateApproved, "intruder", time.Now().UTC()); !errors.Is(err, repository.ErrNotFound) {
			t.Fatalf("cross-tenant transition err = %v, want ErrNotFound", err)
		}
	})

	t.Run("DigestAggregation", func(t *testing.T) {
		digestTenant := mustTenant(t, store.NewTenantRepository())
		dRepo := repo
		base := time.Now().UTC()
		mk := func(app string, sev dlpreview.Severity) dlpreview.ReviewEvent {
			e := newEvent(app, sev, base)
			e.TenantID = digestTenant.ID
			return e
		}
		for i := 0; i < 2; i++ {
			if _, err := dRepo.Enqueue(bgCtx(), digestTenant.ID, mk("chatgpt", dlpreview.SeverityHigh)); err != nil {
				t.Fatalf("enqueue: %v", err)
			}
		}
		blocked := mk(dlpreview.SuspectedAppSentinel, dlpreview.SeverityCritical)
		if _, err := dRepo.Enqueue(bgCtx(), digestTenant.ID, blocked); err != nil {
			t.Fatalf("enqueue: %v", err)
		}
		if _, err := dRepo.Transition(bgCtx(), digestTenant.ID, blocked.ID, dlpreview.StateBlocked, "r", time.Now().UTC()); err != nil {
			t.Fatalf("block: %v", err)
		}

		sum, err := dRepo.Summary(bgCtx(), digestTenant.ID, base.Add(-time.Hour))
		if err != nil {
			t.Fatalf("summary: %v", err)
		}
		if sum.Total != 3 || sum.Pending != 2 {
			t.Fatalf("summary totals = %+v", sum)
		}
		if sum.ByState[dlpreview.StateBlocked] != 1 {
			t.Fatalf("blocked = %d, want 1", sum.ByState[dlpreview.StateBlocked])
		}
		if sum.PendingByApp["chatgpt"] != 2 {
			t.Fatalf("pending chatgpt = %d, want 2", sum.PendingByApp["chatgpt"])
		}
	})
}
