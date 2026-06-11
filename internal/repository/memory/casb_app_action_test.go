package memory_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
)

// The in-memory NoOps store must isolate tenants (one tenant never sees
// another's rows) and order the audit trail deterministically.

func TestCASBNoOpsStore_TenantIsolation(t *testing.T) {
	store := memory.NewCASBNoOpsStore()
	ctx := context.Background()
	tA, tB := uuid.New(), uuid.New()

	if _, err := store.UpsertClassification(ctx, tA, repository.AppClassification{AppName: "Slack", RiskScore: 60, Sanction: repository.SanctionUnsanctioned}); err != nil {
		t.Fatalf("upsert A: %v", err)
	}
	if _, err := store.AppendAction(ctx, tA, repository.CASBAppAction{AppName: "Slack", Enforcement: repository.ActionProtect}); err != nil {
		t.Fatalf("append A: %v", err)
	}

	// Tenant B sees nothing of A's.
	if cls, err := store.ListClassifications(ctx, tB); err != nil || len(cls) != 0 {
		t.Fatalf("B classifications = %v err=%v, want empty", cls, err)
	}
	if acts, err := store.ListActions(ctx, tB, 100); err != nil || len(acts) != 0 {
		t.Fatalf("B actions = %v err=%v, want empty", acts, err)
	}
	if _, err := store.GetClassification(ctx, tB, "Slack"); err != repository.ErrNotFound {
		t.Fatalf("B get = %v, want ErrNotFound", err)
	}

	// Tenant A still sees its own.
	if cls, err := store.ListClassifications(ctx, tA); err != nil || len(cls) != 1 {
		t.Fatalf("A classifications = %v err=%v, want 1", cls, err)
	}
}

func TestCASBNoOpsStore_ActionOrdering(t *testing.T) {
	store := memory.NewCASBNoOpsStore()
	ctx := context.Background()
	tid := uuid.New()
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	for i, ts := range []time.Time{base, base.Add(time.Hour), base.Add(2 * time.Hour)} {
		if _, err := store.AppendAction(ctx, tid, repository.CASBAppAction{
			AppName:   "app",
			CreatedAt: ts,
			Reason:    string(rune('a' + i)),
		}); err != nil {
			t.Fatalf("append: %v", err)
		}
	}

	// ListActions is newest-first.
	recent, err := store.ListActions(ctx, tid, 2)
	if err != nil {
		t.Fatalf("ListActions: %v", err)
	}
	if len(recent) != 2 || !recent[0].CreatedAt.After(recent[1].CreatedAt) {
		t.Fatalf("ListActions not newest-first/limited: %+v", recent)
	}

	// ListActionsSince is oldest-first and excludes the boundary.
	since, err := store.ListActionsSince(ctx, tid, base)
	if err != nil {
		t.Fatalf("ListActionsSince: %v", err)
	}
	if len(since) != 2 {
		t.Fatalf("ListActionsSince(base) = %d, want 2 (strictly after)", len(since))
	}
	if !since[0].CreatedAt.Before(since[1].CreatedAt) {
		t.Fatalf("ListActionsSince not oldest-first: %+v", since)
	}
}

func TestCASBNoOpsStore_PolicyAndDigestNotFound(t *testing.T) {
	store := memory.NewCASBNoOpsStore()
	ctx := context.Background()
	tid := uuid.New()

	if _, err := store.GetActionPolicy(ctx, tid); err != repository.ErrNotFound {
		t.Fatalf("policy err = %v, want ErrNotFound", err)
	}
	if _, err := store.GetDigestState(ctx, tid); err != repository.ErrNotFound {
		t.Fatalf("digest err = %v, want ErrNotFound", err)
	}

	p, err := store.UpsertActionPolicy(ctx, tid, repository.ActionPolicy{AutoEnforceEnabled: true, MinRisk: 60, MinConfidence: 80})
	if err != nil {
		t.Fatalf("upsert policy: %v", err)
	}
	if p.TenantID != tid || p.UpdatedAt.IsZero() {
		t.Fatalf("policy not stamped: %+v", p)
	}
	got, err := store.GetActionPolicy(ctx, tid)
	if err != nil || got.MinRisk != 60 {
		t.Fatalf("get policy = %+v err=%v", got, err)
	}
}
