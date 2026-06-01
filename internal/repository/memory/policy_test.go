package memory_test

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
)

// seedPolicyTenant returns a store + tenant for use by the
// draft/promote tests below. We don't reuse seedRolloutTenant…
// because these tests own their PolicyRepository and don't need
// the seeded graph.
func seedPolicyTenant(t *testing.T) (*memory.Store, repository.Tenant) {
	t.Helper()
	s := newStore(t)
	tr := memory.NewTenantRepository(s)
	tnt, err := tr.Create(ctx(), repository.Tenant{
		Name: "P", Slug: "p",
		Status: repository.TenantStatusActive,
		Tier:   repository.TenantTierStarter,
	})
	if err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	return s, tnt
}

func TestPolicyRepo_GetCurrentGraph_SkipsDrafts(t *testing.T) {
	t.Parallel()
	s, tnt := seedPolicyTenant(t)
	repo := memory.NewPolicyRepository(s)

	// Live v1.
	live, err := repo.CreateGraph(ctx(), tnt.ID, repository.PolicyGraph{
		Graph: json.RawMessage(`{"default_action":"deny"}`),
	})
	if err != nil {
		t.Fatalf("create live: %v", err)
	}

	// Draft v2 — would be MAX(version) if drafts counted, so
	// this is the test that proves GetCurrentGraph skips it.
	draft, err := repo.CreateGraph(ctx(), tnt.ID, repository.PolicyGraph{
		Graph:   json.RawMessage(`{"default_action":"allow"}`),
		IsDraft: true,
	})
	if err != nil {
		t.Fatalf("create draft: %v", err)
	}
	if draft.Version <= live.Version {
		t.Fatalf("draft.Version = %d, want > %d", draft.Version, live.Version)
	}

	got, err := repo.GetCurrentGraph(ctx(), tnt.ID)
	if err != nil {
		t.Fatalf("get current: %v", err)
	}
	if got.ID != live.ID {
		t.Fatalf("current = %s (v=%d), want live %s (v=%d) — draft must be skipped",
			got.ID, got.Version, live.ID, live.Version)
	}
}

func TestPolicyRepo_GetGraph_ReturnsDraft(t *testing.T) {
	t.Parallel()
	s, tnt := seedPolicyTenant(t)
	repo := memory.NewPolicyRepository(s)

	draft, err := repo.CreateGraph(ctx(), tnt.ID, repository.PolicyGraph{
		Graph:   json.RawMessage(`{}`),
		IsDraft: true,
	})
	if err != nil {
		t.Fatalf("create draft: %v", err)
	}
	got, err := repo.GetGraph(ctx(), tnt.ID, draft.ID)
	if err != nil {
		t.Fatalf("get by id: %v", err)
	}
	if !got.IsDraft || got.ID != draft.ID {
		t.Fatalf("got %+v, want draft id %s", got, draft.ID)
	}
}

func TestPolicyRepo_GetGraph_RespectsTenantIsolation(t *testing.T) {
	t.Parallel()
	s, tnt := seedPolicyTenant(t)
	repo := memory.NewPolicyRepository(s)
	draft, _ := repo.CreateGraph(ctx(), tnt.ID, repository.PolicyGraph{
		Graph: json.RawMessage(`{}`), IsDraft: true,
	})

	other := uuid.New()
	if _, err := repo.GetGraph(ctx(), other, draft.ID); !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("cross-tenant get err = %v, want ErrNotFound", err)
	}
}

func TestPolicyRepo_PromoteGraph_FlipsIsDraftAndMakesCurrent(t *testing.T) {
	t.Parallel()
	s, tnt := seedPolicyTenant(t)
	repo := memory.NewPolicyRepository(s)

	live, _ := repo.CreateGraph(ctx(), tnt.ID, repository.PolicyGraph{
		Graph: json.RawMessage(`{"default_action":"deny"}`),
	})
	draft, _ := repo.CreateGraph(ctx(), tnt.ID, repository.PolicyGraph{
		Graph: json.RawMessage(`{"default_action":"allow"}`), IsDraft: true,
	})

	// Pre-promote: live is current.
	if cur, _ := repo.GetCurrentGraph(ctx(), tnt.ID); cur.ID != live.ID {
		t.Fatalf("pre-promote current = %s, want %s", cur.ID, live.ID)
	}

	promoted, err := repo.PromoteGraph(ctx(), tnt.ID, draft.ID)
	if err != nil {
		t.Fatalf("promote: %v", err)
	}
	if promoted.IsDraft {
		t.Fatalf("promoted.IsDraft = true, want false")
	}

	// Post-promote: draft is current (higher version wins).
	cur, err := repo.GetCurrentGraph(ctx(), tnt.ID)
	if err != nil {
		t.Fatalf("post-promote current: %v", err)
	}
	if cur.ID != draft.ID {
		t.Fatalf("post-promote current = %s, want %s", cur.ID, draft.ID)
	}
}

func TestPolicyRepo_PromoteGraph_IsIdempotent(t *testing.T) {
	t.Parallel()
	s, tnt := seedPolicyTenant(t)
	repo := memory.NewPolicyRepository(s)

	live, _ := repo.CreateGraph(ctx(), tnt.ID, repository.PolicyGraph{
		Graph: json.RawMessage(`{}`),
	})
	// Promoting an already-live graph must succeed and be a
	// no-op on the row state.
	got, err := repo.PromoteGraph(ctx(), tnt.ID, live.ID)
	if err != nil {
		t.Fatalf("re-promote live: %v", err)
	}
	if got.IsDraft || got.ID != live.ID {
		t.Fatalf("re-promote got %+v, want live id %s, !IsDraft", got, live.ID)
	}
}

func TestPolicyRepo_PromoteGraph_UnknownID(t *testing.T) {
	t.Parallel()
	s, tnt := seedPolicyTenant(t)
	repo := memory.NewPolicyRepository(s)
	if _, err := repo.PromoteGraph(ctx(), tnt.ID, uuid.New()); !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}
