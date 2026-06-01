package memory_test

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
)

func seedRolloutTenantAndGraph(t *testing.T) (*memory.Store, repository.Tenant, repository.PolicyGraph) {
	t.Helper()
	s := newStore(t)
	tr := memory.NewTenantRepository(s)
	tnt, err := tr.Create(ctx(), repository.Tenant{
		Name: "A", Slug: "a",
		Status: repository.TenantStatusActive,
		Tier:   repository.TenantTierStarter,
	})
	if err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	pr := memory.NewPolicyRepository(s)
	g, err := pr.CreateGraph(ctx(), tnt.ID, repository.PolicyGraph{
		Graph: json.RawMessage(`{"default_action":"deny"}`),
	})
	if err != nil {
		t.Fatalf("seed graph: %v", err)
	}
	return s, tnt, g
}

func makeRollout(tenantID, graphID uuid.UUID) repository.PolicyRollout {
	return repository.PolicyRollout{
		TenantID:      tenantID,
		GraphID:       graphID,
		Stage:         repository.PolicyRolloutStageDryRun,
		CanaryPercent: 0,
		SimulationID:  uuid.New(),
		Notes:         "initial",
	}
}

func TestRollout_Create_HappyPath(t *testing.T) {
	s, tnt, g := seedRolloutTenantAndGraph(t)
	repo := memory.NewPolicyRolloutRepository(s)
	saved, err := repo.Create(ctx(), tnt.ID, makeRollout(tnt.ID, g.ID))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if saved.ID == uuid.Nil {
		t.Fatalf("missing id")
	}
	if saved.Stage != repository.PolicyRolloutStageDryRun {
		t.Fatalf("stage = %s, want dry_run", saved.Stage)
	}
}

func TestRollout_Create_UnknownGraphFails(t *testing.T) {
	s, tnt, _ := seedRolloutTenantAndGraph(t)
	repo := memory.NewPolicyRolloutRepository(s)
	_, err := repo.Create(ctx(), tnt.ID, makeRollout(tnt.ID, uuid.New()))
	if !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestRollout_Create_RejectsTerminalStage(t *testing.T) {
	s, tnt, g := seedRolloutTenantAndGraph(t)
	repo := memory.NewPolicyRolloutRepository(s)
	rl := makeRollout(tnt.ID, g.ID)
	rl.Stage = repository.PolicyRolloutStageCompleted
	_, err := repo.Create(ctx(), tnt.ID, rl)
	if !errors.Is(err, repository.ErrInvalidArgument) {
		t.Fatalf("err = %v, want ErrInvalidArgument", err)
	}
}

func TestRollout_UpdateStage_MonotonicForward(t *testing.T) {
	s, tnt, g := seedRolloutTenantAndGraph(t)
	repo := memory.NewPolicyRolloutRepository(s)
	saved, err := repo.Create(ctx(), tnt.ID, makeRollout(tnt.ID, g.ID))
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	cases := []struct {
		name    string
		next    repository.PolicyRolloutStage
		percent int
		wantErr error
	}{
		{"dry_run -> canary 25", repository.PolicyRolloutStageCanary, 25, nil},
		{"canary -> full", repository.PolicyRolloutStageFull, 0, nil},
		{"full -> completed", repository.PolicyRolloutStageCompleted, 0, nil},
		{"completed -> anything illegal", repository.PolicyRolloutStageCanary, 0, repository.ErrInvalidArgument},
	}
	now := time.Now()
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := repo.UpdateStage(ctx(), tnt.ID, saved.ID, c.next, c.percent, "promoted", nil, now)
			if !errors.Is(err, c.wantErr) {
				t.Fatalf("err = %v, want %v", err, c.wantErr)
			}
		})
	}
}

func TestRollout_UpdateStage_BackwardRejected(t *testing.T) {
	s, tnt, g := seedRolloutTenantAndGraph(t)
	repo := memory.NewPolicyRolloutRepository(s)
	saved, err := repo.Create(ctx(), tnt.ID, makeRollout(tnt.ID, g.ID))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	now := time.Now()
	// dry_run -> canary
	if _, err := repo.UpdateStage(ctx(), tnt.ID, saved.ID,
		repository.PolicyRolloutStageCanary, 25, "", nil, now); err != nil {
		t.Fatalf("advance: %v", err)
	}
	// canary -> dry_run is illegal.
	if _, err := repo.UpdateStage(ctx(), tnt.ID, saved.ID,
		repository.PolicyRolloutStageDryRun, 0, "", nil, now); !errors.Is(err, repository.ErrInvalidArgument) {
		t.Fatalf("backward err = %v, want ErrInvalidArgument", err)
	}
}

func TestRollout_UpdateStage_RolledBackFromAnyNonTerminal(t *testing.T) {
	s, tnt, g := seedRolloutTenantAndGraph(t)
	repo := memory.NewPolicyRolloutRepository(s)
	now := time.Now()
	// From dry_run
	saved, _ := repo.Create(ctx(), tnt.ID, makeRollout(tnt.ID, g.ID))
	if _, err := repo.UpdateStage(ctx(), tnt.ID, saved.ID,
		repository.PolicyRolloutStageRolledBack, 0, "abort", nil, now); err != nil {
		t.Fatalf("dry_run -> rolled_back: %v", err)
	}
	// From canary
	saved2, _ := repo.Create(ctx(), tnt.ID, makeRollout(tnt.ID, g.ID))
	if _, err := repo.UpdateStage(ctx(), tnt.ID, saved2.ID,
		repository.PolicyRolloutStageCanary, 50, "", nil, now); err != nil {
		t.Fatalf("advance: %v", err)
	}
	if _, err := repo.UpdateStage(ctx(), tnt.ID, saved2.ID,
		repository.PolicyRolloutStageRolledBack, 0, "abort", nil, now); err != nil {
		t.Fatalf("canary -> rolled_back: %v", err)
	}
}

func TestRollout_GetActive_PrefersMostRecentNonTerminal(t *testing.T) {
	s, tnt, g := seedRolloutTenantAndGraph(t)
	repo := memory.NewPolicyRolloutRepository(s)
	now := time.Now()
	older, _ := repo.Create(ctx(), tnt.ID, makeRollout(tnt.ID, g.ID))
	if _, err := repo.UpdateStage(ctx(), tnt.ID, older.ID,
		repository.PolicyRolloutStageRolledBack, 0, "", nil, now); err != nil {
		t.Fatalf("rollback older: %v", err)
	}
	newer, _ := repo.Create(ctx(), tnt.ID, makeRollout(tnt.ID, g.ID))
	got, err := repo.GetActive(ctx(), tnt.ID)
	if err != nil {
		t.Fatalf("get active: %v", err)
	}
	if got.ID != newer.ID {
		t.Fatalf("active = %s, want %s (newer)", got.ID, newer.ID)
	}
}

func TestRollout_GetActive_ErrNotFoundWhenAllTerminal(t *testing.T) {
	s, tnt, g := seedRolloutTenantAndGraph(t)
	repo := memory.NewPolicyRolloutRepository(s)
	now := time.Now()
	saved, _ := repo.Create(ctx(), tnt.ID, makeRollout(tnt.ID, g.ID))
	if _, err := repo.UpdateStage(ctx(), tnt.ID, saved.ID,
		repository.PolicyRolloutStageRolledBack, 0, "", nil, now); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if _, err := repo.GetActive(ctx(), tnt.ID); !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestRollout_List_OrdersByCreatedAtDesc(t *testing.T) {
	s, tnt, g := seedRolloutTenantAndGraph(t)
	repo := memory.NewPolicyRolloutRepository(s)
	const n = 3
	ids := make([]uuid.UUID, 0, n)
	for i := 0; i < n; i++ {
		saved, err := repo.Create(ctx(), tnt.ID, makeRollout(tnt.ID, g.ID))
		if err != nil {
			t.Fatalf("create %d: %v", i, err)
		}
		ids = append(ids, saved.ID)
		// Roll back so the next Create doesn't trip a "one active at a time"
		// concept the service layer enforces (not the repo).
		_, _ = repo.UpdateStage(ctx(), tnt.ID, saved.ID,
			repository.PolicyRolloutStageRolledBack, 0, "", nil, time.Now())
	}
	page, err := repo.List(ctx(), tnt.ID, repository.Page{Limit: 10})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(page.Items) != n {
		t.Fatalf("len = %d, want %d", len(page.Items), n)
	}
	// Most-recently-created first.
	if page.Items[0].ID != ids[n-1] {
		t.Fatalf("first = %s, want most-recent %s", page.Items[0].ID, ids[n-1])
	}
}

func TestRollout_UpdateStage_RejectsBadCanaryPercent(t *testing.T) {
	s, tnt, g := seedRolloutTenantAndGraph(t)
	repo := memory.NewPolicyRolloutRepository(s)
	saved, _ := repo.Create(ctx(), tnt.ID, makeRollout(tnt.ID, g.ID))
	now := time.Now()
	if _, err := repo.UpdateStage(ctx(), tnt.ID, saved.ID,
		repository.PolicyRolloutStageCanary, 150, "", nil, now); !errors.Is(err, repository.ErrInvalidArgument) {
		t.Fatalf("err = %v, want ErrInvalidArgument", err)
	}
	if _, err := repo.UpdateStage(ctx(), tnt.ID, saved.ID,
		repository.PolicyRolloutStageCanary, -1, "", nil, now); !errors.Is(err, repository.ErrInvalidArgument) {
		t.Fatalf("err = %v, want ErrInvalidArgument", err)
	}
}

func TestRollout_Get_RespectsTenantIsolation(t *testing.T) {
	s, tntA, gA := seedRolloutTenantAndGraph(t)
	tr := memory.NewTenantRepository(s)
	tntB, err := tr.Create(ctx(), repository.Tenant{
		Name: "B", Slug: "b",
		Status: repository.TenantStatusActive,
		Tier:   repository.TenantTierStarter,
	})
	if err != nil {
		t.Fatalf("seed tenant b: %v", err)
	}
	repo := memory.NewPolicyRolloutRepository(s)
	saved, _ := repo.Create(ctx(), tntA.ID, makeRollout(tntA.ID, gA.ID))
	// Tenant B asking for tenant A's rollout must miss.
	if _, err := repo.Get(ctx(), tntB.ID, saved.ID); !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("cross-tenant Get err = %v, want ErrNotFound", err)
	}
}
