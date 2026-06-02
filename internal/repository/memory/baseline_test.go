// Package memory_test — baseline_test exercises the in-memory
// BaselineModelRepository contract that the postgres impl must
// also satisfy.
//
// The tests pin three behaviours that are easy to regress:
//
//  1. UPSERT semantics — INSERT on first call, optimistic-locked
//     UPDATE on subsequent ones.
//  2. Optimistic lock — a stale Version on Upsert returns
//     ErrConflict and does NOT mutate the persisted row.
//  3. UpdateThreshold leaves Welford / EWMA state untouched.
//
// Each test creates a fresh tenant via the seed helper so RLS
// scoping is honoured for the cross-driver expectation.
package memory_test

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
)

func seedBaselineTenant(t *testing.T) (*memory.Store, repository.Tenant) {
	t.Helper()
	s := newStore(t)
	tr := memory.NewTenantRepository(s)
	tnt, err := tr.Create(ctx(), repository.Tenant{
		Name:   "BL",
		Slug:   "bl",
		Status: repository.TenantStatusActive,
		Tier:   repository.TenantTierStarter,
	})
	if err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	return s, tnt
}

func TestBaseline_Upsert_InsertsOnFirstCall(t *testing.T) {
	s, tnt := seedBaselineTenant(t)
	repo := memory.NewBaselineModelRepository(s)
	m := repository.BaselineModel{
		Dimension:     "dns.queries.NXDOMAIN",
		WindowSeconds: 60,
		Alpha:         0.1,
		ZThreshold:    3.0,
		Samples:       1,
		Mean:          42,
		M2:            0,
		EWMA:          42,
	}
	saved, err := repo.Upsert(ctx(), tnt.ID, m)
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if saved.ID == uuid.Nil {
		t.Fatalf("missing id on insert")
	}
	if saved.Version != 1 {
		t.Fatalf("version = %d, want 1 on insert", saved.Version)
	}
	if saved.Samples != 1 || saved.Mean != 42 {
		t.Fatalf("samples=%d mean=%v want 1 / 42", saved.Samples, saved.Mean)
	}
}

func TestBaseline_Upsert_OptimisticLockConflict(t *testing.T) {
	s, tnt := seedBaselineTenant(t)
	repo := memory.NewBaselineModelRepository(s)
	saved, err := repo.Upsert(ctx(), tnt.ID, repository.BaselineModel{
		Dimension: "auth.failures", WindowSeconds: 60, Alpha: 0.1, ZThreshold: 3.0,
		Samples: 1, Mean: 1, EWMA: 1,
	})
	if err != nil {
		t.Fatalf("seed upsert: %v", err)
	}

	stale := saved
	stale.Version = 99 // wrong version
	stale.Samples = 2
	_, err = repo.Upsert(ctx(), tnt.ID, stale)
	if !errors.Is(err, repository.ErrConflict) {
		t.Fatalf("stale upsert err = %v, want ErrConflict", err)
	}

	// Persisted row must be unchanged.
	cur, err := repo.GetForDimension(ctx(), tnt.ID, "auth.failures", 60)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if cur.Samples != 1 {
		t.Fatalf("samples = %d, want 1 (no mutation under conflict)", cur.Samples)
	}
	if cur.Version != saved.Version {
		t.Fatalf("version = %d, want %d (unchanged)", cur.Version, saved.Version)
	}
}

func TestBaseline_Upsert_UpdatesAndBumpsVersion(t *testing.T) {
	s, tnt := seedBaselineTenant(t)
	repo := memory.NewBaselineModelRepository(s)
	saved, err := repo.Upsert(ctx(), tnt.ID, repository.BaselineModel{
		Dimension: "policy.deny_rate", WindowSeconds: 60, Alpha: 0.1, ZThreshold: 3.0,
		Samples: 1, Mean: 0.1,
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	saved.Samples = 5
	saved.Mean = 0.2
	saved.M2 = 0.05
	saved.EWMA = 0.18
	saved.EWMAVar = 0.001
	updated, err := repo.Upsert(ctx(), tnt.ID, saved)
	if err != nil {
		t.Fatalf("upsert update: %v", err)
	}
	if updated.Version != saved.Version+1 {
		t.Fatalf("version = %d, want %d", updated.Version, saved.Version+1)
	}
	if updated.Samples != 5 || updated.Mean != 0.2 {
		t.Fatalf("samples=%d mean=%v want 5 / 0.2", updated.Samples, updated.Mean)
	}
}

func TestBaseline_GetForDimension_NotFound(t *testing.T) {
	s, tnt := seedBaselineTenant(t)
	repo := memory.NewBaselineModelRepository(s)
	_, err := repo.GetForDimension(ctx(), tnt.ID, "missing.dim", 60)
	if !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestBaseline_UpdateThreshold_PreservesWelford(t *testing.T) {
	s, tnt := seedBaselineTenant(t)
	repo := memory.NewBaselineModelRepository(s)
	saved, err := repo.Upsert(ctx(), tnt.ID, repository.BaselineModel{
		Dimension: "flow.bytes_total", WindowSeconds: 60, Alpha: 0.1, ZThreshold: 3.0,
		Samples: 100, Mean: 1234, M2: 5678, EWMA: 1200, EWMAVar: 200,
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	updated, err := repo.UpdateThreshold(ctx(), tnt.ID, "flow.bytes_total", 60, 4.5)
	if err != nil {
		t.Fatalf("update threshold: %v", err)
	}
	if updated.ZThreshold != 4.5 {
		t.Fatalf("ZThreshold = %v, want 4.5", updated.ZThreshold)
	}
	// Welford / EWMA state must be untouched.
	if updated.Samples != saved.Samples ||
		updated.Mean != saved.Mean ||
		updated.M2 != saved.M2 ||
		updated.EWMA != saved.EWMA ||
		updated.EWMAVar != saved.EWMAVar {
		t.Fatalf("Welford/EWMA state mutated by UpdateThreshold:\nbefore=%+v\nafter=%+v",
			saved, updated)
	}
	if updated.Version != saved.Version+1 {
		t.Fatalf("version = %d, want %d", updated.Version, saved.Version+1)
	}
}

func TestBaseline_UpdateThreshold_NotFound(t *testing.T) {
	s, tnt := seedBaselineTenant(t)
	repo := memory.NewBaselineModelRepository(s)
	_, err := repo.UpdateThreshold(ctx(), tnt.ID, "missing.dim", 60, 4.5)
	if !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestBaseline_UpdateThreshold_RejectsNonPositive(t *testing.T) {
	s, tnt := seedBaselineTenant(t)
	repo := memory.NewBaselineModelRepository(s)
	_, _ = repo.Upsert(ctx(), tnt.ID, repository.BaselineModel{
		Dimension: "x", WindowSeconds: 60, Alpha: 0.1, ZThreshold: 3.0, Samples: 1,
	})
	for _, z := range []float64{0, -1} {
		_, err := repo.UpdateThreshold(ctx(), tnt.ID, "x", 60, z)
		if !errors.Is(err, repository.ErrInvalidArgument) {
			t.Fatalf("z=%v: err = %v, want ErrInvalidArgument", z, err)
		}
	}
}

func TestBaseline_List_TenantScopedAndOrdered(t *testing.T) {
	s, tnt := seedBaselineTenant(t)
	repo := memory.NewBaselineModelRepository(s)

	// Seed a second tenant.
	tr := memory.NewTenantRepository(s)
	otherTnt, err := tr.Create(ctx(), repository.Tenant{
		Name: "Other", Slug: "other", Status: repository.TenantStatusActive,
		Tier: repository.TenantTierStarter,
	})
	if err != nil {
		t.Fatalf("seed other tenant: %v", err)
	}
	_, _ = repo.Upsert(ctx(), otherTnt.ID, repository.BaselineModel{
		Dimension: "leaked.dim", WindowSeconds: 60, Alpha: 0.1, ZThreshold: 3.0, Samples: 1,
	})

	dims := []string{"a", "b", "c"}
	for _, d := range dims {
		_, err := repo.Upsert(ctx(), tnt.ID, repository.BaselineModel{
			Dimension: d, WindowSeconds: 60, Alpha: 0.1, ZThreshold: 3.0, Samples: 1,
		})
		if err != nil {
			t.Fatalf("upsert %s: %v", d, err)
		}
		// Force monotonic LastUpdatedAt via the fixed clock.
		time.Sleep(time.Millisecond)
	}

	pg, err := repo.List(ctx(), tnt.ID, repository.Page{Limit: 10})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(pg.Items) != 3 {
		t.Fatalf("len = %d, want 3 (no cross-tenant leakage)", len(pg.Items))
	}
	for _, m := range pg.Items {
		if m.TenantID != tnt.ID {
			t.Fatalf("cross-tenant leak: model %s belongs to %s", m.Dimension, m.TenantID)
		}
	}
	// Most recently updated first.
	for i := 0; i < len(pg.Items)-1; i++ {
		if pg.Items[i].LastUpdatedAt.Before(pg.Items[i+1].LastUpdatedAt) {
			t.Fatalf("not LastUpdatedAt-DESC at %d", i)
		}
	}
}

func TestBaseline_Upsert_RejectsInvalidArgs(t *testing.T) {
	s, tnt := seedBaselineTenant(t)
	repo := memory.NewBaselineModelRepository(s)
	for _, tc := range []struct {
		name string
		m    repository.BaselineModel
	}{
		{"empty dimension", repository.BaselineModel{Dimension: "", WindowSeconds: 60, Alpha: 0.1, ZThreshold: 3.0}},
		{"zero window", repository.BaselineModel{Dimension: "d", WindowSeconds: 0, Alpha: 0.1, ZThreshold: 3.0}},
		{"alpha out of range high", repository.BaselineModel{Dimension: "d", WindowSeconds: 60, Alpha: 1.5, ZThreshold: 3.0}},
		{"alpha out of range low", repository.BaselineModel{Dimension: "d", WindowSeconds: 60, Alpha: 0, ZThreshold: 3.0}},
		{"non-positive threshold", repository.BaselineModel{Dimension: "d", WindowSeconds: 60, Alpha: 0.1, ZThreshold: 0}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := repo.Upsert(ctx(), tnt.ID, tc.m)
			if !errors.Is(err, repository.ErrInvalidArgument) {
				t.Fatalf("err = %v, want ErrInvalidArgument", err)
			}
		})
	}
}
