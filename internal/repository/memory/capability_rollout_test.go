// Package memory_test — capability_rollout_test pins the write-time
// validation, created_at preservation and tenant-isolation contract for
// the CapabilityRolloutRepository so the memory store stays a faithful
// double for the Postgres CHECK constraints and RLS policy in migration
// 066.
package memory_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
	"github.com/kennguy3n/visible-fishbone/internal/service/rollout"
)

func TestCapabilityRolloutRepository_GetNotFound(t *testing.T) {
	t.Parallel()
	repo := memory.NewCapabilityRolloutRepository()
	_, err := repo.Get(context.Background(), uuid.New(), rollout.CapabilityClamAVSWG)
	if !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("Get on empty store = %v, want ErrNotFound", err)
	}
}

func TestCapabilityRolloutRepository_Validation(t *testing.T) {
	t.Parallel()
	repo := memory.NewCapabilityRolloutRepository()
	ctx := context.Background()
	tenant := uuid.New()

	cases := []struct {
		name string
		rec  rollout.Record
		tid  uuid.UUID
	}{
		{"nil tenant", rollout.Record{Capability: rollout.CapabilityClamAVSWG, State: rollout.StateMonitor}, uuid.Nil},
		{"bad capability", rollout.Record{Capability: "nope", State: rollout.StateMonitor}, tenant},
		{"bad state", rollout.Record{Capability: rollout.CapabilityClamAVSWG, State: "nope"}, tenant},
		{"tenant mismatch", rollout.Record{TenantID: uuid.New(), Capability: rollout.CapabilityClamAVSWG, State: rollout.StateMonitor}, tenant},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := repo.Upsert(ctx, c.tid, c.rec); !errors.Is(err, repository.ErrInvalidArgument) {
				t.Fatalf("Upsert(%s) = %v, want ErrInvalidArgument", c.name, err)
			}
		})
	}
}

func TestCapabilityRolloutRepository_UpsertPreservesCreatedAt(t *testing.T) {
	t.Parallel()
	repo := memory.NewCapabilityRolloutRepository()
	clock := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	repo.SetClock(func() time.Time { return clock })
	ctx := context.Background()
	tenant := uuid.New()

	first, err := repo.Upsert(ctx, tenant, rollout.Record{
		Capability: rollout.CapabilityClamAVSWG, State: rollout.StateMonitor, UpdatedBy: "op",
	})
	if err != nil {
		t.Fatalf("first upsert: %v", err)
	}

	clock = clock.Add(time.Hour)
	second, err := repo.Upsert(ctx, tenant, rollout.Record{
		Capability: rollout.CapabilityClamAVSWG, State: rollout.StateEnforce, UpdatedBy: "op2",
	})
	if err != nil {
		t.Fatalf("second upsert: %v", err)
	}
	if !second.CreatedAt.Equal(first.CreatedAt) {
		t.Fatalf("created_at changed across update: %s != %s", second.CreatedAt, first.CreatedAt)
	}
	if !second.UpdatedAt.After(first.UpdatedAt) {
		t.Fatalf("updated_at did not advance: %s !> %s", second.UpdatedAt, first.UpdatedAt)
	}
	if second.State != rollout.StateEnforce {
		t.Fatalf("state = %s, want enforce", second.State)
	}
}

func TestCapabilityRolloutRepository_TenantIsolation(t *testing.T) {
	t.Parallel()
	repo := memory.NewCapabilityRolloutRepository()
	ctx := context.Background()
	tenantA, tenantB := uuid.New(), uuid.New()

	if _, err := repo.Upsert(ctx, tenantA, rollout.Record{
		Capability: rollout.CapabilityClamAVSWG, State: rollout.StateMonitor, UpdatedBy: "a",
	}); err != nil {
		t.Fatalf("seed tenant A: %v", err)
	}
	if _, err := repo.Upsert(ctx, tenantB, rollout.Record{
		Capability: rollout.CapabilityIDPDirectorySync, State: rollout.StateEnforce, UpdatedBy: "b",
	}); err != nil {
		t.Fatalf("seed tenant B: %v", err)
	}

	// Tenant A sees only its own row; B's row is invisible.
	listA, err := repo.List(ctx, tenantA)
	if err != nil {
		t.Fatalf("list A: %v", err)
	}
	if len(listA) != 1 || listA[0].Capability != rollout.CapabilityClamAVSWG {
		t.Fatalf("tenant A list leaked across tenants: %+v", listA)
	}
	if _, err := repo.Get(ctx, tenantA, rollout.CapabilityIDPDirectorySync); !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("tenant A read of B's capability = %v, want ErrNotFound", err)
	}
}
