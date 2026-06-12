//go:build integration

package postgres_test

import (
	"errors"
	"testing"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/postgres"
	"github.com/kennguy3n/visible-fishbone/internal/service/rollout"
)

// TestCapabilityRollout_Integration exercises the Postgres-backed
// rollout store (migration 066) against a real container: the
// insert/update round-trip with created_at preservation, the default
// (no-row == off) read contract, and RLS tenant isolation. Run with
// `go test -tags integration ./...`.
func TestCapabilityRollout_Integration(t *testing.T) {
	t.Parallel()
	store, cleanup := startPostgres(t)
	t.Cleanup(cleanup)

	repo := postgres.NewCapabilityRolloutRepository(store)
	tnt := mustTenant(t, store.NewTenantRepository())

	t.Run("DefaultNoRowIsNotFound", func(t *testing.T) {
		if _, err := repo.Get(bgCtx(), tnt.ID, rollout.CapabilityClamAVSWG); !errors.Is(err, repository.ErrNotFound) {
			t.Fatalf("get on empty = %v, want ErrNotFound", err)
		}
		recs, err := repo.List(bgCtx(), tnt.ID)
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		if len(recs) != 0 {
			t.Fatalf("list on empty = %d rows, want 0", len(recs))
		}
	})

	t.Run("UpsertRoundTripPreservesCreatedAt", func(t *testing.T) {
		first, err := repo.Upsert(bgCtx(), tnt.ID, rollout.Record{
			Capability: rollout.CapabilityNoOpsAutoEnforce,
			State:      rollout.StateMonitor,
			Reason:     "begin rollout",
			UpdatedBy:  "operator-1",
		})
		if err != nil {
			t.Fatalf("first upsert: %v", err)
		}
		if first.CreatedAt.IsZero() || first.UpdatedAt.IsZero() {
			t.Fatalf("timestamps not populated: %+v", first)
		}

		second, err := repo.Upsert(bgCtx(), tnt.ID, rollout.Record{
			Capability: rollout.CapabilityNoOpsAutoEnforce,
			State:      rollout.StateEnforce,
			Reason:     "promote",
			UpdatedBy:  "operator-2",
		})
		if err != nil {
			t.Fatalf("second upsert: %v", err)
		}
		if !second.CreatedAt.Equal(first.CreatedAt) {
			t.Fatalf("created_at changed on update: %s != %s", second.CreatedAt, first.CreatedAt)
		}
		if !second.UpdatedAt.After(first.UpdatedAt) {
			t.Fatalf("updated_at trigger did not advance: %s !> %s", second.UpdatedAt, first.UpdatedAt)
		}

		got, err := repo.Get(bgCtx(), tnt.ID, rollout.CapabilityNoOpsAutoEnforce)
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		if got.State != rollout.StateEnforce || got.UpdatedBy != "operator-2" {
			t.Fatalf("round-trip mismatch: %+v", got)
		}
	})

	t.Run("InvalidStateRejectedByCheck", func(t *testing.T) {
		// The service never sends a bad state, but the schema CHECK is the
		// backstop. The repo guard rejects it before the query, so this
		// asserts the defense-in-depth contract holds at the repo edge.
		if _, err := repo.Upsert(bgCtx(), tnt.ID, rollout.Record{
			Capability: rollout.CapabilityClamAVSWG,
			State:      rollout.State("bogus"),
			UpdatedBy:  "x",
		}); !errors.Is(err, repository.ErrInvalidArgument) {
			t.Fatalf("bad state = %v, want ErrInvalidArgument", err)
		}
	})

	t.Run("RLSTenantIsolation", func(t *testing.T) {
		other := mustTenant(t, store.NewTenantRepository())
		if _, err := repo.Upsert(bgCtx(), tnt.ID, rollout.Record{
			Capability: rollout.CapabilityIDPDirectorySync,
			State:      rollout.StateMonitor,
			UpdatedBy:  "owner",
		}); err != nil {
			t.Fatalf("seed: %v", err)
		}
		// The other tenant's RLS scope hides the row entirely.
		if _, err := repo.Get(bgCtx(), other.ID, rollout.CapabilityIDPDirectorySync); !errors.Is(err, repository.ErrNotFound) {
			t.Fatalf("cross-tenant get = %v, want ErrNotFound", err)
		}
		recs, err := repo.List(bgCtx(), other.ID)
		if err != nil {
			t.Fatalf("list other: %v", err)
		}
		for _, r := range recs {
			if r.Capability == rollout.CapabilityIDPDirectorySync {
				t.Fatalf("RLS leak: tenant %s saw tenant %s's row", other.ID, tnt.ID)
			}
		}
	})

	t.Run("CapabilityIsOpaqueKeyNotConstrained", func(t *testing.T) {
		// The capability column is intentionally NOT constrained by a CHECK
		// (extensibility: new capabilities need no migration). The repo
		// guard blocks unknown capabilities today, but a future capability
		// added to the enum must persist without a schema change — proven
		// here by writing every current capability successfully.
		for _, c := range rollout.AllCapabilities() {
			if _, err := repo.Upsert(bgCtx(), tnt.ID, rollout.Record{
				Capability: c, State: rollout.StateOff, UpdatedBy: "op",
			}); err != nil {
				t.Fatalf("upsert %s: %v", c, err)
			}
		}
	})
}
