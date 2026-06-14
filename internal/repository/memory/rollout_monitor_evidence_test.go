package memory_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
	"github.com/kennguy3n/visible-fishbone/internal/service/rollout"
)

func TestRolloutMonitorEvidenceRepository(t *testing.T) {
	t.Parallel()
	repo := memory.NewRolloutMonitorEvidenceRepository()
	ctx := context.Background()
	tenant := uuid.New()
	capID := rollout.CapabilityNoOpsAutoEnforce
	t0 := time.Unix(1_700_000_000, 0).UTC()

	// Missing key: not found, no error.
	if _, _, found, err := repo.GetSnapshot(ctx, tenant, capID); err != nil || found {
		t.Fatalf("missing GetSnapshot = (found %v, err %v), want (false, nil)", found, err)
	}

	// Invalid keys are no-ops, not errors.
	if err := repo.PutSnapshot(ctx, uuid.Nil, capID, rollout.MonitorMetrics{Samples: 1}, t0); err != nil {
		t.Fatalf("nil-tenant put: %v", err)
	}
	if err := repo.PutSnapshot(ctx, tenant, rollout.Capability("bogus"), rollout.MonitorMetrics{Samples: 1}, t0); err != nil {
		t.Fatalf("bad-cap put: %v", err)
	}

	// Store, then read back.
	if err := repo.PutSnapshot(ctx, tenant, capID, rollout.MonitorMetrics{Samples: 100, Errors: 2, Denies: 5}, t0); err != nil {
		t.Fatalf("put: %v", err)
	}
	m, at, found, err := repo.GetSnapshot(ctx, tenant, capID)
	if err != nil || !found || m.Samples != 100 || m.Errors != 2 || m.Denies != 5 || !at.Equal(t0) {
		t.Fatalf("GetSnapshot = (%+v, %v, %v, %v), want samples 100 @ t0", m, at, found, err)
	}

	// A newer observed_at wins.
	t1 := t0.Add(time.Hour)
	if err := repo.PutSnapshot(ctx, tenant, capID, rollout.MonitorMetrics{Samples: 200}, t1); err != nil {
		t.Fatalf("newer put: %v", err)
	}
	if m, at, _, _ := repo.GetSnapshot(ctx, tenant, capID); m.Samples != 200 || !at.Equal(t1) {
		t.Fatalf("after newer put = (%+v @ %v), want samples 200 @ t1", m, at)
	}

	// An OLDER out-of-order write must not clobber the fresher snapshot.
	if err := repo.PutSnapshot(ctx, tenant, capID, rollout.MonitorMetrics{Samples: 1}, t0); err != nil {
		t.Fatalf("stale put: %v", err)
	}
	if m, at, _, _ := repo.GetSnapshot(ctx, tenant, capID); m.Samples != 200 || !at.Equal(t1) {
		t.Fatalf("after stale put = (%+v @ %v), want unchanged samples 200 @ t1", m, at)
	}
}
