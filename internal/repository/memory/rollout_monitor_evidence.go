package memory

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/service/rollout"
)

// RolloutMonitorEvidenceRepository is the memory-backed implementation of
// rollout.MonitorMetricsStore (migration 069): the durable cache of the
// latest monitor-phase observation per (tenant, capability) the WS-5
// auto-promoter reads as promotion evidence. Tenant isolation is enforced
// by keying on tenant_id, mirroring the Postgres RLS policy.
//
// Like the capability_rollout repo, this is a self-contained feature
// whose table is introduced by a single migration, so its state is kept
// local rather than hanging off the shared Store.
type RolloutMonitorEvidenceRepository struct {
	mu   sync.RWMutex
	rows map[monitorEvidenceKey]monitorEvidenceRow
}

type monitorEvidenceKey struct {
	tenant     uuid.UUID
	capability rollout.Capability
}

type monitorEvidenceRow struct {
	metrics    rollout.MonitorMetrics
	observedAt time.Time
}

// NewRolloutMonitorEvidenceRepository returns an empty in-memory store.
func NewRolloutMonitorEvidenceRepository() *RolloutMonitorEvidenceRepository {
	return &RolloutMonitorEvidenceRepository{
		rows: make(map[monitorEvidenceKey]monitorEvidenceRow),
	}
}

var _ rollout.MonitorMetricsStore = (*RolloutMonitorEvidenceRepository)(nil)

// PutSnapshot inserts or updates the latest snapshot for (tenant,
// capability). It mirrors the Postgres upsert: the newest observed_at
// wins, so an out-of-order older write never overwrites fresher evidence.
func (r *RolloutMonitorEvidenceRepository) PutSnapshot(ctx context.Context, tenantID uuid.UUID, c rollout.Capability, m rollout.MonitorMetrics, observedAt time.Time) error {
	if err := errCtxIfNeeded(ctx); err != nil {
		return err
	}
	if tenantID == uuid.Nil || !c.Valid() {
		return nil
	}
	key := monitorEvidenceKey{tenant: tenantID, capability: c}
	r.mu.Lock()
	defer r.mu.Unlock()
	if cur, ok := r.rows[key]; ok && observedAt.Before(cur.observedAt) {
		return nil
	}
	r.rows[key] = monitorEvidenceRow{metrics: m, observedAt: observedAt}
	return nil
}

// GetSnapshot returns the stored snapshot for (tenant, capability).
// found is false (err nil) when none is stored.
func (r *RolloutMonitorEvidenceRepository) GetSnapshot(ctx context.Context, tenantID uuid.UUID, c rollout.Capability) (rollout.MonitorMetrics, time.Time, bool, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return rollout.MonitorMetrics{}, time.Time{}, false, err
	}
	if tenantID == uuid.Nil || !c.Valid() {
		return rollout.MonitorMetrics{}, time.Time{}, false, nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	row, ok := r.rows[monitorEvidenceKey{tenant: tenantID, capability: c}]
	if !ok {
		return rollout.MonitorMetrics{}, time.Time{}, false, nil
	}
	return row.metrics, row.observedAt, true, nil
}
