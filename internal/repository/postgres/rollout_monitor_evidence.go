package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/kennguy3n/visible-fishbone/internal/service/rollout"
)

// RolloutMonitorEvidenceRepository owns the rollout_monitor_evidence
// table (migration 069): the durable cache of the latest monitor-phase
// observation per (tenant, capability) the WS-5 auto-promoter reads as
// promotion evidence so the dwell clock survives a leader failover. Every
// query runs inside withTenant/withTenantRO so the `sng.tenant_id` GUC is
// set and RLS scopes the rows to the caller's tenant.
//
// It implements rollout.MonitorMetricsStore (declared in the service
// package), so the dependency points inward and this file is the only
// place that knows both the SQL schema and the domain type.
type RolloutMonitorEvidenceRepository struct{ s *Store }

// NewRolloutMonitorEvidenceRepository binds the Store to the
// rollout.MonitorMetricsStore interface.
func NewRolloutMonitorEvidenceRepository(s *Store) *RolloutMonitorEvidenceRepository {
	return &RolloutMonitorEvidenceRepository{s: s}
}

var _ rollout.MonitorMetricsStore = (*RolloutMonitorEvidenceRepository)(nil)

// PutSnapshot upserts the latest snapshot for (tenant, capability). The
// newest observed_at wins, so an out-of-order older write (e.g. a delayed
// goroutine) never overwrites fresher evidence.
func (r *RolloutMonitorEvidenceRepository) PutSnapshot(ctx context.Context, tenantID uuid.UUID, c rollout.Capability, m rollout.MonitorMetrics, observedAt time.Time) error {
	if tenantID == uuid.Nil || !c.Valid() {
		return nil
	}
	if observedAt.IsZero() {
		observedAt = time.Now().UTC()
	}
	return r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		const q = `
			INSERT INTO rollout_monitor_evidence
				(tenant_id, capability, samples, errors, denies, observed_at)
			VALUES ($1::uuid, $2, $3, $4, $5, $6)
			ON CONFLICT (tenant_id, capability) DO UPDATE SET
				samples     = EXCLUDED.samples,
				errors      = EXCLUDED.errors,
				denies      = EXCLUDED.denies,
				observed_at = EXCLUDED.observed_at
			WHERE EXCLUDED.observed_at >= rollout_monitor_evidence.observed_at`
		if _, err := tx.Exec(ctx, q,
			tenantID, string(c), m.Samples, m.Errors, m.Denies, observedAt); err != nil {
			return fmt.Errorf("upsert rollout_monitor_evidence: %w", err)
		}
		return nil
	})
}

// GetSnapshot returns the stored snapshot for (tenant, capability).
// found is false (err nil) when none is stored.
func (r *RolloutMonitorEvidenceRepository) GetSnapshot(ctx context.Context, tenantID uuid.UUID, c rollout.Capability) (rollout.MonitorMetrics, time.Time, bool, error) {
	if tenantID == uuid.Nil || !c.Valid() {
		return rollout.MonitorMetrics{}, time.Time{}, false, nil
	}
	var (
		m          rollout.MonitorMetrics
		observedAt time.Time
		found      bool
	)
	err := r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		const q = `
			SELECT samples, errors, denies, observed_at
			FROM rollout_monitor_evidence
			WHERE tenant_id = $1::uuid AND capability = $2`
		row := tx.QueryRow(ctx, q, tenantID, string(c))
		if err := row.Scan(&m.Samples, &m.Errors, &m.Denies, &observedAt); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return nil
			}
			return fmt.Errorf("get rollout_monitor_evidence: %w", err)
		}
		found = true
		return nil
	})
	if err != nil {
		return rollout.MonitorMetrics{}, time.Time{}, false, err
	}
	return m, observedAt, found, nil
}
