package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// PolicyReviewScheduleRepository owns the policy_review_schedules table.
type PolicyReviewScheduleRepository struct{ s *Store }

func (r *PolicyReviewScheduleRepository) Create(ctx context.Context, tenantID uuid.UUID, sched repository.PolicyReviewSchedule) (repository.PolicyReviewSchedule, error) {
	if tenantID == uuid.Nil || sched.PolicyID == uuid.Nil {
		return repository.PolicyReviewSchedule{}, repository.ErrInvalidArgument
	}
	var out repository.PolicyReviewSchedule
	err := r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		const q = `
			INSERT INTO policy_review_schedules
				(tenant_id, policy_id, last_reviewed_at, next_review_at, review_interval_days)
			VALUES ($1::uuid, $2::uuid, $3, $4, $5)
			RETURNING id, tenant_id, policy_id, last_reviewed_at, next_review_at,
			          review_interval_days, created_at`
		row := tx.QueryRow(ctx, q,
			tenantID, sched.PolicyID, nilTime(sched.LastReviewedAt),
			nilTime(sched.NextReviewAt), sched.ReviewIntervalDays,
		)
		var lastReviewed deletedAtScan
		var nextReview deletedAtScan
		if err := row.Scan(
			&out.ID, &out.TenantID, &out.PolicyID,
			&lastReviewed, &nextReview,
			&out.ReviewIntervalDays, &out.CreatedAt,
		); err != nil {
			if isUniqueViolation(err) {
				return repository.ErrConflict
			}
			return fmt.Errorf("insert policy_review_schedule: %w", err)
		}
		if lastReviewed.Valid {
			t := lastReviewed.Time
			out.LastReviewedAt = &t
		}
		if nextReview.Valid {
			t := nextReview.Time
			out.NextReviewAt = &t
		}
		return nil
	})
	return out, err
}

func (r *PolicyReviewScheduleRepository) Get(ctx context.Context, tenantID, policyID uuid.UUID) (repository.PolicyReviewSchedule, error) {
	var out repository.PolicyReviewSchedule
	err := r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		const q = `
			SELECT id, tenant_id, policy_id, last_reviewed_at, next_review_at,
			       review_interval_days, created_at
			FROM policy_review_schedules
			WHERE policy_id = $1::uuid
			LIMIT 1`
		row := tx.QueryRow(ctx, q, policyID)
		var lastReviewed deletedAtScan
		var nextReview deletedAtScan
		if err := row.Scan(
			&out.ID, &out.TenantID, &out.PolicyID,
			&lastReviewed, &nextReview,
			&out.ReviewIntervalDays, &out.CreatedAt,
		); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return repository.ErrNotFound
			}
			return fmt.Errorf("get policy_review_schedule: %w", err)
		}
		if lastReviewed.Valid {
			t := lastReviewed.Time
			out.LastReviewedAt = &t
		}
		if nextReview.Valid {
			t := nextReview.Time
			out.NextReviewAt = &t
		}
		return nil
	})
	return out, err
}

func (r *PolicyReviewScheduleRepository) ListDue(ctx context.Context, before time.Time, limit int) ([]repository.PolicyReviewSchedule, error) {
	if limit <= 0 {
		limit = 100
	}
	var out []repository.PolicyReviewSchedule
	err := r.s.withSystem(ctx, func(tx pgx.Tx) error {
		const q = `
			SELECT id, tenant_id, policy_id, last_reviewed_at, next_review_at,
			       review_interval_days, created_at
			FROM policy_review_schedules
			WHERE next_review_at <= $1
			ORDER BY next_review_at ASC
			LIMIT $2`
		rows, err := tx.Query(ctx, q, before, limit)
		if err != nil {
			return fmt.Errorf("list due review schedules: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var s repository.PolicyReviewSchedule
			var lastReviewed deletedAtScan
			var nextReview deletedAtScan
			if err := rows.Scan(
				&s.ID, &s.TenantID, &s.PolicyID,
				&lastReviewed, &nextReview,
				&s.ReviewIntervalDays, &s.CreatedAt,
			); err != nil {
				return fmt.Errorf("scan review schedule: %w", err)
			}
			if lastReviewed.Valid {
				t := lastReviewed.Time
				s.LastReviewedAt = &t
			}
			if nextReview.Valid {
				t := nextReview.Time
				s.NextReviewAt = &t
			}
			out = append(out, s)
		}
		return rows.Err()
	})
	return out, err
}

func (r *PolicyReviewScheduleRepository) UpdateLastReviewed(ctx context.Context, tenantID, policyID uuid.UUID, at time.Time) error {
	return r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		const q = `
			UPDATE policy_review_schedules
			SET last_reviewed_at = $1,
			    next_review_at   = $1 + make_interval(days => review_interval_days)
			WHERE policy_id = $2::uuid`
		tag, err := tx.Exec(ctx, q, at, policyID)
		if err != nil {
			return fmt.Errorf("update last_reviewed: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return repository.ErrNotFound
		}
		return nil
	})
}

// OpsHealthSnapshotRepository owns the ops_health_snapshots table.
type OpsHealthSnapshotRepository struct{ s *Store }

func (r *OpsHealthSnapshotRepository) Create(ctx context.Context, tenantID uuid.UUID, snap repository.OpsHealthSnapshot) (repository.OpsHealthSnapshot, error) {
	if tenantID == uuid.Nil {
		return repository.OpsHealthSnapshot{}, repository.ErrInvalidArgument
	}
	var out repository.OpsHealthSnapshot
	err := r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		const q = `
			INSERT INTO ops_health_snapshots (tenant_id, health_score, component_scores)
			VALUES ($1::uuid, $2, $3)
			RETURNING id, tenant_id, health_score, component_scores, created_at`
		row := tx.QueryRow(ctx, q, tenantID, snap.HealthScore, snap.ComponentScores)
		if err := row.Scan(&out.ID, &out.TenantID, &out.HealthScore,
			&out.ComponentScores, &out.CreatedAt); err != nil {
			return fmt.Errorf("insert ops_health_snapshot: %w", err)
		}
		return nil
	})
	return out, err
}

func (r *OpsHealthSnapshotRepository) GetLatest(ctx context.Context, tenantID uuid.UUID) (repository.OpsHealthSnapshot, error) {
	var out repository.OpsHealthSnapshot
	err := r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		const q = `
			SELECT id, tenant_id, health_score, component_scores, created_at
			FROM ops_health_snapshots
			ORDER BY created_at DESC
			LIMIT 1`
		row := tx.QueryRow(ctx, q)
		if err := row.Scan(&out.ID, &out.TenantID, &out.HealthScore,
			&out.ComponentScores, &out.CreatedAt); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return repository.ErrNotFound
			}
			return fmt.Errorf("get latest ops_health_snapshot: %w", err)
		}
		return nil
	})
	return out, err
}

func (r *OpsHealthSnapshotRepository) ListHistory(ctx context.Context, tenantID uuid.UUID, since time.Time) ([]repository.OpsHealthSnapshot, error) {
	var out []repository.OpsHealthSnapshot
	err := r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		const q = `
			SELECT id, tenant_id, health_score, component_scores, created_at
			FROM ops_health_snapshots
			WHERE created_at >= $1
			ORDER BY created_at DESC
			LIMIT $2`
		rows, err := tx.Query(ctx, q, since, repository.MaxOpsHealthHistory)
		if err != nil {
			return fmt.Errorf("list ops_health_snapshot history: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var s repository.OpsHealthSnapshot
			if err := rows.Scan(&s.ID, &s.TenantID, &s.HealthScore,
				&s.ComponentScores, &s.CreatedAt); err != nil {
				return fmt.Errorf("scan ops_health_snapshot: %w", err)
			}
			out = append(out, s)
		}
		return rows.Err()
	})
	return out, err
}

func nilTime(t *time.Time) any {
	if t == nil {
		return nil
	}
	return *t
}
