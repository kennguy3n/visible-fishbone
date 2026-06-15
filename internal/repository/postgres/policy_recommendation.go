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

// PolicyRecommendationRepository owns the policy_recommendations table.
type PolicyRecommendationRepository struct{ s *Store }

var _ repository.PolicyRecommendationRepository = (*PolicyRecommendationRepository)(nil)

const policyRecommendationSelectColumns = `
id, tenant_id, status, window_start, window_end,
candidate_graph, summary, coverage, rule_count,
applied_graph_id, created_at, applied_at, actor_id
`

func scanPolicyRecommendation(row pgx.Row) (repository.PolicyRecommendation, error) {
	var (
		rec       repository.PolicyRecommendation
		status    string
		appliedID nullableUUID
		appliedAt deletedAtScan
		actorID   nullableUUID
	)
	if err := row.Scan(
		&rec.ID, &rec.TenantID, &status, &rec.WindowStart, &rec.WindowEnd,
		&rec.CandidateGraph, &rec.Summary, &rec.Coverage, &rec.RuleCount,
		&appliedID, &rec.CreatedAt, &appliedAt, &actorID,
	); err != nil {
		return repository.PolicyRecommendation{}, err
	}
	rec.Status = repository.PolicyRecommendationStatus(status)
	if appliedID.Valid {
		v := appliedID.ID
		rec.AppliedGraphID = &v
	}
	if appliedAt.Valid {
		v := appliedAt.Time
		rec.AppliedAt = &v
	}
	if actorID.Valid {
		v := actorID.ID
		rec.ActorID = &v
	}
	return rec, nil
}

func (r *PolicyRecommendationRepository) Create(ctx context.Context, tenantID uuid.UUID, rec repository.PolicyRecommendation) (repository.PolicyRecommendation, error) {
	if rec.ID == uuid.Nil {
		rec.ID = uuid.New()
	}
	rec.TenantID = tenantID
	if rec.Status == "" {
		rec.Status = repository.PolicyRecommendationStatusPending
	}

	var out repository.PolicyRecommendation
	err := r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx, `
			INSERT INTO policy_recommendations
				(id, tenant_id, status, window_start, window_end,
				 candidate_graph, summary, coverage, rule_count)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
			RETURNING `+policyRecommendationSelectColumns,
			rec.ID, tenantID, string(rec.Status), rec.WindowStart, rec.WindowEnd,
			rec.CandidateGraph, rec.Summary, rec.Coverage, rec.RuleCount,
		)
		var err error
		out, err = scanPolicyRecommendation(row)
		return err
	})
	if err != nil {
		return repository.PolicyRecommendation{}, fmt.Errorf("policy_recommendation create: %w", err)
	}
	return out, nil
}

func (r *PolicyRecommendationRepository) Get(ctx context.Context, tenantID, id uuid.UUID) (repository.PolicyRecommendation, error) {
	var out repository.PolicyRecommendation
	err := r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx,
			`SELECT `+policyRecommendationSelectColumns+` FROM policy_recommendations WHERE id = $1`, id)
		var err error
		out, err = scanPolicyRecommendation(row)
		return err
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return repository.PolicyRecommendation{}, repository.ErrNotFound
		}
		return repository.PolicyRecommendation{}, fmt.Errorf("policy_recommendation get: %w", err)
	}
	return out, nil
}

func (r *PolicyRecommendationRepository) List(ctx context.Context, tenantID uuid.UUID, status *string, page repository.Page) (repository.PageResult[repository.PolicyRecommendation], error) {
	page = page.Normalize()
	var result repository.PageResult[repository.PolicyRecommendation]

	err := r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		query := `SELECT ` + policyRecommendationSelectColumns + ` FROM policy_recommendations WHERE 1=1`
		args := []any{}
		argN := 1

		if status != nil {
			query += fmt.Sprintf(` AND status = $%d`, argN)
			args = append(args, *status)
			argN++
		}

		if page.After != "" {
			cur, err := decodeCursor(page.After)
			if err != nil {
				return repository.ErrInvalidArgument
			}
			if page.Order == repository.SortAsc {
				query += fmt.Sprintf(` AND (created_at, id) > ($%d, $%d)`, argN, argN+1)
			} else {
				query += fmt.Sprintf(` AND (created_at, id) < ($%d, $%d)`, argN, argN+1)
			}
			args = append(args, cur.T, cur.I)
			argN += 2
		}

		if page.Order == repository.SortAsc {
			query += ` ORDER BY created_at ASC, id ASC`
		} else {
			query += ` ORDER BY created_at DESC, id DESC`
		}
		query += fmt.Sprintf(` LIMIT $%d`, argN)
		args = append(args, page.Limit)

		rows, err := tx.Query(ctx, query, args...)
		if err != nil {
			return fmt.Errorf("list query: %w", err)
		}
		defer rows.Close()

		for rows.Next() {
			rec, err := scanPolicyRecommendation(rows)
			if err != nil {
				return fmt.Errorf("scan: %w", err)
			}
			result.Items = append(result.Items, rec)
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("rows: %w", err)
		}

		if len(result.Items) == page.Limit {
			last := result.Items[len(result.Items)-1]
			result.NextCursor = encodeCursor(pageCursor{T: last.CreatedAt, I: last.ID})
		}
		return nil
	})
	if err != nil {
		return repository.PageResult[repository.PolicyRecommendation]{}, fmt.Errorf("policy_recommendation list: %w", err)
	}
	if result.Items == nil {
		result.Items = []repository.PolicyRecommendation{}
	}
	return result, nil
}

func (r *PolicyRecommendationRepository) MarkApplied(ctx context.Context, tenantID, id, appliedGraphID uuid.UUID, actorID *uuid.UUID) error {
	return r.transition(ctx, tenantID, id, repository.PolicyRecommendationStatusApplied, &appliedGraphID, actorID)
}

func (r *PolicyRecommendationRepository) MarkDismissed(ctx context.Context, tenantID, id uuid.UUID, actorID *uuid.UUID) error {
	return r.transition(ctx, tenantID, id, repository.PolicyRecommendationStatusDismissed, nil, actorID)
}

func (r *PolicyRecommendationRepository) transition(ctx context.Context, tenantID, id uuid.UUID, newStatus repository.PolicyRecommendationStatus, appliedGraphID *uuid.UUID, actorID *uuid.UUID) error {
	return r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		// applied_at is the application timestamp; a dismissal leaves it
		// NULL. COALESCE keeps the existing value when $2 is nil.
		var appliedAt *time.Time
		if newStatus == repository.PolicyRecommendationStatusApplied {
			now := time.Now().UTC()
			appliedAt = &now
		}
		tag, err := tx.Exec(ctx, `
			UPDATE policy_recommendations
			   SET status = $1,
			       applied_at = COALESCE($2, applied_at),
			       applied_graph_id = COALESCE($3, applied_graph_id),
			       actor_id = COALESCE($4, actor_id)
			 WHERE id = $5 AND status = 'pending'`,
			string(newStatus), appliedAt, appliedGraphID, actorID, id,
		)
		if err != nil {
			return fmt.Errorf("transition: %w", err)
		}
		if tag.RowsAffected() == 0 {
			// Disambiguate not-found (404) from a non-pending status
			// (409), matching the convention used by the other
			// postgres repositories.
			var exists bool
			if err := tx.QueryRow(ctx,
				`SELECT EXISTS (SELECT 1 FROM policy_recommendations WHERE id = $1)`, id,
			).Scan(&exists); err != nil {
				return fmt.Errorf("transition existence check: %w", err)
			}
			if !exists {
				return repository.ErrNotFound
			}
			return repository.ErrConflict
		}
		return nil
	})
}
