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

// AISuggestionRepository owns the ai_policy_suggestions table.
type AISuggestionRepository struct{ s *Store }

var _ repository.AISuggestionRepository = (*AISuggestionRepository)(nil)

const aiSuggestionSelectColumns = `
id, tenant_id, rule_id, category, suggestion_json,
confidence, status, created_at, reviewed_at,
reviewer_id, feedback
`

func scanAISuggestion(row pgx.Row) (repository.AISuggestion, error) {
	var (
		s          repository.AISuggestion
		status     string
		reviewedAt deletedAtScan
		reviewerID nullableUUID
		feedback   *string
	)
	if err := row.Scan(
		&s.ID, &s.TenantID, &s.RuleID, &s.Category, &s.SuggestionJSON,
		&s.Confidence, &status, &s.CreatedAt, &reviewedAt,
		&reviewerID, &feedback,
	); err != nil {
		return repository.AISuggestion{}, err
	}
	s.Status = repository.AISuggestionStatus(status)
	if reviewedAt.Valid {
		v := reviewedAt.Time
		s.ReviewedAt = &v
	}
	if reviewerID.Valid {
		v := reviewerID.ID
		s.ReviewerID = &v
	}
	s.Feedback = feedback
	return s, nil
}

func (r *AISuggestionRepository) Create(ctx context.Context, tenantID uuid.UUID, s repository.AISuggestion) (repository.AISuggestion, error) {
	if s.ID == uuid.Nil {
		s.ID = uuid.New()
	}
	s.TenantID = tenantID
	if s.Status == "" {
		s.Status = repository.AISuggestionStatusPending
	}

	var out repository.AISuggestion
	err := r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx, `
			INSERT INTO ai_policy_suggestions
				(id, tenant_id, rule_id, category, suggestion_json, confidence, status)
			VALUES ($1, $2, $3, $4, $5, $6, $7)
			RETURNING `+aiSuggestionSelectColumns,
			s.ID, tenantID, s.RuleID, s.Category,
			s.SuggestionJSON, s.Confidence, string(s.Status),
		)
		var err error
		out, err = scanAISuggestion(row)
		return err
	})
	if err != nil {
		return repository.AISuggestion{}, fmt.Errorf("ai_suggestion create: %w", err)
	}
	return out, nil
}

func (r *AISuggestionRepository) Get(ctx context.Context, tenantID, id uuid.UUID) (repository.AISuggestion, error) {
	var out repository.AISuggestion
	err := r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx,
			`SELECT `+aiSuggestionSelectColumns+` FROM ai_policy_suggestions WHERE id = $1`, id)
		var err error
		out, err = scanAISuggestion(row)
		return err
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return repository.AISuggestion{}, repository.ErrNotFound
		}
		return repository.AISuggestion{}, fmt.Errorf("ai_suggestion get: %w", err)
	}
	return out, nil
}

func (r *AISuggestionRepository) List(ctx context.Context, tenantID uuid.UUID, status *string, page repository.Page) (repository.PageResult[repository.AISuggestion], error) {
	page = page.Normalize()
	var result repository.PageResult[repository.AISuggestion]

	err := r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		query := `SELECT ` + aiSuggestionSelectColumns + ` FROM ai_policy_suggestions WHERE 1=1`
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
			s, err := scanAISuggestion(rows)
			if err != nil {
				return fmt.Errorf("scan: %w", err)
			}
			result.Items = append(result.Items, s)
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
		return repository.PageResult[repository.AISuggestion]{}, fmt.Errorf("ai_suggestion list: %w", err)
	}
	if result.Items == nil {
		result.Items = []repository.AISuggestion{}
	}
	return result, nil
}

func (r *AISuggestionRepository) UpdateStatus(ctx context.Context, tenantID, id uuid.UUID, expectedStatus, newStatus string, reviewerID *uuid.UUID, feedback *string) error {
	err := r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		now := time.Now().UTC()
		tag, err := tx.Exec(ctx, `
			UPDATE ai_policy_suggestions
			   SET status = $1, reviewed_at = $2, reviewer_id = $3, feedback = $4
			 WHERE id = $5 AND status = $6`,
			newStatus, now, reviewerID, feedback, id, expectedStatus,
		)
		if err != nil {
			return fmt.Errorf("update status: %w", err)
		}
		if tag.RowsAffected() == 0 {
			// Zero rows can mean either the row does not exist (or is
			// hidden by RLS) or it exists but its status no longer
			// matches expectedStatus. Disambiguate so callers get the
			// right HTTP status (404 vs 409), matching the convention
			// used by the other postgres repositories.
			var exists bool
			if err := tx.QueryRow(ctx,
				`SELECT EXISTS (SELECT 1 FROM ai_policy_suggestions WHERE id = $1)`, id,
			).Scan(&exists); err != nil {
				return fmt.Errorf("update status existence check: %w", err)
			}
			if !exists {
				return repository.ErrNotFound
			}
			return repository.ErrConflict
		}
		return nil
	})
	return err
}
