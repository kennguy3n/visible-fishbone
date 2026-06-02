package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// AICorrelationRepository owns the ai_alert_correlations table.
type AICorrelationRepository struct{ s *Store }

const aiCorrelationSelectColumns = `
id, tenant_id, alert_ids, summary, severity, status,
created_at, updated_at
`

func scanAICorrelation(row pgx.Row) (repository.AICorrelation, error) {
	var c repository.AICorrelation
	if err := row.Scan(
		&c.ID, &c.TenantID, &c.AlertIDs, &c.Summary,
		&c.Severity, &c.Status,
		&c.CreatedAt, &c.UpdatedAt,
	); err != nil {
		return repository.AICorrelation{}, err
	}
	return c, nil
}

// Create inserts a new correlation cluster.
func (r *AICorrelationRepository) Create(ctx context.Context, tenantID uuid.UUID, c repository.AICorrelation) (repository.AICorrelation, error) {
	var out repository.AICorrelation
	err := r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		status := c.Status
		if status == "" {
			status = "open"
		}
		row := tx.QueryRow(ctx,
			`INSERT INTO ai_alert_correlations (tenant_id, alert_ids, summary, severity, status)
			 VALUES ($1, $2, $3, $4, $5)
			 RETURNING `+aiCorrelationSelectColumns,
			tenantID, c.AlertIDs, c.Summary, c.Severity, status,
		)
		var err error
		out, err = scanAICorrelation(row)
		return err
	})
	if err != nil {
		if isUniqueViolation(err) {
			return repository.AICorrelation{}, repository.ErrConflict
		}
		return repository.AICorrelation{}, fmt.Errorf("ai_correlation create: %w", err)
	}
	return out, nil
}

// Get returns one correlation by ID, scoped to tenant.
func (r *AICorrelationRepository) Get(ctx context.Context, tenantID, id uuid.UUID) (repository.AICorrelation, error) {
	var out repository.AICorrelation
	err := r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx,
			`SELECT `+aiCorrelationSelectColumns+` FROM ai_alert_correlations WHERE id = $1`,
			id,
		)
		var err error
		out, err = scanAICorrelation(row)
		return err
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return repository.AICorrelation{}, repository.ErrNotFound
		}
		return repository.AICorrelation{}, fmt.Errorf("ai_correlation get: %w", err)
	}
	return out, nil
}

// List enumerates correlations in CreatedAt-DESC order with cursor
// pagination.
func (r *AICorrelationRepository) List(ctx context.Context, tenantID uuid.UUID, page repository.Page) (repository.PageResult[repository.AICorrelation], error) {
	page = page.Normalize()
	var result repository.PageResult[repository.AICorrelation]
	err := r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		query := `SELECT ` + aiCorrelationSelectColumns + ` FROM ai_alert_correlations`
		args := []any{}
		argN := 1

		if page.After != "" {
			cur, cerr := decodeCursor(page.After)
			if cerr != nil {
				return repository.ErrInvalidArgument
			}
			if page.Order == repository.SortAsc {
				query += fmt.Sprintf(` WHERE (created_at, id) > ($%d, $%d)`, argN, argN+1)
			} else {
				query += fmt.Sprintf(` WHERE (created_at, id) < ($%d, $%d)`, argN, argN+1)
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
		args = append(args, page.Limit+1)

		rows, err := tx.Query(ctx, query, args...)
		if err != nil {
			return err
		}
		defer rows.Close()

		items := make([]repository.AICorrelation, 0, page.Limit)
		for rows.Next() {
			c, serr := scanAICorrelation(rows)
			if serr != nil {
				return serr
			}
			items = append(items, c)
		}

		if len(items) > page.Limit {
			items = items[:page.Limit]
			last := items[len(items)-1]
			result.NextCursor = encodeCursor(pageCursor{T: last.CreatedAt, I: last.ID})
		}
		result.Items = items
		return rows.Err()
	})
	if err != nil {
		return repository.PageResult[repository.AICorrelation]{}, fmt.Errorf("ai_correlation list: %w", err)
	}
	return result, nil
}

// UpdateStatus transitions the status of a correlation.
func (r *AICorrelationRepository) UpdateStatus(ctx context.Context, tenantID, id uuid.UUID, status string) error {
	return r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		ct, err := tx.Exec(ctx,
			`UPDATE ai_alert_correlations SET status = $1, updated_at = now() WHERE id = $2`,
			status, id,
		)
		if err != nil {
			return err
		}
		if ct.RowsAffected() == 0 {
			return repository.ErrNotFound
		}
		return nil
	})
}
