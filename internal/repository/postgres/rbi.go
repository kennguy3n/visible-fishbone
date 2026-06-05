package postgres

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

const rbiSessionSelectColumns = `id, tenant_id, user_id, target_url, status, expires_at, created_at, updated_at`

// RBISessionRepository is the Postgres-backed implementation of
// repository.RBISessionRepository against the rbi_sessions table
// (migration 043). Every operation runs through withTenant /
// withTenantRO so the table's RLS policy enforces isolation.
type RBISessionRepository struct{ s *Store }

var _ repository.RBISessionRepository = (*RBISessionRepository)(nil)

func scanRBISession(row pgx.Row) (repository.RBISession, error) {
	var s repository.RBISession
	err := row.Scan(
		&s.ID, &s.TenantID, &s.UserID, &s.TargetURL,
		&s.Status, &s.ExpiresAt, &s.CreatedAt, &s.UpdatedAt,
	)
	return s, err
}

func (repo *RBISessionRepository) Create(
	ctx context.Context,
	tenantID uuid.UUID,
	s repository.RBISession,
) (repository.RBISession, error) {
	if s.ID == uuid.Nil {
		s.ID = uuid.New()
	}
	var out repository.RBISession
	err := repo.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx, `
			INSERT INTO rbi_sessions
				(id, tenant_id, user_id, target_url, status, expires_at)
			VALUES ($1, $2, $3, $4, $5, $6)
			RETURNING `+rbiSessionSelectColumns,
			s.ID, tenantID, s.UserID, s.TargetURL, s.Status, s.ExpiresAt)
		var serr error
		out, serr = scanRBISession(row)
		return serr
	})
	if err != nil {
		if isForeignKeyViolation(err) {
			return repository.RBISession{}, repository.ErrNotFound
		}
		if isCheckViolation(err) {
			return repository.RBISession{}, repository.ErrInvalidArgument
		}
		return repository.RBISession{}, err
	}
	return out, nil
}

func (repo *RBISessionRepository) Get(
	ctx context.Context,
	tenantID, id uuid.UUID,
) (repository.RBISession, error) {
	var out repository.RBISession
	err := repo.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx, `
			SELECT `+rbiSessionSelectColumns+`
			FROM rbi_sessions
			WHERE id = $1`, id)
		var serr error
		out, serr = scanRBISession(row)
		return serr
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return repository.RBISession{}, repository.ErrNotFound
		}
		return repository.RBISession{}, err
	}
	return out, nil
}

func (repo *RBISessionRepository) List(
	ctx context.Context,
	tenantID uuid.UUID,
	limit int,
) ([]repository.RBISession, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	var out []repository.RBISession
	err := repo.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		rows, qerr := tx.Query(ctx, `
			SELECT `+rbiSessionSelectColumns+`
			FROM rbi_sessions
			ORDER BY created_at DESC, id
			LIMIT $1`, limit)
		if qerr != nil {
			return qerr
		}
		defer rows.Close()
		for rows.Next() {
			s, serr := scanRBISession(rows)
			if serr != nil {
				return serr
			}
			out = append(out, s)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (repo *RBISessionRepository) Close(
	ctx context.Context,
	tenantID, id uuid.UUID,
) error {
	return repo.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `
			UPDATE rbi_sessions SET status = 'closed' WHERE id = $1 AND status = 'active'`, id)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return repository.ErrNotFound
		}
		return nil
	})
}
