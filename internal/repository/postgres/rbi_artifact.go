package postgres

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

const rbiArtifactSelectColumns = `id, tenant_id, session_id, kind, direction, filename, sha256, size_bytes, created_at`

// RBIArtifactRepository is the Postgres-backed implementation of
// repository.RBIArtifactRepository against the rbi_session_artifacts
// table (migration 048). Every operation runs through withTenant /
// withTenantRO so the table's RLS policy enforces isolation.
type RBIArtifactRepository struct{ s *Store }

var _ repository.RBIArtifactRepository = (*RBIArtifactRepository)(nil)

func scanRBIArtifact(row pgx.Row) (repository.RBIArtifact, error) {
	var a repository.RBIArtifact
	err := row.Scan(
		&a.ID, &a.TenantID, &a.SessionID, &a.Kind, &a.Direction,
		&a.Filename, &a.SHA256, &a.SizeBytes, &a.CreatedAt,
	)
	return a, err
}

func (repo *RBIArtifactRepository) Create(
	ctx context.Context,
	tenantID uuid.UUID,
	a repository.RBIArtifact,
) (repository.RBIArtifact, error) {
	if a.ID == uuid.Nil {
		a.ID = uuid.New()
	}
	var out repository.RBIArtifact
	err := repo.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx, `
			INSERT INTO rbi_session_artifacts
				(id, tenant_id, session_id, kind, direction, filename, sha256, size_bytes)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
			RETURNING `+rbiArtifactSelectColumns,
			a.ID, tenantID, a.SessionID, a.Kind, a.Direction,
			a.Filename, a.SHA256, a.SizeBytes)
		var serr error
		out, serr = scanRBIArtifact(row)
		return serr
	})
	if err != nil {
		if isForeignKeyViolation(err) {
			return repository.RBIArtifact{}, repository.ErrNotFound
		}
		if isCheckViolation(err) {
			return repository.RBIArtifact{}, repository.ErrInvalidArgument
		}
		return repository.RBIArtifact{}, err
	}
	return out, nil
}

func (repo *RBIArtifactRepository) ListBySession(
	ctx context.Context,
	tenantID, sessionID uuid.UUID,
	limit int,
) ([]repository.RBIArtifact, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	var out []repository.RBIArtifact
	err := repo.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		rows, qerr := tx.Query(ctx, `
			SELECT `+rbiArtifactSelectColumns+`
			FROM rbi_session_artifacts
			WHERE session_id = $1
			ORDER BY created_at DESC, id
			LIMIT $2`, sessionID, limit)
		if qerr != nil {
			return qerr
		}
		defer rows.Close()
		for rows.Next() {
			a, serr := scanRBIArtifact(rows)
			if serr != nil {
				return serr
			}
			out = append(out, a)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
