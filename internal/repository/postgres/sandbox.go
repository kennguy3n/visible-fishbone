package postgres

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

const sandboxVerdictSelectColumns = `id, tenant_id, sha256, classification, confidence, provider, sandbox_id, summary, status, analyzed_at, created_at, updated_at`

// SandboxVerdictRepository is the Postgres-backed implementation of
// repository.SandboxVerdictRepository against the sandbox_verdicts
// table (migration 042). Every operation runs through withTenant /
// withTenantRO so the table's RLS policy (sng.tenant_id) enforces
// isolation.
type SandboxVerdictRepository struct{ s *Store }

var _ repository.SandboxVerdictRepository = (*SandboxVerdictRepository)(nil)

func scanSandboxVerdict(row pgx.Row) (repository.SandboxVerdict, error) {
	var v repository.SandboxVerdict
	err := row.Scan(
		&v.ID, &v.TenantID, &v.SHA256, &v.Classification, &v.Confidence,
		&v.Provider, &v.SandboxID, &v.Summary, &v.Status, &v.AnalyzedAt,
		&v.CreatedAt, &v.UpdatedAt,
	)
	return v, err
}

func (repo *SandboxVerdictRepository) Upsert(
	ctx context.Context,
	tenantID uuid.UUID,
	v repository.SandboxVerdict,
) (repository.SandboxVerdict, error) {
	if v.ID == uuid.Nil {
		v.ID = uuid.New()
	}
	var out repository.SandboxVerdict
	err := repo.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		// Upsert on (tenant_id, sha256): a re-submission of the same
		// file overwrites the prior verdict in place. created_at is
		// preserved (it is not in the UPDATE set); updated_at is
		// bumped by the trigger.
		row := tx.QueryRow(ctx, `
			INSERT INTO sandbox_verdicts
				(id, tenant_id, sha256, classification, confidence, provider, sandbox_id, summary, status, analyzed_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
			ON CONFLICT (tenant_id, sha256) DO UPDATE SET
				classification = EXCLUDED.classification,
				confidence     = EXCLUDED.confidence,
				provider       = EXCLUDED.provider,
				sandbox_id     = EXCLUDED.sandbox_id,
				summary        = EXCLUDED.summary,
				status         = EXCLUDED.status,
				analyzed_at    = EXCLUDED.analyzed_at
			RETURNING `+sandboxVerdictSelectColumns,
			v.ID, tenantID, v.SHA256, v.Classification, v.Confidence,
			v.Provider, v.SandboxID, v.Summary, v.Status, v.AnalyzedAt)
		var serr error
		out, serr = scanSandboxVerdict(row)
		return serr
	})
	if err != nil {
		if isForeignKeyViolation(err) {
			return repository.SandboxVerdict{}, repository.ErrNotFound
		}
		if isCheckViolation(err) {
			return repository.SandboxVerdict{}, repository.ErrInvalidArgument
		}
		return repository.SandboxVerdict{}, err
	}
	return out, nil
}

func (repo *SandboxVerdictRepository) GetBySHA256(
	ctx context.Context,
	tenantID uuid.UUID,
	sha256 string,
) (repository.SandboxVerdict, error) {
	var out repository.SandboxVerdict
	err := repo.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx, `
			SELECT `+sandboxVerdictSelectColumns+`
			FROM sandbox_verdicts
			WHERE sha256 = $1`, sha256)
		var serr error
		out, serr = scanSandboxVerdict(row)
		return serr
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return repository.SandboxVerdict{}, repository.ErrNotFound
		}
		return repository.SandboxVerdict{}, err
	}
	return out, nil
}

func (repo *SandboxVerdictRepository) List(
	ctx context.Context,
	tenantID uuid.UUID,
	limit int,
) ([]repository.SandboxVerdict, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	var out []repository.SandboxVerdict
	err := repo.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		rows, qerr := tx.Query(ctx, `
			SELECT `+sandboxVerdictSelectColumns+`
			FROM sandbox_verdicts
			ORDER BY created_at DESC, id
			LIMIT $1`, limit)
		if qerr != nil {
			return qerr
		}
		defer rows.Close()
		for rows.Next() {
			v, serr := scanSandboxVerdict(rows)
			if serr != nil {
				return serr
			}
			out = append(out, v)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
