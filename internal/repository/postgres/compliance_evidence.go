package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// ComplianceEvidenceRepository is the Postgres-backed
// ComplianceEvidenceRepository.
//
// The compliance_evidence table is PLATFORM-level (migration 039):
// it has no tenant_id and NO row-level security, so every operation
// runs through onPrimary (which adopts the app role without setting a
// tenant/system GUC). There is intentionally no withTenant here.
type ComplianceEvidenceRepository struct{ s *Store }

const complianceEvidenceCols = `id, collection_type, collected_at, s3_key, signature, status, created_at`

func scanComplianceEvidence(row pgx.Row) (repository.ComplianceEvidence, error) {
	var e repository.ComplianceEvidence
	if err := row.Scan(
		&e.ID,
		&e.CollectionType,
		&e.CollectedAt,
		&e.S3Key,
		&e.Signature,
		&e.Status,
		&e.CreatedAt,
	); err != nil {
		return repository.ComplianceEvidence{}, err
	}
	return e, nil
}

func (r *ComplianceEvidenceRepository) Create(ctx context.Context, e repository.ComplianceEvidence) (repository.ComplianceEvidence, error) {
	// The caller-supplied ID is authoritative: EvidenceService embeds it
	// in the signed bundle and derives the S3 object key from it, so the
	// index row's id MUST equal the bundle's id. Insert it explicitly
	// (mirroring tenants/sites) rather than letting the column DEFAULT
	// gen_random_uuid() mint a different value. Generate one only when the
	// caller passes the nil UUID, matching the memory backend.
	if e.ID == uuid.Nil {
		e.ID = uuid.New()
	}
	var out repository.ComplianceEvidence
	err := r.s.onPrimary(ctx, func(q pgxQuerier) error {
		const sql = `
INSERT INTO compliance_evidence (id, collection_type, collected_at, s3_key, signature, status)
VALUES ($1::uuid, $2, $3, $4, $5, $6)
RETURNING ` + complianceEvidenceCols
		scanned, err := scanComplianceEvidence(q.QueryRow(ctx, sql,
			e.ID,
			e.CollectionType,
			e.CollectedAt,
			e.S3Key,
			e.Signature,
			e.Status,
		))
		if isUniqueViolation(err) {
			return repository.ErrConflict
		}
		if err != nil {
			return fmt.Errorf("insert compliance_evidence: %w", err)
		}
		out = scanned
		return nil
	})
	return out, err
}

func (r *ComplianceEvidenceRepository) Get(ctx context.Context, id uuid.UUID) (repository.ComplianceEvidence, error) {
	var out repository.ComplianceEvidence
	err := r.s.onPrimary(ctx, func(q pgxQuerier) error {
		const sql = `SELECT ` + complianceEvidenceCols + ` FROM compliance_evidence WHERE id = $1`
		scanned, err := scanComplianceEvidence(q.QueryRow(ctx, sql, id))
		if errors.Is(err, pgx.ErrNoRows) {
			return repository.ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("get compliance_evidence: %w", err)
		}
		out = scanned
		return nil
	})
	return out, err
}

func (r *ComplianceEvidenceRepository) List(ctx context.Context, filter repository.ComplianceEvidenceFilter, page repository.Page) (repository.PageResult[repository.ComplianceEvidence], error) {
	var out repository.PageResult[repository.ComplianceEvidence]
	err := r.s.onPrimary(ctx, func(q pgxQuerier) error {
		page = page.Normalize()
		cur, err := decodeCursor(page.After)
		if err != nil {
			return repository.ErrInvalidArgument
		}

		cmp, dir := "<", "DESC"
		if page.Order == repository.SortAsc {
			cmp, dir = ">", "ASC"
		}

		sql := `SELECT ` + complianceEvidenceCols + ` FROM compliance_evidence`
		var (
			args    []any
			clauses []string
		)
		if filter.CollectionType != "" {
			args = append(args, filter.CollectionType)
			clauses = append(clauses, fmt.Sprintf("collection_type = $%d", len(args)))
		}
		if filter.Status != "" {
			args = append(args, filter.Status)
			clauses = append(clauses, fmt.Sprintf("status = $%d", len(args)))
		}
		if !cur.T.IsZero() {
			args = append(args, cur.T)
			tArg := len(args)
			args = append(args, cur.I)
			iArg := len(args)
			clauses = append(clauses, fmt.Sprintf("(collected_at, id) %s ($%d, $%d)", cmp, tArg, iArg))
		}
		for i, c := range clauses {
			if i == 0 {
				sql += " WHERE " + c
			} else {
				sql += " AND " + c
			}
		}

		args = append(args, page.Limit)
		sql += fmt.Sprintf(" ORDER BY collected_at %s, id %s LIMIT $%d", dir, dir, len(args))

		rows, err := q.Query(ctx, sql, args...)
		if err != nil {
			return fmt.Errorf("list compliance_evidence: %w", err)
		}
		defer rows.Close()

		var items []repository.ComplianceEvidence
		for rows.Next() {
			item, err := scanComplianceEvidence(rows)
			if err != nil {
				return err
			}
			items = append(items, item)
		}
		if err := rows.Err(); err != nil {
			return err
		}

		next := ""
		if len(items) == page.Limit {
			last := items[len(items)-1]
			next = encodeCursor(pageCursor{T: last.CollectedAt, I: last.ID})
		}
		out = repository.PageResult[repository.ComplianceEvidence]{Items: items, NextCursor: next}
		return nil
	})
	return out, err
}

func (r *ComplianceEvidenceRepository) UpdateStatus(ctx context.Context, id uuid.UUID, status string) (repository.ComplianceEvidence, error) {
	if status == "" {
		return repository.ComplianceEvidence{}, repository.ErrInvalidArgument
	}
	var out repository.ComplianceEvidence
	err := r.s.onPrimary(ctx, func(q pgxQuerier) error {
		const sql = `
UPDATE compliance_evidence SET status = $2 WHERE id = $1
RETURNING ` + complianceEvidenceCols
		scanned, err := scanComplianceEvidence(q.QueryRow(ctx, sql, id, status))
		if errors.Is(err, pgx.ErrNoRows) {
			return repository.ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("update compliance_evidence status: %w", err)
		}
		out = scanned
		return nil
	})
	return out, err
}

func (r *ComplianceEvidenceRepository) LatestByType(ctx context.Context, collectionType string) (repository.ComplianceEvidence, error) {
	if collectionType == "" {
		return repository.ComplianceEvidence{}, repository.ErrInvalidArgument
	}
	var out repository.ComplianceEvidence
	err := r.s.onPrimary(ctx, func(q pgxQuerier) error {
		const sql = `
SELECT ` + complianceEvidenceCols + `
FROM compliance_evidence
WHERE collection_type = $1
ORDER BY collected_at DESC, id DESC
LIMIT 1`
		scanned, err := scanComplianceEvidence(q.QueryRow(ctx, sql, collectionType))
		if errors.Is(err, pgx.ErrNoRows) {
			return repository.ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("latest compliance_evidence by type: %w", err)
		}
		out = scanned
		return nil
	})
	return out, err
}
