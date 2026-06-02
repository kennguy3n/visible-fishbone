package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// ComplianceReportRepository is the Postgres-backed ComplianceReportRepository.
type ComplianceReportRepository struct{ s *Store }

func scanComplianceReport(row pgx.Row) (repository.ComplianceReport, error) {
	var r repository.ComplianceReport
	if err := row.Scan(
		&r.ID,
		&r.TenantID,
		&r.Framework,
		&r.Score,
		&r.MaxScore,
		&r.Controls,
		&r.EvidencePack,
		&r.GeneratedAt,
		&r.CreatedAt,
	); err != nil {
		return repository.ComplianceReport{}, err
	}
	return r, nil
}

func (r *ComplianceReportRepository) Create(ctx context.Context, tenantID uuid.UUID, report repository.ComplianceReport) (repository.ComplianceReport, error) {
	var out repository.ComplianceReport
	err := r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		const q = `
INSERT INTO compliance_reports (tenant_id, framework, score, max_score, controls, evidence_pack, generated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7)
RETURNING id, tenant_id, framework, score, max_score, controls, evidence_pack, generated_at, created_at`
		scanned, err := scanComplianceReport(tx.QueryRow(ctx, q,
			tenantID,
			report.Framework,
			report.Score,
			report.MaxScore,
			report.Controls,
			report.EvidencePack,
			report.GeneratedAt,
		))
		if err != nil {
			return fmt.Errorf("insert compliance_reports: %w", err)
		}
		out = scanned
		return nil
	})
	return out, err
}

func (r *ComplianceReportRepository) Get(ctx context.Context, tenantID, id uuid.UUID) (repository.ComplianceReport, error) {
	var out repository.ComplianceReport
	err := r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		const q = `
SELECT id, tenant_id, framework, score, max_score, controls, evidence_pack, generated_at, created_at
FROM compliance_reports WHERE id = $1`
		scanned, err := scanComplianceReport(tx.QueryRow(ctx, q, id))
		if errors.Is(err, pgx.ErrNoRows) {
			return repository.ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("get compliance_reports: %w", err)
		}
		out = scanned
		return nil
	})
	return out, err
}

func (r *ComplianceReportRepository) List(ctx context.Context, tenantID uuid.UUID, page repository.Page) (repository.PageResult[repository.ComplianceReport], error) {
	var out repository.PageResult[repository.ComplianceReport]
	err := r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		page = page.Normalize()
		cur, err := decodeCursor(page.After)
		if err != nil {
			return repository.ErrInvalidArgument
		}

		cmp, dir := "<", "DESC"
		if page.Order == repository.SortAsc {
			cmp, dir = ">", "ASC"
		}

		q := `SELECT id, tenant_id, framework, score, max_score, controls, evidence_pack, generated_at, created_at
FROM compliance_reports`
		args := []any{}
		argN := 0

		if !cur.T.IsZero() {
			argN++
			tArg := argN
			argN++
			iArg := argN
			q += fmt.Sprintf(` WHERE (created_at, id) %s ($%d, $%d)`, cmp, tArg, iArg)
			args = append(args, cur.T, cur.I)
		}

		argN++
		q += fmt.Sprintf(` ORDER BY created_at %s, id %s LIMIT $%d`, dir, dir, argN)
		args = append(args, page.Limit)

		rows, err := tx.Query(ctx, q, args...)
		if err != nil {
			return err
		}
		defer rows.Close()

		var items []repository.ComplianceReport
		for rows.Next() {
			item, err := scanComplianceReport(rows)
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
			next = encodeCursor(pageCursor{T: last.CreatedAt, I: last.ID})
		}
		out = repository.PageResult[repository.ComplianceReport]{Items: items, NextCursor: next}
		return nil
	})
	return out, err
}
