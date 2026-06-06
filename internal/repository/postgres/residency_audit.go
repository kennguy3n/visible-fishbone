package postgres

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// defaultResidencyListLimit bounds List when the caller passes a
// non-positive limit.
const defaultResidencyListLimit = 100

// ResidencyAuditRepository owns the residency_audit table (migration
// 046): the append-only record of fail-closed data-residency
// rejections. Every query runs inside withTenant/withTenantRO so the
// `sng.tenant_id` GUC is set and RLS scopes the rows to the caller's
// tenant.
type ResidencyAuditRepository struct{ s *Store }

var _ repository.ResidencyAuditRepository = (*ResidencyAuditRepository)(nil)

func (r *ResidencyAuditRepository) Record(ctx context.Context, tenantID uuid.UUID, e repository.ResidencyAuditEntry) (repository.ResidencyAuditEntry, error) {
	if tenantID == uuid.Nil || e.Plane == "" || e.DesignatedRegion == "" {
		return repository.ResidencyAuditEntry{}, repository.ErrInvalidArgument
	}
	var out repository.ResidencyAuditEntry
	err := r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		const q = `
			INSERT INTO residency_audit
				(tenant_id, plane, designated_region, attempted_region, detail)
			VALUES ($1::uuid, $2, $3, $4, $5)
			RETURNING id, tenant_id, plane, designated_region,
			          attempted_region, detail, created_at`
		row := tx.QueryRow(ctx, q, tenantID, e.Plane, e.DesignatedRegion, e.AttemptedRegion, e.Detail)
		return scanResidencyAudit(row, &out)
	})
	if err != nil {
		return repository.ResidencyAuditEntry{}, err
	}
	return out, nil
}

func (r *ResidencyAuditRepository) List(ctx context.Context, tenantID uuid.UUID, limit int) ([]repository.ResidencyAuditEntry, error) {
	if limit <= 0 {
		limit = defaultResidencyListLimit
	}
	var out []repository.ResidencyAuditEntry
	err := r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		const q = `
			SELECT id, tenant_id, plane, designated_region,
			       attempted_region, detail, created_at
			FROM residency_audit
			ORDER BY created_at DESC, id
			LIMIT $1`
		rows, err := tx.Query(ctx, q, limit)
		if err != nil {
			return fmt.Errorf("query residency_audit: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var e repository.ResidencyAuditEntry
			if err := rows.Scan(&e.ID, &e.TenantID, &e.Plane, &e.DesignatedRegion,
				&e.AttemptedRegion, &e.Detail, &e.CreatedAt); err != nil {
				return fmt.Errorf("scan residency_audit: %w", err)
			}
			out = append(out, e)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// scanResidencyAudit scans a single residency_audit row in column
// order into e.
func scanResidencyAudit(row pgx.Row, e *repository.ResidencyAuditEntry) error {
	return row.Scan(&e.ID, &e.TenantID, &e.Plane, &e.DesignatedRegion,
		&e.AttemptedRegion, &e.Detail, &e.CreatedAt)
}
