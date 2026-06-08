package postgres

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// IPSRuleCategoryRepository is the Postgres-backed implementation of
// repository.IPSRuleCategoryRepository against the ips_rule_categories
// and ips_rule_category_stats tables (migration 050). Every operation
// runs through withTenant / withTenantRO so the tables' RLS policies
// (sng.tenant_id) enforce isolation; the explicit tenant_id passed on
// writes satisfies the NOT NULL column and the WITH CHECK clause.
type IPSRuleCategoryRepository struct{ s *Store }

var _ repository.IPSRuleCategoryRepository = (*IPSRuleCategoryRepository)(nil)

func (repo *IPSRuleCategoryRepository) ListSelections(
	ctx context.Context,
	tenantID uuid.UUID,
) ([]repository.IPSRuleCategorySelection, error) {
	var out []repository.IPSRuleCategorySelection
	err := repo.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		rows, qerr := tx.Query(ctx, `
			SELECT tenant_id, category, enabled, created_at, updated_at
			FROM ips_rule_categories
			ORDER BY category`)
		if qerr != nil {
			return qerr
		}
		defer rows.Close()
		for rows.Next() {
			var s repository.IPSRuleCategorySelection
			if serr := rows.Scan(&s.TenantID, &s.Category, &s.Enabled, &s.CreatedAt, &s.UpdatedAt); serr != nil {
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

func (repo *IPSRuleCategoryRepository) SetEnabled(
	ctx context.Context,
	tenantID uuid.UUID,
	category string,
	enabled bool,
) (repository.IPSRuleCategorySelection, error) {
	var out repository.IPSRuleCategorySelection
	err := repo.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		// Upsert on the (tenant_id, category) primary key: flipping a
		// category's enablement overwrites the prior override in place.
		// created_at is preserved; updated_at is bumped by the trigger.
		row := tx.QueryRow(ctx, `
			INSERT INTO ips_rule_categories (tenant_id, category, enabled)
			VALUES ($1, $2, $3)
			ON CONFLICT (tenant_id, category) DO UPDATE SET
				enabled = EXCLUDED.enabled
			RETURNING tenant_id, category, enabled, created_at, updated_at`,
			tenantID, category, enabled)
		return row.Scan(&out.TenantID, &out.Category, &out.Enabled, &out.CreatedAt, &out.UpdatedAt)
	})
	if err != nil {
		if isForeignKeyViolation(err) {
			return repository.IPSRuleCategorySelection{}, repository.ErrNotFound
		}
		if isCheckViolation(err) {
			return repository.IPSRuleCategorySelection{}, repository.ErrInvalidArgument
		}
		return repository.IPSRuleCategorySelection{}, err
	}
	return out, nil
}

func (repo *IPSRuleCategoryRepository) AddHits(
	ctx context.Context,
	tenantID uuid.UUID,
	category string,
	day time.Time,
	delta int64,
) error {
	if delta < 0 {
		return repository.ErrInvalidArgument
	}
	d := day.UTC().Format("2006-01-02")
	err := repo.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		// Accumulate onto the (tenant, category, day) counter; the row
		// is created on first hit and incremented thereafter.
		_, eerr := tx.Exec(ctx, `
			INSERT INTO ips_rule_category_stats (tenant_id, category, day, hits)
			VALUES ($1, $2, $3::date, $4)
			ON CONFLICT (tenant_id, category, day) DO UPDATE SET
				hits = ips_rule_category_stats.hits + EXCLUDED.hits`,
			tenantID, category, d, delta)
		return eerr
	})
	if err != nil {
		if isForeignKeyViolation(err) {
			return repository.ErrNotFound
		}
		if isCheckViolation(err) {
			return repository.ErrInvalidArgument
		}
		return err
	}
	return nil
}

func (repo *IPSRuleCategoryRepository) StatsSince(
	ctx context.Context,
	tenantID uuid.UUID,
	since time.Time,
) ([]repository.IPSRuleCategoryDailyStat, error) {
	d := since.UTC().Format("2006-01-02")
	var out []repository.IPSRuleCategoryDailyStat
	err := repo.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		rows, qerr := tx.Query(ctx, `
			SELECT tenant_id, category, day, hits
			FROM ips_rule_category_stats
			WHERE day >= $1::date
			ORDER BY day DESC, category`, d)
		if qerr != nil {
			return qerr
		}
		defer rows.Close()
		for rows.Next() {
			var s repository.IPSRuleCategoryDailyStat
			if serr := rows.Scan(&s.TenantID, &s.Category, &s.Day, &s.Hits); serr != nil {
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
