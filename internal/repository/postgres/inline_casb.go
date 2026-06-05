package postgres

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

const inlineCASBSelectColumns = `id, tenant_id, app_id, action, verdict, conditions, enabled, priority, created_at, updated_at`

// InlineCASBRuleRepository is the Postgres-backed implementation of
// repository.InlineCASBRuleRepository against the inline_casb_rules
// table (migration 037). Every operation runs through withTenant /
// withTenantRO so the table's RLS policy (sng.tenant_id) enforces
// isolation; the explicit tenant_id passed on Create satisfies the
// NOT NULL column and the WITH CHECK clause.
type InlineCASBRuleRepository struct{ s *Store }

var _ repository.InlineCASBRuleRepository = (*InlineCASBRuleRepository)(nil)

func scanInlineCASBRule(row pgx.Row) (repository.InlineCASBRule, error) {
	var r repository.InlineCASBRule
	err := row.Scan(
		&r.ID, &r.TenantID, &r.AppID, &r.Action, &r.Verdict,
		&r.Conditions, &r.Enabled, &r.Priority, &r.CreatedAt, &r.UpdatedAt,
	)
	return r, err
}

func (repo *InlineCASBRuleRepository) List(
	ctx context.Context,
	tenantID uuid.UUID,
) ([]repository.InlineCASBRule, error) {
	var out []repository.InlineCASBRule
	err := repo.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		rows, qerr := tx.Query(ctx, `
			SELECT `+inlineCASBSelectColumns+`
			FROM inline_casb_rules
			ORDER BY priority DESC, id`)
		if qerr != nil {
			return qerr
		}
		defer rows.Close()
		for rows.Next() {
			r, serr := scanInlineCASBRule(rows)
			if serr != nil {
				return serr
			}
			out = append(out, r)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (repo *InlineCASBRuleRepository) Get(
	ctx context.Context,
	tenantID, id uuid.UUID,
) (repository.InlineCASBRule, error) {
	var out repository.InlineCASBRule
	err := repo.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx, `
			SELECT `+inlineCASBSelectColumns+`
			FROM inline_casb_rules
			WHERE id = $1`, id)
		var serr error
		out, serr = scanInlineCASBRule(row)
		return serr
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return repository.InlineCASBRule{}, repository.ErrNotFound
		}
		return repository.InlineCASBRule{}, err
	}
	return out, nil
}

func (repo *InlineCASBRuleRepository) Create(
	ctx context.Context,
	tenantID uuid.UUID,
	rule repository.InlineCASBRule,
) (repository.InlineCASBRule, error) {
	if rule.ID == uuid.Nil {
		rule.ID = uuid.New()
	}
	conditions := rule.Conditions
	if len(conditions) == 0 {
		conditions = json.RawMessage(`{}`)
	}
	var out repository.InlineCASBRule
	err := repo.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx, `
			INSERT INTO inline_casb_rules
				(id, tenant_id, app_id, action, verdict, conditions, enabled, priority)
			VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, $8)
			RETURNING `+inlineCASBSelectColumns,
			rule.ID, tenantID, rule.AppID, rule.Action, rule.Verdict,
			conditions, rule.Enabled, rule.Priority)
		var serr error
		out, serr = scanInlineCASBRule(row)
		return serr
	})
	if err != nil {
		if isUniqueViolation(err) {
			return repository.InlineCASBRule{}, repository.ErrConflict
		}
		if isForeignKeyViolation(err) {
			return repository.InlineCASBRule{}, repository.ErrNotFound
		}
		if isCheckViolation(err) {
			return repository.InlineCASBRule{}, repository.ErrInvalidArgument
		}
		return repository.InlineCASBRule{}, err
	}
	return out, nil
}

func (repo *InlineCASBRuleRepository) Update(
	ctx context.Context,
	tenantID uuid.UUID,
	rule repository.InlineCASBRule,
) (repository.InlineCASBRule, error) {
	conditions := rule.Conditions
	if len(conditions) == 0 {
		conditions = json.RawMessage(`{}`)
	}
	var out repository.InlineCASBRule
	err := repo.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx, `
			UPDATE inline_casb_rules
			SET app_id     = $2,
			    action     = $3,
			    verdict    = $4,
			    conditions = $5::jsonb,
			    enabled    = $6,
			    priority   = $7
			WHERE id = $1
			RETURNING `+inlineCASBSelectColumns,
			rule.ID, rule.AppID, rule.Action, rule.Verdict,
			conditions, rule.Enabled, rule.Priority)
		var serr error
		out, serr = scanInlineCASBRule(row)
		return serr
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return repository.InlineCASBRule{}, repository.ErrNotFound
		}
		if isCheckViolation(err) {
			return repository.InlineCASBRule{}, repository.ErrInvalidArgument
		}
		return repository.InlineCASBRule{}, err
	}
	return out, nil
}

func (repo *InlineCASBRuleRepository) Delete(
	ctx context.Context,
	tenantID, id uuid.UUID,
) error {
	return repo.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM inline_casb_rules WHERE id = $1`, id)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return repository.ErrNotFound
		}
		return nil
	})
}
