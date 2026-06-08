package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// BrowserPolicyRepository owns the browser_policies table.
type BrowserPolicyRepository struct{ s *Store }

const browserPolicySelectColumns = `
	id, tenant_id, name, rules, action, scope, enabled, created_at, updated_at
`

func scanBrowserPolicy(row pgx.Row) (repository.BrowserPolicy, error) {
	var (
		p     repository.BrowserPolicy
		rules []byte
	)
	if err := row.Scan(&p.ID, &p.TenantID, &p.Name, &rules, &p.Action, &p.Scope, &p.Enabled, &p.CreatedAt, &p.UpdatedAt); err != nil {
		return repository.BrowserPolicy{}, err
	}
	if len(rules) > 0 {
		if err := json.Unmarshal(rules, &p.Rules); err != nil {
			return repository.BrowserPolicy{}, fmt.Errorf("decode browser rules: %w", err)
		}
	}
	return p, nil
}

func (r *BrowserPolicyRepository) Create(ctx context.Context, tenantID uuid.UUID, p repository.BrowserPolicy) (repository.BrowserPolicy, error) {
	if tenantID == uuid.Nil {
		return repository.BrowserPolicy{}, repository.ErrInvalidArgument
	}
	if p.ID == uuid.Nil {
		p.ID = uuid.New()
	}
	if p.Action == "" {
		p.Action = repository.BrowserPolicyActionBlock
	}
	if p.Scope == "" {
		p.Scope = repository.BrowserPolicyScopeUser
	}
	rules, err := json.Marshal(p.Rules)
	if err != nil {
		return repository.BrowserPolicy{}, repository.ErrInvalidArgument
	}
	var out repository.BrowserPolicy
	err = r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		const q = `
			INSERT INTO browser_policies (id, tenant_id, name, rules, action, scope, enabled)
			VALUES ($1::uuid, $2::uuid, $3, $4::jsonb, $5, $6, $7)
			RETURNING ` + browserPolicySelectColumns
		var err error
		out, err = scanBrowserPolicy(tx.QueryRow(ctx, q, p.ID, tenantID, p.Name, rules, string(p.Action), string(p.Scope), p.Enabled))
		return mapWriteErr(err, "insert browser policy")
	})
	return out, err
}

func (r *BrowserPolicyRepository) Get(ctx context.Context, tenantID, id uuid.UUID) (repository.BrowserPolicy, error) {
	var out repository.BrowserPolicy
	err := r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		const q = `SELECT ` + browserPolicySelectColumns + ` FROM browser_policies WHERE id = $1::uuid`
		var err error
		out, err = scanBrowserPolicy(tx.QueryRow(ctx, q, id))
		if errors.Is(err, pgx.ErrNoRows) {
			return repository.ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("select browser policy: %w", err)
		}
		return nil
	})
	return out, err
}

func (r *BrowserPolicyRepository) List(ctx context.Context, tenantID uuid.UUID, page repository.Page) (repository.PageResult[repository.BrowserPolicy], error) {
	page = page.Normalize()
	cur, err := decodeCursor(page.After)
	if err != nil {
		return repository.PageResult[repository.BrowserPolicy]{}, repository.ErrInvalidArgument
	}
	res := repository.PageResult[repository.BrowserPolicy]{}
	err = r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		q, args := buildListQuery("browser_policies", browserPolicySelectColumns, cur, page.Order, page.Limit)
		rows, err := tx.Query(ctx, q, args...)
		if err != nil {
			return fmt.Errorf("list browser policies: %w", err)
		}
		defer rows.Close()
		items := make([]repository.BrowserPolicy, 0, page.Limit)
		for rows.Next() {
			p, err := scanBrowserPolicy(rows)
			if err != nil {
				return fmt.Errorf("scan browser policy: %w", err)
			}
			items = append(items, p)
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("iterate browser policies: %w", err)
		}
		res.Items = items
		if len(items) == page.Limit && len(items) > 0 {
			last := items[len(items)-1]
			res.NextCursor = encodeCursor(pageCursor{T: last.CreatedAt, I: last.ID})
		}
		return nil
	})
	return res, err
}

func (r *BrowserPolicyRepository) Update(ctx context.Context, tenantID, id uuid.UUID, patch repository.BrowserPolicyPatch) (repository.BrowserPolicy, error) {
	var nameArg, actionArg, scopeArg, enabledArg, rulesArg any
	if patch.Name != nil {
		nameArg = *patch.Name
	}
	if patch.Action != nil {
		actionArg = string(*patch.Action)
	}
	if patch.Scope != nil {
		scopeArg = string(*patch.Scope)
	}
	if patch.Enabled != nil {
		enabledArg = *patch.Enabled
	}
	if patch.Rules != nil {
		b, err := json.Marshal(patch.Rules)
		if err != nil {
			return repository.BrowserPolicy{}, repository.ErrInvalidArgument
		}
		rulesArg = b
	}
	var out repository.BrowserPolicy
	err := r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		const q = `
			UPDATE browser_policies
			SET name    = COALESCE($2, name),
			    rules   = COALESCE($3::jsonb, rules),
			    action  = COALESCE($4, action),
			    scope   = COALESCE($5, scope),
			    enabled = COALESCE($6, enabled)
			WHERE id = $1::uuid
			RETURNING ` + browserPolicySelectColumns
		var err error
		out, err = scanBrowserPolicy(tx.QueryRow(ctx, q, id, nameArg, rulesArg, actionArg, scopeArg, enabledArg))
		if errors.Is(err, pgx.ErrNoRows) {
			return repository.ErrNotFound
		}
		return mapWriteErr(err, "update browser policy")
	})
	return out, err
}

func (r *BrowserPolicyRepository) Delete(ctx context.Context, tenantID, id uuid.UUID) error {
	return r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		ct, err := tx.Exec(ctx, `DELETE FROM browser_policies WHERE id = $1::uuid`, id)
		if err != nil {
			return fmt.Errorf("delete browser policy: %w", err)
		}
		if ct.RowsAffected() == 0 {
			return repository.ErrNotFound
		}
		return nil
	})
}
