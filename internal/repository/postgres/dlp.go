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

// DLPPolicyRepository owns the dlp_policies table.
type DLPPolicyRepository struct{ s *Store }

const dlpPolicySelectColumns = `
	id, tenant_id, name, description, rules, action, enabled, created_at, updated_at
`

func scanDLPPolicy(row pgx.Row) (repository.DLPPolicy, error) {
	var (
		p     repository.DLPPolicy
		rules []byte
	)
	if err := row.Scan(&p.ID, &p.TenantID, &p.Name, &p.Description, &rules, &p.Action, &p.Enabled, &p.CreatedAt, &p.UpdatedAt); err != nil {
		return repository.DLPPolicy{}, err
	}
	if len(rules) > 0 {
		if err := json.Unmarshal(rules, &p.Rules); err != nil {
			return repository.DLPPolicy{}, fmt.Errorf("decode dlp rules: %w", err)
		}
	}
	return p, nil
}

func (r *DLPPolicyRepository) Create(ctx context.Context, tenantID uuid.UUID, p repository.DLPPolicy) (repository.DLPPolicy, error) {
	if tenantID == uuid.Nil || p.Name == "" {
		return repository.DLPPolicy{}, repository.ErrInvalidArgument
	}
	if p.ID == uuid.Nil {
		p.ID = uuid.New()
	}
	rules, err := json.Marshal(p.Rules)
	if err != nil {
		return repository.DLPPolicy{}, repository.ErrInvalidArgument
	}
	if p.Action == "" {
		p.Action = repository.DLPActionLog
	}
	var out repository.DLPPolicy
	err = r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		const q = `
			INSERT INTO dlp_policies (id, tenant_id, name, description, rules, action, enabled)
			VALUES ($1::uuid, $2::uuid, $3, $4, $5::jsonb, $6, $7)
			RETURNING ` + dlpPolicySelectColumns
		row := tx.QueryRow(ctx, q, p.ID, tenantID, p.Name, p.Description, rules, string(p.Action), p.Enabled)
		out, err = scanDLPPolicy(row)
		return mapWriteErr(err, "insert dlp policy")
	})
	return out, err
}

func (r *DLPPolicyRepository) Get(ctx context.Context, tenantID, id uuid.UUID) (repository.DLPPolicy, error) {
	var out repository.DLPPolicy
	err := r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		const q = `SELECT ` + dlpPolicySelectColumns + ` FROM dlp_policies WHERE id = $1::uuid`
		var err error
		out, err = scanDLPPolicy(tx.QueryRow(ctx, q, id))
		if errors.Is(err, pgx.ErrNoRows) {
			return repository.ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("select dlp policy: %w", err)
		}
		return nil
	})
	return out, err
}

func (r *DLPPolicyRepository) List(ctx context.Context, tenantID uuid.UUID, page repository.Page) (repository.PageResult[repository.DLPPolicy], error) {
	page = page.Normalize()
	cur, err := decodeCursor(page.After)
	if err != nil {
		return repository.PageResult[repository.DLPPolicy]{}, repository.ErrInvalidArgument
	}
	res := repository.PageResult[repository.DLPPolicy]{}
	err = r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		q, args := buildListQuery("dlp_policies", dlpPolicySelectColumns, cur, page.Order, page.Limit)
		rows, err := tx.Query(ctx, q, args...)
		if err != nil {
			return fmt.Errorf("list dlp policies: %w", err)
		}
		defer rows.Close()
		items := make([]repository.DLPPolicy, 0, page.Limit)
		for rows.Next() {
			p, err := scanDLPPolicy(rows)
			if err != nil {
				return fmt.Errorf("scan dlp policy: %w", err)
			}
			items = append(items, p)
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("iterate dlp policies: %w", err)
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

func (r *DLPPolicyRepository) Update(ctx context.Context, tenantID, id uuid.UUID, patch repository.DLPPolicyPatch) (repository.DLPPolicy, error) {
	var (
		nameArg, descArg, actionArg, enabledArg, rulesArg any
	)
	if patch.Name != nil {
		nameArg = *patch.Name
	}
	if patch.Description != nil {
		descArg = *patch.Description
	}
	if patch.Action != nil {
		actionArg = string(*patch.Action)
	}
	if patch.Enabled != nil {
		enabledArg = *patch.Enabled
	}
	if patch.Rules != nil {
		b, err := json.Marshal(*patch.Rules)
		if err != nil {
			return repository.DLPPolicy{}, repository.ErrInvalidArgument
		}
		rulesArg = b
	}
	var out repository.DLPPolicy
	err := r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		const q = `
			UPDATE dlp_policies
			SET name        = COALESCE($2, name),
			    description = COALESCE($3, description),
			    rules       = COALESCE($4::jsonb, rules),
			    action      = COALESCE($5, action),
			    enabled     = COALESCE($6, enabled)
			WHERE id = $1::uuid
			RETURNING ` + dlpPolicySelectColumns
		var err error
		out, err = scanDLPPolicy(tx.QueryRow(ctx, q, id, nameArg, descArg, rulesArg, actionArg, enabledArg))
		if errors.Is(err, pgx.ErrNoRows) {
			return repository.ErrNotFound
		}
		return mapWriteErr(err, "update dlp policy")
	})
	return out, err
}

func (r *DLPPolicyRepository) Delete(ctx context.Context, tenantID, id uuid.UUID) error {
	return r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		ct, err := tx.Exec(ctx, `DELETE FROM dlp_policies WHERE id = $1::uuid`, id)
		if err != nil {
			return fmt.Errorf("delete dlp policy: %w", err)
		}
		if ct.RowsAffected() == 0 {
			return repository.ErrNotFound
		}
		return nil
	})
}

func (r *DLPPolicyRepository) ListEnabled(ctx context.Context, tenantID uuid.UUID) ([]repository.DLPPolicy, error) {
	var items []repository.DLPPolicy
	err := r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		const q = `SELECT ` + dlpPolicySelectColumns + `
			FROM dlp_policies WHERE enabled = true ORDER BY created_at ASC, id ASC`
		rows, err := tx.Query(ctx, q)
		if err != nil {
			return fmt.Errorf("list enabled dlp policies: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			p, err := scanDLPPolicy(rows)
			if err != nil {
				return fmt.Errorf("scan dlp policy: %w", err)
			}
			items = append(items, p)
		}
		return rows.Err()
	})
	return items, err
}

// DLPFingerprintRepository owns the dlp_fingerprints table.
type DLPFingerprintRepository struct{ s *Store }

const dlpFingerprintSelectColumns = `
	id, tenant_id, name, hash, content_type, registered_at
`

func scanDLPFingerprint(row pgx.Row) (repository.DLPFingerprint, error) {
	var f repository.DLPFingerprint
	if err := row.Scan(&f.ID, &f.TenantID, &f.Name, &f.Hash, &f.ContentType, &f.RegisteredAt); err != nil {
		return repository.DLPFingerprint{}, err
	}
	return f, nil
}

func (r *DLPFingerprintRepository) Create(ctx context.Context, tenantID uuid.UUID, f repository.DLPFingerprint) (repository.DLPFingerprint, error) {
	if tenantID == uuid.Nil || f.Name == "" {
		return repository.DLPFingerprint{}, repository.ErrInvalidArgument
	}
	if f.ID == uuid.Nil {
		f.ID = uuid.New()
	}
	var out repository.DLPFingerprint
	err := r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		const q = `
			INSERT INTO dlp_fingerprints (id, tenant_id, name, hash, content_type)
			VALUES ($1::uuid, $2::uuid, $3, $4, $5)
			RETURNING ` + dlpFingerprintSelectColumns
		var err error
		out, err = scanDLPFingerprint(tx.QueryRow(ctx, q, f.ID, tenantID, f.Name, f.Hash, f.ContentType))
		return mapWriteErr(err, "insert dlp fingerprint")
	})
	return out, err
}

func (r *DLPFingerprintRepository) Get(ctx context.Context, tenantID, id uuid.UUID) (repository.DLPFingerprint, error) {
	var out repository.DLPFingerprint
	err := r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		const q = `SELECT ` + dlpFingerprintSelectColumns + ` FROM dlp_fingerprints WHERE id = $1::uuid`
		var err error
		out, err = scanDLPFingerprint(tx.QueryRow(ctx, q, id))
		if errors.Is(err, pgx.ErrNoRows) {
			return repository.ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("select dlp fingerprint: %w", err)
		}
		return nil
	})
	return out, err
}

func (r *DLPFingerprintRepository) List(ctx context.Context, tenantID uuid.UUID, page repository.Page) (repository.PageResult[repository.DLPFingerprint], error) {
	page = page.Normalize()
	cur, err := decodeCursor(page.After)
	if err != nil {
		return repository.PageResult[repository.DLPFingerprint]{}, repository.ErrInvalidArgument
	}
	res := repository.PageResult[repository.DLPFingerprint]{}
	err = r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		q, args := buildSortedListQuery("dlp_fingerprints", dlpFingerprintSelectColumns, "registered_at", cur, page.Order, page.Limit, nil)
		rows, err := tx.Query(ctx, q, args...)
		if err != nil {
			return fmt.Errorf("list dlp fingerprints: %w", err)
		}
		defer rows.Close()
		items := make([]repository.DLPFingerprint, 0, page.Limit)
		for rows.Next() {
			f, err := scanDLPFingerprint(rows)
			if err != nil {
				return fmt.Errorf("scan dlp fingerprint: %w", err)
			}
			items = append(items, f)
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("iterate dlp fingerprints: %w", err)
		}
		res.Items = items
		if len(items) == page.Limit && len(items) > 0 {
			last := items[len(items)-1]
			res.NextCursor = encodeCursor(pageCursor{T: last.RegisteredAt, I: last.ID})
		}
		return nil
	})
	return res, err
}

func (r *DLPFingerprintRepository) Delete(ctx context.Context, tenantID, id uuid.UUID) error {
	return r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		ct, err := tx.Exec(ctx, `DELETE FROM dlp_fingerprints WHERE id = $1::uuid`, id)
		if err != nil {
			return fmt.Errorf("delete dlp fingerprint: %w", err)
		}
		if ct.RowsAffected() == 0 {
			return repository.ErrNotFound
		}
		return nil
	})
}

func (r *DLPFingerprintRepository) ListAll(ctx context.Context, tenantID uuid.UUID) ([]repository.DLPFingerprint, error) {
	var items []repository.DLPFingerprint
	err := r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		const q = `SELECT ` + dlpFingerprintSelectColumns + ` FROM dlp_fingerprints ORDER BY registered_at ASC, id ASC`
		rows, err := tx.Query(ctx, q)
		if err != nil {
			return fmt.Errorf("list all dlp fingerprints: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			f, err := scanDLPFingerprint(rows)
			if err != nil {
				return fmt.Errorf("scan dlp fingerprint: %w", err)
			}
			items = append(items, f)
		}
		return rows.Err()
	})
	return items, err
}

// DLPMatchRepository owns the dlp_matches audit table.
type DLPMatchRepository struct{ s *Store }

const dlpMatchSelectColumns = `
	id, tenant_id, policy_id, source, matched_at, details
`

func scanDLPMatch(row pgx.Row) (repository.DLPMatch, error) {
	var (
		m       repository.DLPMatch
		details []byte
	)
	if err := row.Scan(&m.ID, &m.TenantID, &m.PolicyID, &m.Source, &m.MatchedAt, &details); err != nil {
		return repository.DLPMatch{}, err
	}
	m.Details = json.RawMessage(details)
	return m, nil
}

func (r *DLPMatchRepository) Create(ctx context.Context, tenantID uuid.UUID, m repository.DLPMatch) (repository.DLPMatch, error) {
	if tenantID == uuid.Nil {
		return repository.DLPMatch{}, repository.ErrInvalidArgument
	}
	if m.ID == uuid.Nil {
		m.ID = uuid.New()
	}
	if len(m.Details) == 0 {
		m.Details = json.RawMessage(`{}`)
	}
	var out repository.DLPMatch
	err := r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		const q = `
			INSERT INTO dlp_matches (id, tenant_id, policy_id, source, details)
			VALUES ($1::uuid, $2::uuid, $3::uuid, $4, $5::jsonb)
			RETURNING ` + dlpMatchSelectColumns
		var err error
		out, err = scanDLPMatch(tx.QueryRow(ctx, q, m.ID, tenantID, m.PolicyID, m.Source, []byte(m.Details)))
		return mapWriteErr(err, "insert dlp match")
	})
	return out, err
}

func (r *DLPMatchRepository) List(ctx context.Context, tenantID uuid.UUID, policyID *uuid.UUID, page repository.Page) (repository.PageResult[repository.DLPMatch], error) {
	page = page.Normalize()
	cur, err := decodeCursor(page.After)
	if err != nil {
		return repository.PageResult[repository.DLPMatch]{}, repository.ErrInvalidArgument
	}
	res := repository.PageResult[repository.DLPMatch]{}
	err = r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		var extra *filterClause
		if policyID != nil {
			extra = &filterClause{column: "policy_id", value: *policyID}
		}
		q, args := buildSortedListQuery("dlp_matches", dlpMatchSelectColumns, "matched_at", cur, page.Order, page.Limit, extra)
		rows, err := tx.Query(ctx, q, args...)
		if err != nil {
			return fmt.Errorf("list dlp matches: %w", err)
		}
		defer rows.Close()
		items := make([]repository.DLPMatch, 0, page.Limit)
		for rows.Next() {
			m, err := scanDLPMatch(rows)
			if err != nil {
				return fmt.Errorf("scan dlp match: %w", err)
			}
			items = append(items, m)
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("iterate dlp matches: %w", err)
		}
		res.Items = items
		if len(items) == page.Limit && len(items) > 0 {
			last := items[len(items)-1]
			res.NextCursor = encodeCursor(pageCursor{T: last.MatchedAt, I: last.ID})
		}
		return nil
	})
	return res, err
}
