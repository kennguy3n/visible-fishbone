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

// TenantRepository owns the tenants table in Postgres.
type TenantRepository struct{ s *Store }

const tenantSelectColumns = `
	id, name, slug, msp_id, status, COALESCE(region, ''), tier,
	settings, created_at, updated_at, deleted_at
`

func scanTenant(row pgx.Row) (repository.Tenant, error) {
	var (
		t       repository.Tenant
		mspID   nullableUUID
		region  string
		setBuf  []byte
		deleted *deletedAtScan
	)
	deleted = &deletedAtScan{}
	if err := row.Scan(
		&t.ID, &t.Name, &t.Slug, &mspID, &t.Status, &region, &t.Tier,
		&setBuf, &t.CreatedAt, &t.UpdatedAt, deleted,
	); err != nil {
		return repository.Tenant{}, err
	}
	if mspID.Valid {
		id := mspID.ID
		t.MSPID = &id
	}
	t.Region = region
	t.Settings = json.RawMessage(setBuf)
	if deleted.Valid {
		ts := deleted.Time
		t.DeletedAt = &ts
	}
	return t, nil
}

func (r *TenantRepository) Create(ctx context.Context, t repository.Tenant) (repository.Tenant, error) {
	if t.Slug == "" {
		return repository.Tenant{}, repository.ErrInvalidArgument
	}
	if t.ID == uuid.Nil {
		t.ID = uuid.New()
	}
	if t.Status == "" {
		t.Status = repository.TenantStatusActive
	}
	if len(t.Settings) == 0 {
		t.Settings = json.RawMessage(`{}`)
	}

	// Tenant Create does NOT use withTenant — the tenant doesn't
	// exist yet, so there is nothing for the RLS GUC to scope to.
	// We open a tx anyway because callers (e.g. tenant service)
	// will commonly seed audit-log rows that DO require the GUC.
	tx, err := r.s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return repository.Tenant{}, fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	const q = `
		INSERT INTO tenants (id, name, slug, status, region, tier, settings)
		VALUES ($1::uuid, $2, $3, $4, NULLIF($5, ''), $6, $7::jsonb)
		RETURNING ` + tenantSelectColumns
	row := tx.QueryRow(ctx, q, t.ID, t.Name, t.Slug, t.Status, t.Region, t.Tier, []byte(t.Settings))
	out, err := scanTenant(row)
	if err != nil {
		if isUniqueViolation(err) {
			return repository.Tenant{}, repository.ErrConflict
		}
		if isCheckViolation(err) {
			return repository.Tenant{}, repository.ErrInvalidArgument
		}
		return repository.Tenant{}, fmt.Errorf("insert tenant: %w", err)
	}

	// Set the GUC for any subsequent inserts the caller may layer
	// onto this transaction (the service layer's pattern). For
	// the bare Create case it is harmless.
	if _, err := tx.Exec(ctx, "SELECT set_config('sng.tenant_id', $1, true)", out.ID); err != nil {
		return repository.Tenant{}, fmt.Errorf("set tenant context: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return repository.Tenant{}, fmt.Errorf("commit: %w", err)
	}
	return out, nil
}

func (r *TenantRepository) Get(ctx context.Context, id uuid.UUID) (repository.Tenant, error) {
	const q = `SELECT ` + tenantSelectColumns + ` FROM tenants WHERE id = $1::uuid`
	out, err := scanTenant(r.s.pool.QueryRow(ctx, q, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return repository.Tenant{}, repository.ErrNotFound
	}
	if err != nil {
		return repository.Tenant{}, fmt.Errorf("select tenant: %w", err)
	}
	return out, nil
}

func (r *TenantRepository) GetBySlug(ctx context.Context, slug string) (repository.Tenant, error) {
	const q = `SELECT ` + tenantSelectColumns + ` FROM tenants WHERE slug = $1`
	out, err := scanTenant(r.s.pool.QueryRow(ctx, q, slug))
	if errors.Is(err, pgx.ErrNoRows) {
		return repository.Tenant{}, repository.ErrNotFound
	}
	if err != nil {
		return repository.Tenant{}, fmt.Errorf("select tenant by slug: %w", err)
	}
	return out, nil
}

func (r *TenantRepository) List(ctx context.Context, page repository.Page) (repository.PageResult[repository.Tenant], error) {
	page = page.Normalize()
	cur, err := decodeCursor(page.After)
	if err != nil {
		return repository.PageResult[repository.Tenant]{}, repository.ErrInvalidArgument
	}

	// ORDER BY (created_at, id) is a total order; the cursor uses
	// (cur.T, cur.I) as the strict lower bound. The query is the
	// same shape for ASC and DESC apart from direction operators.
	var q string
	args := []any{cur.T, cur.I, page.Limit}
	switch page.Order {
	case repository.SortAsc:
		q = `
			SELECT ` + tenantSelectColumns + `
			FROM tenants
			WHERE ($1::timestamptz IS NULL OR (created_at, id) > ($1::timestamptz, $2::uuid))
			ORDER BY created_at ASC, id ASC
			LIMIT $3
		`
		if cur.T.IsZero() {
			args[0] = nil
		}
	default:
		q = `
			SELECT ` + tenantSelectColumns + `
			FROM tenants
			WHERE ($1::timestamptz IS NULL OR (created_at, id) < ($1::timestamptz, $2::uuid))
			ORDER BY created_at DESC, id DESC
			LIMIT $3
		`
		if cur.T.IsZero() {
			args[0] = nil
		}
	}

	rows, err := r.s.pool.Query(ctx, q, args...)
	if err != nil {
		return repository.PageResult[repository.Tenant]{}, fmt.Errorf("list tenants: %w", err)
	}
	defer rows.Close()

	out := make([]repository.Tenant, 0, page.Limit)
	for rows.Next() {
		t, err := scanTenant(rows)
		if err != nil {
			return repository.PageResult[repository.Tenant]{}, fmt.Errorf("scan tenant: %w", err)
		}
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		return repository.PageResult[repository.Tenant]{}, fmt.Errorf("iterate tenants: %w", err)
	}

	res := repository.PageResult[repository.Tenant]{Items: out}
	if len(out) == page.Limit && len(out) > 0 {
		last := out[len(out)-1]
		res.NextCursor = encodeCursor(pageCursor{T: last.CreatedAt, I: last.ID})
	}
	return res, nil
}

func (r *TenantRepository) Update(ctx context.Context, id uuid.UUID, patch repository.TenantPatch) (repository.Tenant, error) {
	if id == uuid.Nil {
		return repository.Tenant{}, repository.ErrInvalidArgument
	}
	// Build a sparse UPDATE that drives each column off a
	// `<param> IS NULL` probe: when the caller passes a nil
	// pointer the parameter binds to SQL NULL and the CASE keeps
	// the existing value; otherwise the supplied value is
	// applied verbatim, *including* the empty string. The
	// previous implementation used `COALESCE(NULLIF($x, ''),
	// col)` which collapsed "absent" and "clear" into the same
	// `''` wire value and made it impossible to PATCH the
	// optional Region column back to empty once it had been
	// set — exactly the bug the round-4 review flagged.
	const q = `
		UPDATE tenants
		SET name     = CASE WHEN $2::text IS NULL THEN name     ELSE $2::text END,
		    slug     = CASE WHEN $3::text IS NULL THEN slug     ELSE $3::text END,
		    status   = CASE WHEN $4::text IS NULL THEN status   ELSE $4::text END,
		    region   = CASE WHEN $5::text IS NULL THEN region   ELSE $5::text END,
		    tier     = CASE WHEN $6::text IS NULL THEN tier     ELSE $6::text END,
		    settings = CASE WHEN $7::jsonb IS NULL THEN settings ELSE $7::jsonb END
		WHERE id = $1::uuid
		RETURNING ` + tenantSelectColumns
	var (
		nameArg   any
		slugArg   any
		statusArg any
		regionArg any
		tierArg   any
		settings  any
	)
	if patch.Name != nil {
		nameArg = *patch.Name
	}
	if patch.Slug != nil {
		slugArg = *patch.Slug
	}
	if patch.Status != nil {
		statusArg = string(*patch.Status)
	}
	if patch.Region != nil {
		regionArg = *patch.Region
	}
	if patch.Tier != nil {
		tierArg = string(*patch.Tier)
	}
	if patch.Settings != nil {
		// An explicit empty payload (`json.RawMessage{}`) means
		// "clear to SQL NULL is not the operator's intent" — we
		// store the literal empty JSON object instead so the
		// column remains valid JSONB. A genuine "reset to {}"
		// is therefore expressible by the caller; a "wipe the
		// column to NULL" requires a separate schema operation.
		payload := *patch.Settings
		if len(payload) == 0 {
			payload = []byte("{}")
		}
		settings = []byte(payload)
	}
	out, err := scanTenant(r.s.pool.QueryRow(ctx, q,
		id, nameArg, slugArg, statusArg, regionArg, tierArg, settings,
	))
	if errors.Is(err, pgx.ErrNoRows) {
		return repository.Tenant{}, repository.ErrNotFound
	}
	if isUniqueViolation(err) {
		return repository.Tenant{}, repository.ErrConflict
	}
	if isCheckViolation(err) {
		return repository.Tenant{}, repository.ErrInvalidArgument
	}
	if err != nil {
		return repository.Tenant{}, fmt.Errorf("update tenant: %w", err)
	}
	return out, nil
}

func (r *TenantRepository) UpdateStatus(ctx context.Context, id uuid.UUID, status repository.TenantStatus) (repository.Tenant, error) {
	switch status {
	case repository.TenantStatusActive, repository.TenantStatusSuspended, repository.TenantStatusDeleted:
	default:
		return repository.Tenant{}, repository.ErrInvalidArgument
	}
	const q = `
		UPDATE tenants
		SET status     = $2,
		    deleted_at = CASE WHEN $2 = 'deleted' THEN COALESCE(deleted_at, NOW()) ELSE deleted_at END
		WHERE id = $1::uuid
		RETURNING ` + tenantSelectColumns
	out, err := scanTenant(r.s.pool.QueryRow(ctx, q, id, string(status)))
	if errors.Is(err, pgx.ErrNoRows) {
		return repository.Tenant{}, repository.ErrNotFound
	}
	if err != nil {
		return repository.Tenant{}, fmt.Errorf("update status: %w", err)
	}
	return out, nil
}

// SetMSPOwner is the storage primitive for the denormalised
// tenants.msp_id column. The MSP service's AssignTenant /
// UnassignTenant paths call this alongside the msp_tenants join
// row update so the denormalised column and the join stay in
// lockstep. Passing a nil mspID clears the column.
func (r *TenantRepository) SetMSPOwner(ctx context.Context, tenantID uuid.UUID, mspID *uuid.UUID) (repository.Tenant, error) {
	if tenantID == uuid.Nil {
		return repository.Tenant{}, repository.ErrInvalidArgument
	}
	const q = `
		UPDATE tenants
		SET msp_id = $2::uuid
		WHERE id = $1::uuid
		RETURNING ` + tenantSelectColumns
	var arg any
	if mspID != nil {
		arg = *mspID
	}
	out, err := scanTenant(r.s.pool.QueryRow(ctx, q, tenantID, arg))
	if errors.Is(err, pgx.ErrNoRows) {
		return repository.Tenant{}, repository.ErrNotFound
	}
	if err != nil {
		return repository.Tenant{}, fmt.Errorf("set msp owner: %w", err)
	}
	return out, nil
}

func (r *TenantRepository) TransitionStatus(ctx context.Context, id uuid.UUID, from, to repository.TenantStatus) (repository.Tenant, error) {
	switch to {
	case repository.TenantStatusActive, repository.TenantStatusSuspended, repository.TenantStatusDeleted:
	default:
		return repository.Tenant{}, repository.ErrInvalidArgument
	}
	// Single atomic UPDATE: the WHERE clause enforces the
	// precondition (current status = $3) and prevents the TOCTOU
	// window present in a Get+UpdateStatus pair. If the row does not
	// exist we get pgx.ErrNoRows -> ErrNotFound; if the row exists
	// but the precondition fails we must distinguish ErrForbidden,
	// so we run a follow-up existence check.
	const q = `
		UPDATE tenants
		SET status     = $2,
		    deleted_at = CASE WHEN $2 = 'deleted' THEN COALESCE(deleted_at, NOW()) ELSE deleted_at END
		WHERE id = $1::uuid AND status = $3
		RETURNING ` + tenantSelectColumns
	out, err := scanTenant(r.s.pool.QueryRow(ctx, q, id, string(to), string(from)))
	if err == nil {
		return out, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return repository.Tenant{}, fmt.Errorf("transition status: %w", err)
	}
	// Either the tenant doesn't exist (NotFound) or it exists with a
	// different status (Forbidden). One extra round-trip to
	// disambiguate; rare path so cost is acceptable.
	var dummyStatus string
	if scanErr := r.s.pool.QueryRow(ctx, `SELECT status FROM tenants WHERE id = $1::uuid`, id).Scan(&dummyStatus); scanErr != nil {
		if errors.Is(scanErr, pgx.ErrNoRows) {
			return repository.Tenant{}, repository.ErrNotFound
		}
		return repository.Tenant{}, fmt.Errorf("transition status lookup: %w", scanErr)
	}
	return repository.Tenant{}, repository.ErrForbidden
}

// Delete atomically soft-deletes a tenant. Returns ErrForbidden if
// the tenant is already deleted, ErrNotFound if it does not exist.
// The WHERE clause prevents the TOCTOU window present in a
// Get+UpdateStatus pair.
func (r *TenantRepository) Delete(ctx context.Context, id uuid.UUID) error {
	const q = `
		UPDATE tenants
		SET status     = 'deleted',
		    deleted_at = COALESCE(deleted_at, NOW())
		WHERE id = $1::uuid AND status <> 'deleted'`
	tag, err := r.s.pool.Exec(ctx, q, id)
	if err != nil {
		return fmt.Errorf("delete tenant: %w", err)
	}
	if tag.RowsAffected() == 1 {
		return nil
	}
	// Distinguish ErrForbidden (already deleted) from ErrNotFound.
	var status string
	if scanErr := r.s.pool.QueryRow(ctx, `SELECT status FROM tenants WHERE id = $1::uuid`, id).Scan(&status); scanErr != nil {
		if errors.Is(scanErr, pgx.ErrNoRows) {
			return repository.ErrNotFound
		}
		return fmt.Errorf("delete tenant lookup: %w", scanErr)
	}
	return repository.ErrForbidden
}
