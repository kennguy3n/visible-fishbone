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

// MSPRepository owns the msps + msp_tenants tables in Postgres.
//
// The shape mirrors TenantRepository — top-level entity, not
// RLS-scoped. AssignTenant / UnassignTenant run inside a single
// pgx.Tx so the join row and the denormalised tenants.msp_id
// pointer always commit together; a crash mid-flow cannot leave
// the two storage sites out of sync.
type MSPRepository struct{ s *Store }

const mspSelectColumns = `
	id, name, slug, status, branding, settings,
	created_at, updated_at, deleted_at
`

func scanMSP(row pgx.Row) (repository.MSP, error) {
	var (
		m         repository.MSP
		brandBuf  []byte
		setBuf    []byte
		deleted   *deletedAtScan
	)
	deleted = &deletedAtScan{}
	if err := row.Scan(
		&m.ID, &m.Name, &m.Slug, &m.Status, &brandBuf, &setBuf,
		&m.CreatedAt, &m.UpdatedAt, deleted,
	); err != nil {
		return repository.MSP{}, err
	}
	if len(brandBuf) > 0 {
		if err := json.Unmarshal(brandBuf, &m.Branding); err != nil {
			return repository.MSP{}, fmt.Errorf("decode branding: %w", err)
		}
	}
	m.Settings = json.RawMessage(setBuf)
	if deleted.Valid {
		ts := deleted.Time
		m.DeletedAt = &ts
	}
	return m, nil
}

// --- CRUD ---------------------------------------------------------

func (r *MSPRepository) Create(ctx context.Context, m repository.MSP) (repository.MSP, error) {
	if m.Slug == "" {
		return repository.MSP{}, repository.ErrInvalidArgument
	}
	if m.ID == uuid.Nil {
		m.ID = uuid.New()
	}
	if m.Status == "" {
		m.Status = repository.MSPStatusActive
	}
	if len(m.Settings) == 0 {
		m.Settings = json.RawMessage(`{}`)
	}
	brandBuf, err := json.Marshal(m.Branding)
	if err != nil {
		return repository.MSP{}, fmt.Errorf("encode branding: %w", err)
	}
	const q = `
		INSERT INTO msps (id, name, slug, status, branding, settings)
		VALUES ($1::uuid, $2, $3, $4, $5::jsonb, $6::jsonb)
		RETURNING ` + mspSelectColumns
	out, err := scanMSP(r.s.pool.QueryRow(ctx, q,
		m.ID, m.Name, m.Slug, string(m.Status), brandBuf, []byte(m.Settings),
	))
	if err != nil {
		if isUniqueViolation(err) {
			return repository.MSP{}, repository.ErrConflict
		}
		if isCheckViolation(err) {
			return repository.MSP{}, repository.ErrInvalidArgument
		}
		return repository.MSP{}, fmt.Errorf("insert msp: %w", err)
	}
	return out, nil
}

func (r *MSPRepository) Get(ctx context.Context, id uuid.UUID) (repository.MSP, error) {
	const q = `SELECT ` + mspSelectColumns + ` FROM msps WHERE id = $1::uuid`
	out, err := scanMSP(r.s.pool.QueryRow(ctx, q, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return repository.MSP{}, repository.ErrNotFound
	}
	if err != nil {
		return repository.MSP{}, fmt.Errorf("select msp: %w", err)
	}
	return out, nil
}

func (r *MSPRepository) GetBySlug(ctx context.Context, slug string) (repository.MSP, error) {
	const q = `SELECT ` + mspSelectColumns + ` FROM msps WHERE slug = $1`
	out, err := scanMSP(r.s.pool.QueryRow(ctx, q, slug))
	if errors.Is(err, pgx.ErrNoRows) {
		return repository.MSP{}, repository.ErrNotFound
	}
	if err != nil {
		return repository.MSP{}, fmt.Errorf("select msp by slug: %w", err)
	}
	return out, nil
}

func (r *MSPRepository) List(ctx context.Context, page repository.Page) (repository.PageResult[repository.MSP], error) {
	page = page.Normalize()
	cur, err := decodeCursor(page.After)
	if err != nil {
		return repository.PageResult[repository.MSP]{}, repository.ErrInvalidArgument
	}
	var q string
	args := []any{cur.T, cur.I, page.Limit}
	switch page.Order {
	case repository.SortAsc:
		q = `
			SELECT ` + mspSelectColumns + `
			FROM msps
			WHERE ($1::timestamptz IS NULL OR (created_at, id) > ($1::timestamptz, $2::uuid))
			ORDER BY created_at ASC, id ASC
			LIMIT $3
		`
		if cur.T.IsZero() {
			args[0] = nil
		}
	default:
		q = `
			SELECT ` + mspSelectColumns + `
			FROM msps
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
		return repository.PageResult[repository.MSP]{}, fmt.Errorf("list msps: %w", err)
	}
	defer rows.Close()
	out := make([]repository.MSP, 0, page.Limit)
	for rows.Next() {
		m, err := scanMSP(rows)
		if err != nil {
			return repository.PageResult[repository.MSP]{}, fmt.Errorf("scan msp: %w", err)
		}
		out = append(out, m)
	}
	if err := rows.Err(); err != nil {
		return repository.PageResult[repository.MSP]{}, fmt.Errorf("iterate msps: %w", err)
	}
	res := repository.PageResult[repository.MSP]{Items: out}
	if len(out) == page.Limit && len(out) > 0 {
		last := out[len(out)-1]
		res.NextCursor = encodeCursor(pageCursor{T: last.CreatedAt, I: last.ID})
	}
	return res, nil
}

func (r *MSPRepository) Update(ctx context.Context, id uuid.UUID, patch repository.MSPPatch) (repository.MSP, error) {
	if id == uuid.Nil {
		return repository.MSP{}, repository.ErrInvalidArgument
	}
	// Same sparse explicit-clear PATCH shape as
	// TenantRepository.Update: nil arg → keep, non-nil arg → set
	// to value (including zero).
	const q = `
		UPDATE msps
		SET name     = CASE WHEN $2::text IS NULL THEN name     ELSE $2::text END,
		    slug     = CASE WHEN $3::text IS NULL THEN slug     ELSE $3::text END,
		    status   = CASE WHEN $4::text IS NULL THEN status   ELSE $4::text END,
		    branding = CASE WHEN $5::jsonb IS NULL THEN branding ELSE $5::jsonb END,
		    settings = CASE WHEN $6::jsonb IS NULL THEN settings ELSE $6::jsonb END
		WHERE id = $1::uuid
		RETURNING ` + mspSelectColumns
	var (
		nameArg     any
		slugArg     any
		statusArg   any
		brandingArg any
		settingsArg any
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
	if patch.Branding != nil {
		buf, err := json.Marshal(*patch.Branding)
		if err != nil {
			return repository.MSP{}, fmt.Errorf("encode branding: %w", err)
		}
		brandingArg = buf
	}
	if patch.Settings != nil {
		payload := *patch.Settings
		if len(payload) == 0 {
			payload = []byte("{}")
		}
		settingsArg = []byte(payload)
	}
	out, err := scanMSP(r.s.pool.QueryRow(ctx, q,
		id, nameArg, slugArg, statusArg, brandingArg, settingsArg,
	))
	if errors.Is(err, pgx.ErrNoRows) {
		return repository.MSP{}, repository.ErrNotFound
	}
	if isUniqueViolation(err) {
		return repository.MSP{}, repository.ErrConflict
	}
	if isCheckViolation(err) {
		return repository.MSP{}, repository.ErrInvalidArgument
	}
	if err != nil {
		return repository.MSP{}, fmt.Errorf("update msp: %w", err)
	}
	return out, nil
}

func (r *MSPRepository) UpdateStatus(ctx context.Context, id uuid.UUID, status repository.MSPStatus) (repository.MSP, error) {
	switch status {
	case repository.MSPStatusActive, repository.MSPStatusSuspended, repository.MSPStatusDeleted:
	default:
		return repository.MSP{}, repository.ErrInvalidArgument
	}
	const q = `
		UPDATE msps
		SET status     = $2,
		    deleted_at = CASE WHEN $2 = 'deleted' THEN COALESCE(deleted_at, NOW()) ELSE deleted_at END
		WHERE id = $1::uuid
		RETURNING ` + mspSelectColumns
	out, err := scanMSP(r.s.pool.QueryRow(ctx, q, id, string(status)))
	if errors.Is(err, pgx.ErrNoRows) {
		return repository.MSP{}, repository.ErrNotFound
	}
	if err != nil {
		return repository.MSP{}, fmt.Errorf("update msp status: %w", err)
	}
	return out, nil
}

// Delete soft-deletes the MSP. The Postgres FK on msp_tenants is
// ON DELETE CASCADE so the join rows go automatically; the FK on
// tenants.msp_id is ON DELETE SET NULL so the denormalised pointer
// is cleared automatically too. We only need to mark the row
// deleted here; the cascades fire on actual row DELETE, which the
// soft-delete path simulates via UPDATE.
//
// To preserve the cascade behaviour without losing audit history,
// the implementation explicitly drops the join rows and clears the
// pointers inside a single tx alongside the status update.
func (r *MSPRepository) Delete(ctx context.Context, id uuid.UUID) error {
	tx, err := r.s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	const updateQ = `
		UPDATE msps
		SET status     = 'deleted',
		    deleted_at = COALESCE(deleted_at, NOW())
		WHERE id = $1::uuid AND status <> 'deleted'`
	tag, err := tx.Exec(ctx, updateQ, id)
	if err != nil {
		return fmt.Errorf("delete msp: %w", err)
	}
	if tag.RowsAffected() == 0 {
		var status string
		if scanErr := tx.QueryRow(ctx, `SELECT status FROM msps WHERE id = $1::uuid`, id).Scan(&status); scanErr != nil {
			if errors.Is(scanErr, pgx.ErrNoRows) {
				return repository.ErrNotFound
			}
			return fmt.Errorf("delete msp lookup: %w", scanErr)
		}
		return repository.ErrForbidden
	}
	if _, err := tx.Exec(ctx, `DELETE FROM msp_tenants WHERE msp_id = $1::uuid`, id); err != nil {
		return fmt.Errorf("cascade msp_tenants: %w", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE tenants SET msp_id = NULL WHERE msp_id = $1::uuid`, id); err != nil {
		return fmt.Errorf("cascade tenants.msp_id: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	return nil
}

// --- Binding ops --------------------------------------------------

// AssignTenant inserts (or upgrades) the msp_tenants row binding
// the tenant to this MSP. Runs inside a single transaction with
// the denormalised tenants.msp_id update so the join and the
// pointer always commit together.
//
// When relationship is Owner, any other owner binding for the
// tenant is removed first — the partial UNIQUE index in
// migration 015 enforces "at most one owner per tenant" at the
// storage layer, so a manual DELETE of the previous owner is the
// only safe way to take ownership atomically.
func (r *MSPRepository) AssignTenant(
	ctx context.Context,
	mspID, tenantID uuid.UUID,
	relationship repository.MSPRelationship,
	actor *uuid.UUID,
) (repository.MSPTenantBinding, error) {
	if mspID == uuid.Nil || tenantID == uuid.Nil {
		return repository.MSPTenantBinding{}, repository.ErrInvalidArgument
	}
	if !relationship.IsValid() {
		return repository.MSPTenantBinding{}, repository.ErrInvalidArgument
	}
	tx, err := r.s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return repository.MSPTenantBinding{}, fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Pre-flight existence checks so the FK violation
	// distinguishes "msp missing" from "tenant missing" via a
	// clean ErrNotFound rather than a Postgres FK violation
	// error code surfaced upstream.
	var dummy uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT id FROM msps WHERE id = $1::uuid`, mspID).Scan(&dummy); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return repository.MSPTenantBinding{}, repository.ErrNotFound
		}
		return repository.MSPTenantBinding{}, fmt.Errorf("lookup msp: %w", err)
	}
	if err := tx.QueryRow(ctx, `SELECT id FROM tenants WHERE id = $1::uuid`, tenantID).Scan(&dummy); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return repository.MSPTenantBinding{}, repository.ErrNotFound
		}
		return repository.MSPTenantBinding{}, fmt.Errorf("lookup tenant: %w", err)
	}

	if relationship == repository.MSPRelationshipOwner {
		// Evict any pre-existing owner binding for this tenant
		// from any other MSP. The partial UNIQUE index would
		// otherwise reject the INSERT.
		if _, err := tx.Exec(ctx,
			`DELETE FROM msp_tenants WHERE tenant_id = $1::uuid AND relationship = 'owner' AND msp_id <> $2::uuid`,
			tenantID, mspID,
		); err != nil {
			return repository.MSPTenantBinding{}, fmt.Errorf("evict prior owner: %w", err)
		}
	}

	const upsertQ = `
		INSERT INTO msp_tenants (msp_id, tenant_id, relationship, created_by)
		VALUES ($1::uuid, $2::uuid, $3, $4::uuid)
		ON CONFLICT (msp_id, tenant_id) DO UPDATE
		    SET relationship = EXCLUDED.relationship
		RETURNING msp_id, tenant_id, relationship, created_at, created_by`
	var (
		actorArg  any
		createdBy nullableUUID
		binding   repository.MSPTenantBinding
	)
	if actor != nil {
		actorArg = *actor
	}
	if err := tx.QueryRow(ctx, upsertQ, mspID, tenantID, string(relationship), actorArg).Scan(
		&binding.MSPID, &binding.TenantID, &binding.Relationship,
		&binding.CreatedAt, &createdBy,
	); err != nil {
		return repository.MSPTenantBinding{}, fmt.Errorf("upsert binding: %w", err)
	}
	if createdBy.Valid {
		v := createdBy.ID
		binding.CreatedBy = &v
	}

	if relationship == repository.MSPRelationshipOwner {
		if _, err := tx.Exec(ctx,
			`UPDATE tenants SET msp_id = $2::uuid, updated_at = NOW() WHERE id = $1::uuid`,
			tenantID, mspID,
		); err != nil {
			return repository.MSPTenantBinding{}, fmt.Errorf("set tenant owner: %w", err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return repository.MSPTenantBinding{}, fmt.Errorf("commit: %w", err)
	}
	return binding, nil
}

// UnassignTenant removes the (msp, tenant) binding. If the binding
// was an owner, the denormalised tenants.msp_id is cleared in the
// same transaction.
func (r *MSPRepository) UnassignTenant(ctx context.Context, mspID, tenantID uuid.UUID) error {
	tx, err := r.s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var relationship string
	const delQ = `
		DELETE FROM msp_tenants
		WHERE msp_id = $1::uuid AND tenant_id = $2::uuid
		RETURNING relationship`
	if err := tx.QueryRow(ctx, delQ, mspID, tenantID).Scan(&relationship); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return repository.ErrNotFound
		}
		return fmt.Errorf("delete binding: %w", err)
	}
	if repository.MSPRelationship(relationship) == repository.MSPRelationshipOwner {
		if _, err := tx.Exec(ctx,
			`UPDATE tenants SET msp_id = NULL, updated_at = NOW() WHERE id = $1::uuid AND msp_id = $2::uuid`,
			tenantID, mspID,
		); err != nil {
			return fmt.Errorf("clear tenant owner: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	return nil
}

func (r *MSPRepository) ListTenants(ctx context.Context, mspID uuid.UUID, page repository.Page) (repository.PageResult[repository.MSPTenantBinding], error) {
	page = page.Normalize()
	cur, err := decodeCursor(page.After)
	if err != nil {
		return repository.PageResult[repository.MSPTenantBinding]{}, repository.ErrInvalidArgument
	}
	const q = `
		SELECT msp_id, tenant_id, relationship, created_at, created_by
		FROM msp_tenants
		WHERE msp_id = $1::uuid
		  AND ($2::timestamptz IS NULL OR (created_at, tenant_id) < ($2::timestamptz, $3::uuid))
		ORDER BY created_at DESC, tenant_id DESC
		LIMIT $4`
	args := []any{mspID, cur.T, cur.I, page.Limit}
	if cur.T.IsZero() {
		args[1] = nil
	}
	rows, err := r.s.pool.Query(ctx, q, args...)
	if err != nil {
		return repository.PageResult[repository.MSPTenantBinding]{}, fmt.Errorf("list msp tenants: %w", err)
	}
	defer rows.Close()
	out := make([]repository.MSPTenantBinding, 0, page.Limit)
	for rows.Next() {
		var (
			b         repository.MSPTenantBinding
			createdBy nullableUUID
		)
		if err := rows.Scan(&b.MSPID, &b.TenantID, &b.Relationship, &b.CreatedAt, &createdBy); err != nil {
			return repository.PageResult[repository.MSPTenantBinding]{}, fmt.Errorf("scan binding: %w", err)
		}
		if createdBy.Valid {
			v := createdBy.ID
			b.CreatedBy = &v
		}
		out = append(out, b)
	}
	if err := rows.Err(); err != nil {
		return repository.PageResult[repository.MSPTenantBinding]{}, fmt.Errorf("iterate bindings: %w", err)
	}
	res := repository.PageResult[repository.MSPTenantBinding]{Items: out}
	if len(out) == page.Limit && len(out) > 0 {
		last := out[len(out)-1]
		res.NextCursor = encodeCursor(pageCursor{T: last.CreatedAt, I: last.TenantID})
	}
	return res, nil
}

func (r *MSPRepository) ListBindings(ctx context.Context, tenantID uuid.UUID) ([]repository.MSPTenantBinding, error) {
	const q = `
		SELECT msp_id, tenant_id, relationship, created_at, created_by
		FROM msp_tenants
		WHERE tenant_id = $1::uuid
		ORDER BY created_at DESC`
	rows, err := r.s.pool.Query(ctx, q, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list bindings: %w", err)
	}
	defer rows.Close()
	out := make([]repository.MSPTenantBinding, 0)
	for rows.Next() {
		var (
			b         repository.MSPTenantBinding
			createdBy nullableUUID
		)
		if err := rows.Scan(&b.MSPID, &b.TenantID, &b.Relationship, &b.CreatedAt, &createdBy); err != nil {
			return nil, fmt.Errorf("scan binding: %w", err)
		}
		if createdBy.Valid {
			v := createdBy.ID
			b.CreatedBy = &v
		}
		out = append(out, b)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate bindings: %w", err)
	}
	return out, nil
}
