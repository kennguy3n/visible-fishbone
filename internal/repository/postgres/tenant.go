package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// TenantRepository owns the tenants table in Postgres.
type TenantRepository struct{ s *Store }

const tenantSelectColumns = `
	id, name, slug, msp_id, status, COALESCE(region, ''), tier,
	settings, created_at, updated_at, deleted_at, last_active_at
`

func scanTenant(row pgx.Row) (repository.Tenant, error) {
	var (
		t          repository.Tenant
		mspID      nullableUUID
		region     string
		setBuf     []byte
		deleted    *deletedAtScan
		lastActive *deletedAtScan
	)
	deleted = &deletedAtScan{}
	lastActive = &deletedAtScan{}
	if err := row.Scan(
		&t.ID, &t.Name, &t.Slug, &mspID, &t.Status, &region, &t.Tier,
		&setBuf, &t.CreatedAt, &t.UpdatedAt, deleted, lastActive,
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
	if lastActive.Valid {
		ts := lastActive.Time
		t.LastActiveAt = &ts
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
	tx, err := r.s.pool.Primary().BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return repository.Tenant{}, fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// In PgBouncer mode the AfterConnect SET SESSION ROLE hook is
	// disabled, so adopt the app role transaction-locally before
	// the INSERT (and any audit rows the caller layers onto this
	// tx) — they would otherwise run as the unprivileged login
	// role and fail with permission denied / bypass RLS.
	if err := r.s.adoptLocalRole(ctx, tx); err != nil {
		return repository.Tenant{}, err
	}

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
	var out repository.Tenant
	err := r.s.onPrimary(ctx, func(db pgxQuerier) error {
		var e error
		out, e = scanTenant(db.QueryRow(ctx, q, id))
		return e
	})
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
	var out repository.Tenant
	err := r.s.onPrimary(ctx, func(db pgxQuerier) error {
		var e error
		out, e = scanTenant(db.QueryRow(ctx, q, slug))
		return e
	})
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

	out := make([]repository.Tenant, 0, page.Limit)
	if err := r.s.onPrimary(ctx, func(db pgxQuerier) error {
		rows, e := db.Query(ctx, q, args...)
		if e != nil {
			return fmt.Errorf("list tenants: %w", e)
		}
		defer rows.Close()
		for rows.Next() {
			t, e := scanTenant(rows)
			if e != nil {
				return fmt.Errorf("scan tenant: %w", e)
			}
			out = append(out, t)
		}
		if e := rows.Err(); e != nil {
			return fmt.Errorf("iterate tenants: %w", e)
		}
		return nil
	}); err != nil {
		return repository.PageResult[repository.Tenant]{}, err
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
	// Soft-delete immutability guard. Round-26 of Devin Review on
	// PR #42 (ANALYSIS_0006) flagged that this WHERE clause lacked
	// the `status <> 'deleted' AND deleted_at IS NULL` predicate
	// that MSPRepository.Update enforces at internal/repository/
	// postgres/msp.go:294 — a PATCH on a soft-deleted tenant
	// silently rewrote the tombstoned row's name/slug/region/tier/
	// status/settings, bypassing the lifecycle invariant
	// `(status='deleted' ⇔ deleted_at != NULL)`. The matching
	// memory backend now rejects soft-deleted Updates with
	// ErrForbidden (see internal/repository/memory/tenant.go:147).
	// As with msp.go, the dual `status <> 'deleted' AND
	// deleted_at IS NULL` predicate is defence-in-depth against a
	// hypothetical corrupt row violating the invariant — under the
	// invariant both halves are equivalent, but a corrupt row with
	// only one half set would otherwise slip past exactly one of
	// the backends. Returns ErrForbidden via the disambiguation
	// query below when the row exists but is soft-deleted.
	const q = `
		UPDATE tenants
		SET name     = CASE WHEN $2::text IS NULL THEN name     ELSE $2::text END,
		    slug     = CASE WHEN $3::text IS NULL THEN slug     ELSE $3::text END,
		    status   = CASE WHEN $4::text IS NULL THEN status   ELSE $4::text END,
		    region   = CASE WHEN $5::text IS NULL THEN region   ELSE $5::text END,
		    tier     = CASE WHEN $6::text IS NULL THEN tier     ELSE $6::text END,
		    settings = CASE WHEN $7::jsonb IS NULL THEN settings ELSE $7::jsonb END
		WHERE id = $1::uuid AND status <> 'deleted' AND deleted_at IS NULL
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
	var out repository.Tenant
	err := r.s.onPrimary(ctx, func(db pgxQuerier) error {
		var e error
		out, e = scanTenant(db.QueryRow(ctx, q,
			id, nameArg, slugArg, statusArg, regionArg, tierArg, settings,
		))
		return e
	})
	if errors.Is(err, pgx.ErrNoRows) {
		// Either the row doesn't exist (NotFound) or the row
		// exists but is soft-deleted (Forbidden, per the
		// round-26 ANALYSIS_0006 guard above). Mirrors the
		// disambiguation MSPRepository.Update uses at
		// internal/repository/postgres/msp.go:345-357 — one
		// extra round-trip on the rare zero-rows-affected path
		// to give callers the precise error.
		var dummy uuid.UUID
		scanErr := r.s.onPrimary(ctx, func(db pgxQuerier) error {
			return db.QueryRow(ctx, `SELECT id FROM tenants WHERE id = $1::uuid`, id).Scan(&dummy)
		})
		if scanErr != nil {
			if errors.Is(scanErr, pgx.ErrNoRows) {
				return repository.Tenant{}, repository.ErrNotFound
			}
			return repository.Tenant{}, fmt.Errorf("update tenant lookup: %w", scanErr)
		}
		return repository.Tenant{}, repository.ErrForbidden
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

// UpdateSettingsKey atomically merges `value` into the
// tenants.settings JSONB document at top-level `key`. The
// `jsonb_set` mutation is applied inside the same row UPDATE so
// concurrent callers cannot lose updates the way a service-side
// RMW (Get→unmarshal→merge→marshal→Update) could. Round-17 of
// Devin Review on PR #42 (ANALYSIS_0003) flagged the lost-update
// race that motivated this primitive. Returns ErrNotFound if the
// row does not exist.
func (r *TenantRepository) UpdateSettingsKey(ctx context.Context, id uuid.UUID, key string, value json.RawMessage) (repository.Tenant, error) {
	if id == uuid.Nil {
		return repository.Tenant{}, repository.ErrInvalidArgument
	}
	if key == "" {
		return repository.Tenant{}, repository.ErrInvalidArgument
	}
	// Validate `value` is well-formed JSON before sending it to
	// the database — a malformed payload would surface as a
	// driver-level error and we want a clean ErrInvalidArgument.
	if !json.Valid(value) {
		return repository.Tenant{}, fmt.Errorf("update settings key %q: %w", key, repository.ErrInvalidArgument)
	}
	// jsonb_set with create_missing=true (the 4th arg, default
	// true) inserts the key when the path does not exist; the
	// COALESCE(settings, '{}'::jsonb) ensures we treat SQL NULL
	// as an empty document rather than returning NULL.
	//
	// Soft-delete filter (round-21 of Devin Review on PR #42 —
	// ANALYSIS_0002). The interface doc promises "Returns
	// ErrNotFound if the row does not exist or has been
	// soft-deleted." The prior WHERE clause was `WHERE id =
	// $1::uuid` with no `deleted_at IS NULL` predicate, so a
	// tombstoned tenant's JSONB document could be mutated by any
	// caller that knew the (still-valid) UUID — and the
	// silent-success response would convince the caller the write
	// had landed on a live row. Add the predicate so the
	// pgx.ErrNoRows path covers BOTH "no such id" and "id refers
	// to a soft-deleted row", which the existing error mapping
	// already collapses into ErrNotFound — matching the interface
	// contract exactly. The check is against `deleted_at` (rather
	// than `status`) because `deleted_at` is the canonical signal
	// across the tenant lifecycle: TransitionStatus / Delete both
	// stamp it, and the partial unique index
	// `tenants_slug_uniq_idx WHERE deleted_at IS NULL` already
	// keys off it.
	const q = `
		UPDATE tenants
		SET settings = jsonb_set(COALESCE(settings, '{}'::jsonb), ARRAY[$2::text], $3::jsonb, true)
		WHERE id = $1::uuid AND deleted_at IS NULL
		RETURNING ` + tenantSelectColumns
	var out repository.Tenant
	err := r.s.onPrimary(ctx, func(db pgxQuerier) error {
		var e error
		out, e = scanTenant(db.QueryRow(ctx, q, id, key, []byte(value)))
		return e
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return repository.Tenant{}, repository.ErrNotFound
	}
	if err != nil {
		return repository.Tenant{}, fmt.Errorf("update settings key %q: %w", key, err)
	}
	return out, nil
}

// DeleteSettingsKey atomically removes top-level `key` from
// tenants.settings using the JSONB `-` operator. Same atomicity
// guarantees as UpdateSettingsKey. A no-op for keys not present.
func (r *TenantRepository) DeleteSettingsKey(ctx context.Context, id uuid.UUID, key string) (repository.Tenant, error) {
	if id == uuid.Nil {
		return repository.Tenant{}, repository.ErrInvalidArgument
	}
	if key == "" {
		return repository.Tenant{}, repository.ErrInvalidArgument
	}
	// Soft-delete filter (round-21 of Devin Review on PR #42 —
	// ANALYSIS_0002). Mirrors the matching guard on
	// UpdateSettingsKey above: the interface contract is
	// "ErrNotFound if the row does not exist or has been
	// soft-deleted", so the WHERE clause filters tombstones via
	// `deleted_at IS NULL`. See the upstream comment for the full
	// rationale.
	const q = `
		UPDATE tenants
		SET settings = COALESCE(settings, '{}'::jsonb) - $2::text
		WHERE id = $1::uuid AND deleted_at IS NULL
		RETURNING ` + tenantSelectColumns
	var out repository.Tenant
	err := r.s.onPrimary(ctx, func(db pgxQuerier) error {
		var e error
		out, e = scanTenant(db.QueryRow(ctx, q, id, key))
		return e
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return repository.Tenant{}, repository.ErrNotFound
	}
	if err != nil {
		return repository.Tenant{}, fmt.Errorf("delete settings key %q: %w", key, err)
	}
	return out, nil
}

// UpdateStatus mutates the tenant's status enum directly. Round-17
// of Devin Review on PR #42 (ANALYSIS_0005) flagged that this
// method could be used to resurrect a soft-deleted tenant
// (`deleted` → `active`/`suspended`), which would break the
// lifecycle invariant `(status='deleted' ⇔ deleted_at != NULL)`
// because `deleted_at` would stay stamped on a now-active row and
// the partial unique index `tenants_slug_uniq_idx WHERE deleted_at
// IS NULL` would consider the resurrected row alongside any
// post-deletion replacement, surfacing as a unique-constraint
// violation on first write. The resurrection guard below rejects
// any transition out of `deleted` with ErrForbidden; operators that
// genuinely need to restore a tombstoned row must clear
// `deleted_at` via a dedicated restore path (not yet exposed).
// Idempotent self-transitions stay allowed (Delete→Delete) so
// callers that already handle that case keep working.
// TransitionStatus enforces the same invariant atomically for
// callers that want to gate on a known prior status. The guard is
// expressed as a WHERE predicate so the precondition and the
// UPDATE land in the same SQL statement — a Get-then-Update pair
// would have a TOCTOU window where a concurrent Delete could
// tombstone the row between our checks.
func (r *TenantRepository) UpdateStatus(ctx context.Context, id uuid.UUID, status repository.TenantStatus) (repository.Tenant, error) {
	switch status {
	case repository.TenantStatusActive, repository.TenantStatusSuspended, repository.TenantStatusDeleted:
	default:
		return repository.Tenant{}, repository.ErrInvalidArgument
	}
	// `status <> 'deleted' OR $2 = 'deleted'` is the resurrection
	// guard: if the row is already deleted we only accept another
	// transition to deleted (idempotent self-loop), and reject
	// every other target with ErrForbidden via the follow-up
	// lookup. See doc above for why this is wrong without the
	// guard.
	const q = `
		UPDATE tenants
		SET status     = $2,
		    deleted_at = CASE WHEN $2 = 'deleted' THEN COALESCE(deleted_at, NOW()) ELSE deleted_at END
		WHERE id = $1::uuid AND (status <> 'deleted' OR $2 = 'deleted')
		RETURNING ` + tenantSelectColumns
	var out repository.Tenant
	err := r.s.onPrimary(ctx, func(db pgxQuerier) error {
		var e error
		out, e = scanTenant(db.QueryRow(ctx, q, id, string(status)))
		return e
	})
	if err == nil {
		return out, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return repository.Tenant{}, fmt.Errorf("update status: %w", err)
	}
	// No row matched. Either the tenant does not exist (ErrNotFound)
	// or it exists but is already deleted and the caller asked for
	// a non-deleted target (ErrForbidden — resurrection rejected).
	var dummy string
	scanErr := r.s.onPrimary(ctx, func(db pgxQuerier) error {
		return db.QueryRow(ctx, `SELECT status FROM tenants WHERE id = $1::uuid`, id).Scan(&dummy)
	})
	if scanErr != nil {
		if errors.Is(scanErr, pgx.ErrNoRows) {
			return repository.Tenant{}, repository.ErrNotFound
		}
		return repository.Tenant{}, fmt.Errorf("update status lookup: %w", scanErr)
	}
	return repository.Tenant{}, repository.ErrForbidden
}

// TouchLastActive advances last_active_at to `seen`, forward-only. The
// `GREATEST(last_active_at, $2)` (NULL-safe via COALESCE) makes the
// write monotonic at the SQL level, so concurrent or out-of-order
// pings from multiple PoPs converge on the latest timestamp without a
// read-modify-write race. The WHERE filters soft-deleted tenants so a
// stray ping cannot resurrect activity on a tombstoned row. updated_at
// is intentionally left untouched: the tenants-specific trigger from
// migration 063 detects a last_active_at-only change and skips the
// bump, so this high-rate path never churns the config timestamp.
func (r *TenantRepository) TouchLastActive(ctx context.Context, id uuid.UUID, seen time.Time) error {
	if id == uuid.Nil {
		return repository.ErrInvalidArgument
	}
	const q = `
		UPDATE tenants
		SET last_active_at = GREATEST(COALESCE(last_active_at, $2::timestamptz), $2::timestamptz)
		WHERE id = $1::uuid AND status <> 'deleted' AND deleted_at IS NULL`
	var tag int64
	err := r.s.onPrimary(ctx, func(db pgxQuerier) error {
		ct, e := db.Exec(ctx, q, id, seen.UTC())
		if e != nil {
			return e
		}
		tag = ct.RowsAffected()
		return nil
	})
	if err != nil {
		return fmt.Errorf("touch last_active_at: %w", err)
	}
	if tag == 0 {
		return repository.ErrNotFound
	}
	return nil
}

// ListTenantActivity returns (id, last_active_at) for every live
// tenant in one indexed scan, ordered by id. This is the single cheap
// query a sweep planner runs per cycle to bucket tenants by recency —
// it never loads the heavy Tenant row, so enumeration stays O(1)
// queries regardless of tenant count.
func (r *TenantRepository) ListTenantActivity(ctx context.Context) ([]repository.TenantActivity, error) {
	const q = `
		SELECT id, last_active_at
		FROM tenants
		WHERE deleted_at IS NULL
		ORDER BY id`
	out := make([]repository.TenantActivity, 0, 256)
	err := r.s.onPrimary(ctx, func(db pgxQuerier) error {
		rows, e := db.Query(ctx, q)
		if e != nil {
			return fmt.Errorf("list tenant activity: %w", e)
		}
		defer rows.Close()
		for rows.Next() {
			var (
				a          repository.TenantActivity
				lastActive deletedAtScan
			)
			if e := rows.Scan(&a.ID, &lastActive); e != nil {
				return fmt.Errorf("scan tenant activity: %w", e)
			}
			if lastActive.Valid {
				ts := lastActive.Time
				a.LastActiveAt = &ts
			}
			out = append(out, a)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
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
	var out repository.Tenant
	err := r.s.onPrimary(ctx, func(db pgxQuerier) error {
		var e error
		out, e = scanTenant(db.QueryRow(ctx, q, id, string(to), string(from)))
		return e
	})
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
	scanErr := r.s.onPrimary(ctx, func(db pgxQuerier) error {
		return db.QueryRow(ctx, `SELECT status FROM tenants WHERE id = $1::uuid`, id).Scan(&dummyStatus)
	})
	if scanErr != nil {
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
	var affected int64
	err := r.s.onPrimary(ctx, func(db pgxQuerier) error {
		tag, e := db.Exec(ctx, q, id)
		if e != nil {
			return e
		}
		affected = tag.RowsAffected()
		return nil
	})
	if err != nil {
		return fmt.Errorf("delete tenant: %w", err)
	}
	if affected == 1 {
		return nil
	}
	// Distinguish ErrForbidden (already deleted) from ErrNotFound.
	var status string
	scanErr := r.s.onPrimary(ctx, func(db pgxQuerier) error {
		return db.QueryRow(ctx, `SELECT status FROM tenants WHERE id = $1::uuid`, id).Scan(&status)
	})
	if scanErr != nil {
		if errors.Is(scanErr, pgx.ErrNoRows) {
			return repository.ErrNotFound
		}
		return fmt.Errorf("delete tenant lookup: %w", scanErr)
	}
	return repository.ErrForbidden
}
