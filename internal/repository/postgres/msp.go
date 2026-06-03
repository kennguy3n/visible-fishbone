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
		m        repository.MSP
		brandBuf []byte
		setBuf   []byte
		deleted  *deletedAtScan
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
	// Default empty / JSON-`null` settings to `{}` so the column
	// holds an object per the OpenAPI declaration
	// `settings: type: object`. Round-22 of Devin Review on
	// PR #42 (ANALYSIS_0005) flagged that a client sending
	// `{"settings": null}` produces `m.Settings =
	// json.RawMessage("null")` (4 bytes, NOT zero), bypassing
	// the previous `len(m.Settings) == 0` default and writing
	// the scalar `'null'::jsonb`. The handler boundary now 400s
	// the `null` literal; the repo normalisation closes the gap
	// for internal callers. Cross-backend parity lives in
	// internal/repository/memory/msp.go.
	if len(m.Settings) == 0 || isJSONNullLiteral(m.Settings) {
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
	var out repository.MSP
	err = r.s.onPrimary(ctx, func(db pgxQuerier) error {
		var e error
		out, e = scanMSP(db.QueryRow(ctx, q,
			m.ID, m.Name, m.Slug, string(m.Status), brandBuf, []byte(m.Settings),
		))
		return e
	})
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
	var out repository.MSP
	err := r.s.onPrimary(ctx, func(db pgxQuerier) error {
		var e error
		out, e = scanMSP(db.QueryRow(ctx, q, id))
		return e
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return repository.MSP{}, repository.ErrNotFound
	}
	if err != nil {
		return repository.MSP{}, fmt.Errorf("select msp: %w", err)
	}
	return out, nil
}

// GetBySlug looks up the active (non-soft-deleted) MSP by slug. The
// migration enforces uniqueness only among non-deleted rows via
// `msps_slug_uniq_idx WHERE deleted_at IS NULL`, so after a
// soft-delete + slug reuse cycle two rows can share the same slug.
// Without the explicit filter QueryRow's result is whichever row
// the planner happens to return first (no ORDER BY) — typically the
// older tombstone. Filtering on `deleted_at IS NULL` keeps the
// lookup deterministic and aligned with the memory backend.
func (r *MSPRepository) GetBySlug(ctx context.Context, slug string) (repository.MSP, error) {
	const q = `SELECT ` + mspSelectColumns + ` FROM msps WHERE slug = $1 AND deleted_at IS NULL`
	var out repository.MSP
	err := r.s.onPrimary(ctx, func(db pgxQuerier) error {
		var e error
		out, e = scanMSP(db.QueryRow(ctx, q, slug))
		return e
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return repository.MSP{}, repository.ErrNotFound
	}
	if err != nil {
		return repository.MSP{}, fmt.Errorf("select msp by slug: %w", err)
	}
	return out, nil
}

func (r *MSPRepository) List(ctx context.Context, page repository.Page, filter repository.MSPListFilter) (repository.PageResult[repository.MSP], error) {
	page = page.Normalize()
	cur, err := decodeCursor(page.After)
	if err != nil {
		return repository.PageResult[repository.MSP]{}, repository.ErrInvalidArgument
	}
	// Round-17 of Devin Review on PR #42 — filter out
	// soft-deleted rows unless an admin caller opts in.
	// `deleted_at IS NULL` matches the partial unique index
	// `msps_slug_uniq_idx WHERE deleted_at IS NULL` and the
	// lifecycle invariant `(status='deleted' ⇔ deleted_at !=
	// NULL)`. Composed via a SQL fragment so both ASC and DESC
	// branches share it. Note: the cursor predicate uses an
	// already-NULL probe on $1::timestamptz; appending the
	// deleted_at filter via AND keeps that working.
	deletedFilter := " AND deleted_at IS NULL"
	if filter.IncludeDeleted {
		deletedFilter = ""
	}
	var q string
	args := []any{cur.T, cur.I, page.Limit}
	switch page.Order {
	case repository.SortAsc:
		q = `
			SELECT ` + mspSelectColumns + `
			FROM msps
			WHERE ($1::timestamptz IS NULL OR (created_at, id) > ($1::timestamptz, $2::uuid))` + deletedFilter + `
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
			WHERE ($1::timestamptz IS NULL OR (created_at, id) < ($1::timestamptz, $2::uuid))` + deletedFilter + `
			ORDER BY created_at DESC, id DESC
			LIMIT $3
		`
		if cur.T.IsZero() {
			args[0] = nil
		}
	}
	out := make([]repository.MSP, 0, page.Limit)
	if err := r.s.onPrimary(ctx, func(db pgxQuerier) error {
		rows, e := db.Query(ctx, q, args...)
		if e != nil {
			return fmt.Errorf("list msps: %w", e)
		}
		defer rows.Close()
		for rows.Next() {
			m, e := scanMSP(rows)
			if e != nil {
				return fmt.Errorf("scan msp: %w", e)
			}
			out = append(out, m)
		}
		if e := rows.Err(); e != nil {
			return fmt.Errorf("iterate msps: %w", e)
		}
		return nil
	}); err != nil {
		return repository.PageResult[repository.MSP]{}, err
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
	// Defense-in-depth: reject empty Name / Slug here even though the
	// HTTP handler already 400s on `{"name": ""}` and `{"slug": ""}`.
	// Round-8 of Devin Review caught the cross-backend divergence:
	// the previous postgres `CASE WHEN $X::text IS NULL THEN col ELSE
	// $X::text END` arm bound an empty string into NOT NULL columns,
	// while the memory backend silently dropped the empty value with
	// `if *patch.Name != ""`. Both behaviours are wrong for an
	// internal caller that bypasses the handler:
	//   - postgres: corrupts the row (empty NOT NULL string, both
	//     required-on-create fields nulled out),
	//   - memory: silently no-ops with no diagnostic.
	// Failing fast with ErrInvalidArgument keeps the two backends
	// observably identical and makes any future internal caller see
	// the bug at the repo boundary instead of producing a corrupted
	// row or a silent drop. The handler keeps producing the friendlier
	// 400 copy ("cannot be cleared via PATCH; omit the field to leave
	// unchanged") for HTTP callers.
	if patch.Name != nil && *patch.Name == "" {
		return repository.MSP{}, repository.ErrInvalidArgument
	}
	if patch.Slug != nil && *patch.Slug == "" {
		return repository.MSP{}, repository.ErrInvalidArgument
	}
	// Reject `patch.Status = MSPStatusDeleted` at the repo boundary.
	// The handler already 400s on this via validMSPCreateStatus, but
	// an internal caller (admin tool, migration script, future RPC)
	// that constructs `MSPPatch{Status: &MSPStatusDeleted}` would
	// otherwise let the UPDATE below write `status='deleted'` onto
	// the row without the `deleted_at` stamping that Delete()
	// performs as part of the cascade. That produces the corrupt
	// `(status='deleted', deleted_at IS NULL)` state the lifecycle
	// invariant is designed to prevent, AND leaves msp_tenants /
	// tenants.msp_id pointing at the now-deleted MSP (Delete() is
	// the only path that cascades). Round-21 of Devin Review on
	// PR #42 (ANALYSIS_0001) flagged this. The legal transition
	// into `deleted` is Delete(); the legal transitions to active
	// / suspended go through TransitionStatus. Mirrors the matching
	// guard in internal/repository/memory/msp.go so cross-backend
	// parity is enforced for every internal caller.
	if patch.Status != nil && *patch.Status == repository.MSPStatusDeleted {
		return repository.MSP{}, repository.ErrInvalidArgument
	}
	// Round-22 of Devin Review on PR #42 (ANALYSIS_0001) flagged
	// the cross-backend divergence for `patch.Status = &""`: the
	// CASE arm below binds `$4::text = ''` into the status column,
	// the table-level CHECK rejects with `invalid_text_representation`
	// (postgres surfaces as a generic error), while the memory
	// backend silently skips empty via `if *patch.Status != ""`.
	// An internal caller bypassing the handler would see two
	// different observable outcomes (one error, one no-op) for
	// the same input. The handler boundary at
	// internal/handler/msp.go converts "" to nil before constructing
	// the patch, so this is unreachable via HTTP today, but the
	// repo boundary should fail fast and identically across
	// backends regardless of caller. Mirrors the existing
	// empty-Name / empty-Slug guards above.
	if patch.Status != nil && *patch.Status == "" {
		return repository.MSP{}, repository.ErrInvalidArgument
	}
	// Same sparse explicit-clear PATCH shape as
	// TenantRepository.Update: nil arg → keep, non-nil arg → set
	// to value (including zero).
	//
	// Soft-delete immutability (defense-in-depth, round-14 of Devin
	// Review on PR #42 — ANALYSIS_0002): the guard rejects a PATCH
	// if EITHER `status = 'deleted'` OR `deleted_at IS NOT NULL`.
	// Under the lifecycle invariant `(status='deleted' ⇔ deleted_at
	// != NULL)` the two predicates are logically equivalent, but a
	// hypothetical corrupt row (e.g. status='deleted' with deleted_at
	// IS NULL, or vice versa) would otherwise bypass exactly one of
	// the backends. Round-13 introduced the `deleted_at IS NULL` half
	// of this guard; round-14 mirrors the additional `status <>
	// 'deleted'` check so postgres and memory enforce parity against
	// the same failure modes. Distinguishing ErrForbidden (row exists
	// but is deleted) from ErrNotFound (row absent) requires the
	// secondary lookup below on zero rows affected.
	const q = `
		UPDATE msps
		SET name     = CASE WHEN $2::text IS NULL THEN name     ELSE $2::text END,
		    slug     = CASE WHEN $3::text IS NULL THEN slug     ELSE $3::text END,
		    status   = CASE WHEN $4::text IS NULL THEN status   ELSE $4::text END,
		    branding = CASE WHEN $5::jsonb IS NULL THEN branding ELSE $5::jsonb END,
		    settings = CASE WHEN $6::jsonb IS NULL THEN settings ELSE $6::jsonb END
		WHERE id = $1::uuid AND status <> 'deleted' AND deleted_at IS NULL
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
		// Normalise the empty / JSON-`null` payload to the
		// empty-object default `{}`. Round-22 of Devin Review on
		// PR #42 (ANALYSIS_0005) flagged that a client sending
		// `{"settings": null}` produces `*patch.Settings =
		// json.RawMessage("null")` (4 bytes), bypassing the
		// existing `len(payload) == 0` default and writing the
		// scalar `'null'::jsonb` to the column — valid JSONB but
		// in conflict with the OpenAPI declaration
		// `settings: type: object`. The handler boundary at
		// internal/handler/msp.go now 400s the `null` literal, but
		// the repo defence-in-depth normalisation here closes the
		// gap for internal callers (admin tools, migration
		// scripts, future RPC) that construct `MSPPatch{Settings:
		// &json.RawMessage("null")}` directly. Cross-backend
		// parity: the matching normalisation lives in
		// internal/repository/memory/msp.go.
		if len(payload) == 0 || isJSONNullLiteral(payload) {
			payload = []byte("{}")
		}
		settingsArg = []byte(payload)
	}
	var out repository.MSP
	err := r.s.onPrimary(ctx, func(db pgxQuerier) error {
		var e error
		out, e = scanMSP(db.QueryRow(ctx, q,
			id, nameArg, slugArg, statusArg, brandingArg, settingsArg,
		))
		return e
	})
	if errors.Is(err, pgx.ErrNoRows) {
		// Either the row doesn't exist (NotFound) or the row exists
		// but is soft-deleted (Forbidden — soft-delete immutability
		// guard, round-13). One extra round-trip to disambiguate;
		// rare path so cost is acceptable.
		var dummy uuid.UUID
		scanErr := r.s.onPrimary(ctx, func(db pgxQuerier) error {
			return db.QueryRow(ctx, `SELECT id FROM msps WHERE id = $1::uuid`, id).Scan(&dummy)
		})
		if scanErr != nil {
			if errors.Is(scanErr, pgx.ErrNoRows) {
				return repository.MSP{}, repository.ErrNotFound
			}
			return repository.MSP{}, fmt.Errorf("update msp lookup: %w", scanErr)
		}
		return repository.MSP{}, repository.ErrForbidden
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

// TransitionStatus atomically updates the MSP status while refusing
// to mutate a soft-deleted row. The single UPDATE statement carries
// the precondition (`status <> 'deleted'`) in its WHERE clause,
// eliminating the TOCTOU window present in a Get-then-UpdateStatus
// pair (round-13 of Devin Review on PR #42 — BUG_0001).
//
// `to` is restricted to MSPStatusActive or MSPStatusSuspended; the
// terminal MSPStatusDeleted transition is owned by Delete() because
// it cascades msp_tenants + tenants.msp_id in the same transaction.
//
// On zero rows affected we run a follow-up existence check to
// distinguish ErrForbidden (row exists but is deleted) from
// ErrNotFound (row absent). Rare path so the extra round-trip is
// acceptable.
func (r *MSPRepository) TransitionStatus(ctx context.Context, id uuid.UUID, to repository.MSPStatus) (repository.MSP, error) {
	switch to {
	case repository.MSPStatusActive, repository.MSPStatusSuspended:
	default:
		return repository.MSP{}, repository.ErrInvalidArgument
	}
	// Defense-in-depth (round-19 of Devin Review on PR #42 —
	// ANALYSIS_0002). Under the lifecycle invariant `(status =
	// 'deleted' ⇔ deleted_at IS NOT NULL)` the status check is
	// sufficient, but Update()'s WHERE clause checks BOTH for
	// parity against any hypothetical corrupt row (status =
	// 'deleted' with deleted_at IS NULL, or vice versa — produced
	// e.g. by a partial migration or a buggy admin tool that
	// touched one column without the other). Mirror the
	// belt-and-suspenders shape on TransitionStatus so callers
	// observe the same refusal regardless of which side of the
	// invariant the corruption manifests on. The matching memory
	// backend at internal/repository/memory/msp.go now checks
	// `existing.Status == Deleted || existing.DeletedAt != nil`
	// for the same reason.
	const q = `
		UPDATE msps
		SET status = $2
		WHERE id = $1::uuid AND status <> 'deleted' AND deleted_at IS NULL
		RETURNING ` + mspSelectColumns
	var out repository.MSP
	err := r.s.onPrimary(ctx, func(db pgxQuerier) error {
		var e error
		out, e = scanMSP(db.QueryRow(ctx, q, id, string(to)))
		return e
	})
	if err == nil {
		return out, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return repository.MSP{}, fmt.Errorf("transition msp status: %w", err)
	}
	var dummy string
	scanErr := r.s.onPrimary(ctx, func(db pgxQuerier) error {
		return db.QueryRow(ctx, `SELECT status FROM msps WHERE id = $1::uuid`, id).Scan(&dummy)
	})
	if scanErr != nil {
		if errors.Is(scanErr, pgx.ErrNoRows) {
			return repository.MSP{}, repository.ErrNotFound
		}
		return repository.MSP{}, fmt.Errorf("transition msp status lookup: %w", scanErr)
	}
	return repository.MSP{}, repository.ErrForbidden
}

func (r *MSPRepository) UpdateStatus(ctx context.Context, id uuid.UUID, status repository.MSPStatus) (repository.MSP, error) {
	switch status {
	case repository.MSPStatusActive, repository.MSPStatusSuspended, repository.MSPStatusDeleted:
	default:
		return repository.MSP{}, repository.ErrInvalidArgument
	}
	// Resurrection guard (round-17 of Devin Review on PR #42 —
	// ANALYSIS_0005). UpdateStatus is no longer exposed on the
	// handler-narrow MSPService interface, but the method remains
	// on the public MSPRepository for admin tools / migrations.
	// Without the `WHERE status <> 'deleted' AND deleted_at IS
	// NULL` precondition below, a stray UpdateStatus(deleted_row,
	// 'active') would resurrect a soft-deleted row and corrupt
	// the lifecycle invariant `(status='deleted' ⇔ deleted_at
	// != NULL)` — that in turn breaks the partial unique index
	// `WHERE deleted_at IS NULL` on slug and produces the
	// (status='active', deleted_at != NULL) state the lifecycle
	// machinery elsewhere does not handle. ErrNoRows from the
	// guarded UPDATE is disambiguated (NotFound vs Forbidden via
	// a follow-up SELECT) so callers learn the precise reason
	// — same pattern Delete() uses for its own precondition.
	// Matched by the memory backend's
	// (existing.Status==Deleted||existing.DeletedAt!=nil) check.
	const q = `
		UPDATE msps
		SET status     = $2,
		    deleted_at = CASE WHEN $2 = 'deleted' THEN COALESCE(deleted_at, NOW()) ELSE deleted_at END
		WHERE id = $1::uuid AND status <> 'deleted' AND deleted_at IS NULL
		RETURNING ` + mspSelectColumns
	var out repository.MSP
	err := r.s.onPrimary(ctx, func(db pgxQuerier) error {
		var e error
		out, e = scanMSP(db.QueryRow(ctx, q, id, string(status)))
		return e
	})
	if errors.Is(err, pgx.ErrNoRows) {
		// Either the row does not exist, or it's already deleted.
		// Resolve via a separate SELECT so callers learn the precise
		// reason.
		var existing string
		scanErr := r.s.onPrimary(ctx, func(db pgxQuerier) error {
			return db.QueryRow(ctx,
				`SELECT status FROM msps WHERE id = $1::uuid`, id).Scan(&existing)
		})
		if scanErr != nil {
			if errors.Is(scanErr, pgx.ErrNoRows) {
				return repository.MSP{}, repository.ErrNotFound
			}
			return repository.MSP{}, fmt.Errorf("update msp status lookup: %w", scanErr)
		}
		return repository.MSP{}, repository.ErrForbidden
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
	// withSystem sets `sng.system_role='true'` on the transaction
	// so any RLS policy keyed off that GUC will permit the
	// cross-tenant cascade. Today the tenants table has no RLS
	// (migrations/015_msps.up.sql:125-129 — "enforced at the
	// application layer"), and msp_tenants is a top-level join
	// table with no per-tenant policy, so the cascade works
	// regardless. But round-21 of Devin Review on PR #42
	// (ANALYSIS_0005) correctly flagged that the cascade is brittle
	// against a future change that adds `FORCE ROW LEVEL SECURITY`
	// to either table: without a system context, the cascade
	// UPDATE/DELETE would silently match zero rows, the soft-delete
	// status flip would still land, and the denormalised
	// tenants.msp_id pointer would be left dangling at a
	// tombstoned MSP. Running inside withSystem future-proofs the
	// cascade against any such RLS migration without changing the
	// observable behaviour today, and matches the pattern used by
	// other cross-tenant background paths in this package (the
	// integration delivery worker's ListPending, the app_registry
	// CRUD, the apikey CRUD, and the webhook delivery worker all
	// run under withSystem for the same reason).
	return r.s.withSystem(ctx, func(tx pgx.Tx) error {
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
		// Explicit `updated_at = NOW()` on the tenants cascade.
		// Round-28 of Devin Review on PR #42 (ANALYSIS_0001)
		// flagged a pattern divergence within this file: both
		// AssignTenant (line ~709) and UnassignTenant (lines
		// ~726, ~760) write `updated_at = NOW()` explicitly when
		// they mutate the tenants.msp_id pointer, while this
		// Delete cascade relied on the `sng_set_updated_at`
		// BEFORE UPDATE trigger to fill it in. The memory backend
		// (internal/repository/memory/msp.go) ALSO sets
		// `t.UpdatedAt = r.s.clock()` explicitly on its Delete
		// cascade, so the trigger-dependent shape here was the
		// outlier across both backends + both binding-mutation
		// neighbours. Setting it explicitly here closes the
		// pattern gap, removes the silent dependency on a
		// schema-side trigger we don't own at this layer, and
		// keeps the audit story consistent: every write that
		// mutates `tenants.msp_id` also stamps `updated_at`
		// from the same statement.
		if _, err := tx.Exec(ctx, `UPDATE tenants SET msp_id = NULL, updated_at = NOW() WHERE msp_id = $1::uuid`, id); err != nil {
			return fmt.Errorf("cascade tenants.msp_id: %w", err)
		}
		return nil
	})
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
	// Run inside withSystem so the cross-tenant cascade
	// `UPDATE tenants SET msp_id = ...` is forward-proof against
	// any future migration adding `FORCE ROW LEVEL SECURITY` to the
	// tenants table. Today tenants has no RLS, so this is a no-op
	// in observable behaviour; the value is purely future-proofing
	// parity with Delete (which already runs under withSystem for
	// the same cascade — see internal/repository/postgres/msp.go
	// Delete and the round-21 ANALYSIS_0005 note). Round-24 of
	// Devin Review on PR #42 (ANALYSIS_0001) flagged the asymmetry
	// where AssignTenant + UnassignTenant + Delete all touch the
	// denormalised tenants.msp_id pointer but only Delete had the
	// system context: under future RLS on tenants the Assign /
	// Unassign cascades would silently match zero rows, leaving
	// the join table and the pointer drifted.
	var binding repository.MSPTenantBinding
	err := r.s.withSystem(ctx, func(tx pgx.Tx) error {
		b, err := r.assignTenantTx(ctx, tx, mspID, tenantID, relationship, actor)
		if err != nil {
			return err
		}
		binding = b
		return nil
	})
	if err != nil {
		return repository.MSPTenantBinding{}, err
	}
	return binding, nil
}

// assignTenantTx implements AssignTenant inside a single
// transaction. Split out so the outer wrapper can run it under
// withSystem (forward-proof RLS) without bloating that public
// method. All ErrNotFound / ErrForbidden / ErrInvalidArgument
// sentinels propagate through unchanged.
func (r *MSPRepository) assignTenantTx(
	ctx context.Context,
	tx pgx.Tx,
	mspID, tenantID uuid.UUID,
	relationship repository.MSPRelationship,
	actor *uuid.UUID,
) (repository.MSPTenantBinding, error) {
	// Pre-flight existence checks so the FK violation
	// distinguishes "msp missing" from "tenant missing" via a
	// clean ErrNotFound rather than a Postgres FK violation
	// error code surfaced upstream.
	//
	// The MSP lookup additionally filters soft-deletes so a
	// tombstoned row (`status='deleted'` AND `deleted_at IS NOT
	// NULL`) doesn't accept new bindings. Update() and
	// TransitionStatus() both guard against deleted rows already —
	// AssignTenant was the only writer in the MSP surface that
	// didn't. Round-20 of Devin Review on PR #42 (ANALYSIS_0002)
	// flagged this; the memory backend has the matching guard at
	// internal/repository/memory/msp.go (just before this comment's
	// mirrored note). We return `ErrForbidden` when the row exists
	// but is soft-deleted so callers can distinguish "msp never
	// existed" (ErrNotFound) from "msp tombstoned" (ErrForbidden)
	// — the latter is recoverable via Restore, the former is not.
	var (
		dummy      uuid.UUID
		mspStatus  string
		mspDeleted *time.Time
	)
	if err := tx.QueryRow(ctx,
		`SELECT id, status, deleted_at FROM msps WHERE id = $1::uuid`, mspID,
	).Scan(&dummy, &mspStatus, &mspDeleted); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return repository.MSPTenantBinding{}, repository.ErrNotFound
		}
		return repository.MSPTenantBinding{}, fmt.Errorf("lookup msp: %w", err)
	}
	if mspDeleted != nil || mspStatus == string(repository.MSPStatusDeleted) {
		return repository.MSPTenantBinding{}, repository.ErrForbidden
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

	// Capture the previous relationship (if any) before the upsert so
	// we can correctly cascade a downgrade away from `owner` to the
	// denormalised `tenants.msp_id` pointer below. Round-14 of Devin
	// Review on PR #42 (ANALYSIS_0003) flagged that without this
	// lookup an `AssignTenant(mspID, tenantID, co_manager)` after a
	// prior `owner` binding for the same pair would leave the join
	// table reading `co_manager` while the denormalised column still
	// pointed at this MSP — a cross-storage-site drift. The query
	// runs in the same transaction as the upsert + UPDATE, so the
	// (read prev, upsert, conditionally clear) sequence commits
	// atomically.
	var (
		prevRel string
		hadPrev bool
	)
	if err := tx.QueryRow(ctx,
		`SELECT relationship FROM msp_tenants WHERE msp_id = $1::uuid AND tenant_id = $2::uuid`,
		mspID, tenantID,
	).Scan(&prevRel); err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			return repository.MSPTenantBinding{}, fmt.Errorf("lookup prior binding: %w", err)
		}
	} else {
		hadPrev = true
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

	switch {
	case relationship == repository.MSPRelationshipOwner:
		if _, err := tx.Exec(ctx,
			`UPDATE tenants SET msp_id = $2::uuid, updated_at = NOW() WHERE id = $1::uuid`,
			tenantID, mspID,
		); err != nil {
			return repository.MSPTenantBinding{}, fmt.Errorf("set tenant owner: %w", err)
		}
	case hadPrev && prevRel == string(repository.MSPRelationshipOwner):
		// Downgrade: the same (msp, tenant) binding flipped from
		// owner to a non-owner relationship. Clear the
		// denormalised pointer if it still references this MSP so
		// the join table and `tenants.msp_id` stay consistent.
		// The `msp_id = $2::uuid` predicate scopes the clear to
		// rows still owned by this MSP — if some other MSP
		// owner-bound this tenant in between (unlikely under
		// normal flows; the partial UNIQUE index would block it
		// for owner relationships) we must not stomp their
		// pointer.
		if _, err := tx.Exec(ctx,
			`UPDATE tenants SET msp_id = NULL, updated_at = NOW() WHERE id = $1::uuid AND msp_id = $2::uuid`,
			tenantID, mspID,
		); err != nil {
			return repository.MSPTenantBinding{}, fmt.Errorf("clear stale owner pointer: %w", err)
		}
	}

	return binding, nil
}

// UnassignTenant removes the (msp, tenant) binding. If the binding
// was an owner, the denormalised tenants.msp_id is cleared in the
// same transaction.
//
// Runs inside withSystem for the same forward-proofing argument as
// AssignTenant + Delete: the `UPDATE tenants SET msp_id = NULL`
// cascade must continue to work under any future migration that
// adds RLS to the tenants table. Round-24 of Devin Review on
// PR #42 (ANALYSIS_0001).
func (r *MSPRepository) UnassignTenant(ctx context.Context, mspID, tenantID uuid.UUID) error {
	return r.s.withSystem(ctx, func(tx pgx.Tx) error {
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
		return nil
	})
}

func (r *MSPRepository) ListTenants(ctx context.Context, mspID uuid.UUID, page repository.Page) (repository.PageResult[repository.MSPTenantBinding], error) {
	page = page.Normalize()
	cur, err := decodeCursor(page.After)
	if err != nil {
		return repository.PageResult[repository.MSPTenantBinding]{}, repository.ErrInvalidArgument
	}
	// Mirror the ASC/DESC branches from List above so a caller
	// passing SortAsc gets honest ascending ordering at the
	// Postgres backend instead of silently receiving DESC. The
	// memory backend already respects page.Order via
	// page.Normalize() + sortByCreatedAtDesc/Asc; the previous
	// single-branch DESC query here created a latent backend
	// inconsistency that would only surface if a future caller
	// (e.g. an audit-trail UI rendering oldest-first) flipped
	// the param.
	var q string
	args := []any{mspID, cur.T, cur.I, page.Limit}
	switch page.Order {
	case repository.SortAsc:
		q = `
		SELECT msp_id, tenant_id, relationship, created_at, created_by
		FROM msp_tenants
		WHERE msp_id = $1::uuid
		  AND ($2::timestamptz IS NULL OR (created_at, tenant_id) > ($2::timestamptz, $3::uuid))
		ORDER BY created_at ASC, tenant_id ASC
		LIMIT $4`
	default:
		q = `
		SELECT msp_id, tenant_id, relationship, created_at, created_by
		FROM msp_tenants
		WHERE msp_id = $1::uuid
		  AND ($2::timestamptz IS NULL OR (created_at, tenant_id) < ($2::timestamptz, $3::uuid))
		ORDER BY created_at DESC, tenant_id DESC
		LIMIT $4`
	}
	if cur.T.IsZero() {
		args[1] = nil
	}
	out := make([]repository.MSPTenantBinding, 0, page.Limit)
	if err := r.s.onPrimary(ctx, func(db pgxQuerier) error {
		rows, e := db.Query(ctx, q, args...)
		if e != nil {
			return fmt.Errorf("list msp tenants: %w", e)
		}
		defer rows.Close()
		for rows.Next() {
			var (
				b         repository.MSPTenantBinding
				createdBy nullableUUID
			)
			if e := rows.Scan(&b.MSPID, &b.TenantID, &b.Relationship, &b.CreatedAt, &createdBy); e != nil {
				return fmt.Errorf("scan binding: %w", e)
			}
			if createdBy.Valid {
				v := createdBy.ID
				b.CreatedBy = &v
			}
			out = append(out, b)
		}
		if e := rows.Err(); e != nil {
			return fmt.Errorf("iterate bindings: %w", e)
		}
		return nil
	}); err != nil {
		return repository.PageResult[repository.MSPTenantBinding]{}, err
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
	out := make([]repository.MSPTenantBinding, 0)
	if err := r.s.onPrimary(ctx, func(db pgxQuerier) error {
		rows, e := db.Query(ctx, q, tenantID)
		if e != nil {
			return fmt.Errorf("list bindings: %w", e)
		}
		defer rows.Close()
		for rows.Next() {
			var (
				b         repository.MSPTenantBinding
				createdBy nullableUUID
			)
			if e := rows.Scan(&b.MSPID, &b.TenantID, &b.Relationship, &b.CreatedAt, &createdBy); e != nil {
				return fmt.Errorf("scan binding: %w", e)
			}
			if createdBy.Valid {
				v := createdBy.ID
				b.CreatedBy = &v
			}
			out = append(out, b)
		}
		if e := rows.Err(); e != nil {
			return fmt.Errorf("iterate bindings: %w", e)
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return out, nil
}
