// Package postgres — baseline.go is the postgres implementation
// of repository.BaselineModelRepository.
//
// The hot path is Upsert under optimistic concurrency on
// `version`. INSERTs stamp version=1; UPDATEs gate on
// `WHERE version = $old_version` and translate a zero-row
// affected count into ErrConflict so the service layer retries
// the load+fold+write cycle instead of silently losing one of
// two concurrent observers.
package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// BaselineModelRepository owns the baseline_models table.
type BaselineModelRepository struct{ s *Store }

const baselineModelSelectColumns = `
id, tenant_id, dimension, window_seconds,
samples, mean, m2, ewma, ewma_var, alpha, z_threshold,
COALESCE(last_observed_at, 'epoch'::timestamptz), last_updated_at, created_at, version
`

// scanBaselineModel walks one row out of a pgx.Row into the typed
// struct. last_observed_at is nullable; we materialise NULL as
// zero-value Time so the cold-start callers get an explicit
// IsZero() check.
func scanBaselineModel(row pgx.Row) (repository.BaselineModel, error) {
	var (
		m            repository.BaselineModel
		lastObserved time.Time
	)
	if err := row.Scan(
		&m.ID, &m.TenantID, &m.Dimension, &m.WindowSeconds,
		&m.Samples, &m.Mean, &m.M2, &m.EWMA, &m.EWMAVar,
		&m.Alpha, &m.ZThreshold,
		&lastObserved, &m.LastUpdatedAt, &m.CreatedAt, &m.Version,
	); err != nil {
		return repository.BaselineModel{}, err
	}
	if !lastObserved.IsZero() && lastObserved.Year() > 1970 {
		m.LastObservedAt = lastObserved.UTC()
	}
	return m, nil
}

// GetForDimension returns the model for the supplied tuple.
// ErrNotFound when no row exists (caller falls back to a
// cold-start BaselineModel).
func (r *BaselineModelRepository) GetForDimension(
	ctx context.Context,
	tenantID uuid.UUID,
	dimension string,
	windowSeconds int,
) (repository.BaselineModel, error) {
	if tenantID == uuid.Nil || dimension == "" || windowSeconds <= 0 {
		return repository.BaselineModel{}, repository.ErrInvalidArgument
	}
	var out repository.BaselineModel
	err := r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		const q = `SELECT ` + baselineModelSelectColumns + `
		FROM baseline_models
		WHERE tenant_id = $1::uuid
		  AND dimension = $2
		  AND window_seconds = $3`
		row := tx.QueryRow(ctx, q, tenantID, dimension, windowSeconds)
		m, err := scanBaselineModel(row)
		if errors.Is(err, pgx.ErrNoRows) {
			return repository.ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("select baseline_models: %w", err)
		}
		out = m
		return nil
	})
	return out, err
}

// Upsert INSERTs on cold-start or UPDATEs under optimistic
// concurrency. The UPDATE arm gates on `WHERE version =
// $old_version` and translates zero rows affected into
// ErrConflict.
func (r *BaselineModelRepository) Upsert(
	ctx context.Context,
	tenantID uuid.UUID,
	m repository.BaselineModel,
) (repository.BaselineModel, error) {
	if tenantID == uuid.Nil || m.Dimension == "" || m.WindowSeconds <= 0 {
		return repository.BaselineModel{}, repository.ErrInvalidArgument
	}
	if m.Alpha <= 0 || m.Alpha > 1 {
		return repository.BaselineModel{}, repository.ErrInvalidArgument
	}
	if m.ZThreshold <= 0 {
		return repository.BaselineModel{}, repository.ErrInvalidArgument
	}
	var out repository.BaselineModel
	err := r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		// Try UPDATE first when a non-zero Version is
		// supplied. Version=0 means "I have not observed
		// any row yet; do an INSERT" — the cold-start path.
		if m.Version > 0 {
			const upd = `
UPDATE baseline_models
SET samples           = $4,
    mean              = $5,
    m2                = $6,
    ewma              = $7,
    ewma_var          = $8,
    alpha             = $9,
    z_threshold       = $10,
    last_observed_at  = NULLIF($11::timestamptz, 'epoch'::timestamptz),
    last_updated_at   = NOW(),
    version           = version + 1
WHERE tenant_id    = $1::uuid
  AND dimension    = $2
  AND window_seconds = $3
  AND version      = $12
RETURNING ` + baselineModelSelectColumns
			var lastObs time.Time
			if !m.LastObservedAt.IsZero() {
				lastObs = m.LastObservedAt.UTC()
			}
			row := tx.QueryRow(ctx, upd,
				tenantID, m.Dimension, m.WindowSeconds,
				m.Samples, m.Mean, m.M2, m.EWMA, m.EWMAVar,
				m.Alpha, m.ZThreshold, lastObs, m.Version,
			)
			scanned, err := scanBaselineModel(row)
			if errors.Is(err, pgx.ErrNoRows) {
				// No row was updated — either the model
				// vanished (unlikely under FK) or the
				// version moved under us. The latter is
				// the optimistic-conflict case.
				return repository.ErrConflict
			}
			if err != nil {
				if isCheckViolation(err) {
					return repository.ErrInvalidArgument
				}
				return fmt.Errorf("update baseline_models: %w", err)
			}
			out = scanned
			return nil
		}
		// INSERT path. ON CONFLICT (tenant_id, dimension,
		// window_seconds) means we tried to cold-start a
		// model that already exists — surface as ErrConflict
		// so the caller re-loads and retries Upsert with a
		// proper version.
		if m.ID == uuid.Nil {
			m.ID = uuid.New()
		}
		const ins = `
INSERT INTO baseline_models
    (id, tenant_id, dimension, window_seconds,
     samples, mean, m2, ewma, ewma_var, alpha, z_threshold,
     last_observed_at, version)
VALUES
    ($1::uuid, $2::uuid, $3, $4,
     $5, $6, $7, $8, $9, $10, $11,
     NULLIF($12::timestamptz, 'epoch'::timestamptz), 1)
RETURNING ` + baselineModelSelectColumns
		var lastObs time.Time
		if !m.LastObservedAt.IsZero() {
			lastObs = m.LastObservedAt.UTC()
		}
		row := tx.QueryRow(ctx, ins,
			m.ID, tenantID, m.Dimension, m.WindowSeconds,
			m.Samples, m.Mean, m.M2, m.EWMA, m.EWMAVar,
			m.Alpha, m.ZThreshold, lastObs,
		)
		scanned, err := scanBaselineModel(row)
		if err != nil {
			if isUniqueViolation(err) {
				return repository.ErrConflict
			}
			if isCheckViolation(err) {
				return repository.ErrInvalidArgument
			}
			if isForeignKeyViolation(err) {
				return repository.ErrNotFound
			}
			return fmt.Errorf("insert baseline_models: %w", err)
		}
		out = scanned
		return nil
	})
	return out, err
}

// List enumerates models in LastUpdatedAt-DESC order. The cursor
// uses (last_updated_at, id) so a paged list stays stable across
// hot-write workloads.
func (r *BaselineModelRepository) List(
	ctx context.Context,
	tenantID uuid.UUID,
	page repository.Page,
) (repository.PageResult[repository.BaselineModel], error) {
	if tenantID == uuid.Nil {
		return repository.PageResult[repository.BaselineModel]{}, repository.ErrInvalidArgument
	}
	page = page.Normalize()
	cur, err := decodeCursor(page.After)
	if err != nil {
		return repository.PageResult[repository.BaselineModel]{}, repository.ErrInvalidArgument
	}
	res := repository.PageResult[repository.BaselineModel]{}
	err = r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		var cmp string
		var dir string
		if page.Order == repository.SortAsc {
			cmp, dir = ">", "ASC"
		} else {
			cmp, dir = "<", "DESC"
		}
		var args = []any{nil, nil, page.Limit}
		if !cur.T.IsZero() || cur.I != uuid.Nil {
			args[0] = cur.T
			args[1] = cur.I
		}
		q := fmt.Sprintf(`
SELECT %s
FROM baseline_models
WHERE ($1::timestamptz IS NULL OR (last_updated_at, id) %s ($1::timestamptz, $2::uuid))
ORDER BY last_updated_at %s, id %s
LIMIT $3
`, baselineModelSelectColumns, cmp, dir, dir)
		rows, qerr := tx.Query(ctx, q, args...)
		if qerr != nil {
			return fmt.Errorf("list baseline_models: %w", qerr)
		}
		defer rows.Close()
		items := make([]repository.BaselineModel, 0, page.Limit)
		for rows.Next() {
			m, err := scanBaselineModel(rows)
			if err != nil {
				return fmt.Errorf("scan baseline_models: %w", err)
			}
			items = append(items, m)
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("iterate baseline_models: %w", err)
		}
		res.Items = items
		if len(items) == page.Limit && len(items) > 0 {
			last := items[len(items)-1]
			res.NextCursor = encodeCursor(pageCursor{T: last.LastUpdatedAt, I: last.ID})
		}
		return nil
	})
	return res, err
}

// UpdateThreshold patches the ZThreshold in-place. The Welford
// / EWMA state is untouched; the version is bumped so the next
// concurrent Upsert from the Engine will hit a conflict (the
// service layer retries cleanly).
func (r *BaselineModelRepository) UpdateThreshold(
	ctx context.Context,
	tenantID uuid.UUID,
	dimension string,
	windowSeconds int,
	zThreshold float64,
) (repository.BaselineModel, error) {
	if tenantID == uuid.Nil || dimension == "" || windowSeconds <= 0 || zThreshold <= 0 {
		return repository.BaselineModel{}, repository.ErrInvalidArgument
	}
	var out repository.BaselineModel
	err := r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		const q = `
UPDATE baseline_models
SET z_threshold     = $4,
    last_updated_at = NOW(),
    version         = version + 1
WHERE tenant_id      = $1::uuid
  AND dimension      = $2
  AND window_seconds = $3
RETURNING ` + baselineModelSelectColumns
		row := tx.QueryRow(ctx, q, tenantID, dimension, windowSeconds, zThreshold)
		scanned, err := scanBaselineModel(row)
		if errors.Is(err, pgx.ErrNoRows) {
			return repository.ErrNotFound
		}
		if err != nil {
			if isCheckViolation(err) {
				return repository.ErrInvalidArgument
			}
			return fmt.Errorf("update baseline_models threshold: %w", err)
		}
		out = scanned
		return nil
	})
	return out, err
}
