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

// tenantMigrationColumns is the canonical SELECT/RETURNING column list,
// kept in one place so every query and the single scan helper stay in
// lock-step.
const tenantMigrationColumns = `id, tenant_id, source_region, target_region,
	state, dual_read, checkpoint, detail, attempts,
	created_at, updated_at, started_at, completed_at`

// TenantMigrationRepository owns the tenant_migrations table (migration
// 059): the resumable cross-region migration state machine. Tenant
// reads/writes run inside withTenant/withTenantRO so the `sng.tenant_id`
// GUC scopes RLS to the caller's tenant; ListResumable runs inside
// withSystem so the background resume runner can scan across tenants
// via the system-role policy.
type TenantMigrationRepository struct{ s *Store }

func (r *TenantMigrationRepository) Create(ctx context.Context, tenantID uuid.UUID, m repository.TenantMigration) (repository.TenantMigration, error) {
	if tenantID == uuid.Nil || m.SourceRegion == "" || m.TargetRegion == "" || m.SourceRegion == m.TargetRegion {
		return repository.TenantMigration{}, repository.ErrInvalidArgument
	}
	state := m.State
	if state == "" {
		state = repository.MigrationStatePending
	}
	checkpoint := m.Checkpoint
	if len(checkpoint) == 0 {
		checkpoint = json.RawMessage(`{}`)
	}
	var out repository.TenantMigration
	err := r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		const q = `
			INSERT INTO tenant_migrations
				(tenant_id, source_region, target_region, state,
				 dual_read, checkpoint, detail, attempts,
				 started_at, completed_at)
			VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, $8, $9, $10)
			RETURNING ` + tenantMigrationColumns
		row := tx.QueryRow(ctx, q,
			tenantID, m.SourceRegion, m.TargetRegion, state,
			m.DualRead, []byte(checkpoint), m.Detail, m.Attempts,
			m.StartedAt, m.CompletedAt)
		return scanTenantMigration(row, &out)
	})
	if err != nil {
		// The partial unique index uq_tenant_migrations_active surfaces
		// a second in-flight migration for the tenant as a uniqueness
		// violation; translate to the repository's conflict sentinel.
		if isUniqueViolation(err) {
			return repository.TenantMigration{}, repository.ErrConflict
		}
		return repository.TenantMigration{}, err
	}
	return out, nil
}

func (r *TenantMigrationRepository) Get(ctx context.Context, tenantID, id uuid.UUID) (repository.TenantMigration, error) {
	if tenantID == uuid.Nil || id == uuid.Nil {
		return repository.TenantMigration{}, repository.ErrInvalidArgument
	}
	var out repository.TenantMigration
	err := r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		const q = `SELECT ` + tenantMigrationColumns + `
			FROM tenant_migrations WHERE id = $1::uuid`
		return scanTenantMigration(tx.QueryRow(ctx, q, id), &out)
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return repository.TenantMigration{}, repository.ErrNotFound
		}
		return repository.TenantMigration{}, err
	}
	return out, nil
}

func (r *TenantMigrationRepository) GetActive(ctx context.Context, tenantID uuid.UUID) (repository.TenantMigration, error) {
	if tenantID == uuid.Nil {
		return repository.TenantMigration{}, repository.ErrInvalidArgument
	}
	var out repository.TenantMigration
	err := r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		const q = `SELECT ` + tenantMigrationColumns + `
			FROM tenant_migrations
			WHERE state NOT IN ('completed', 'rolled_back', 'failed')
			ORDER BY created_at DESC, id
			LIMIT 1`
		return scanTenantMigration(tx.QueryRow(ctx, q), &out)
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return repository.TenantMigration{}, repository.ErrNotFound
		}
		return repository.TenantMigration{}, err
	}
	return out, nil
}

func (r *TenantMigrationRepository) Latest(ctx context.Context, tenantID uuid.UUID) (repository.TenantMigration, error) {
	if tenantID == uuid.Nil {
		return repository.TenantMigration{}, repository.ErrInvalidArgument
	}
	var out repository.TenantMigration
	err := r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		const q = `SELECT ` + tenantMigrationColumns + `
			FROM tenant_migrations
			ORDER BY created_at DESC, id
			LIMIT 1`
		return scanTenantMigration(tx.QueryRow(ctx, q), &out)
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return repository.TenantMigration{}, repository.ErrNotFound
		}
		return repository.TenantMigration{}, err
	}
	return out, nil
}

func (r *TenantMigrationRepository) Update(ctx context.Context, tenantID uuid.UUID, m repository.TenantMigration) (repository.TenantMigration, error) {
	if tenantID == uuid.Nil || m.ID == uuid.Nil {
		return repository.TenantMigration{}, repository.ErrInvalidArgument
	}
	checkpoint := m.Checkpoint
	if len(checkpoint) == 0 {
		checkpoint = json.RawMessage(`{}`)
	}
	var out repository.TenantMigration
	err := r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		// updated_at is bumped by the tenant_migrations_set_updated_at
		// trigger, so it is deliberately not in the SET list.
		const q = `
			UPDATE tenant_migrations SET
				state = $2,
				dual_read = $3,
				checkpoint = $4,
				detail = $5,
				attempts = $6,
				started_at = $7,
				completed_at = $8
			WHERE id = $1::uuid
			RETURNING ` + tenantMigrationColumns
		row := tx.QueryRow(ctx, q,
			m.ID, m.State, m.DualRead, []byte(checkpoint),
			m.Detail, m.Attempts, m.StartedAt, m.CompletedAt)
		return scanTenantMigration(row, &out)
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return repository.TenantMigration{}, repository.ErrNotFound
		}
		if isUniqueViolation(err) {
			return repository.TenantMigration{}, repository.ErrConflict
		}
		return repository.TenantMigration{}, err
	}
	return out, nil
}

func (r *TenantMigrationRepository) ListResumable(ctx context.Context) ([]repository.TenantMigration, error) {
	var out []repository.TenantMigration
	err := r.s.withSystem(ctx, func(tx pgx.Tx) error {
		const q = `SELECT ` + tenantMigrationColumns + `
			FROM tenant_migrations
			WHERE state NOT IN ('completed', 'rolled_back', 'failed')
			ORDER BY updated_at ASC, id`
		rows, err := tx.Query(ctx, q)
		if err != nil {
			return fmt.Errorf("query tenant_migrations: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var m repository.TenantMigration
			if err := scanTenantMigration(rows, &m); err != nil {
				return fmt.Errorf("scan tenant_migrations: %w", err)
			}
			out = append(out, m)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// scanTenantMigration scans a single tenant_migrations row, in
// tenantMigrationColumns order, into m. The nullable started_at /
// completed_at columns are scanned through deletedAtScan and projected
// into *time.Time; checkpoint (jsonb) is normalized so an absent/`null`
// payload becomes the `{}` object the rest of the stack expects.
func scanTenantMigration(row pgx.Row, m *repository.TenantMigration) error {
	var (
		checkpoint  []byte
		startedAt   deletedAtScan
		completedAt deletedAtScan
	)
	if err := row.Scan(
		&m.ID, &m.TenantID, &m.SourceRegion, &m.TargetRegion,
		&m.State, &m.DualRead, &checkpoint, &m.Detail, &m.Attempts,
		&m.CreatedAt, &m.UpdatedAt, &startedAt, &completedAt,
	); err != nil {
		return err
	}
	if len(checkpoint) == 0 || isJSONNullLiteral(checkpoint) {
		m.Checkpoint = json.RawMessage(`{}`)
	} else {
		m.Checkpoint = json.RawMessage(checkpoint)
	}
	if startedAt.Valid {
		t := startedAt.Time
		m.StartedAt = &t
	}
	if completedAt.Valid {
		t := completedAt.Time
		m.CompletedAt = &t
	}
	return nil
}
