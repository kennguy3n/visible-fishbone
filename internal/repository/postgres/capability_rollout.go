package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/service/rollout"
)

// capabilityRolloutColumns is the canonical column order shared by every
// SELECT/RETURNING in this file, so the scan helper stays in lock-step
// with the queries.
const capabilityRolloutColumns = `
	tenant_id, capability, state, reason, updated_by, created_at, updated_at`

// CapabilityRolloutRepository owns the capability_rollout table
// (migration 066): the per-tenant, per-capability staged-enablement
// state for the platform's default-OFF gates. Every query runs inside
// withTenant/withTenantRO so the `sng.tenant_id` GUC is set and RLS
// scopes the rows to the caller's tenant.
//
// It implements rollout.Repository (declared in the service package),
// so the dependency points inward and this file is the only place that
// knows both the SQL schema and the domain type.
type CapabilityRolloutRepository struct{ s *Store }

// NewCapabilityRolloutRepository binds the Store to the
// rollout.Repository interface.
func NewCapabilityRolloutRepository(s *Store) *CapabilityRolloutRepository {
	return &CapabilityRolloutRepository{s: s}
}

var _ rollout.Repository = (*CapabilityRolloutRepository)(nil)

// Get returns the stored record for (tenant, capability), or
// repository.ErrNotFound when the tenant has never transitioned it.
func (r *CapabilityRolloutRepository) Get(ctx context.Context, tenantID uuid.UUID, c rollout.Capability) (rollout.Record, error) {
	if tenantID == uuid.Nil || !c.Valid() {
		return rollout.Record{}, repository.ErrInvalidArgument
	}
	var out rollout.Record
	err := r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		const q = `SELECT ` + capabilityRolloutColumns + `
			FROM capability_rollout
			WHERE tenant_id = $1::uuid AND capability = $2`
		row := tx.QueryRow(ctx, q, tenantID, string(c))
		scanned, scanErr := scanCapabilityRollout(row)
		if scanErr != nil {
			if errors.Is(scanErr, pgx.ErrNoRows) {
				return repository.ErrNotFound
			}
			return fmt.Errorf("get capability_rollout: %w", scanErr)
		}
		out = scanned
		return nil
	})
	if err != nil {
		return rollout.Record{}, err
	}
	return out, nil
}

// List returns every stored record for the tenant, in a deterministic
// capability order.
func (r *CapabilityRolloutRepository) List(ctx context.Context, tenantID uuid.UUID) ([]rollout.Record, error) {
	if tenantID == uuid.Nil {
		return nil, repository.ErrInvalidArgument
	}
	out := make([]rollout.Record, 0)
	err := r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		const q = `SELECT ` + capabilityRolloutColumns + `
			FROM capability_rollout
			WHERE tenant_id = $1::uuid
			ORDER BY capability`
		rows, err := tx.Query(ctx, q, tenantID)
		if err != nil {
			return fmt.Errorf("query capability_rollout: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			rec, scanErr := scanCapabilityRolloutRows(rows)
			if scanErr != nil {
				return fmt.Errorf("scan capability_rollout: %w", scanErr)
			}
			out = append(out, rec)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Upsert inserts or updates the (tenant, capability) row and returns the
// stored record. The state CHECK and tenant FK are enforced by the
// schema; an invalid state surfaces as a write error.
func (r *CapabilityRolloutRepository) Upsert(ctx context.Context, tenantID uuid.UUID, rec rollout.Record) (rollout.Record, error) {
	if tenantID == uuid.Nil || !rec.Capability.Valid() || !rec.State.Valid() {
		return rollout.Record{}, repository.ErrInvalidArgument
	}
	if rec.TenantID != uuid.Nil && rec.TenantID != tenantID {
		return rollout.Record{}, repository.ErrInvalidArgument
	}
	var out rollout.Record
	err := r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		const q = `
			INSERT INTO capability_rollout
				(tenant_id, capability, state, reason, updated_by)
			VALUES ($1::uuid, $2, $3, $4, $5)
			ON CONFLICT (tenant_id, capability) DO UPDATE SET
				state      = EXCLUDED.state,
				reason     = EXCLUDED.reason,
				updated_by = EXCLUDED.updated_by
			RETURNING ` + capabilityRolloutColumns
		row := tx.QueryRow(ctx, q,
			tenantID, string(rec.Capability), string(rec.State), rec.Reason, rec.UpdatedBy)
		scanned, scanErr := scanCapabilityRollout(row)
		if scanErr != nil {
			return fmt.Errorf("upsert capability_rollout: %w", scanErr)
		}
		out = scanned
		return nil
	})
	if err != nil {
		return rollout.Record{}, err
	}
	return out, nil
}

// rowScanner is the minimal surface shared by pgx.Row and pgx.Rows so a
// single scan helper serves both the single-row and multi-row paths.
type rolloutRowScanner interface {
	Scan(dest ...any) error
}

func scanCapabilityRollout(row pgx.Row) (rollout.Record, error) {
	return scanCapabilityRolloutFrom(row)
}

func scanCapabilityRolloutRows(rows pgx.Rows) (rollout.Record, error) {
	return scanCapabilityRolloutFrom(rows)
}

func scanCapabilityRolloutFrom(sc rolloutRowScanner) (rollout.Record, error) {
	var (
		rec        rollout.Record
		capability string
		state      string
	)
	if err := sc.Scan(
		&rec.TenantID,
		&capability,
		&state,
		&rec.Reason,
		&rec.UpdatedBy,
		&rec.CreatedAt,
		&rec.UpdatedAt,
	); err != nil {
		return rollout.Record{}, err
	}
	rec.Capability = rollout.Capability(capability)
	rec.State = rollout.State(state)
	return rec, nil
}
