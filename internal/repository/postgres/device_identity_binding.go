package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// DeviceIdentityBindingRepository owns the device_identity_bindings
// table (migration 044): the device ↔ iam-core user mapping. Every
// query runs inside withTenant/withTenantRO so the `sng.tenant_id` GUC
// is set and RLS scopes the rows to the caller's tenant.
type DeviceIdentityBindingRepository struct{ s *Store }

var _ repository.DeviceIdentityBindingRepository = (*DeviceIdentityBindingRepository)(nil)

func (r *DeviceIdentityBindingRepository) Upsert(ctx context.Context, tenantID uuid.UUID, b repository.DeviceIdentityBinding) (repository.DeviceIdentityBinding, error) {
	if tenantID == uuid.Nil || b.DeviceID == uuid.Nil || b.IAMCoreUserID == "" || b.Ed25519PublicKey == "" {
		return repository.DeviceIdentityBinding{}, repository.ErrInvalidArgument
	}
	var out repository.DeviceIdentityBinding
	err := r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		const q = `
			INSERT INTO device_identity_bindings
				(tenant_id, device_id, iam_core_user_id, ed25519_public_key)
			VALUES ($1::uuid, $2::uuid, $3, $4)
			ON CONFLICT (tenant_id, device_id)
			DO UPDATE SET iam_core_user_id   = EXCLUDED.iam_core_user_id,
			              ed25519_public_key = EXCLUDED.ed25519_public_key,
			              updated_at         = NOW()
			RETURNING id, tenant_id, device_id, iam_core_user_id,
			          ed25519_public_key, created_at, updated_at`
		row := tx.QueryRow(ctx, q, tenantID, b.DeviceID, b.IAMCoreUserID, b.Ed25519PublicKey)
		return scanBinding(row, &out)
	})
	if err != nil {
		return repository.DeviceIdentityBinding{}, err
	}
	return out, nil
}

func (r *DeviceIdentityBindingRepository) GetByDevice(ctx context.Context, tenantID, deviceID uuid.UUID) (repository.DeviceIdentityBinding, error) {
	var out repository.DeviceIdentityBinding
	err := r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		const q = `
			SELECT id, tenant_id, device_id, iam_core_user_id,
			       ed25519_public_key, created_at, updated_at
			FROM device_identity_bindings
			WHERE device_id = $1::uuid`
		row := tx.QueryRow(ctx, q, deviceID)
		if err := scanBinding(row, &out); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return repository.ErrNotFound
			}
			return err
		}
		return nil
	})
	if err != nil {
		return repository.DeviceIdentityBinding{}, err
	}
	return out, nil
}

func (r *DeviceIdentityBindingRepository) ListByIAMCoreUser(ctx context.Context, tenantID uuid.UUID, iamCoreUserID string) ([]repository.DeviceIdentityBinding, error) {
	var out []repository.DeviceIdentityBinding
	err := r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		const q = `
			SELECT id, tenant_id, device_id, iam_core_user_id,
			       ed25519_public_key, created_at, updated_at
			FROM device_identity_bindings
			WHERE iam_core_user_id = $1
			ORDER BY device_id`
		rows, err := tx.Query(ctx, q, iamCoreUserID)
		if err != nil {
			return fmt.Errorf("query device_identity_bindings: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var b repository.DeviceIdentityBinding
			if err := rows.Scan(&b.ID, &b.TenantID, &b.DeviceID, &b.IAMCoreUserID,
				&b.Ed25519PublicKey, &b.CreatedAt, &b.UpdatedAt); err != nil {
				return fmt.Errorf("scan device_identity_binding: %w", err)
			}
			out = append(out, b)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (r *DeviceIdentityBindingRepository) DeleteByDevice(ctx context.Context, tenantID, deviceID uuid.UUID) error {
	return r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		// Idempotent: a missing row is not an error.
		_, err := tx.Exec(ctx, `DELETE FROM device_identity_bindings WHERE device_id = $1::uuid`, deviceID)
		if err != nil {
			return fmt.Errorf("delete device_identity_binding: %w", err)
		}
		return nil
	})
}

// scanBinding scans a single device_identity_bindings row in column
// order into b.
func scanBinding(row pgx.Row, b *repository.DeviceIdentityBinding) error {
	return row.Scan(&b.ID, &b.TenantID, &b.DeviceID, &b.IAMCoreUserID,
		&b.Ed25519PublicKey, &b.CreatedAt, &b.UpdatedAt)
}
