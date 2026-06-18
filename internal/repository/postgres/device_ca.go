package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// DeviceCARepository owns the device_cas table: the per-tenant device
// certificate authority that signs enrollment certificates.
type DeviceCARepository struct{ s *Store }

var _ repository.DeviceCARepository = (*DeviceCARepository)(nil)

func (r *DeviceCARepository) GetCA(ctx context.Context, tenantID uuid.UUID) (repository.DeviceCA, error) {
	if tenantID == uuid.Nil {
		return repository.DeviceCA{}, repository.ErrInvalidArgument
	}
	var out repository.DeviceCA
	err := r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		const q = `
			SELECT tenant_id, cert_pem, private_key, created_at
			FROM device_cas
			WHERE tenant_id = $1::uuid
			LIMIT 1`
		row := tx.QueryRow(ctx, q, tenantID)
		if err := row.Scan(&out.TenantID, &out.CertPEM, &out.PrivateKeySealed, &out.CreatedAt); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return repository.ErrNotFound
			}
			return fmt.Errorf("select device_ca: %w", err)
		}
		return nil
	})
	return out, err
}

func (r *DeviceCARepository) CreateCA(ctx context.Context, tenantID uuid.UUID, ca repository.DeviceCA) (repository.DeviceCA, error) {
	if tenantID == uuid.Nil {
		return repository.DeviceCA{}, repository.ErrInvalidArgument
	}
	if ca.CertPEM == "" || len(ca.PrivateKeySealed) == 0 {
		return repository.DeviceCA{}, repository.ErrInvalidArgument
	}
	var out repository.DeviceCA
	err := r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		const q = `
			INSERT INTO device_cas (tenant_id, cert_pem, private_key)
			VALUES ($1::uuid, $2, $3)
			RETURNING tenant_id, cert_pem, private_key, created_at`
		row := tx.QueryRow(ctx, q, tenantID, ca.CertPEM, ca.PrivateKeySealed)
		if err := row.Scan(&out.TenantID, &out.CertPEM, &out.PrivateKeySealed, &out.CreatedAt); err != nil {
			if isUniqueViolation(err) {
				return repository.ErrConflict
			}
			return fmt.Errorf("insert device_ca: %w", err)
		}
		return nil
	})
	return out, err
}
