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

// DeviceEnrollmentRepository owns the device_enrollments and
// device_certificates tables.
type DeviceEnrollmentRepository struct{ s *Store }

func (r *DeviceEnrollmentRepository) CreateEnrollment(ctx context.Context, tenantID uuid.UUID, e repository.DeviceEnrollment) (repository.DeviceEnrollment, error) {
	if tenantID == uuid.Nil || e.DeviceID == uuid.Nil {
		return repository.DeviceEnrollment{}, repository.ErrInvalidArgument
	}
	var out repository.DeviceEnrollment
	err := r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		const q = `
			INSERT INTO device_enrollments (device_id, tenant_id, public_key, status, enrolled_at)
			VALUES ($1::uuid, $2::uuid, $3, $4, $5)
			ON CONFLICT (device_id, tenant_id)
			DO UPDATE SET public_key   = EXCLUDED.public_key,
			              status       = EXCLUDED.status,
			              enrolled_at  = EXCLUDED.enrolled_at,
			              revoked_at   = NULL,
			              last_cert_issued_at = NULL
			WHERE device_enrollments.status = 'revoked'
			RETURNING device_id, tenant_id, public_key, status, enrolled_at,
			          last_cert_issued_at, revoked_at`
		row := tx.QueryRow(ctx, q,
			e.DeviceID, tenantID, e.PublicKey, e.Status, e.EnrolledAt,
		)
		var enrolled deletedAtScan
		var lastCert deletedAtScan
		var revoked deletedAtScan
		if err := row.Scan(
			&out.DeviceID, &out.TenantID, &out.PublicKey, &out.Status,
			&enrolled, &lastCert, &revoked,
		); err != nil {
			if isUniqueViolation(err) || errors.Is(err, pgx.ErrNoRows) {
				return repository.ErrConflict
			}
			return fmt.Errorf("insert device_enrollment: %w", err)
		}
		out.EnrolledAt = enrolled.Time
		if lastCert.Valid {
			t := lastCert.Time
			out.LastCertIssuedAt = &t
		}
		if revoked.Valid {
			t := revoked.Time
			out.RevokedAt = &t
		}
		return nil
	})
	return out, err
}

func (r *DeviceEnrollmentRepository) GetEnrollment(ctx context.Context, tenantID uuid.UUID, deviceID uuid.UUID) (repository.DeviceEnrollment, error) {
	var out repository.DeviceEnrollment
	err := r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		const q = `
			SELECT device_id, tenant_id, public_key, status, enrolled_at,
			       last_cert_issued_at, revoked_at
			FROM device_enrollments
			WHERE device_id = $1::uuid AND status != 'revoked'
			LIMIT 1`
		row := tx.QueryRow(ctx, q, deviceID)
		var enrolled deletedAtScan
		var lastCert deletedAtScan
		var revoked deletedAtScan
		if err := row.Scan(
			&out.DeviceID, &out.TenantID, &out.PublicKey, &out.Status,
			&enrolled, &lastCert, &revoked,
		); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return repository.ErrNotFound
			}
			return fmt.Errorf("select device_enrollment: %w", err)
		}
		out.EnrolledAt = enrolled.Time
		if lastCert.Valid {
			t := lastCert.Time
			out.LastCertIssuedAt = &t
		}
		if revoked.Valid {
			t := revoked.Time
			out.RevokedAt = &t
		}
		return nil
	})
	return out, err
}

func (r *DeviceEnrollmentRepository) GetEnrollmentAnyStatus(ctx context.Context, tenantID uuid.UUID, deviceID uuid.UUID) (repository.DeviceEnrollment, error) {
	var out repository.DeviceEnrollment
	err := r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		const q = `
			SELECT device_id, tenant_id, public_key, status, enrolled_at,
			       last_cert_issued_at, revoked_at
			FROM device_enrollments
			WHERE device_id = $1::uuid
			LIMIT 1`
		row := tx.QueryRow(ctx, q, deviceID)
		var enrolled deletedAtScan
		var lastCert deletedAtScan
		var revoked deletedAtScan
		if err := row.Scan(
			&out.DeviceID, &out.TenantID, &out.PublicKey, &out.Status,
			&enrolled, &lastCert, &revoked,
		); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return repository.ErrNotFound
			}
			return fmt.Errorf("select device_enrollment: %w", err)
		}
		out.EnrolledAt = enrolled.Time
		if lastCert.Valid {
			t := lastCert.Time
			out.LastCertIssuedAt = &t
		}
		if revoked.Valid {
			t := revoked.Time
			out.RevokedAt = &t
		}
		return nil
	})
	return out, err
}

func (r *DeviceEnrollmentRepository) UpdateEnrollmentStatus(ctx context.Context, tenantID uuid.UUID, deviceID uuid.UUID, status repository.EnrollmentStatus) error {
	return r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		var q string
		if status == repository.EnrollmentStatusRevoked {
			q = `UPDATE device_enrollments SET status = $2, revoked_at = now()
			     WHERE device_id = $1::uuid AND status != 'revoked'`
		} else {
			q = `UPDATE device_enrollments SET status = $2
			     WHERE device_id = $1::uuid AND status != 'revoked'`
		}
		tag, err := tx.Exec(ctx, q, deviceID, status)
		if err != nil {
			return fmt.Errorf("update enrollment status: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return repository.ErrNotFound
		}
		return nil
	})
}

func (r *DeviceEnrollmentRepository) UpdateLastCertIssuedAt(ctx context.Context, tenantID uuid.UUID, deviceID uuid.UUID, at time.Time) error {
	return r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		const q = `UPDATE device_enrollments SET last_cert_issued_at = $2
		           WHERE device_id = $1::uuid AND status != 'revoked'`
		tag, err := tx.Exec(ctx, q, deviceID, at)
		if err != nil {
			return fmt.Errorf("update last_cert_issued_at: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return repository.ErrNotFound
		}
		return nil
	})
}

func (r *DeviceEnrollmentRepository) CreateCertificate(ctx context.Context, tenantID uuid.UUID, c repository.DeviceCertificate) (repository.DeviceCertificate, error) {
	if c.ID == uuid.Nil {
		c.ID = uuid.New()
	}
	var out repository.DeviceCertificate
	err := r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		const q = `
			INSERT INTO device_certificates (id, device_id, tenant_id, serial, cert_pem, issued_at, expires_at)
			VALUES ($1::uuid, $2::uuid, $3::uuid, $4, $5, $6, $7)
			RETURNING id, device_id, tenant_id, serial, cert_pem, issued_at, expires_at, revoked_at`
		row := tx.QueryRow(ctx, q,
			c.ID, c.DeviceID, tenantID, c.Serial, c.CertPEM, c.IssuedAt, c.ExpiresAt,
		)
		var revoked deletedAtScan
		if err := row.Scan(
			&out.ID, &out.DeviceID, &out.TenantID, &out.Serial, &out.CertPEM,
			&out.IssuedAt, &out.ExpiresAt, &revoked,
		); err != nil {
			return fmt.Errorf("insert device_certificate: %w", err)
		}
		if revoked.Valid {
			t := revoked.Time
			out.RevokedAt = &t
		}
		return nil
	})
	return out, err
}

func (r *DeviceEnrollmentRepository) RevokeAllCertificates(ctx context.Context, tenantID uuid.UUID, deviceID uuid.UUID, at time.Time) error {
	return r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		const q = `UPDATE device_certificates SET revoked_at = $2
		           WHERE device_id = $1::uuid AND revoked_at IS NULL`
		_, err := tx.Exec(ctx, q, deviceID, at)
		return err
	})
}
