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

// PolicySigningKeyRepository owns the policy_signing_keys table.
// Tenant isolation is enforced by RLS — every method runs inside a
// withTenant / withTenantRO transaction that sets the sng.tenant_id
// GUC for the duration of the statement.
type PolicySigningKeyRepository struct{ s *Store }

const policySigningKeySelectColumns = `
	id, tenant_id, key_id, algorithm, public_key, private_key,
	status, activated_at, rotated_at, revoked_at, created_at
`

func scanPolicySigningKey(row pgx.Row) (repository.PolicySigningKey, error) {
	var (
		k         repository.PolicySigningKey
		rotatedAt deletedAtScan
		revokedAt deletedAtScan
	)
	if err := row.Scan(
		&k.ID, &k.TenantID, &k.KeyID, &k.Algorithm,
		&k.PublicKey, &k.PrivateKey, &k.Status,
		&k.ActivatedAt, &rotatedAt, &revokedAt, &k.CreatedAt,
	); err != nil {
		return repository.PolicySigningKey{}, err
	}
	if rotatedAt.Valid {
		t := rotatedAt.Time
		k.RotatedAt = &t
	}
	if revokedAt.Valid {
		t := revokedAt.Time
		k.RevokedAt = &t
	}
	return k, nil
}

func (r *PolicySigningKeyRepository) Create(ctx context.Context, tenantID uuid.UUID, k repository.PolicySigningKey) (repository.PolicySigningKey, error) {
	if tenantID == uuid.Nil {
		return repository.PolicySigningKey{}, repository.ErrInvalidArgument
	}
	if k.KeyID == "" || k.Algorithm == "" || len(k.PublicKey) == 0 || len(k.PrivateKey) == 0 {
		return repository.PolicySigningKey{}, repository.ErrInvalidArgument
	}
	if k.ID == uuid.Nil {
		k.ID = uuid.New()
	}
	if k.Status == "" {
		k.Status = repository.PolicySigningKeyStatusActive
	}
	if k.ActivatedAt.IsZero() {
		k.ActivatedAt = time.Now().UTC()
	}
	var out repository.PolicySigningKey
	err := r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx, `
			INSERT INTO policy_signing_keys (
				id, tenant_id, key_id, algorithm,
				public_key, private_key, status, activated_at
			)
			VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, $7, $8)
			RETURNING `+policySigningKeySelectColumns,
			k.ID, tenantID, k.KeyID, k.Algorithm,
			k.PublicKey, k.PrivateKey, k.Status, k.ActivatedAt.UTC(),
		)
		var err error
		out, err = scanPolicySigningKey(row)
		if err != nil {
			if isUniqueViolation(err) {
				return repository.ErrConflict
			}
			if isCheckViolation(err) {
				return repository.ErrInvalidArgument
			}
			return fmt.Errorf("insert signing key: %w", err)
		}
		return nil
	})
	return out, err
}

func (r *PolicySigningKeyRepository) GetActive(ctx context.Context, tenantID uuid.UUID) (repository.PolicySigningKey, error) {
	var out repository.PolicySigningKey
	err := r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx, `
			SELECT `+policySigningKeySelectColumns+`
			FROM policy_signing_keys
			WHERE status = 'active'
			LIMIT 1
		`)
		var err error
		out, err = scanPolicySigningKey(row)
		if errors.Is(err, pgx.ErrNoRows) {
			return repository.ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("select active signing key: %w", err)
		}
		return nil
	})
	return out, err
}

func (r *PolicySigningKeyRepository) GetByKeyID(ctx context.Context, tenantID uuid.UUID, keyID string) (repository.PolicySigningKey, error) {
	if keyID == "" {
		return repository.PolicySigningKey{}, repository.ErrInvalidArgument
	}
	var out repository.PolicySigningKey
	err := r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx, `
			SELECT `+policySigningKeySelectColumns+`
			FROM policy_signing_keys
			WHERE key_id = $1
			LIMIT 1
		`, keyID)
		var err error
		out, err = scanPolicySigningKey(row)
		if errors.Is(err, pgx.ErrNoRows) {
			return repository.ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("select signing key by key_id: %w", err)
		}
		return nil
	})
	return out, err
}

func (r *PolicySigningKeyRepository) List(ctx context.Context, tenantID uuid.UUID) ([]repository.PolicySigningKey, error) {
	var out []repository.PolicySigningKey
	err := r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT `+policySigningKeySelectColumns+`
			FROM policy_signing_keys
			ORDER BY activated_at DESC, id ASC
		`)
		if err != nil {
			return fmt.Errorf("list signing keys: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			k, err := scanPolicySigningKey(rows)
			if err != nil {
				return fmt.Errorf("scan signing key: %w", err)
			}
			out = append(out, k)
		}
		return rows.Err()
	})
	return out, err
}

func (r *PolicySigningKeyRepository) Rotate(ctx context.Context, tenantID uuid.UUID, newKey repository.PolicySigningKey, at time.Time) (repository.PolicySigningKey, error) {
	if tenantID == uuid.Nil {
		return repository.PolicySigningKey{}, repository.ErrInvalidArgument
	}
	if newKey.KeyID == "" || newKey.Algorithm == "" || len(newKey.PublicKey) == 0 || len(newKey.PrivateKey) == 0 {
		return repository.PolicySigningKey{}, repository.ErrInvalidArgument
	}
	if newKey.ID == uuid.Nil {
		newKey.ID = uuid.New()
	}
	if at.IsZero() {
		at = time.Now().UTC()
	}
	var out repository.PolicySigningKey
	err := r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		// Step 1: transition the existing active key to
		// 'rotated'. UPDATE returns the number of affected rows
		// via tag so we can distinguish "no active key" (caller
		// should use Create) from "found and updated".
		tag, err := tx.Exec(ctx, `
			UPDATE policy_signing_keys
			SET status     = 'rotated',
			    rotated_at = $1::timestamptz
			WHERE status = 'active'
		`, at.UTC())
		if err != nil {
			return fmt.Errorf("rotate existing key: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return repository.ErrNotFound
		}

		// Step 2: insert the new active key. The partial unique
		// index on (tenant_id) WHERE status='active' guarantees a
		// concurrent rotation by another worker will surface here
		// as a unique-violation, which we translate to ErrConflict.
		row := tx.QueryRow(ctx, `
			INSERT INTO policy_signing_keys (
				id, tenant_id, key_id, algorithm,
				public_key, private_key, status, activated_at
			)
			VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, 'active', $7::timestamptz)
			RETURNING `+policySigningKeySelectColumns,
			newKey.ID, tenantID, newKey.KeyID, newKey.Algorithm,
			newKey.PublicKey, newKey.PrivateKey, at.UTC(),
		)
		out, err = scanPolicySigningKey(row)
		if err != nil {
			if isUniqueViolation(err) {
				return repository.ErrConflict
			}
			if isCheckViolation(err) {
				return repository.ErrInvalidArgument
			}
			return fmt.Errorf("insert rotated key: %w", err)
		}
		return nil
	})
	return out, err
}

func (r *PolicySigningKeyRepository) Revoke(ctx context.Context, tenantID uuid.UUID, keyID string, at time.Time) (repository.PolicySigningKey, error) {
	if keyID == "" {
		return repository.PolicySigningKey{}, repository.ErrInvalidArgument
	}
	if at.IsZero() {
		at = time.Now().UTC()
	}
	var out repository.PolicySigningKey
	err := r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx, `
			UPDATE policy_signing_keys
			SET status     = 'revoked',
			    revoked_at = $1::timestamptz
			WHERE key_id = $2
			  AND status IN ('active', 'rotated')
			RETURNING `+policySigningKeySelectColumns,
			at.UTC(), keyID,
		)
		var err error
		out, err = scanPolicySigningKey(row)
		if errors.Is(err, pgx.ErrNoRows) {
			return repository.ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("revoke signing key: %w", err)
		}
		return nil
	})
	return out, err
}
