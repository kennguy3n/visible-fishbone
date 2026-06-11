package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// IDPDirectoryCredentialRepository owns the idp_directory_credentials
// table (migration 064): the sealed per-tenant directory-API secrets
// the IdP SyncService unseals to call provider directories. Every query
// runs inside withTenant/withTenantRO so the `sng.tenant_id` GUC is set
// and RLS scopes the rows to the caller's tenant; the bytes stored here
// are already sealed by identity.CredentialVault (this layer never sees
// plaintext).
//
// It implements identity.DirectoryCredentialStore (declared in the
// service package). The interface is satisfied structurally — this file
// deliberately does NOT import the identity package, because identity
// imports middleware which imports this postgres package, so an explicit
// import would create a cycle. The compile-time check happens instead at
// the wiring site (cmd/sng-control), where the repository is passed to
// identity.NewCredentialVault.
type IDPDirectoryCredentialRepository struct{ s *Store }

// NewIDPDirectoryCredentialRepository binds the Store to the
// identity.DirectoryCredentialStore interface.
func (s *Store) NewIDPDirectoryCredentialRepository() *IDPDirectoryCredentialRepository {
	return &IDPDirectoryCredentialRepository{s: s}
}

// GetSealed returns the sealed credential blob for a config, or
// repository.ErrNotFound when none is stored.
func (r *IDPDirectoryCredentialRepository) GetSealed(ctx context.Context, tenantID, configID uuid.UUID) ([]byte, error) {
	if tenantID == uuid.Nil || configID == uuid.Nil {
		return nil, repository.ErrInvalidArgument
	}
	var sealed []byte
	err := r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		const q = `SELECT sealed FROM idp_directory_credentials WHERE config_id = $1::uuid`
		row := tx.QueryRow(ctx, q, configID)
		if scanErr := row.Scan(&sealed); scanErr != nil {
			if errors.Is(scanErr, pgx.ErrNoRows) {
				return repository.ErrNotFound
			}
			return fmt.Errorf("select directory credential: %w", scanErr)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return sealed, nil
}

// SetSealed upserts the sealed credential for a config. The config_id FK
// (ON DELETE CASCADE) plus the RLS WITH CHECK on tenant_id ensure the
// row can only be written for a config that exists; the handler
// additionally verifies the config belongs to the tenant before calling
// this so a caller can't seed a credential against another tenant's
// config id. A foreign-key violation (unknown config) maps to
// ErrNotFound.
func (r *IDPDirectoryCredentialRepository) SetSealed(ctx context.Context, tenantID, configID uuid.UUID, sealed []byte) error {
	if tenantID == uuid.Nil || configID == uuid.Nil {
		return repository.ErrInvalidArgument
	}
	if len(sealed) == 0 {
		return repository.ErrInvalidArgument
	}
	return r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		const q = `
			INSERT INTO idp_directory_credentials (config_id, tenant_id, sealed)
			VALUES ($1::uuid, $2::uuid, $3)
			ON CONFLICT (config_id) DO UPDATE
				SET sealed = EXCLUDED.sealed, updated_at = now()`
		if _, err := tx.Exec(ctx, q, configID, tenantID, sealed); err != nil {
			if isForeignKeyViolation(err) {
				return repository.ErrNotFound
			}
			return fmt.Errorf("upsert directory credential: %w", err)
		}
		return nil
	})
}

// DeleteSealed removes a config's credential, returning ErrNotFound when
// none was stored.
func (r *IDPDirectoryCredentialRepository) DeleteSealed(ctx context.Context, tenantID, configID uuid.UUID) error {
	if tenantID == uuid.Nil || configID == uuid.Nil {
		return repository.ErrInvalidArgument
	}
	return r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		const q = `DELETE FROM idp_directory_credentials WHERE config_id = $1::uuid`
		tag, err := tx.Exec(ctx, q, configID)
		if err != nil {
			return fmt.Errorf("delete directory credential: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return repository.ErrNotFound
		}
		return nil
	})
}
