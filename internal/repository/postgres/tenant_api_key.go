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

// TenantAPIKeyRepository owns the tenant_api_keys table.
//
// Per-tenant paths run under `sng.tenant_id` via withTenant /
// withTenantRO. `LookupByHash` is the only cross-tenant path; it
// runs under `sng.system_role='true'` via withSystem because the
// caller (the auth middleware) does not yet know which tenant the
// presented key belongs to.
type TenantAPIKeyRepository struct{ s *Store }

// tenantAPIKeySelectColumns is the ordered column list every SELECT
// against tenant_api_keys uses. Centralised so scanTenantAPIKey and
// the various callers stay in lockstep — adding a column means
// editing exactly this list and the Scan.
// #nosec G101 — this is a SQL column list, not a literal credential.
const tenantAPIKeySelectColumns = `
	id, tenant_id, name, subject, hash, status,
	expires_at, last_used_at, created_by, created_at, revoked_at
`

func scanTenantAPIKey(row pgx.Row) (repository.TenantAPIKey, error) {
	var (
		k         repository.TenantAPIKey
		expires   deletedAtScan
		lastUsed  deletedAtScan
		createdBy nullableUUID
		revokedAt deletedAtScan
	)
	if err := row.Scan(
		&k.ID, &k.TenantID, &k.Name, &k.Subject, &k.Hash, &k.Status,
		&expires, &lastUsed, &createdBy, &k.CreatedAt, &revokedAt,
	); err != nil {
		return repository.TenantAPIKey{}, err
	}
	if expires.Valid {
		t := expires.Time
		k.ExpiresAt = &t
	}
	if lastUsed.Valid {
		t := lastUsed.Time
		k.LastUsedAt = &t
	}
	if createdBy.Valid {
		u := createdBy.ID
		k.CreatedBy = &u
	}
	if revokedAt.Valid {
		t := revokedAt.Time
		k.RevokedAt = &t
	}
	return k, nil
}

func (r *TenantAPIKeyRepository) Create(ctx context.Context, tenantID uuid.UUID, k repository.TenantAPIKey) (repository.TenantAPIKey, error) {
	if tenantID == uuid.Nil || k.Name == "" || k.Subject == "" || len(k.Hash) == 0 {
		return repository.TenantAPIKey{}, repository.ErrInvalidArgument
	}
	if k.ID == uuid.Nil {
		k.ID = uuid.New()
	}
	if k.Status == "" {
		k.Status = repository.TenantAPIKeyStatusActive
	}
	var (
		expires *time.Time
	)
	if k.ExpiresAt != nil {
		t := k.ExpiresAt.UTC()
		expires = &t
	}
	var out repository.TenantAPIKey
	err := r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx, `
			INSERT INTO tenant_api_keys (
				id, tenant_id, name, subject, hash, status,
				expires_at, created_by
			)
			VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, $7, $8)
			RETURNING `+tenantAPIKeySelectColumns,
			k.ID, tenantID, k.Name, k.Subject, k.Hash, k.Status,
			expires, k.CreatedBy,
		)
		var err error
		out, err = scanTenantAPIKey(row)
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
			return fmt.Errorf("insert tenant api key: %w", err)
		}
		return nil
	})
	return out, err
}

func (r *TenantAPIKeyRepository) Get(ctx context.Context, tenantID, id uuid.UUID) (repository.TenantAPIKey, error) {
	var out repository.TenantAPIKey
	err := r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx, `
			SELECT `+tenantAPIKeySelectColumns+`
			FROM tenant_api_keys
			WHERE id = $1::uuid
		`, id)
		var err error
		out, err = scanTenantAPIKey(row)
		if errors.Is(err, pgx.ErrNoRows) {
			return repository.ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("select tenant api key: %w", err)
		}
		return nil
	})
	return out, err
}

func (r *TenantAPIKeyRepository) List(ctx context.Context, tenantID uuid.UUID) ([]repository.TenantAPIKey, error) {
	var out []repository.TenantAPIKey
	err := r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT `+tenantAPIKeySelectColumns+`
			FROM tenant_api_keys
			ORDER BY created_at DESC, id ASC
		`)
		if err != nil {
			return fmt.Errorf("list tenant api keys: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			k, err := scanTenantAPIKey(rows)
			if err != nil {
				return fmt.Errorf("scan tenant api key: %w", err)
			}
			out = append(out, k)
		}
		return rows.Err()
	})
	return out, err
}

func (r *TenantAPIKeyRepository) Revoke(ctx context.Context, tenantID, id uuid.UUID, at time.Time) (repository.TenantAPIKey, error) {
	var out repository.TenantAPIKey
	err := r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx, `
			UPDATE tenant_api_keys
			SET status = 'revoked',
			    revoked_at = COALESCE(revoked_at, $2)
			WHERE id = $1::uuid
			RETURNING `+tenantAPIKeySelectColumns,
			id, at.UTC(),
		)
		var err error
		out, err = scanTenantAPIKey(row)
		if errors.Is(err, pgx.ErrNoRows) {
			return repository.ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("revoke tenant api key: %w", err)
		}
		return nil
	})
	return out, err
}

func (r *TenantAPIKeyRepository) LookupByHash(ctx context.Context, hash []byte) (repository.TenantAPIKey, error) {
	if len(hash) == 0 {
		return repository.TenantAPIKey{}, repository.ErrInvalidArgument
	}
	var out repository.TenantAPIKey
	// Cross-tenant lookup — the caller hasn't identified the tenant
	// yet, so we drop the per-tenant RLS check via the system-role
	// GUC. This is the only call site that does so. Auth-policy
	// checks (status, expiry, revocation) live in the service
	// layer, not here.
	err := r.s.withSystem(ctx, func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx, `
			SELECT `+tenantAPIKeySelectColumns+`
			FROM tenant_api_keys
			WHERE hash = $1
			LIMIT 1
		`, hash)
		var err error
		out, err = scanTenantAPIKey(row)
		if errors.Is(err, pgx.ErrNoRows) {
			return repository.ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("lookup tenant api key by hash: %w", err)
		}
		return nil
	})
	return out, err
}

func (r *TenantAPIKeyRepository) TouchLastUsed(ctx context.Context, tenantID, id uuid.UUID, at time.Time) error {
	return r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		ct, err := tx.Exec(ctx, `
			UPDATE tenant_api_keys
			SET last_used_at = $2
			WHERE id = $1::uuid
		`, id, at.UTC())
		if err != nil {
			return fmt.Errorf("touch tenant api key last_used: %w", err)
		}
		if ct.RowsAffected() == 0 {
			return repository.ErrNotFound
		}
		return nil
	})
}
