package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// IDPConfigRepository owns the idp_configs table — per-tenant OIDC
// provider configurations for mobile native SSO.
type IDPConfigRepository struct{ s *Store }

const idpConfigSelectColumns = `
	id, tenant_id, provider_type, issuer_url, client_id,
	allowed_domains, group_claim_path, enabled, created_at, updated_at
`

func scanIDPConfig(row pgx.Row) (repository.IDPConfig, error) {
	var (
		c            repository.IDPConfig
		providerType string
	)
	if err := row.Scan(
		&c.ID, &c.TenantID, &providerType, &c.IssuerURL, &c.ClientID,
		&c.AllowedDomains, &c.GroupClaimPath, &c.Enabled, &c.CreatedAt, &c.UpdatedAt,
	); err != nil {
		return repository.IDPConfig{}, err
	}
	c.ProviderType = repository.IDPProviderType(providerType)
	return c, nil
}

func (r *IDPConfigRepository) Create(ctx context.Context, tenantID uuid.UUID, c repository.IDPConfig) (repository.IDPConfig, error) {
	if tenantID == uuid.Nil || c.IssuerURL == "" || c.ClientID == "" {
		return repository.IDPConfig{}, repository.ErrInvalidArgument
	}
	if err := repository.ValidateIDPProviderType(c.ProviderType); err != nil {
		return repository.IDPConfig{}, err
	}
	if c.ID == uuid.Nil {
		c.ID = uuid.New()
	}
	if c.AllowedDomains == nil {
		c.AllowedDomains = []string{}
	}
	var out repository.IDPConfig
	err := r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		const q = `
			INSERT INTO idp_configs
			    (id, tenant_id, provider_type, issuer_url, client_id,
			     allowed_domains, group_claim_path, enabled)
			VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6::text[], $7, $8)
			RETURNING ` + idpConfigSelectColumns
		row := tx.QueryRow(ctx, q,
			c.ID, tenantID, string(c.ProviderType), c.IssuerURL, c.ClientID,
			c.AllowedDomains, c.GroupClaimPath, c.Enabled)
		var err error
		out, err = scanIDPConfig(row)
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
			return fmt.Errorf("insert idp config: %w", err)
		}
		return nil
	})
	return out, err
}

func (r *IDPConfigRepository) Get(ctx context.Context, tenantID, id uuid.UUID) (repository.IDPConfig, error) {
	var out repository.IDPConfig
	err := r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		const q = `SELECT ` + idpConfigSelectColumns + ` FROM idp_configs WHERE id = $1::uuid`
		row := tx.QueryRow(ctx, q, id)
		var err error
		out, err = scanIDPConfig(row)
		if errors.Is(err, pgx.ErrNoRows) {
			return repository.ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("select idp config: %w", err)
		}
		return nil
	})
	return out, err
}

func (r *IDPConfigRepository) List(ctx context.Context, tenantID uuid.UUID) ([]repository.IDPConfig, error) {
	out := make([]repository.IDPConfig, 0)
	err := r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		const q = `SELECT ` + idpConfigSelectColumns + `
			FROM idp_configs
			ORDER BY created_at DESC, id DESC`
		rows, err := tx.Query(ctx, q)
		if err != nil {
			return fmt.Errorf("list idp configs: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			c, err := scanIDPConfig(rows)
			if err != nil {
				return fmt.Errorf("scan idp config: %w", err)
			}
			out = append(out, c)
		}
		return rows.Err()
	})
	return out, err
}

func (r *IDPConfigRepository) Update(ctx context.Context, tenantID uuid.UUID, c repository.IDPConfig) (repository.IDPConfig, error) {
	if tenantID == uuid.Nil || c.ID == uuid.Nil || c.IssuerURL == "" || c.ClientID == "" {
		return repository.IDPConfig{}, repository.ErrInvalidArgument
	}
	if err := repository.ValidateIDPProviderType(c.ProviderType); err != nil {
		return repository.IDPConfig{}, err
	}
	if c.AllowedDomains == nil {
		c.AllowedDomains = []string{}
	}
	var out repository.IDPConfig
	err := r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		const q = `
			UPDATE idp_configs
			SET provider_type    = $2,
			    issuer_url       = $3,
			    client_id        = $4,
			    allowed_domains  = $5::text[],
			    group_claim_path = $6,
			    enabled          = $7,
			    updated_at       = now()
			WHERE id = $1::uuid
			RETURNING ` + idpConfigSelectColumns
		row := tx.QueryRow(ctx, q,
			c.ID, string(c.ProviderType), c.IssuerURL, c.ClientID,
			c.AllowedDomains, c.GroupClaimPath, c.Enabled)
		var scanErr error
		out, scanErr = scanIDPConfig(row)
		if errors.Is(scanErr, pgx.ErrNoRows) {
			return repository.ErrNotFound
		}
		if isUniqueViolation(scanErr) {
			return repository.ErrConflict
		}
		if isCheckViolation(scanErr) {
			return repository.ErrInvalidArgument
		}
		if scanErr != nil {
			return fmt.Errorf("update idp config: %w", scanErr)
		}
		return nil
	})
	return out, err
}

func (r *IDPConfigRepository) Delete(ctx context.Context, tenantID, id uuid.UUID) error {
	return r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		ct, err := tx.Exec(ctx, `DELETE FROM idp_configs WHERE id = $1::uuid`, id)
		if err != nil {
			return fmt.Errorf("delete idp config: %w", err)
		}
		if ct.RowsAffected() == 0 {
			return repository.ErrNotFound
		}
		return nil
	})
}
