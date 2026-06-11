package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/service/policytemplates/ptmodel"
)

// PolicyTemplateRepository implements policytemplates.Repository over
// Postgres (migration 062). The global catalog table is fleet-wide and
// written in a system-role transaction; the per-tenant applied state is
// RLS-scoped via the standard sng.tenant_id GUC (withTenant /
// withTenantRO).
type PolicyTemplateRepository struct{ s *Store }

// NewPolicyTemplateRepository returns a repository backed by the Store.
func NewPolicyTemplateRepository(s *Store) *PolicyTemplateRepository {
	return &PolicyTemplateRepository{s: s}
}

const appliedTemplateCols = `
tenant_id, industry, country, regime, template_ids,
graph_hash, graph, version, created_at, updated_at
`

// UpsertCatalog idempotently writes the catalog. The ON CONFLICT guard
// only rewrites a row when its content_hash actually changed, so a
// no-op seed leaves created_at/updated_at untouched.
func (r *PolicyTemplateRepository) UpsertCatalog(ctx context.Context, rows []ptmodel.CatalogRow) error {
	if len(rows) == 0 {
		return nil
	}
	return r.s.withSystem(ctx, func(tx pgx.Tx) error {
		for _, row := range rows {
			_, err := tx.Exec(ctx, `
				INSERT INTO policy_templates
					(id, kind, industry, regime, name, description, spec, content_hash, version)
				VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8, $9)
				ON CONFLICT (id) DO UPDATE SET
					kind         = EXCLUDED.kind,
					industry     = EXCLUDED.industry,
					regime       = EXCLUDED.regime,
					name         = EXCLUDED.name,
					description  = EXCLUDED.description,
					spec         = EXCLUDED.spec,
					content_hash = EXCLUDED.content_hash,
					version      = EXCLUDED.version,
					updated_at   = NOW()
				WHERE policy_templates.content_hash IS DISTINCT FROM EXCLUDED.content_hash
			`,
				row.ID, row.Kind, row.Industry, row.Regime, row.Name,
				row.Description, []byte(row.Spec), row.ContentHash, row.Version,
			)
			if err != nil {
				if isCheckViolation(err) {
					return repository.ErrInvalidArgument
				}
				return fmt.Errorf("upsert policy_templates %q: %w", row.ID, err)
			}
		}
		return nil
	})
}

// ListCatalog returns every catalog row sorted by id.
func (r *PolicyTemplateRepository) ListCatalog(ctx context.Context) ([]ptmodel.CatalogRow, error) {
	var out []ptmodel.CatalogRow
	err := r.s.withSystem(ctx, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT id, kind, industry, regime, name, description, spec, content_hash, version, created_at, updated_at
			FROM policy_templates
			ORDER BY id
		`)
		if err != nil {
			return fmt.Errorf("list policy_templates: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var (
				row  ptmodel.CatalogRow
				spec []byte
			)
			if err := rows.Scan(
				&row.ID, &row.Kind, &row.Industry, &row.Regime, &row.Name,
				&row.Description, &spec, &row.ContentHash, &row.Version,
				&row.CreatedAt, &row.UpdatedAt,
			); err != nil {
				return fmt.Errorf("scan policy_templates: %w", err)
			}
			row.Spec = json.RawMessage(spec)
			out = append(out, row)
		}
		return rows.Err()
	})
	return out, err
}

// GetApplied returns a tenant's applied baseline, or ErrNotFound.
func (r *PolicyTemplateRepository) GetApplied(ctx context.Context, tenantID uuid.UUID) (ptmodel.AppliedTemplate, error) {
	var out ptmodel.AppliedTemplate
	err := r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		// Defence-in-depth: predicate on tenant_id in addition to RLS,
		// so the query stays correct even if RLS enforcement is
		// misconfigured on a connection.
		row := tx.QueryRow(ctx, `
			SELECT `+appliedTemplateCols+`
			FROM tenant_policy_templates
			WHERE tenant_id = $1::uuid
		`, tenantID)
		var err error
		out, err = scanAppliedTemplate(row)
		if errors.Is(err, pgx.ErrNoRows) {
			return repository.ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("get tenant_policy_templates: %w", err)
		}
		return nil
	})
	return out, err
}

// UpsertApplied inserts or replaces a tenant's applied baseline,
// keyed on tenant_id, and returns the stored row. created_at is set
// once on insert and preserved across updates.
func (r *PolicyTemplateRepository) UpsertApplied(ctx context.Context, applied ptmodel.AppliedTemplate) (ptmodel.AppliedTemplate, error) {
	if len(applied.Graph) == 0 {
		applied.Graph = json.RawMessage(`{}`)
	}
	if applied.TemplateIDs == nil {
		applied.TemplateIDs = []string{}
	}
	var out ptmodel.AppliedTemplate
	err := r.s.withTenant(ctx, applied.TenantID.String(), func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx, `
			INSERT INTO tenant_policy_templates
				(tenant_id, industry, country, regime, template_ids, graph_hash, graph, version)
			VALUES ($1::uuid, $2, $3, $4, $5, $6, $7::jsonb, $8)
			ON CONFLICT (tenant_id) DO UPDATE SET
				industry     = EXCLUDED.industry,
				country      = EXCLUDED.country,
				regime       = EXCLUDED.regime,
				template_ids = EXCLUDED.template_ids,
				graph_hash   = EXCLUDED.graph_hash,
				graph        = EXCLUDED.graph,
				version      = EXCLUDED.version,
				updated_at   = NOW()
			RETURNING `+appliedTemplateCols,
			applied.TenantID, applied.Industry, applied.Country, applied.Regime,
			applied.TemplateIDs, applied.GraphHash, []byte(applied.Graph), applied.Version,
		)
		var err error
		out, err = scanAppliedTemplate(row)
		if err != nil {
			if isForeignKeyViolation(err) {
				// Unknown tenant_id (no such tenant).
				return repository.ErrInvalidArgument
			}
			return fmt.Errorf("upsert tenant_policy_templates: %w", err)
		}
		return nil
	})
	return out, err
}

// scanAppliedTemplate scans the appliedTemplateCols column list.
func scanAppliedTemplate(row pgx.Row) (ptmodel.AppliedTemplate, error) {
	var (
		out   ptmodel.AppliedTemplate
		graph []byte
	)
	if err := row.Scan(
		&out.TenantID, &out.Industry, &out.Country, &out.Regime, &out.TemplateIDs,
		&out.GraphHash, &graph, &out.Version, &out.CreatedAt, &out.UpdatedAt,
	); err != nil {
		return ptmodel.AppliedTemplate{}, err
	}
	out.Graph = json.RawMessage(graph)
	return out, nil
}
