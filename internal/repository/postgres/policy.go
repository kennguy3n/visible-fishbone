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

// PolicyRepository owns policy_graphs + policy_bundles.
type PolicyRepository struct{ s *Store }

const policyGraphSelectColumns = `
	id, tenant_id, version, graph, compiled_at, COALESCE(compiler_version, ''), created_at
`

func scanPolicyGraph(row pgx.Row) (repository.PolicyGraph, error) {
	var (
		g          repository.PolicyGraph
		compiledAt deletedAtScan
		graphBuf   []byte
	)
	if err := row.Scan(&g.ID, &g.TenantID, &g.Version, &graphBuf, &compiledAt, &g.CompilerVersion, &g.CreatedAt); err != nil {
		return repository.PolicyGraph{}, err
	}
	g.Graph = json.RawMessage(graphBuf)
	if compiledAt.Valid {
		t := compiledAt.Time
		g.CompiledAt = &t
	}
	return g, nil
}

const policyBundleSelectColumns = `
	id, policy_graph_id, target_type, bundle, signature, COALESCE(key_id, ''), sha256, created_at
`

func scanPolicyBundle(row pgx.Row) (repository.PolicyBundle, error) {
	var b repository.PolicyBundle
	if err := row.Scan(&b.ID, &b.PolicyGraphID, &b.TargetType, &b.Bundle, &b.Signature, &b.KeyID, &b.Sha256, &b.CreatedAt); err != nil {
		return repository.PolicyBundle{}, err
	}
	return b, nil
}

// policyBundleMetaSelectColumns omits the `bundle` BYTEA so a SELECT
// on the agent-pull HEAD path never round-trips the bundle bytes
// out of Postgres. `octet_length(bundle)` carries the byte count so
// the handler can emit Content-Length on HEAD without the payload.
const policyBundleMetaSelectColumns = `
	id, policy_graph_id, target_type, signature, COALESCE(key_id, ''), sha256, octet_length(bundle), created_at
`

func scanPolicyBundleMeta(row pgx.Row) (repository.PolicyBundleMetadata, error) {
	var m repository.PolicyBundleMetadata
	if err := row.Scan(
		&m.ID, &m.PolicyGraphID, &m.TargetType, &m.Signature, &m.KeyID, &m.Sha256, &m.BundleSize, &m.CreatedAt,
	); err != nil {
		return repository.PolicyBundleMetadata{}, err
	}
	return m, nil
}

func (r *PolicyRepository) CreateGraph(ctx context.Context, tenantID uuid.UUID, g repository.PolicyGraph) (repository.PolicyGraph, error) {
	if tenantID == uuid.Nil {
		return repository.PolicyGraph{}, repository.ErrInvalidArgument
	}
	if g.ID == uuid.Nil {
		g.ID = uuid.New()
	}
	if len(g.Graph) == 0 {
		g.Graph = json.RawMessage(`{}`)
	}
	var out repository.PolicyGraph
	err := r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		// Auto-version: select MAX(version) and increment when
		// the caller leaves Version unset. This sits inside the
		// same transaction so two concurrent CreateGraph calls
		// on the same tenant will race on the (tenant_id,
		// version) UNIQUE constraint, surfacing as ErrConflict
		// for the loser — the service retries in that case.
		var version int
		if g.Version <= 0 {
			err := tx.QueryRow(ctx,
				`SELECT COALESCE(MAX(version), 0) + 1 FROM policy_graphs WHERE tenant_id = $1::uuid`,
				tenantID,
			).Scan(&version)
			if err != nil {
				return fmt.Errorf("select next version: %w", err)
			}
		} else {
			version = g.Version
		}
		var compiledAt any
		if g.CompiledAt != nil {
			compiledAt = g.CompiledAt.UTC()
		}
		var compilerVersion any
		if g.CompilerVersion != "" {
			compilerVersion = g.CompilerVersion
		}
		row := tx.QueryRow(ctx, `
			INSERT INTO policy_graphs (id, tenant_id, version, graph, compiled_at, compiler_version)
			VALUES ($1::uuid, $2::uuid, $3, $4::jsonb, $5, $6)
			RETURNING `+policyGraphSelectColumns,
			g.ID, tenantID, version, []byte(g.Graph), compiledAt, compilerVersion,
		)
		var err error
		out, err = scanPolicyGraph(row)
		if err != nil {
			if isUniqueViolation(err) {
				return repository.ErrConflict
			}
			if isCheckViolation(err) {
				return repository.ErrInvalidArgument
			}
			return fmt.Errorf("insert policy graph: %w", err)
		}
		return nil
	})
	return out, err
}

func (r *PolicyRepository) GetCurrentGraph(ctx context.Context, tenantID uuid.UUID) (repository.PolicyGraph, error) {
	var out repository.PolicyGraph
	err := r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx, `
			SELECT `+policyGraphSelectColumns+`
			FROM policy_graphs
			ORDER BY version DESC
			LIMIT 1
		`)
		var err error
		out, err = scanPolicyGraph(row)
		if errors.Is(err, pgx.ErrNoRows) {
			return repository.ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("select current graph: %w", err)
		}
		return nil
	})
	return out, err
}

func (r *PolicyRepository) ListGraphVersions(ctx context.Context, tenantID uuid.UUID, page repository.Page) (repository.PageResult[repository.PolicyGraph], error) {
	page = page.Normalize()
	cur, err := decodeCursor(page.After)
	if err != nil {
		return repository.PageResult[repository.PolicyGraph]{}, repository.ErrInvalidArgument
	}
	res := repository.PageResult[repository.PolicyGraph]{}
	err = r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		q, args := buildListQuery("policy_graphs", policyGraphSelectColumns, cur, page.Order, page.Limit)
		rows, err := tx.Query(ctx, q, args...)
		if err != nil {
			return fmt.Errorf("list graphs: %w", err)
		}
		defer rows.Close()
		items := make([]repository.PolicyGraph, 0, page.Limit)
		for rows.Next() {
			g, err := scanPolicyGraph(rows)
			if err != nil {
				return fmt.Errorf("scan graph: %w", err)
			}
			items = append(items, g)
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("iterate graphs: %w", err)
		}
		res.Items = items
		if len(items) == page.Limit && len(items) > 0 {
			last := items[len(items)-1]
			res.NextCursor = encodeCursor(pageCursor{T: last.CreatedAt, I: last.ID})
		}
		return nil
	})
	return res, err
}

func (r *PolicyRepository) CreateBundle(ctx context.Context, tenantID uuid.UUID, b repository.PolicyBundle) (repository.PolicyBundle, error) {
	switch b.TargetType {
	case repository.PolicyBundleTargetEdge, repository.PolicyBundleTargetEndpoint,
		repository.PolicyBundleTargetCloud, repository.PolicyBundleTargetMobile:
	default:
		return repository.PolicyBundle{}, repository.ErrInvalidArgument
	}
	if len(b.Bundle) == 0 || len(b.Signature) == 0 {
		return repository.PolicyBundle{}, repository.ErrInvalidArgument
	}
	if b.ID == uuid.Nil {
		b.ID = uuid.New()
	}
	var out repository.PolicyBundle
	err := r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		// Confirm the parent graph belongs to this tenant. We
		// rely on RLS to filter the SELECT — a graph owned by a
		// different tenant returns zero rows here.
		var ownerTenant uuid.UUID
		err := tx.QueryRow(ctx,
			`SELECT tenant_id FROM policy_graphs WHERE id = $1::uuid`,
			b.PolicyGraphID,
		).Scan(&ownerTenant)
		if errors.Is(err, pgx.ErrNoRows) {
			return repository.ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("verify graph ownership: %w", err)
		}
		var keyID any
		if b.KeyID != "" {
			keyID = b.KeyID
		}
		// Compute sha256 in the database so the value is byte-
		// identical to the digest a Go caller would have produced
		// before the column existed (sha256(bundle)) — keeps in-
		// flight client ETag caches valid across the migration
		// boundary and avoids serialising a redundant 32-byte
		// parameter from the caller. Pgcrypto's `digest()` is
		// available because migration 001 enables the extension.
		row := tx.QueryRow(ctx, `
			INSERT INTO policy_bundles (id, policy_graph_id, target_type, bundle, signature, key_id, sha256)
			VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, digest($4, 'sha256'))
			RETURNING `+policyBundleSelectColumns,
			b.ID, b.PolicyGraphID, b.TargetType, b.Bundle, b.Signature, keyID,
		)
		out, err = scanPolicyBundle(row)
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
			return fmt.Errorf("insert bundle: %w", err)
		}
		return nil
	})
	return out, err
}

func (r *PolicyRepository) GetBundle(ctx context.Context, tenantID, id uuid.UUID) (repository.PolicyBundle, error) {
	var out repository.PolicyBundle
	err := r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx, `
			SELECT b.id, b.policy_graph_id, b.target_type, b.bundle, b.signature, COALESCE(b.key_id, ''), b.sha256, b.created_at
			FROM policy_bundles b
			JOIN policy_graphs g ON g.id = b.policy_graph_id
			WHERE b.id = $1::uuid
		`, id)
		var err error
		out, err = scanPolicyBundle(row)
		if errors.Is(err, pgx.ErrNoRows) {
			return repository.ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("select bundle: %w", err)
		}
		return nil
	})
	return out, err
}

func (r *PolicyRepository) GetLatestBundle(ctx context.Context, tenantID uuid.UUID, target repository.PolicyBundleTarget) (repository.PolicyBundle, error) {
	switch target {
	case repository.PolicyBundleTargetEdge, repository.PolicyBundleTargetEndpoint,
		repository.PolicyBundleTargetCloud, repository.PolicyBundleTargetMobile:
	default:
		return repository.PolicyBundle{}, repository.ErrInvalidArgument
	}
	var out repository.PolicyBundle
	err := r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx, `
			SELECT b.id, b.policy_graph_id, b.target_type, b.bundle, b.signature, COALESCE(b.key_id, ''), b.sha256, b.created_at
			FROM policy_bundles b
			JOIN policy_graphs g ON g.id = b.policy_graph_id
			WHERE b.target_type = $1
			ORDER BY g.version DESC, b.created_at DESC
			LIMIT 1
		`, target)
		var err error
		out, err = scanPolicyBundle(row)
		if errors.Is(err, pgx.ErrNoRows) {
			return repository.ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("select latest bundle: %w", err)
		}
		return nil
	})
	return out, err
}

// GetLatestBundleMetadata mirrors GetLatestBundle but never selects
// the bundle BYTEA. Same ordering (graph version desc, created_at
// desc) so HEAD and GET round-trip identical rows.
func (r *PolicyRepository) GetLatestBundleMetadata(ctx context.Context, tenantID uuid.UUID, target repository.PolicyBundleTarget) (repository.PolicyBundleMetadata, error) {
	switch target {
	case repository.PolicyBundleTargetEdge, repository.PolicyBundleTargetEndpoint,
		repository.PolicyBundleTargetCloud, repository.PolicyBundleTargetMobile:
	default:
		return repository.PolicyBundleMetadata{}, repository.ErrInvalidArgument
	}
	var out repository.PolicyBundleMetadata
	err := r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx, `
			SELECT `+policyBundleMetaSelectColumns+`
			FROM policy_bundles b
			JOIN policy_graphs g ON g.id = b.policy_graph_id
			WHERE b.target_type = $1
			ORDER BY g.version DESC, b.created_at DESC
			LIMIT 1
		`, target)
		var err error
		out, err = scanPolicyBundleMeta(row)
		if errors.Is(err, pgx.ErrNoRows) {
			return repository.ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("select latest bundle metadata: %w", err)
		}
		return nil
	})
	return out, err
}
