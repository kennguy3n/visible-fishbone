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

// DLPModelRepository owns the dlp_ml_models table and the single
// per-tenant dlp_ml_model_assignments row.
type DLPModelRepository struct{ s *Store }

const dlpModelSelectColumns = `
	id, tenant_id, name, version, status, entity_classes,
	object_key, size_bytes, sha256, signature, created_at, updated_at
`

// dlpModelSelectColumnsM is the m-qualified column list for the
// assignment JOIN, where tenant_id/id appear in both tables.
const dlpModelSelectColumnsM = `
	m.id, m.tenant_id, m.name, m.version, m.status, m.entity_classes,
	m.object_key, m.size_bytes, m.sha256, m.signature, m.created_at, m.updated_at
`

func scanDLPModel(row pgx.Row) (repository.DLPModel, error) {
	var (
		m       repository.DLPModel
		classes []byte
	)
	if err := row.Scan(
		&m.ID, &m.TenantID, &m.Name, &m.Version, &m.Status, &classes,
		&m.ObjectKey, &m.SizeBytes, &m.SHA256, &m.Signature, &m.CreatedAt, &m.UpdatedAt,
	); err != nil {
		return repository.DLPModel{}, err
	}
	if len(classes) > 0 {
		if err := json.Unmarshal(classes, &m.EntityClasses); err != nil {
			return repository.DLPModel{}, fmt.Errorf("decode entity classes: %w", err)
		}
	}
	return m, nil
}

func (r *DLPModelRepository) CreateModel(ctx context.Context, tenantID uuid.UUID, m repository.DLPModel) (repository.DLPModel, error) {
	if tenantID == uuid.Nil || m.Name == "" {
		return repository.DLPModel{}, repository.ErrInvalidArgument
	}
	if m.ID == uuid.Nil {
		m.ID = uuid.New()
	}
	if m.Status == "" {
		m.Status = repository.DLPModelStatusDraft
	}
	classes, err := json.Marshal(m.EntityClasses)
	if err != nil {
		return repository.DLPModel{}, repository.ErrInvalidArgument
	}
	var out repository.DLPModel
	err = r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		const q = `
			INSERT INTO dlp_ml_models
				(id, tenant_id, name, version, status, entity_classes, object_key, size_bytes, sha256, signature)
			VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6::jsonb, $7, $8, $9, $10)
			RETURNING ` + dlpModelSelectColumns
		var err error
		out, err = scanDLPModel(tx.QueryRow(ctx, q,
			m.ID, tenantID, m.Name, m.Version, string(m.Status), classes,
			m.ObjectKey, m.SizeBytes, m.SHA256, m.Signature))
		return mapWriteErr(err, "insert dlp model")
	})
	return out, err
}

func (r *DLPModelRepository) GetModel(ctx context.Context, tenantID, id uuid.UUID) (repository.DLPModel, error) {
	var out repository.DLPModel
	err := r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		const q = `SELECT ` + dlpModelSelectColumns + ` FROM dlp_ml_models WHERE id = $1::uuid`
		var err error
		out, err = scanDLPModel(tx.QueryRow(ctx, q, id))
		if errors.Is(err, pgx.ErrNoRows) {
			return repository.ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("select dlp model: %w", err)
		}
		return nil
	})
	return out, err
}

func (r *DLPModelRepository) ListModels(ctx context.Context, tenantID uuid.UUID, page repository.Page) (repository.PageResult[repository.DLPModel], error) {
	page = page.Normalize()
	cur, err := decodeCursor(page.After)
	if err != nil {
		return repository.PageResult[repository.DLPModel]{}, repository.ErrInvalidArgument
	}
	res := repository.PageResult[repository.DLPModel]{}
	err = r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		q, args := buildListQuery("dlp_ml_models", dlpModelSelectColumns, cur, page.Order, page.Limit)
		rows, err := tx.Query(ctx, q, args...)
		if err != nil {
			return fmt.Errorf("list dlp models: %w", err)
		}
		defer rows.Close()
		items := make([]repository.DLPModel, 0, page.Limit)
		for rows.Next() {
			m, err := scanDLPModel(rows)
			if err != nil {
				return fmt.Errorf("scan dlp model: %w", err)
			}
			items = append(items, m)
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("iterate dlp models: %w", err)
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

func (r *DLPModelRepository) UpdateModel(ctx context.Context, tenantID, id uuid.UUID, patch repository.DLPModelPatch) (repository.DLPModel, error) {
	var statusArg, sigArg, classesArg any
	if patch.Status != nil {
		statusArg = string(*patch.Status)
	}
	if patch.Signature != nil {
		sigArg = *patch.Signature
	}
	if patch.EntityClasses != nil {
		b, err := json.Marshal(*patch.EntityClasses)
		if err != nil {
			return repository.DLPModel{}, repository.ErrInvalidArgument
		}
		classesArg = b
	}
	var out repository.DLPModel
	err := r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		const q = `
			UPDATE dlp_ml_models
			SET status         = COALESCE($2, status),
			    signature      = COALESCE($3, signature),
			    entity_classes = COALESCE($4::jsonb, entity_classes)
			WHERE id = $1::uuid
			RETURNING ` + dlpModelSelectColumns
		var err error
		out, err = scanDLPModel(tx.QueryRow(ctx, q, id, statusArg, sigArg, classesArg))
		if errors.Is(err, pgx.ErrNoRows) {
			return repository.ErrNotFound
		}
		return mapWriteErr(err, "update dlp model")
	})
	return out, err
}

func (r *DLPModelRepository) DeleteModel(ctx context.Context, tenantID, id uuid.UUID) error {
	return r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		// A model that is the tenant's active assignment cannot be
		// deleted out from under the endpoint bundle; the caller must
		// clear it first. We check explicitly rather than relying on the
		// ON DELETE CASCADE, which would silently drop the assignment.
		var assignedTo uuid.UUID
		err := tx.QueryRow(ctx,
			`SELECT model_id FROM dlp_ml_model_assignments WHERE model_id = $1::uuid`, id).Scan(&assignedTo)
		switch {
		case err == nil:
			return repository.ErrConflict
		case errors.Is(err, pgx.ErrNoRows):
			// not assigned — proceed
		default:
			return fmt.Errorf("check dlp model assignment: %w", err)
		}
		ct, err := tx.Exec(ctx, `DELETE FROM dlp_ml_models WHERE id = $1::uuid`, id)
		if err != nil {
			return fmt.Errorf("delete dlp model: %w", err)
		}
		if ct.RowsAffected() == 0 {
			return repository.ErrNotFound
		}
		return nil
	})
}

func (r *DLPModelRepository) AssignModel(ctx context.Context, tenantID, modelID uuid.UUID) (repository.DLPModelAssignment, error) {
	if tenantID == uuid.Nil {
		return repository.DLPModelAssignment{}, repository.ErrInvalidArgument
	}
	var out repository.DLPModelAssignment
	err := r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		// Verify the model exists for this tenant (RLS scopes the read).
		var exists bool
		if err := tx.QueryRow(ctx,
			`SELECT EXISTS(SELECT 1 FROM dlp_ml_models WHERE id = $1::uuid)`, modelID).Scan(&exists); err != nil {
			return fmt.Errorf("verify dlp model: %w", err)
		}
		if !exists {
			return repository.ErrNotFound
		}
		const q = `
			INSERT INTO dlp_ml_model_assignments (tenant_id, model_id)
			VALUES ($1::uuid, $2::uuid)
			ON CONFLICT (tenant_id) DO UPDATE SET model_id = EXCLUDED.model_id, assigned_at = NOW()
			RETURNING tenant_id, model_id, assigned_at`
		if err := tx.QueryRow(ctx, q, tenantID, modelID).Scan(&out.TenantID, &out.ModelID, &out.AssignedAt); err != nil {
			return mapWriteErr(err, "assign dlp model")
		}
		return nil
	})
	return out, err
}

func (r *DLPModelRepository) ClearAssignment(ctx context.Context, tenantID uuid.UUID) error {
	return r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		// Idempotent: clearing an absent assignment is a no-op.
		if _, err := tx.Exec(ctx, `DELETE FROM dlp_ml_model_assignments WHERE tenant_id = $1::uuid`, tenantID); err != nil {
			return fmt.Errorf("clear dlp model assignment: %w", err)
		}
		return nil
	})
}

func (r *DLPModelRepository) GetAssignedModel(ctx context.Context, tenantID uuid.UUID) (repository.DLPModel, error) {
	var out repository.DLPModel
	err := r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		const q = `
			SELECT ` + dlpModelSelectColumnsM + `
			FROM dlp_ml_models m
			JOIN dlp_ml_model_assignments a ON a.model_id = m.id
			WHERE a.tenant_id = $1::uuid`
		var err error
		out, err = scanDLPModel(tx.QueryRow(ctx, q, tenantID))
		if errors.Is(err, pgx.ErrNoRows) {
			return repository.ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("select assigned dlp model: %w", err)
		}
		return nil
	})
	return out, err
}
