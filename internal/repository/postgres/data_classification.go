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

// DataClassificationRepository owns the data_classifications table.
type DataClassificationRepository struct{ s *Store }

const dataClassificationSelectColumns = `
	id, tenant_id, label, level, description, handling_rules, created_at, updated_at
`

func scanDataClassification(row pgx.Row) (repository.DataClassification, error) {
	var (
		dc    repository.DataClassification
		rules []byte
	)
	if err := row.Scan(&dc.ID, &dc.TenantID, &dc.Label, &dc.Level, &dc.Description, &rules, &dc.CreatedAt, &dc.UpdatedAt); err != nil {
		return repository.DataClassification{}, err
	}
	dc.HandlingRules = json.RawMessage(rules)
	return dc, nil
}

func (r *DataClassificationRepository) Create(ctx context.Context, tenantID uuid.UUID, dc repository.DataClassification) (repository.DataClassification, error) {
	if tenantID == uuid.Nil {
		return repository.DataClassification{}, repository.ErrInvalidArgument
	}
	if dc.ID == uuid.Nil {
		dc.ID = uuid.New()
	}
	if len(dc.HandlingRules) == 0 {
		dc.HandlingRules = json.RawMessage(`{}`)
	}
	var out repository.DataClassification
	err := r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		const q = `
			INSERT INTO data_classifications (id, tenant_id, label, level, description, handling_rules)
			VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6::jsonb)
			RETURNING ` + dataClassificationSelectColumns
		var err error
		out, err = scanDataClassification(tx.QueryRow(ctx, q, dc.ID, tenantID, dc.Label, string(dc.Level), dc.Description, []byte(dc.HandlingRules)))
		return mapWriteErr(err, "insert data classification")
	})
	return out, err
}

func (r *DataClassificationRepository) Get(ctx context.Context, tenantID, id uuid.UUID) (repository.DataClassification, error) {
	var out repository.DataClassification
	err := r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		const q = `SELECT ` + dataClassificationSelectColumns + ` FROM data_classifications WHERE id = $1::uuid`
		var err error
		out, err = scanDataClassification(tx.QueryRow(ctx, q, id))
		if errors.Is(err, pgx.ErrNoRows) {
			return repository.ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("select data classification: %w", err)
		}
		return nil
	})
	return out, err
}

func (r *DataClassificationRepository) GetByLevel(ctx context.Context, tenantID uuid.UUID, level repository.ClassificationLevel) (repository.DataClassification, error) {
	var out repository.DataClassification
	err := r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		const q = `SELECT ` + dataClassificationSelectColumns + ` FROM data_classifications WHERE level = $1`
		var err error
		out, err = scanDataClassification(tx.QueryRow(ctx, q, string(level)))
		if errors.Is(err, pgx.ErrNoRows) {
			return repository.ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("select data classification by level: %w", err)
		}
		return nil
	})
	return out, err
}

func (r *DataClassificationRepository) List(ctx context.Context, tenantID uuid.UUID, page repository.Page) (repository.PageResult[repository.DataClassification], error) {
	page = page.Normalize()
	cur, err := decodeCursor(page.After)
	if err != nil {
		return repository.PageResult[repository.DataClassification]{}, repository.ErrInvalidArgument
	}
	res := repository.PageResult[repository.DataClassification]{}
	err = r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		q, args := buildListQuery("data_classifications", dataClassificationSelectColumns, cur, page.Order, page.Limit)
		rows, err := tx.Query(ctx, q, args...)
		if err != nil {
			return fmt.Errorf("list data classifications: %w", err)
		}
		defer rows.Close()
		items := make([]repository.DataClassification, 0, page.Limit)
		for rows.Next() {
			dc, err := scanDataClassification(rows)
			if err != nil {
				return fmt.Errorf("scan data classification: %w", err)
			}
			items = append(items, dc)
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("iterate data classifications: %w", err)
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

func (r *DataClassificationRepository) Update(ctx context.Context, tenantID, id uuid.UUID, patch repository.DataClassificationPatch) (repository.DataClassification, error) {
	var labelArg, levelArg, descArg, rulesArg any
	if patch.Label != nil {
		labelArg = *patch.Label
	}
	if patch.Level != nil {
		levelArg = string(*patch.Level)
	}
	if patch.Description != nil {
		descArg = *patch.Description
	}
	if patch.HandlingRules != nil {
		rulesArg = []byte(*patch.HandlingRules)
	}
	var out repository.DataClassification
	err := r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		const q = `
			UPDATE data_classifications
			SET label          = COALESCE($2, label),
			    level          = COALESCE($3, level),
			    description    = COALESCE($4, description),
			    handling_rules = COALESCE($5::jsonb, handling_rules)
			WHERE id = $1::uuid
			RETURNING ` + dataClassificationSelectColumns
		var err error
		out, err = scanDataClassification(tx.QueryRow(ctx, q, id, labelArg, levelArg, descArg, rulesArg))
		if errors.Is(err, pgx.ErrNoRows) {
			return repository.ErrNotFound
		}
		return mapWriteErr(err, "update data classification")
	})
	return out, err
}

func (r *DataClassificationRepository) Delete(ctx context.Context, tenantID, id uuid.UUID) error {
	return r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		ct, err := tx.Exec(ctx, `DELETE FROM data_classifications WHERE id = $1::uuid`, id)
		if err != nil {
			return fmt.Errorf("delete data classification: %w", err)
		}
		if ct.RowsAffected() == 0 {
			return repository.ErrNotFound
		}
		return nil
	})
}
