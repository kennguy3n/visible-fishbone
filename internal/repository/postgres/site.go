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

// SiteRepository owns the sites table.
type SiteRepository struct{ s *Store }

const siteSelectColumns = `
	id, tenant_id, name, slug, template, config, created_at, updated_at
`

func scanSite(row pgx.Row) (repository.Site, error) {
	var (
		s   repository.Site
		cfg []byte
	)
	if err := row.Scan(&s.ID, &s.TenantID, &s.Name, &s.Slug, &s.Template, &cfg, &s.CreatedAt, &s.UpdatedAt); err != nil {
		return repository.Site{}, err
	}
	s.Config = json.RawMessage(cfg)
	return s, nil
}

func (r *SiteRepository) Create(ctx context.Context, tenantID uuid.UUID, site repository.Site) (repository.Site, error) {
	if tenantID == uuid.Nil || site.Slug == "" {
		return repository.Site{}, repository.ErrInvalidArgument
	}
	if site.ID == uuid.Nil {
		site.ID = uuid.New()
	}
	if len(site.Config) == 0 {
		site.Config = json.RawMessage(`{}`)
	}

	var out repository.Site
	err := r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		const q = `
			INSERT INTO sites (id, tenant_id, name, slug, template, config)
			VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6::jsonb)
			RETURNING ` + siteSelectColumns
		row := tx.QueryRow(ctx, q, site.ID, tenantID, site.Name, site.Slug, site.Template, []byte(site.Config))
		var err error
		out, err = scanSite(row)
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
			return fmt.Errorf("insert site: %w", err)
		}
		return nil
	})
	return out, err
}

func (r *SiteRepository) Get(ctx context.Context, tenantID, id uuid.UUID) (repository.Site, error) {
	var out repository.Site
	err := r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		const q = `SELECT ` + siteSelectColumns + ` FROM sites WHERE id = $1::uuid`
		row := tx.QueryRow(ctx, q, id)
		var err error
		out, err = scanSite(row)
		if errors.Is(err, pgx.ErrNoRows) {
			return repository.ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("select site: %w", err)
		}
		return nil
	})
	return out, err
}

func (r *SiteRepository) List(ctx context.Context, tenantID uuid.UUID, page repository.Page) (repository.PageResult[repository.Site], error) {
	page = page.Normalize()
	cur, err := decodeCursor(page.After)
	if err != nil {
		return repository.PageResult[repository.Site]{}, repository.ErrInvalidArgument
	}
	res := repository.PageResult[repository.Site]{}
	err = r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		q, args := buildListQuery("sites", siteSelectColumns, cur, page.Order, page.Limit)
		rows, err := tx.Query(ctx, q, args...)
		if err != nil {
			return fmt.Errorf("list sites: %w", err)
		}
		defer rows.Close()
		items := make([]repository.Site, 0, page.Limit)
		for rows.Next() {
			s, err := scanSite(rows)
			if err != nil {
				return fmt.Errorf("scan site: %w", err)
			}
			items = append(items, s)
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("iterate sites: %w", err)
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

func (r *SiteRepository) Update(ctx context.Context, tenantID uuid.UUID, site repository.Site) (repository.Site, error) {
	if tenantID == uuid.Nil || site.ID == uuid.Nil {
		return repository.Site{}, repository.ErrInvalidArgument
	}
	var out repository.Site
	err := r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		const q = `
			UPDATE sites
			SET name     = COALESCE(NULLIF($2, ''), name),
			    slug     = COALESCE(NULLIF($3, ''), slug),
			    template = COALESCE(NULLIF($4, ''), template),
			    config   = COALESCE($5::jsonb, config)
			WHERE id = $1::uuid
			RETURNING ` + siteSelectColumns
		var cfg any
		if len(site.Config) > 0 {
			cfg = []byte(site.Config)
		}
		row := tx.QueryRow(ctx, q, site.ID, site.Name, site.Slug, string(site.Template), cfg)
		var err error
		out, err = scanSite(row)
		if errors.Is(err, pgx.ErrNoRows) {
			return repository.ErrNotFound
		}
		if isUniqueViolation(err) {
			return repository.ErrConflict
		}
		if isCheckViolation(err) {
			return repository.ErrInvalidArgument
		}
		if err != nil {
			return fmt.Errorf("update site: %w", err)
		}
		return nil
	})
	return out, err
}

func (r *SiteRepository) Delete(ctx context.Context, tenantID, id uuid.UUID) error {
	return r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		ct, err := tx.Exec(ctx, `DELETE FROM sites WHERE id = $1::uuid`, id)
		if err != nil {
			return fmt.Errorf("delete site: %w", err)
		}
		if ct.RowsAffected() == 0 {
			return repository.ErrNotFound
		}
		return nil
	})
}

// buildListQuery composes the standard cursor-paginated SELECT for
// any tenant-scoped table whose sort key is (created_at, id). The
// table name and column list are caller-supplied so each repository
// can reuse the same shape without copy-pasting the cursor logic.
func buildListQuery(table, cols string, cur pageCursor, order repository.SortOrder, limit int) (string, []any) {
	var cmp string
	var dir string
	if order == repository.SortAsc {
		cmp = ">"
		dir = "ASC"
	} else {
		cmp = "<"
		dir = "DESC"
	}
	var (
		args = []any{nil, nil, limit}
	)
	if !cur.T.IsZero() || cur.I != uuid.Nil {
		args[0] = cur.T
		args[1] = cur.I
	}
	q := fmt.Sprintf(`
		SELECT %s
		FROM %s
		WHERE ($1::timestamptz IS NULL OR (created_at, id) %s ($1::timestamptz, $2::uuid))
		ORDER BY created_at %s, id %s
		LIMIT $3
	`, cols, table, cmp, dir, dir)
	return q, args
}
