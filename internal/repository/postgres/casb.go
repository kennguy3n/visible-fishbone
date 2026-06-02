package postgres

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// --- CASBConnectorRepository ---

type CASBConnectorRepository struct{ s *Store }

var _ repository.CASBConnectorRepository = (*CASBConnectorRepository)(nil)

func (r *CASBConnectorRepository) Create(
	ctx context.Context,
	tenantID uuid.UUID,
	c repository.CASBConnector,
) (repository.CASBConnector, error) {
	if c.ID == uuid.Nil {
		c.ID = uuid.New()
	}
	var out repository.CASBConnector
	err := r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			INSERT INTO casb_connectors (id, tenant_id, type, name, status, config, secret)
			VALUES ($1, $2, $3, $4, $5, $6, $7)
			RETURNING id, tenant_id, type, name, status, config, secret,
			          last_sync_at, created_at, updated_at`,
			c.ID, tenantID, c.Type, c.Name, c.Status, c.Config, c.Secret,
		).Scan(
			&out.ID, &out.TenantID, &out.Type, &out.Name, &out.Status,
			&out.Config, &out.Secret, &out.LastSyncAt, &out.CreatedAt, &out.UpdatedAt,
		)
	})
	if err != nil {
		if isUniqueViolation(err) {
			return repository.CASBConnector{}, repository.ErrConflict
		}
		if isForeignKeyViolation(err) {
			return repository.CASBConnector{}, repository.ErrNotFound
		}
		if isCheckViolation(err) {
			return repository.CASBConnector{}, repository.ErrInvalidArgument
		}
		return repository.CASBConnector{}, err
	}
	return out, nil
}

func (r *CASBConnectorRepository) Get(
	ctx context.Context,
	tenantID, id uuid.UUID,
) (repository.CASBConnector, error) {
	var out repository.CASBConnector
	err := r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			SELECT id, tenant_id, type, name, status, config, secret,
			       last_sync_at, created_at, updated_at
			FROM casb_connectors
			WHERE id = $1`, id,
		).Scan(
			&out.ID, &out.TenantID, &out.Type, &out.Name, &out.Status,
			&out.Config, &out.Secret, &out.LastSyncAt, &out.CreatedAt, &out.UpdatedAt,
		)
	})
	if err != nil {
		if err == pgx.ErrNoRows {
			return repository.CASBConnector{}, repository.ErrNotFound
		}
		return repository.CASBConnector{}, err
	}
	return out, nil
}

func (r *CASBConnectorRepository) List(
	ctx context.Context,
	tenantID uuid.UUID,
	page repository.Page,
) (repository.PageResult[repository.CASBConnector], error) {
	page = page.Normalize()
	var items []repository.CASBConnector
	err := r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT id, tenant_id, type, name, status, config, secret,
			       last_sync_at, created_at, updated_at
			FROM casb_connectors
			ORDER BY created_at DESC, id DESC
			LIMIT $1`, page.Limit+1)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var c repository.CASBConnector
			if err := rows.Scan(
				&c.ID, &c.TenantID, &c.Type, &c.Name, &c.Status,
				&c.Config, &c.Secret, &c.LastSyncAt, &c.CreatedAt, &c.UpdatedAt,
			); err != nil {
				return err
			}
			items = append(items, c)
		}
		return rows.Err()
	})
	if err != nil {
		return repository.PageResult[repository.CASBConnector]{}, err
	}
	var res repository.PageResult[repository.CASBConnector]
	if len(items) > page.Limit {
		items = items[:page.Limit]
	}
	res.Items = items
	if len(items) == page.Limit && len(items) > 0 {
		last := items[len(items)-1]
		res.NextCursor = encodeCursor(pageCursor{T: last.CreatedAt, I: last.ID})
	}
	return res, nil
}

func (r *CASBConnectorRepository) Update(
	ctx context.Context,
	tenantID uuid.UUID,
	c repository.CASBConnector,
) (repository.CASBConnector, error) {
	var out repository.CASBConnector
	err := r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			UPDATE casb_connectors
			SET name = $2, status = $3, config = $4, secret = $5, last_sync_at = $6
			WHERE id = $1
			RETURNING id, tenant_id, type, name, status, config, secret,
			          last_sync_at, created_at, updated_at`,
			c.ID, c.Name, c.Status, c.Config, c.Secret, c.LastSyncAt,
		).Scan(
			&out.ID, &out.TenantID, &out.Type, &out.Name, &out.Status,
			&out.Config, &out.Secret, &out.LastSyncAt, &out.CreatedAt, &out.UpdatedAt,
		)
	})
	if err != nil {
		if err == pgx.ErrNoRows {
			return repository.CASBConnector{}, repository.ErrNotFound
		}
		if isUniqueViolation(err) {
			return repository.CASBConnector{}, repository.ErrConflict
		}
		return repository.CASBConnector{}, err
	}
	return out, nil
}

func (r *CASBConnectorRepository) Delete(
	ctx context.Context,
	tenantID, id uuid.UUID,
) error {
	return r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM casb_connectors WHERE id = $1`, id)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return repository.ErrNotFound
		}
		return nil
	})
}

// --- CASBDiscoveredAppRepository ---

type CASBDiscoveredAppRepository struct{ s *Store }

var _ repository.CASBDiscoveredAppRepository = (*CASBDiscoveredAppRepository)(nil)

func (r *CASBDiscoveredAppRepository) Upsert(
	ctx context.Context,
	tenantID uuid.UUID,
	app repository.CASBDiscoveredApp,
) (repository.CASBDiscoveredApp, error) {
	if app.ID == uuid.Nil {
		app.ID = uuid.New()
	}
	var out repository.CASBDiscoveredApp
	err := r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			INSERT INTO casb_discovered_apps
			    (id, tenant_id, name, vendor, category, risk_score, users_count, first_seen, last_seen)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
			ON CONFLICT (tenant_id, name) DO UPDATE SET
			    vendor = EXCLUDED.vendor,
			    category = EXCLUDED.category,
			    risk_score = EXCLUDED.risk_score,
			    users_count = EXCLUDED.users_count,
			    last_seen = EXCLUDED.last_seen
			RETURNING id, tenant_id, name, vendor, category, risk_score,
			          users_count, first_seen, last_seen`,
			app.ID, tenantID, app.Name, app.Vendor, app.Category,
			app.RiskScore, app.UsersCount, app.FirstSeen, app.LastSeen,
		).Scan(
			&out.ID, &out.TenantID, &out.Name, &out.Vendor, &out.Category,
			&out.RiskScore, &out.UsersCount, &out.FirstSeen, &out.LastSeen,
		)
	})
	if err != nil {
		return repository.CASBDiscoveredApp{}, err
	}
	return out, nil
}

func (r *CASBDiscoveredAppRepository) List(
	ctx context.Context,
	tenantID uuid.UUID,
) ([]repository.CASBDiscoveredApp, error) {
	var apps []repository.CASBDiscoveredApp
	err := r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT id, tenant_id, name, vendor, category, risk_score,
			       users_count, first_seen, last_seen
			FROM casb_discovered_apps
			ORDER BY last_seen DESC`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var a repository.CASBDiscoveredApp
			if err := rows.Scan(
				&a.ID, &a.TenantID, &a.Name, &a.Vendor, &a.Category,
				&a.RiskScore, &a.UsersCount, &a.FirstSeen, &a.LastSeen,
			); err != nil {
				return err
			}
			apps = append(apps, a)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return apps, nil
}

func (r *CASBDiscoveredAppRepository) Get(
	ctx context.Context,
	tenantID, id uuid.UUID,
) (repository.CASBDiscoveredApp, error) {
	var out repository.CASBDiscoveredApp
	err := r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			SELECT id, tenant_id, name, vendor, category, risk_score,
			       users_count, first_seen, last_seen
			FROM casb_discovered_apps
			WHERE id = $1`, id,
		).Scan(
			&out.ID, &out.TenantID, &out.Name, &out.Vendor, &out.Category,
			&out.RiskScore, &out.UsersCount, &out.FirstSeen, &out.LastSeen,
		)
	})
	if err != nil {
		if err == pgx.ErrNoRows {
			return repository.CASBDiscoveredApp{}, repository.ErrNotFound
		}
		return repository.CASBDiscoveredApp{}, err
	}
	return out, nil
}

// --- CASBPostureCheckRepository ---

type CASBPostureCheckRepository struct{ s *Store }

var _ repository.CASBPostureCheckRepository = (*CASBPostureCheckRepository)(nil)

func (r *CASBPostureCheckRepository) Save(
	ctx context.Context,
	tenantID uuid.UUID,
	appID uuid.UUID,
	checks []repository.CASBPostureCheck,
) error {
	return r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx,
			`DELETE FROM casb_posture_checks WHERE app_id = $1`, appID); err != nil {
			return err
		}
		for _, c := range checks {
			id := c.ID
			if id == uuid.Nil {
				id = uuid.New()
			}
			assessedAt := c.AssessedAt
			if assessedAt.IsZero() {
				assessedAt = time.Now().UTC()
			}
			if _, err := tx.Exec(ctx, `
				INSERT INTO casb_posture_checks
				    (id, tenant_id, app_id, check_name, status, details, assessed_at)
				VALUES ($1, $2, $3, $4, $5, $6, $7)`,
				id, tenantID, appID, c.CheckName, c.Status, c.Details, assessedAt,
			); err != nil {
				return err
			}
		}
		return nil
	})
}

func (r *CASBPostureCheckRepository) GetLatest(
	ctx context.Context,
	tenantID uuid.UUID,
	appID uuid.UUID,
) ([]repository.CASBPostureCheck, error) {
	var checks []repository.CASBPostureCheck
	err := r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT id, tenant_id, app_id, check_name, status, details, assessed_at
			FROM casb_posture_checks
			WHERE app_id = $1
			ORDER BY assessed_at DESC`, appID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var c repository.CASBPostureCheck
			if err := rows.Scan(
				&c.ID, &c.TenantID, &c.AppID, &c.CheckName,
				&c.Status, &c.Details, &c.AssessedAt,
			); err != nil {
				return err
			}
			checks = append(checks, c)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return checks, nil
}
