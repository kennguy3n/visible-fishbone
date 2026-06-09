package postgres

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// AppRegistryRepository owns the global app_registry table. NOT
// tenant-scoped — every tenant reads the same data. Writes happen
// in a system-role transaction so callers without a tenant context
// (e.g. the vendor-endpoint sync worker, the admin REST handler)
// can still mutate the catalog.
type AppRegistryRepository struct{ s *Store }

// AppRegistryOverrideRepository owns the per-tenant
// app_registry_overrides table. All operations run inside a
// withTenant transaction so the `sng.tenant_id` GUC is set and RLS
// isolates the rows.
type AppRegistryOverrideRepository struct{ s *Store }

// appRegistryCols is the shared SELECT list for app_registry. ip_ranges
// is cast to text[] because pgx v5 has no binary decode plan for cidr[]
// (OID 651) into []string; scanAppRegistry parses the text form back into
// netip.Prefix.
const appRegistryCols = `
id, name, COALESCE(vendor, ''), traffic_class, scope,
COALESCE(regions, ARRAY[]::text[]),
domains,
COALESCE(ip_ranges, ARRAY[]::cidr[])::text[],
COALESCE(cert_pins, ARRAY[]::text[]),
COALESCE(metadata_url, ''),
COALESCE(category, ''),
is_system, created_at, updated_at
`

func scanAppRegistry(row pgx.Row) (repository.AppRegistry, error) {
	var (
		app       repository.AppRegistry
		rawRanges []string
	)
	if err := row.Scan(
		&app.ID, &app.Name, &app.Vendor, &app.TrafficClass, &app.Scope,
		&app.Regions, &app.Domains, &rawRanges, &app.CertPins,
		&app.MetadataURL, &app.Category,
		&app.IsSystem, &app.CreatedAt, &app.UpdatedAt,
	); err != nil {
		return repository.AppRegistry{}, err
	}
	if len(rawRanges) > 0 {
		app.IPRanges = make([]netip.Prefix, 0, len(rawRanges))
		for _, raw := range rawRanges {
			p, err := netip.ParsePrefix(raw)
			if err != nil {
				return repository.AppRegistry{}, fmt.Errorf("parse cidr %q: %w", raw, err)
			}
			app.IPRanges = append(app.IPRanges, p)
		}
	}
	return app, nil
}

func ipRangesToText(in []netip.Prefix) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, len(in))
	for i, p := range in {
		out[i] = p.String()
	}
	return out
}

func (r *AppRegistryRepository) Create(ctx context.Context, app repository.AppRegistry) (repository.AppRegistry, error) {
	if strings.TrimSpace(app.Name) == "" || !app.TrafficClass.IsValid() ||
		!app.Scope.IsValid() || len(app.Domains) == 0 {
		return repository.AppRegistry{}, repository.ErrInvalidArgument
	}
	if app.ID == uuid.Nil {
		app.ID = uuid.New()
	}
	var out repository.AppRegistry
	err := r.s.withSystem(ctx, func(tx pgx.Tx) error {
		const q = `
INSERT INTO app_registry (id, name, vendor, traffic_class, scope, regions, domains,
                          ip_ranges, cert_pins, metadata_url, category, is_system)
VALUES ($1::uuid, $2, NULLIF($3, ''), $4, $5, $6, $7, $8::cidr[], $9, NULLIF($10, ''), NULLIF($11, ''), $12)
RETURNING ` + appRegistryCols
		row := tx.QueryRow(ctx, q,
			app.ID, app.Name, app.Vendor, string(app.TrafficClass), string(app.Scope),
			nullableStrings(app.Regions), app.Domains,
			ipRangesToText(app.IPRanges),
			nullableStrings(app.CertPins),
			app.MetadataURL, app.Category, app.IsSystem,
		)
		var err error
		out, err = scanAppRegistry(row)
		if err != nil {
			if isUniqueViolation(err) {
				return repository.ErrConflict
			}
			if isCheckViolation(err) {
				return repository.ErrInvalidArgument
			}
			return fmt.Errorf("insert app_registry: %w", err)
		}
		return nil
	})
	return out, err
}

func (r *AppRegistryRepository) Get(ctx context.Context, id uuid.UUID) (repository.AppRegistry, error) {
	var out repository.AppRegistry
	err := r.s.withSystem(ctx, func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx, `SELECT `+appRegistryCols+` FROM app_registry WHERE id = $1::uuid`, id)
		var err error
		out, err = scanAppRegistry(row)
		if errors.Is(err, pgx.ErrNoRows) {
			return repository.ErrNotFound
		}
		return err
	})
	return out, err
}

func (r *AppRegistryRepository) GetByName(ctx context.Context, name string) (repository.AppRegistry, error) {
	var out repository.AppRegistry
	err := r.s.withSystem(ctx, func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx, `SELECT `+appRegistryCols+` FROM app_registry WHERE name = $1`, name)
		var err error
		out, err = scanAppRegistry(row)
		if errors.Is(err, pgx.ErrNoRows) {
			return repository.ErrNotFound
		}
		return err
	})
	return out, err
}

func (r *AppRegistryRepository) Update(ctx context.Context, app repository.AppRegistry) (repository.AppRegistry, error) {
	if app.ID == uuid.Nil || strings.TrimSpace(app.Name) == "" ||
		!app.TrafficClass.IsValid() || !app.Scope.IsValid() || len(app.Domains) == 0 {
		return repository.AppRegistry{}, repository.ErrInvalidArgument
	}
	var out repository.AppRegistry
	err := r.s.withSystem(ctx, func(tx pgx.Tx) error {
		const q = `
UPDATE app_registry SET
    name           = $2,
    vendor         = NULLIF($3, ''),
    traffic_class  = $4,
    scope          = $5,
    regions        = $6,
    domains        = $7,
    ip_ranges      = $8::cidr[],
    cert_pins      = $9,
    metadata_url   = NULLIF($10, ''),
    category       = NULLIF($11, ''),
    is_system      = $12
WHERE id = $1::uuid
RETURNING ` + appRegistryCols
		row := tx.QueryRow(ctx, q,
			app.ID, app.Name, app.Vendor, string(app.TrafficClass), string(app.Scope),
			nullableStrings(app.Regions), app.Domains,
			ipRangesToText(app.IPRanges),
			nullableStrings(app.CertPins),
			app.MetadataURL, app.Category, app.IsSystem,
		)
		var err error
		out, err = scanAppRegistry(row)
		if errors.Is(err, pgx.ErrNoRows) {
			return repository.ErrNotFound
		}
		if isUniqueViolation(err) {
			return repository.ErrConflict
		}
		if isCheckViolation(err) {
			return repository.ErrInvalidArgument
		}
		return err
	})
	return out, err
}

func (r *AppRegistryRepository) Delete(ctx context.Context, id uuid.UUID) error {
	return r.s.withSystem(ctx, func(tx pgx.Tx) error {
		ct, err := tx.Exec(ctx, `DELETE FROM app_registry WHERE id = $1::uuid`, id)
		if err != nil {
			return fmt.Errorf("delete app_registry: %w", err)
		}
		if ct.RowsAffected() == 0 {
			return repository.ErrNotFound
		}
		return nil
	})
}

func (r *AppRegistryRepository) List(ctx context.Context, filter repository.AppRegistryFilter, page repository.Page) (repository.PageResult[repository.AppRegistry], error) {
	page = page.Normalize()
	cur, err := decodeCursor(page.After)
	if err != nil {
		return repository.PageResult[repository.AppRegistry]{}, repository.ErrInvalidArgument
	}
	res := repository.PageResult[repository.AppRegistry]{}
	err = r.s.withSystem(ctx, func(tx pgx.Tx) error {
		var cmp, dir string
		if page.Order == repository.SortAsc {
			cmp, dir = ">", "ASC"
		} else {
			cmp, dir = "<", "DESC"
		}
		// Filter conditions are appended as additional AND clauses
		// after the cursor predicate. NULL parameters short-circuit
		// to "all rows match" so the same query handles an empty
		// filter without dynamic SQL construction.
		q := fmt.Sprintf(`
SELECT %s
FROM app_registry
WHERE ($1::timestamptz IS NULL OR (created_at, id) %s ($1::timestamptz, $2::uuid))
  AND ($4::text IS NULL OR traffic_class = $4)
  AND ($5::text IS NULL OR scope = $5)
  AND ($6::text IS NULL OR $6 = ANY(regions))
  AND ($7::text IS NULL OR lower(category) = lower($7))
ORDER BY created_at %s, id %s
LIMIT $3`, appRegistryCols, cmp, dir, dir)
		args := []any{nil, nil, page.Limit,
			nilableStr(string(filter.TrafficClass)),
			nilableStr(string(filter.Scope)),
			nilableStr(filter.Region),
			nilableStr(filter.Category),
		}
		if !cur.T.IsZero() || cur.I != uuid.Nil {
			args[0] = cur.T
			args[1] = cur.I
		}
		rows, qerr := tx.Query(ctx, q, args...)
		if qerr != nil {
			return fmt.Errorf("list app_registry: %w", qerr)
		}
		defer rows.Close()
		items := make([]repository.AppRegistry, 0, page.Limit)
		for rows.Next() {
			a, err := scanAppRegistry(rows)
			if err != nil {
				return fmt.Errorf("scan app_registry: %w", err)
			}
			items = append(items, a)
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("iterate app_registry: %w", err)
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

func (r *AppRegistryRepository) ListAll(ctx context.Context) ([]repository.AppRegistry, error) {
	var out []repository.AppRegistry
	err := r.s.withSystem(ctx, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+appRegistryCols+` FROM app_registry ORDER BY name`)
		if err != nil {
			return fmt.Errorf("list app_registry: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			a, err := scanAppRegistry(rows)
			if err != nil {
				return fmt.Errorf("scan app_registry: %w", err)
			}
			out = append(out, a)
		}
		return rows.Err()
	})
	return out, err
}

func (r *AppRegistryRepository) ListWithMetadataURL(ctx context.Context) ([]repository.AppRegistry, error) {
	var out []repository.AppRegistry
	err := r.s.withSystem(ctx, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+appRegistryCols+
			` FROM app_registry WHERE metadata_url IS NOT NULL AND metadata_url <> ''`)
		if err != nil {
			return fmt.Errorf("list app_registry sync: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			a, err := scanAppRegistry(rows)
			if err != nil {
				return fmt.Errorf("scan app_registry: %w", err)
			}
			out = append(out, a)
		}
		return rows.Err()
	})
	return out, err
}

// --- AppRegistryOverride --------------------------------------------------

const appOverrideCols = `
id, tenant_id, app_id,
COALESCE(custom_domains, ARRAY[]::text[]),
traffic_class_override, expires_at, COALESCE(reason, ''),
created_at, updated_at
`

func scanAppOverride(row pgx.Row) (repository.AppRegistryOverride, error) {
	var (
		ov        repository.AppRegistryOverride
		appID     *uuid.UUID
		expiresAt *time.Time
	)
	if err := row.Scan(
		&ov.ID, &ov.TenantID, &appID,
		&ov.CustomDomains,
		&ov.TrafficClassOverride, &expiresAt, &ov.Reason,
		&ov.CreatedAt, &ov.UpdatedAt,
	); err != nil {
		return repository.AppRegistryOverride{}, err
	}
	ov.AppID = appID
	ov.ExpiresAt = expiresAt
	return ov, nil
}

func (r *AppRegistryOverrideRepository) Create(ctx context.Context, tenantID uuid.UUID, ov repository.AppRegistryOverride) (repository.AppRegistryOverride, error) {
	if tenantID == uuid.Nil || !ov.TrafficClassOverride.IsValid() {
		return repository.AppRegistryOverride{}, repository.ErrInvalidArgument
	}
	hasApp := ov.AppID != nil
	hasCustom := len(ov.CustomDomains) > 0
	if hasApp == hasCustom {
		return repository.AppRegistryOverride{}, repository.ErrInvalidArgument
	}
	if ov.ID == uuid.Nil {
		ov.ID = uuid.New()
	}
	var out repository.AppRegistryOverride
	err := r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		const q = `
INSERT INTO app_registry_overrides (
    id, tenant_id, app_id, custom_domains, traffic_class_override, expires_at, reason
) VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, NULLIF($7, ''))
RETURNING ` + appOverrideCols
		row := tx.QueryRow(ctx, q,
			ov.ID, tenantID, ov.AppID,
			nullableStrings(ov.CustomDomains),
			string(ov.TrafficClassOverride),
			ov.ExpiresAt, ov.Reason,
		)
		var err error
		out, err = scanAppOverride(row)
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
			return fmt.Errorf("insert app_registry_overrides: %w", err)
		}
		return nil
	})
	return out, err
}

func (r *AppRegistryOverrideRepository) Get(ctx context.Context, tenantID, id uuid.UUID) (repository.AppRegistryOverride, error) {
	var out repository.AppRegistryOverride
	err := r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx, `SELECT `+appOverrideCols+
			` FROM app_registry_overrides WHERE id = $1::uuid`, id)
		var err error
		out, err = scanAppOverride(row)
		if errors.Is(err, pgx.ErrNoRows) {
			return repository.ErrNotFound
		}
		return err
	})
	return out, err
}

func (r *AppRegistryOverrideRepository) Delete(ctx context.Context, tenantID, id uuid.UUID) error {
	return r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		ct, err := tx.Exec(ctx, `DELETE FROM app_registry_overrides WHERE id = $1::uuid`, id)
		if err != nil {
			return fmt.Errorf("delete app_registry_overrides: %w", err)
		}
		if ct.RowsAffected() == 0 {
			return repository.ErrNotFound
		}
		return nil
	})
}

func (r *AppRegistryOverrideRepository) List(ctx context.Context, tenantID uuid.UUID, page repository.Page) (repository.PageResult[repository.AppRegistryOverride], error) {
	page = page.Normalize()
	cur, err := decodeCursor(page.After)
	if err != nil {
		return repository.PageResult[repository.AppRegistryOverride]{}, repository.ErrInvalidArgument
	}
	res := repository.PageResult[repository.AppRegistryOverride]{}
	err = r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		q, args := buildListQuery("app_registry_overrides", appOverrideCols, cur, page.Order, page.Limit)
		rows, qerr := tx.Query(ctx, q, args...)
		if qerr != nil {
			return fmt.Errorf("list app_registry_overrides: %w", qerr)
		}
		defer rows.Close()
		items := make([]repository.AppRegistryOverride, 0, page.Limit)
		for rows.Next() {
			ov, err := scanAppOverride(rows)
			if err != nil {
				return fmt.Errorf("scan app_registry_overrides: %w", err)
			}
			items = append(items, ov)
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("iterate app_registry_overrides: %w", err)
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

func (r *AppRegistryOverrideRepository) ListAll(ctx context.Context, tenantID uuid.UUID) ([]repository.AppRegistryOverride, error) {
	var out []repository.AppRegistryOverride
	err := r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+appOverrideCols+
			` FROM app_registry_overrides ORDER BY created_at DESC, id DESC`)
		if err != nil {
			return fmt.Errorf("list app_registry_overrides: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			ov, err := scanAppOverride(rows)
			if err != nil {
				return fmt.Errorf("scan app_registry_overrides: %w", err)
			}
			out = append(out, ov)
		}
		return rows.Err()
	})
	return out, err
}

func (r *AppRegistryOverrideRepository) DeleteExpired(ctx context.Context, now time.Time) (int, error) {
	var n int
	err := r.s.withSystem(ctx, func(tx pgx.Tx) error {
		ct, err := tx.Exec(ctx, `DELETE FROM app_registry_overrides WHERE expires_at IS NOT NULL AND expires_at <= $1`, now)
		if err != nil {
			return fmt.Errorf("delete expired app_registry_overrides: %w", err)
		}
		n = int(ct.RowsAffected())
		return nil
	})
	return n, err
}

// nullableStrings returns nil for an empty slice so the column is
// stored as SQL NULL rather than an empty array — matches the
// schema's NULL semantics on regions / cert_pins / custom_domains.
func nullableStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	return in
}

// nilableStr returns nil for "" so SQL `IS NULL` parameters
// short-circuit filter clauses cleanly.
func nilableStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}
