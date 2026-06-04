package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// DeviceRepository owns the devices table.
type DeviceRepository struct{ s *Store }

const deviceSelectColumns = `
	id, tenant_id, site_id, name, platform,
	COALESCE(public_key_ed25519, ''),
	enrolled_at, last_seen_at, status, posture,
	created_at, updated_at
`

func scanDevice(row pgx.Row) (repository.Device, error) {
	var (
		d        repository.Device
		siteID   nullableUUID
		enrolled deletedAtScan
		lastSeen deletedAtScan
		posture  []byte
	)
	if err := row.Scan(
		&d.ID, &d.TenantID, &siteID, &d.Name, &d.Platform, &d.PublicKeyEd25519,
		&enrolled, &lastSeen, &d.Status, &posture, &d.CreatedAt, &d.UpdatedAt,
	); err != nil {
		return repository.Device{}, err
	}
	if siteID.Valid {
		id := siteID.ID
		d.SiteID = &id
	}
	if enrolled.Valid {
		t := enrolled.Time
		d.EnrolledAt = &t
	}
	if lastSeen.Valid {
		t := lastSeen.Time
		d.LastSeenAt = &t
	}
	if len(posture) > 0 {
		// Decode into the typed Posture; preserve unknown fields
		// in the Extra blob so the schema can evolve without
		// migrations.
		if err := json.Unmarshal(posture, &d.Posture); err != nil {
			return repository.Device{}, fmt.Errorf("decode posture: %w", err)
		}
	}
	return d, nil
}

func (r *DeviceRepository) Create(ctx context.Context, tenantID uuid.UUID, d repository.Device) (repository.Device, error) {
	if tenantID == uuid.Nil || d.Platform == "" {
		return repository.Device{}, repository.ErrInvalidArgument
	}
	if d.ID == uuid.Nil {
		d.ID = uuid.New()
	}
	if d.Status == "" {
		d.Status = repository.DeviceStatusPending
	}
	postureJSON, err := json.Marshal(d.Posture)
	if err != nil {
		return repository.Device{}, fmt.Errorf("encode posture: %w", err)
	}

	var out repository.Device
	err = r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		const q = `
			INSERT INTO devices (id, tenant_id, site_id, name, platform,
			                    public_key_ed25519, enrolled_at, last_seen_at,
			                    status, posture)
			VALUES ($1::uuid, $2::uuid, $3, $4, $5,
			        NULLIF($6, ''), $7, $8, $9, $10::jsonb)
			RETURNING ` + deviceSelectColumns
		var siteID any
		if d.SiteID != nil {
			siteID = *d.SiteID
		}
		row := tx.QueryRow(ctx, q,
			d.ID, tenantID, siteID, d.Name, d.Platform,
			d.PublicKeyEd25519, d.EnrolledAt, d.LastSeenAt,
			d.Status, postureJSON,
		)
		var err error
		out, err = scanDevice(row)
		if err != nil {
			if isUniqueViolation(err) {
				return repository.ErrConflict
			}
			if isCheckViolation(err) {
				return repository.ErrInvalidArgument
			}
			if isForeignKeyViolation(err) {
				return repository.ErrInvalidArgument
			}
			return fmt.Errorf("insert device: %w", err)
		}
		return nil
	})
	return out, err
}

func (r *DeviceRepository) Get(ctx context.Context, tenantID, id uuid.UUID) (repository.Device, error) {
	var out repository.Device
	err := r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx, `SELECT `+deviceSelectColumns+` FROM devices WHERE id = $1::uuid`, id)
		var err error
		out, err = scanDevice(row)
		if errors.Is(err, pgx.ErrNoRows) {
			return repository.ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("select device: %w", err)
		}
		return nil
	})
	return out, err
}

func (r *DeviceRepository) GetByPublicKey(ctx context.Context, tenantID uuid.UUID, publicKey string) (repository.Device, error) {
	if publicKey == "" {
		return repository.Device{}, repository.ErrNotFound
	}
	var out repository.Device
	err := r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx,
			`SELECT `+deviceSelectColumns+` FROM devices WHERE public_key_ed25519 = $1`,
			publicKey,
		)
		var err error
		out, err = scanDevice(row)
		if errors.Is(err, pgx.ErrNoRows) {
			return repository.ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("select device by public key: %w", err)
		}
		return nil
	})
	return out, err
}

func (r *DeviceRepository) List(ctx context.Context, tenantID uuid.UUID, filter repository.DeviceListFilter, page repository.Page) (repository.PageResult[repository.Device], error) {
	page = page.Normalize()
	cur, err := decodeCursor(page.After)
	if err != nil {
		return repository.PageResult[repository.Device]{}, repository.ErrInvalidArgument
	}
	// Build dynamic WHERE clause covering optional filters in
	// addition to the cursor comparison.
	var (
		where []string
		args  []any
	)
	args = append(args, nil) // $1 cursor T
	args = append(args, nil) // $2 cursor I
	args = append(args, page.Limit)
	if !cur.T.IsZero() || cur.I != uuid.Nil {
		args[0] = cur.T
		args[1] = cur.I
	}
	cmp := "<"
	dir := "DESC"
	if page.Order == repository.SortAsc {
		cmp = ">"
		dir = "ASC"
	}
	where = append(where, fmt.Sprintf("($1::timestamptz IS NULL OR (created_at, id) %s ($1::timestamptz, $2::uuid))", cmp))
	if filter.Platform != "" {
		args = append(args, string(filter.Platform))
		where = append(where, fmt.Sprintf("platform = $%d", len(args)))
	}
	if filter.Status != "" {
		args = append(args, string(filter.Status))
		where = append(where, fmt.Sprintf("status = $%d", len(args)))
	}
	if filter.SiteID != nil {
		args = append(args, *filter.SiteID)
		where = append(where, fmt.Sprintf("site_id = $%d::uuid", len(args)))
	}
	q := fmt.Sprintf(`
		SELECT %s
		FROM devices
		WHERE %s
		ORDER BY created_at %s, id %s
		LIMIT $3
	`, deviceSelectColumns, strings.Join(where, " AND "), dir, dir)

	res := repository.PageResult[repository.Device]{}
	err = r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, q, args...)
		if err != nil {
			return fmt.Errorf("list devices: %w", err)
		}
		defer rows.Close()
		items := make([]repository.Device, 0, page.Limit)
		for rows.Next() {
			d, err := scanDevice(rows)
			if err != nil {
				return fmt.Errorf("scan device: %w", err)
			}
			items = append(items, d)
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("iterate devices: %w", err)
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

func (r *DeviceRepository) UpdateLastSeen(ctx context.Context, tenantID, id uuid.UUID, at time.Time) error {
	return r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		ct, err := tx.Exec(ctx, `UPDATE devices SET last_seen_at = $2 WHERE id = $1::uuid`, id, at.UTC())
		if err != nil {
			return fmt.Errorf("update last_seen_at: %w", err)
		}
		if ct.RowsAffected() == 0 {
			return repository.ErrNotFound
		}
		return nil
	})
}

func (r *DeviceRepository) UpdatePosture(ctx context.Context, tenantID, id uuid.UUID, posture repository.Posture) error {
	postureJSON, err := json.Marshal(posture)
	if err != nil {
		return fmt.Errorf("encode posture: %w", err)
	}
	return r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		ct, err := tx.Exec(ctx,
			`UPDATE devices SET posture = $2::jsonb WHERE id = $1::uuid`,
			id, postureJSON,
		)
		if err != nil {
			return fmt.Errorf("update posture: %w", err)
		}
		if ct.RowsAffected() == 0 {
			return repository.ErrNotFound
		}
		return nil
	})
}

func (r *DeviceRepository) UpdateStatus(ctx context.Context, tenantID, id uuid.UUID, status repository.DeviceStatus) (repository.Device, error) {
	switch status {
	case repository.DeviceStatusPending, repository.DeviceStatusActive,
		repository.DeviceStatusSuspended, repository.DeviceStatusDeleted:
	default:
		return repository.Device{}, repository.ErrInvalidArgument
	}
	var out repository.Device
	err := r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		const q = `
			UPDATE devices
			SET status      = $2,
			    enrolled_at = CASE
			        WHEN $2 = 'active' AND enrolled_at IS NULL THEN NOW()
			        ELSE enrolled_at
			    END
			WHERE id = $1::uuid
			RETURNING ` + deviceSelectColumns
		row := tx.QueryRow(ctx, q, id, string(status))
		var err error
		out, err = scanDevice(row)
		if errors.Is(err, pgx.ErrNoRows) {
			return repository.ErrNotFound
		}
		if isCheckViolation(err) {
			return repository.ErrInvalidArgument
		}
		if err != nil {
			return fmt.Errorf("update status: %w", err)
		}
		return nil
	})
	return out, err
}

func (r *DeviceRepository) TransitionStatus(ctx context.Context, tenantID, id uuid.UUID, from, to repository.DeviceStatus) (repository.Device, error) {
	switch to {
	case repository.DeviceStatusPending, repository.DeviceStatusActive,
		repository.DeviceStatusSuspended, repository.DeviceStatusDeleted:
	default:
		return repository.Device{}, repository.ErrInvalidArgument
	}
	var out repository.Device
	err := r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		// Single atomic UPDATE: the `status = $3` precondition prevents
		// the TOCTOU window present in a Get+UpdateStatus pair. No rows
		// means either the device doesn't exist (NotFound) or its status
		// no longer equals `from` (Forbidden); a follow-up lookup
		// disambiguates.
		const q = `
			UPDATE devices
			SET status      = $2,
			    enrolled_at = CASE
			        WHEN $2 = 'active' AND enrolled_at IS NULL THEN NOW()
			        ELSE enrolled_at
			    END
			WHERE id = $1::uuid AND status = $3
			RETURNING ` + deviceSelectColumns
		row := tx.QueryRow(ctx, q, id, string(to), string(from))
		var serr error
		out, serr = scanDevice(row)
		if serr == nil {
			return nil
		}
		if isCheckViolation(serr) {
			return repository.ErrInvalidArgument
		}
		if !errors.Is(serr, pgx.ErrNoRows) {
			return fmt.Errorf("transition status: %w", serr)
		}
		var cur string
		if scanErr := tx.QueryRow(ctx, `SELECT status FROM devices WHERE id = $1::uuid`, id).Scan(&cur); scanErr != nil {
			if errors.Is(scanErr, pgx.ErrNoRows) {
				return repository.ErrNotFound
			}
			return fmt.Errorf("transition status lookup: %w", scanErr)
		}
		return repository.ErrForbidden
	})
	return out, err
}
