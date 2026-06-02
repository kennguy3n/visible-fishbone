package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// UserRepository owns the users table.
type UserRepository struct{ s *Store }

const userSelectColumns = `
	id, tenant_id, email, COALESCE(name, ''), COALESCE(external_id, ''),
	COALESCE(idp_subject, ''), status, created_at, updated_at
`

func scanUser(row pgx.Row) (repository.User, error) {
	var u repository.User
	if err := row.Scan(
		&u.ID, &u.TenantID, &u.Email, &u.Name, &u.ExternalID,
		&u.IDPSubject, &u.Status, &u.CreatedAt, &u.UpdatedAt,
	); err != nil {
		return repository.User{}, err
	}
	return u, nil
}

func (r *UserRepository) Create(ctx context.Context, tenantID uuid.UUID, u repository.User) (repository.User, error) {
	if tenantID == uuid.Nil || u.Email == "" {
		return repository.User{}, repository.ErrInvalidArgument
	}
	if u.ID == uuid.Nil {
		u.ID = uuid.New()
	}
	if u.Status == "" {
		u.Status = repository.UserStatusActive
	}
	var out repository.User
	err := r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		const q = `
			INSERT INTO users (id, tenant_id, email, name, external_id, idp_subject, status)
			VALUES ($1::uuid, $2::uuid, $3, NULLIF($4, ''), NULLIF($5, ''), NULLIF($6, ''), $7)
			RETURNING ` + userSelectColumns
		row := tx.QueryRow(ctx, q,
			u.ID, tenantID, u.Email, u.Name, u.ExternalID, u.IDPSubject, string(u.Status),
		)
		var err error
		out, err = scanUser(row)
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
			return fmt.Errorf("insert user: %w", err)
		}
		return nil
	})
	return out, err
}

func (r *UserRepository) Get(ctx context.Context, tenantID, id uuid.UUID) (repository.User, error) {
	var out repository.User
	err := r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx, `SELECT `+userSelectColumns+` FROM users WHERE id = $1::uuid`, id)
		var err error
		out, err = scanUser(row)
		if errors.Is(err, pgx.ErrNoRows) {
			return repository.ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("select user: %w", err)
		}
		return nil
	})
	return out, err
}

func (r *UserRepository) GetByEmail(ctx context.Context, tenantID uuid.UUID, email string) (repository.User, error) {
	var out repository.User
	err := r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx, `SELECT `+userSelectColumns+` FROM users WHERE lower(email) = lower($1)`, email)
		var err error
		out, err = scanUser(row)
		if errors.Is(err, pgx.ErrNoRows) {
			return repository.ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("select user by email: %w", err)
		}
		return nil
	})
	return out, err
}

func (r *UserRepository) List(ctx context.Context, tenantID uuid.UUID, page repository.Page) (repository.PageResult[repository.User], error) {
	page = page.Normalize()
	cur, err := decodeCursor(page.After)
	if err != nil {
		return repository.PageResult[repository.User]{}, repository.ErrInvalidArgument
	}
	res := repository.PageResult[repository.User]{}
	err = r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		q, args := buildListQuery("users", userSelectColumns, cur, page.Order, page.Limit)
		rows, err := tx.Query(ctx, q, args...)
		if err != nil {
			return fmt.Errorf("list users: %w", err)
		}
		defer rows.Close()
		items := make([]repository.User, 0, page.Limit)
		for rows.Next() {
			u, err := scanUser(rows)
			if err != nil {
				return fmt.Errorf("scan user: %w", err)
			}
			items = append(items, u)
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("iterate users: %w", err)
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

func (r *UserRepository) Update(ctx context.Context, tenantID uuid.UUID, u repository.User) (repository.User, error) {
	if tenantID == uuid.Nil || u.ID == uuid.Nil {
		return repository.User{}, repository.ErrInvalidArgument
	}
	var out repository.User
	err := r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		const q = `
			UPDATE users
			SET email       = COALESCE(NULLIF($2, ''), email),
			    name        = COALESCE(NULLIF($3, ''), name),
			    external_id = COALESCE(NULLIF($4, ''), external_id),
			    idp_subject = COALESCE(NULLIF($5, ''), idp_subject),
			    status      = COALESCE(NULLIF($6, ''), status)
			WHERE id = $1::uuid
			RETURNING ` + userSelectColumns
		row := tx.QueryRow(ctx, q, u.ID, u.Email, u.Name, u.ExternalID, u.IDPSubject, string(u.Status))
		var err error
		out, err = scanUser(row)
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
			return fmt.Errorf("update user: %w", err)
		}
		return nil
	})
	return out, err
}

func (r *UserRepository) ClearExternalID(ctx context.Context, tenantID, userID uuid.UUID) (repository.User, error) {
	if tenantID == uuid.Nil || userID == uuid.Nil {
		return repository.User{}, repository.ErrInvalidArgument
	}
	var out repository.User
	err := r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx, `
			UPDATE users SET external_id = NULL
			WHERE id = $1::uuid
			RETURNING `+userSelectColumns, userID)
		var err error
		out, err = scanUser(row)
		if errors.Is(err, pgx.ErrNoRows) {
			return repository.ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("clear external_id: %w", err)
		}
		return nil
	})
	return out, err
}

func (r *UserRepository) UpdateAndClearExternalID(ctx context.Context, tenantID uuid.UUID, u repository.User) (repository.User, error) {
	if tenantID == uuid.Nil || u.ID == uuid.Nil {
		return repository.User{}, repository.ErrInvalidArgument
	}
	var out repository.User
	err := r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		const q = `
			UPDATE users
			SET email       = COALESCE(NULLIF($2, ''), email),
			    name        = COALESCE(NULLIF($3, ''), name),
			    external_id = NULL,
			    idp_subject = COALESCE(NULLIF($4, ''), idp_subject),
			    status      = COALESCE(NULLIF($5, ''), status)
			WHERE id = $1::uuid
			RETURNING ` + userSelectColumns
		row := tx.QueryRow(ctx, q, u.ID, u.Email, u.Name, u.IDPSubject, string(u.Status))
		var err error
		out, err = scanUser(row)
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
			return fmt.Errorf("update user and clear external_id: %w", err)
		}
		return nil
	})
	return out, err
}
