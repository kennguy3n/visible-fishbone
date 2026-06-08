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

// userSearchWhere renders the WHERE predicate for a UserSearchFilter
// and its bound argument, with positional parameters starting at
// argStart. The column name is selected from a fixed whitelist (never
// caller input) so it is safe to interpolate; the match value is always
// bound. COALESCE(col, ”) makes a NULL column behave like the empty
// string, matching the memory backend. Contains/prefix use strpos
// rather than LIKE so wildcard characters in the value are treated
// literally (no LIKE-pattern injection).
func userSearchWhere(filter repository.UserSearchFilter, argStart int) (string, []any) {
	if filter.Field == "" {
		return "TRUE", nil
	}
	var col string
	switch filter.Field {
	case repository.UserSearchFieldEmail:
		col = "email"
	case repository.UserSearchFieldName:
		col = "name"
	case repository.UserSearchFieldExternalID:
		col = "external_id"
	default:
		// Unknown field matches nothing, mirroring the memory backend.
		return "FALSE", nil
	}
	expr := fmt.Sprintf("COALESCE(%s, '')", col)
	switch filter.Op {
	case repository.TextMatchEquals:
		return fmt.Sprintf("lower(%s) = lower($%d)", expr, argStart), []any{filter.Value}
	case repository.TextMatchContains:
		return fmt.Sprintf("strpos(lower(%s), lower($%d)) > 0", expr, argStart), []any{filter.Value}
	case repository.TextMatchPrefix:
		return fmt.Sprintf("strpos(lower(%s), lower($%d)) = 1", expr, argStart), []any{filter.Value}
	default:
		return "FALSE", nil
	}
}

func (r *UserRepository) SearchUsers(ctx context.Context, tenantID uuid.UUID, filter repository.UserSearchFilter, offset, limit int) ([]repository.User, int, error) {
	if offset < 0 {
		offset = 0
	}
	where, whereArgs := userSearchWhere(filter, 1)
	var (
		items []repository.User
		total int
	)
	err := r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		// Total matches independent of the page window — backs SCIM
		// totalResults. Runs in the same RO tx as the page query so
		// both observe a consistent snapshot under the tenant RLS GUC.
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM users WHERE `+where, whereArgs...).Scan(&total); err != nil {
			return fmt.Errorf("count users: %w", err)
		}
		if limit <= 0 || offset >= total {
			items = []repository.User{}
			return nil
		}
		args := make([]any, 0, len(whereArgs)+2)
		args = append(args, whereArgs...)
		args = append(args, limit, offset)
		q := fmt.Sprintf(
			`SELECT %s FROM users WHERE %s ORDER BY created_at DESC, id DESC LIMIT $%d OFFSET $%d`,
			userSelectColumns, where, len(whereArgs)+1, len(whereArgs)+2,
		)
		rows, err := tx.Query(ctx, q, args...)
		if err != nil {
			return fmt.Errorf("search users: %w", err)
		}
		defer rows.Close()
		items = make([]repository.User, 0, limit)
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
		return nil
	})
	if err != nil {
		return nil, 0, err
	}
	return items, total, nil
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
