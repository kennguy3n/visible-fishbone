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

// RoleRepository owns roles + user_roles.
type RoleRepository struct{ s *Store }

const roleSelectColumns = `
	id, tenant_id, name, external_id, permissions, scope, created_at
`

func scanRole(row pgx.Row) (repository.Role, error) {
	var (
		role     repository.Role
		tenantID nullableUUID
		perms    []byte
	)
	if err := row.Scan(&role.ID, &tenantID, &role.Name, &role.ExternalID, &perms, &role.Scope, &role.CreatedAt); err != nil {
		return repository.Role{}, err
	}
	if tenantID.Valid {
		id := tenantID.ID
		role.TenantID = &id
	}
	if len(perms) > 0 {
		if err := json.Unmarshal(perms, &role.Permissions); err != nil {
			return repository.Role{}, fmt.Errorf("decode permissions: %w", err)
		}
	}
	return role, nil
}

func (r *RoleRepository) Create(ctx context.Context, role repository.Role) (repository.Role, error) {
	if role.Name == "" {
		return repository.Role{}, repository.ErrInvalidArgument
	}
	switch role.Scope {
	case repository.RoleScopePlatform, repository.RoleScopeMSP,
		repository.RoleScopeTenant, repository.RoleScopeSite:
	default:
		return repository.Role{}, repository.ErrInvalidArgument
	}
	if role.ID == uuid.Nil {
		role.ID = uuid.New()
	}
	if role.Permissions == nil {
		role.Permissions = []string{}
	}
	perms, err := json.Marshal(role.Permissions)
	if err != nil {
		return repository.Role{}, fmt.Errorf("encode permissions: %w", err)
	}
	// roles is not tenant-RLS'd (system roles must be readable
	// from every tenant), so it does not flow through withTenant.
	// onPrimary still adopts the app role in PgBouncer mode.
	var out repository.Role
	err = r.s.onPrimary(ctx, func(db pgxQuerier) error {
		var e error
		out, e = scanRole(db.QueryRow(ctx, `
		INSERT INTO roles (id, tenant_id, name, external_id, permissions, scope)
		VALUES ($1::uuid, $2, $3, $4, $5::jsonb, $6)
		RETURNING `+roleSelectColumns,
			role.ID, role.TenantID, role.Name, role.ExternalID, perms, role.Scope,
		))
		return e
	})
	if err != nil {
		if isUniqueViolation(err) {
			return repository.Role{}, repository.ErrConflict
		}
		if isCheckViolation(err) {
			return repository.Role{}, repository.ErrInvalidArgument
		}
		if isForeignKeyViolation(err) {
			return repository.Role{}, repository.ErrNotFound
		}
		return repository.Role{}, fmt.Errorf("insert role: %w", err)
	}
	return out, nil
}

func (r *RoleRepository) Get(ctx context.Context, id uuid.UUID) (repository.Role, error) {
	var out repository.Role
	err := r.s.onPrimary(ctx, func(db pgxQuerier) error {
		var e error
		out, e = scanRole(db.QueryRow(ctx, `SELECT `+roleSelectColumns+` FROM roles WHERE id = $1::uuid`, id))
		return e
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return repository.Role{}, repository.ErrNotFound
	}
	if err != nil {
		return repository.Role{}, fmt.Errorf("select role: %w", err)
	}
	return out, nil
}

func (r *RoleRepository) Update(ctx context.Context, id uuid.UUID, name string, externalID string) (repository.Role, error) {
	if name == "" {
		return repository.Role{}, repository.ErrInvalidArgument
	}
	var out repository.Role
	err := r.s.onPrimary(ctx, func(db pgxQuerier) error {
		var e error
		out, e = scanRole(db.QueryRow(ctx, `
		UPDATE roles SET name = $2, external_id = $3
		WHERE id = $1::uuid
		RETURNING `+roleSelectColumns,
			id, name, externalID,
		))
		return e
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return repository.Role{}, repository.ErrNotFound
	}
	if isUniqueViolation(err) {
		return repository.Role{}, repository.ErrConflict
	}
	if err != nil {
		return repository.Role{}, fmt.Errorf("update role: %w", err)
	}
	return out, nil
}

func (r *RoleRepository) Delete(ctx context.Context, id uuid.UUID) error {
	var affected int64
	err := r.s.onPrimary(ctx, func(db pgxQuerier) error {
		ct, e := db.Exec(ctx, `DELETE FROM roles WHERE id = $1::uuid`, id)
		if e != nil {
			return e
		}
		affected = ct.RowsAffected()
		return nil
	})
	if err != nil {
		return fmt.Errorf("delete role: %w", err)
	}
	if affected == 0 {
		return repository.ErrNotFound
	}
	return nil
}

func (r *RoleRepository) List(ctx context.Context, tenantID *uuid.UUID) ([]repository.Role, error) {
	// Visible roles = system roles (tenant_id IS NULL) + the
	// tenant's own roles. With tenantID nil, return everything
	// (administrative path).
	var (
		q    string
		args []any
	)
	if tenantID == nil {
		q = `SELECT ` + roleSelectColumns + ` FROM roles ORDER BY name ASC`
	} else {
		q = `SELECT ` + roleSelectColumns + `
			FROM roles
			WHERE tenant_id IS NULL OR tenant_id = $1::uuid
			ORDER BY name ASC`
		args = []any{*tenantID}
	}
	out := make([]repository.Role, 0)
	if err := r.s.onPrimary(ctx, func(db pgxQuerier) error {
		rows, e := db.Query(ctx, q, args...)
		if e != nil {
			return fmt.Errorf("list roles: %w", e)
		}
		defer rows.Close()
		for rows.Next() {
			role, e := scanRole(rows)
			if e != nil {
				return fmt.Errorf("scan role: %w", e)
			}
			out = append(out, role)
		}
		if e := rows.Err(); e != nil {
			return fmt.Errorf("iterate roles: %w", e)
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return out, nil
}

func (r *RoleRepository) AssignRole(ctx context.Context, ur repository.UserRole) error {
	if ur.UserID == uuid.Nil || ur.RoleID == uuid.Nil {
		return repository.ErrInvalidArgument
	}
	var scopeID any
	if ur.ScopeID != nil {
		scopeID = *ur.ScopeID
	}
	var grantedBy any
	if ur.GrantedBy != nil {
		grantedBy = *ur.GrantedBy
	}
	err := r.s.onPrimary(ctx, func(db pgxQuerier) error {
		_, e := db.Exec(ctx, `
		INSERT INTO user_roles (user_id, role_id, scope_id, granted_by)
		VALUES ($1::uuid, $2::uuid, $3, $4)
	`, ur.UserID, ur.RoleID, scopeID, grantedBy)
		return e
	})
	if isUniqueViolation(err) {
		return repository.ErrConflict
	}
	if isForeignKeyViolation(err) {
		return repository.ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("assign role: %w", err)
	}
	return nil
}

func (r *RoleRepository) RevokeRole(ctx context.Context, userID, roleID uuid.UUID, scopeID *uuid.UUID) error {
	// COALESCE the scope_id to the zero UUID to mirror the
	// generated-column key used by the PK.
	scope := uuid.Nil
	if scopeID != nil {
		scope = *scopeID
	}
	var affected int64
	err := r.s.onPrimary(ctx, func(db pgxQuerier) error {
		ct, e := db.Exec(ctx, `
		DELETE FROM user_roles
		WHERE user_id = $1::uuid
		  AND role_id = $2::uuid
		  AND COALESCE(scope_id, '00000000-0000-0000-0000-000000000000'::uuid) = $3::uuid
	`, userID, roleID, scope)
		if e != nil {
			return e
		}
		affected = ct.RowsAffected()
		return nil
	})
	if err != nil {
		return fmt.Errorf("revoke role: %w", err)
	}
	if affected == 0 {
		return repository.ErrNotFound
	}
	return nil
}

func (r *RoleRepository) GetUserRoles(ctx context.Context, userID uuid.UUID) ([]repository.UserRole, error) {
	out := make([]repository.UserRole, 0)
	if err := r.s.onPrimary(ctx, func(db pgxQuerier) error {
		rows, e := db.Query(ctx, `
		SELECT user_id, role_id, scope_id, granted_at, granted_by
		FROM user_roles
		WHERE user_id = $1::uuid
		ORDER BY granted_at ASC
	`, userID)
		if e != nil {
			return fmt.Errorf("get user roles: %w", e)
		}
		defer rows.Close()
		for rows.Next() {
			var (
				ur        repository.UserRole
				scope     nullableUUID
				grantedBy nullableUUID
			)
			if e := rows.Scan(&ur.UserID, &ur.RoleID, &scope, &ur.GrantedAt, &grantedBy); e != nil {
				return fmt.Errorf("scan user role: %w", e)
			}
			if scope.Valid {
				id := scope.ID
				ur.ScopeID = &id
			}
			if grantedBy.Valid {
				id := grantedBy.ID
				ur.GrantedBy = &id
			}
			out = append(out, ur)
		}
		if e := rows.Err(); e != nil {
			return fmt.Errorf("iterate user roles: %w", e)
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return out, nil
}

func (r *RoleRepository) HasPermission(ctx context.Context, userID uuid.UUID, permission string) (bool, error) {
	// Inline the wildcard check rather than encoding in SQL —
	// `?` containment vs OR-wildcard is straightforward at the
	// app layer and keeps the query plan simple.
	var found bool
	if err := r.s.onPrimary(ctx, func(db pgxQuerier) error {
		rows, e := db.Query(ctx, `
		SELECT r.permissions
		FROM user_roles ur
		JOIN roles r ON r.id = ur.role_id
		WHERE ur.user_id = $1::uuid
	`, userID)
		if e != nil {
			return fmt.Errorf("has permission: %w", e)
		}
		defer rows.Close()
		for rows.Next() {
			var perms []byte
			if e := rows.Scan(&perms); e != nil {
				return fmt.Errorf("scan permissions: %w", e)
			}
			var p []string
			if e := json.Unmarshal(perms, &p); e != nil {
				return fmt.Errorf("decode permissions: %w", e)
			}
			for _, candidate := range p {
				if candidate == permission || candidate == "*" {
					found = true
					return nil
				}
			}
		}
		if e := rows.Err(); e != nil {
			return fmt.Errorf("iterate permissions: %w", e)
		}
		return nil
	}); err != nil {
		return false, err
	}
	return found, nil
}
