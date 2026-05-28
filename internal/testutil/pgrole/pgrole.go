// Package pgrole provides shared PostgreSQL role provisioning
// helpers used by integration test harnesses across the repo.
//
// It lives outside any `_test.go` file so it can be imported by
// `_test` files in different Go packages (`internal/migrate` and
// `internal/repository/postgres` today). It is intentionally
// small and dependency-free beyond pgx, which is already a
// production dependency.
//
// The production deployment runbook (`docs/deploy.md`) is the
// canonical source for what these helpers replicate inside
// testcontainers; if the runbook's initial provisioning SQL ever
// changes, update this package to match so test and production
// stay aligned.
package pgrole

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Executor is the minimal pgx surface `Provision` needs. Both
// `*pgx.Conn` and `*pgxpool.Pool` satisfy it without adapter
// wrappers, which is the whole point of expressing the helper
// against an interface rather than a concrete type.
type Executor interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// Provision creates `role` (with `NOLOGIN`) if it does not already
// exist and grants `bootstrapUser` membership in it so subsequent
// `SET SESSION ROLE <role>` calls succeed. Idempotent — safe to
// re-run on an existing role.
//
// The existence check is parameterized through `$1`; `CREATE ROLE`
// and `GRANT` interpolate via `pgx.Identifier.Sanitize()` since
// PostgreSQL does not accept bind parameters in the role-name
// slot of those statements. Callers today pass hardcoded
// constants, but treating the parameters as untrusted is the
// right long-term posture for a shared test helper.
//
// `NOINHERIT` is deliberately NOT set on `role`: it would only
// govern privileges `role` inherits from roles `role` is a member
// of, which `sng_app` is not. The lever that actually forces an
// explicit `SET SESSION ROLE` lives on the LOGIN user, not on the
// runtime role. See `docs/deploy.md` for the full explanation.
func Provision(ctx context.Context, db Executor, role, bootstrapUser string) error {
	if role == "" {
		return errors.New("pgrole.Provision: role must be non-empty")
	}
	if bootstrapUser == "" {
		return errors.New("pgrole.Provision: bootstrapUser must be non-empty")
	}

	var exists bool
	if err := db.QueryRow(
		ctx,
		"SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $1)",
		role,
	).Scan(&exists); err != nil {
		return fmt.Errorf("pgrole: check role existence: %w", err)
	}
	roleIdent := pgx.Identifier{role}.Sanitize()
	if !exists {
		if _, err := db.Exec(ctx, fmt.Sprintf(
			"CREATE ROLE %s NOLOGIN",
			roleIdent,
		)); err != nil {
			return fmt.Errorf("pgrole: create role: %w", err)
		}
	}

	grant := fmt.Sprintf("GRANT %s TO %s", roleIdent, pgx.Identifier{bootstrapUser}.Sanitize())
	if _, err := db.Exec(ctx, grant); err != nil &&
		!strings.Contains(err.Error(), "already a member") {
		return fmt.Errorf("pgrole: grant membership: %w", err)
	}
	return nil
}
