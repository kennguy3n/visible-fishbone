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

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Executor is the minimal pgx surface `Provision` needs. Both
// `*pgx.Conn` and `*pgxpool.Pool` satisfy it without adapter
// wrappers, which is the whole point of expressing the helper
// against an interface rather than a concrete type. Methods are
// kept to the bare minimum the helper actually uses today; add
// new methods here only if a new `pgrole` helper needs them.
type Executor interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// PostgreSQL SQLSTATEs we treat as benign-idempotent outcomes from
// CREATE ROLE / GRANT. Both are documented in
// https://www.postgresql.org/docs/16/errcodes-appendix.html
const (
	// 42710 — duplicate_object. Raised by `CREATE ROLE` when the
	// role already exists; we treat this as a no-op so concurrent
	// Provision callers don't race on existence-check + CREATE.
	pgErrDuplicateObject = "42710"
)

// Provision creates `role` (with `NOLOGIN`) if it does not already
// exist and grants `bootstrapUser` membership in it so subsequent
// `SET SESSION ROLE <role>` calls succeed. Idempotent — safe to
// re-run concurrently against the same database.
//
// `CREATE ROLE` and `GRANT` interpolate via
// `pgx.Identifier.Sanitize()` since PostgreSQL does not accept bind
// parameters in the role-name slot of those statements. Callers
// today pass hardcoded constants, but treating the parameters as
// untrusted is the right long-term posture for a shared test
// helper.
//
// Race-free CREATE: rather than `SELECT EXISTS` followed by
// `CREATE ROLE`, we issue `CREATE ROLE` unconditionally and ignore
// SQLSTATE 42710 (`duplicate_object`). PostgreSQL serialises
// CREATE ROLE on `pg_authid`, so the only way for two concurrent
// callers to both pass an existence check and both attempt CREATE
// is what the old code did — and what we now sidestep entirely.
// Any other error (network, permissions, syntax) propagates as
// before.
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

	roleIdent := pgx.Identifier{role}.Sanitize()
	if _, err := db.Exec(ctx, fmt.Sprintf("CREATE ROLE %s NOLOGIN", roleIdent)); err != nil {
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != pgErrDuplicateObject {
			return fmt.Errorf("pgrole: create role: %w", err)
		}
		// duplicate_object — role already exists, treat as success.
	}

	// Redundant GRANT membership is intentionally NOT special-cased.
	// PostgreSQL 16 emits a NOTICE (not an error) when the grantee is
	// already a member of the role, and pgx surfaces the NOTICE
	// through `conn.OnNotice` rather than as a returned error — so
	// re-running `Provision` against an already-granted membership
	// returns `err == nil`. Any error here is therefore a real one
	// (network, permissions, syntax) and worth propagating.
	grant := fmt.Sprintf("GRANT %s TO %s", roleIdent, pgx.Identifier{bootstrapUser}.Sanitize())
	if _, err := db.Exec(ctx, grant); err != nil {
		return fmt.Errorf("pgrole: grant membership: %w", err)
	}
	return nil
}
