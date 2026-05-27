// Package postgres is the production implementation of the
// repository interfaces, backed by pgxpool.
//
// Every tenant-scoped operation runs inside a short-lived
// transaction that sets the `sng.tenant_id` GUC at the top of the
// tx (mirroring sn360-security-platform's `withTenant` pattern):
//
//	tx, _ := pool.Begin(ctx)
//	tx.Exec(ctx, "SELECT set_config('sng.tenant_id', $1, true)", id)
//	... queries ...
//	tx.Commit(ctx)
//
// The `true` argument makes set_config transaction-local, so the GUC
// vanishes when the tx commits or rolls back — no leakage onto
// pooled connections that the same client reuses for a different
// tenant.
//
// Tenant CREATE is the one exception: the tenant row does not yet
// exist, so we INSERT it outside the GUC-bound branch and then set
// the GUC for any child rows we may seed in the same tx.
package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Store holds the pgxpool and exposes the repository constructors.
// Construct via NewStore(pool); the embedded *pgxpool.Pool is
// shared across repositories so transactions can be coordinated
// when needed (e.g. tenant create + audit log insert).
type Store struct {
	pool *pgxpool.Pool
}

// NewStore wraps a pgxpool.Pool. The pool must already be configured
// with the production connection settings (see internal/config).
func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

// Pool exposes the underlying pgxpool for callers that need raw
// access (migrations test setup, custom diagnostic queries). Use
// sparingly — anything tenant-scoped MUST go through the wrappers.
func (s *Store) Pool() *pgxpool.Pool { return s.pool }

// withTenant runs `fn` inside a transaction whose `sng.tenant_id`
// GUC is set to `tenantID`. The transaction is rolled back if `fn`
// returns an error, otherwise committed.
//
// `tenantID` is rendered as a string via the pgx driver — passing
// `(*uuid.UUID).String()` is the canonical caller path.
//
// The set_config call uses `true` for `is_local` (transaction-local),
// so the GUC value is automatically released when the transaction
// commits or rolls back. Without this, a recycled pool connection
// would carry the previous tenant's GUC into the next query.
func (s *Store) withTenant(ctx context.Context, tenantID string, fn func(tx pgx.Tx) error) error {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() {
		// Rollback is a no-op if Commit already ran.
		_ = tx.Rollback(ctx)
	}()
	if _, err := tx.Exec(ctx, "SELECT set_config('sng.tenant_id', $1, true)", tenantID); err != nil {
		return fmt.Errorf("set tenant context: %w", err)
	}
	if err := fn(tx); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	return nil
}

// withTenantRO is the read-only variant of withTenant. It opens a
// read-only transaction which lets Postgres skip a few bookkeeping
// steps (no XID assignment, no write lock acquisition). Use it for
// pure SELECT paths to reduce contention under high read load.
func (s *Store) withTenantRO(ctx context.Context, tenantID string, fn func(tx pgx.Tx) error) error {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return fmt.Errorf("begin ro tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, "SELECT set_config('sng.tenant_id', $1, true)", tenantID); err != nil {
		return fmt.Errorf("set tenant context: %w", err)
	}
	if err := fn(tx); err != nil {
		return err
	}
	// Read-only tx still requires Commit/Rollback to release the
	// connection back to the pool; Commit is preferred so the
	// idempotent set_config doesn't show up in error logs.
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit ro tx: %w", err)
	}
	return nil
}

// pgErr unwraps a pgconn.PgError if present; nil otherwise.
func pgErr(err error) *pgconn.PgError {
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		return pe
	}
	return nil
}

// isUniqueViolation reports whether err is a SQLSTATE 23505.
func isUniqueViolation(err error) bool {
	pe := pgErr(err)
	return pe != nil && pe.Code == "23505"
}

// isCheckViolation reports whether err is a SQLSTATE 23514.
func isCheckViolation(err error) bool {
	pe := pgErr(err)
	return pe != nil && pe.Code == "23514"
}

// isForeignKeyViolation reports whether err is a SQLSTATE 23503.
func isForeignKeyViolation(err error) bool {
	pe := pgErr(err)
	return pe != nil && pe.Code == "23503"
}
