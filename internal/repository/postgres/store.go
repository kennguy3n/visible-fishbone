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

// Store holds the connection pools and exposes the repository
// constructors. Construct via NewStore(pool) for a single-pool
// deployment or NewStoreWithPool(rw) to enable the read-write split.
// The embedded *ReadWritePool is shared across repositories so
// transactions can be coordinated when needed (e.g. tenant create +
// audit log insert).
type Store struct {
	pool *ReadWritePool
}

// NewStore wraps a single primary pgxpool.Pool with no read
// replicas — every read and write goes to that pool. The pool must
// already be configured with the production connection settings
// (see internal/config). This is the backward-compatible
// constructor used by tests and single-node deployments.
func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{pool: NewReadWritePool(ReadWritePoolConfig{Primary: pool})}
}

// NewStoreWithPool wraps an explicit ReadWritePool, enabling the
// read-write split: read-only transactions are routed to a healthy
// replica while mutations and system transactions go to the primary.
func NewStoreWithPool(pool *ReadWritePool) *Store {
	return &Store{pool: pool}
}

// Pool exposes the underlying primary pgxpool for callers that need
// raw access (migrations test setup, custom diagnostic queries). Use
// sparingly — anything tenant-scoped MUST go through the wrappers.
func (s *Store) Pool() *pgxpool.Pool { return s.pool.Primary() }

// ReadWritePool exposes the underlying pool pair for callers that
// need to route a read explicitly to a replica.
func (s *Store) ReadWritePool() *ReadWritePool { return s.pool }

// setLocalRoleSQL is the transaction-local role-adoption statement
// issued at the top of every transaction when the pool is in
// PgBouncer (transaction-pooling) mode. It mirrors the session-level
// SET SESSION ROLE that openPostgres installs in session mode, but
// is reverted on commit/rollback so it is safe when consecutive
// transactions land on different server-side connections. The
// identifier is sanitized via pgx.Identifier so an operator-set role
// name cannot inject SQL.
func (s *Store) setLocalRoleSQL() (string, bool) {
	role := s.pool.AppRole()
	if !s.pool.PgBouncerMode() || role == "" {
		return "", false
	}
	return "SET LOCAL ROLE " + pgx.Identifier{role}.Sanitize(), true
}

// adoptLocalRole issues the transaction-local SET LOCAL ROLE when
// the pool is in PgBouncer mode (a no-op otherwise — session mode
// adopts the role once per connection via AfterConnect). Called at
// the top of every transaction helper, before any tenant/system
// GUC is set, so the role is in effect for the whole transaction.
func (s *Store) adoptLocalRole(ctx context.Context, tx pgx.Tx) error {
	sql, ok := s.setLocalRoleSQL()
	if !ok {
		return nil
	}
	if _, err := tx.Exec(ctx, sql); err != nil {
		return fmt.Errorf("set local role: %w", err)
	}
	return nil
}

// pgxQuerier is the subset of pgx's query surface shared by
// *pgxpool.Pool and pgx.Tx. It lets a standalone-query helper hand
// callers either a bare pooled connection (session mode) or a
// transaction (PgBouncer mode) behind a single type, so call sites
// don't branch on the pooling mode themselves.
type pgxQuerier interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// onPrimary runs `fn` against the primary pool for a standalone
// (non-RLS-scoped) query — the access pattern of the top-level
// MSP/Role/Tenant entity repos, which are not tenant-scoped and so
// do not flow through withTenant.
//
// In session mode the app role is already adopted per connection by
// openPostgres's AfterConnect hook, so `fn` runs directly on the
// pool with no transaction overhead. In PgBouncer
// (transaction-pooling) mode that hook is disabled — a session-level
// SET SESSION ROLE would leak across the server connections
// PgBouncer multiplexes between clients — so `fn` instead runs
// inside a short transaction that first issues SET LOCAL ROLE.
// Without this, every standalone MSP/Role/Tenant query in PgBouncer
// mode would execute as the unprivileged LOGIN role rather than the
// app role and fail with "permission denied".
//
// Any pgx.Rows `fn` opens MUST be fully consumed before `fn`
// returns: in PgBouncer mode the transaction commits (and the
// connection is released) the moment it does.
func (s *Store) onPrimary(ctx context.Context, fn func(q pgxQuerier) error) error {
	if _, ok := s.setLocalRoleSQL(); !ok {
		// Session mode (or no app role configured): the connection
		// already runs as the app role; skip the transaction.
		return fn(s.pool.Primary())
	}
	tx, err := s.pool.Primary().BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := s.adoptLocalRole(ctx, tx); err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		// Propagate verbatim (incl. pgx.ErrNoRows and *pgconn.PgError)
		// so callers keep their errors.Is / SQLSTATE classification.
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	return nil
}

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
	tx, err := s.pool.Primary().BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() {
		// Rollback is a no-op if Commit already ran.
		_ = tx.Rollback(ctx)
	}()
	if err := s.adoptLocalRole(ctx, tx); err != nil {
		return err
	}
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
	// Reads are routed to a healthy replica (falling back to the
	// primary when no replica is configured or all are unhealthy).
	// The RLS set_config below runs inside the replica transaction
	// exactly as it does on the primary, so tenant isolation is
	// enforced regardless of which node serves the read.
	tx, err := s.pool.Replica().BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return fmt.Errorf("begin ro tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := s.adoptLocalRole(ctx, tx); err != nil {
		return err
	}
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

// withSystem runs `fn` inside a transaction that signals
// system-level access via `sng.system_role='true'`. RLS policies
// that reference this GUC allow cross-tenant reads/writes. This is
// the only path workers and background jobs should use to drain
// per-tenant queues without a tenant context; do NOT use it from
// per-request handler code.
//
// The GUC, like sng.tenant_id, is transaction-local — it cannot
// leak onto pooled connections after commit/rollback.
func (s *Store) withSystem(ctx context.Context, fn func(tx pgx.Tx) error) error {
	tx, err := s.pool.Primary().BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin system tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := s.adoptLocalRole(ctx, tx); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, "SELECT set_config('sng.system_role', 'true', true)"); err != nil {
		return fmt.Errorf("set system context: %w", err)
	}
	if err := fn(tx); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit system tx: %w", err)
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
