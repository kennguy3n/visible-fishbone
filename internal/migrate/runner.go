// Package migrate wraps golang-migrate/v4 with the embedded SNG
// migration source so the control-plane binary ships with its own
// schema migrations baked in. Operators run migrations without
// shipping a sidecar binary or checking out the repo.
//
// Higher-level CLI flag parsing lives in `cmd/sng-migrate`; this
// package is the reusable engine that the CLI and the test suite
// both drive.
package migrate

import (
	"errors"
	"fmt"
	"io/fs"
	"strings"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/source/iofs"

	// Register the pgx/v5 database driver. The blank import is the
	// standard golang-migrate pattern for opting into a driver.
	// Without this, NewWithSourceInstance fails on a "pgx5://" DSN.
	_ "github.com/golang-migrate/migrate/v4/database/pgx/v5"

	"github.com/kennguy3n/visible-fishbone/migrations"
)

// ErrNoChange re-exports migrate.ErrNoChange so callers can match on
// the "nothing to do" signal without importing the library.
var ErrNoChange = migrate.ErrNoChange

// SourceFS returns the embedded migrations as a generic `fs.FS`.
// Useful for tests that want to walk the migration files (count
// pairs, sanity-check the down files exist) without going through
// the migrate library.
func SourceFS() fs.FS { return migrations.FS }

// Runner is the engine that drives golang-migrate against the
// embedded SQL source. One Runner instance maps to one Postgres
// DSN; create a fresh Runner per command (Up/Down/Status) rather
// than holding one open for the process lifetime so the underlying
// *migrate.Migrate (which holds a database connection) is closed
// promptly between operations.
type Runner struct {
	m *migrate.Migrate
}

// New constructs a Runner bound to the embedded source and the
// supplied Postgres DSN. The DSN must use the "pgx5://" scheme that
// the migrate/v5 pgx driver registers, e.g.:
//
//	pgx5://user:pass@host:5432/dbname?sslmode=disable
//
// Callers wishing to migrate against a non-default schema can
// append `?search_path=foo&x-migrations-table=schema_migrations`
// to the DSN (see golang-migrate docs).
func New(dsn string) (*Runner, error) {
	if dsn == "" {
		return nil, errors.New("migrate: empty DSN")
	}
	source, err := iofs.New(migrations.FS, ".")
	if err != nil {
		return nil, fmt.Errorf("iofs source: %w", err)
	}
	m, err := migrate.NewWithSourceInstance("iofs", source, dsn)
	if err != nil {
		return nil, fmt.Errorf("migrate.NewWithSourceInstance: %w", err)
	}
	return &Runner{m: m}, nil
}

// Close releases the database connection held by the underlying
// migrate.Migrate. It MUST be called when the Runner is no longer
// in use; the migrate library otherwise leaks a connection per
// run. Close returns the first non-nil of (sourceErr, dbErr) — both
// values are also wrapped with the operation name for clarity.
func (r *Runner) Close() error {
	if r == nil || r.m == nil {
		return nil
	}
	sourceErr, dbErr := r.m.Close()
	r.m = nil
	if sourceErr != nil {
		return fmt.Errorf("migrate: close source: %w", sourceErr)
	}
	if dbErr != nil {
		return fmt.Errorf("migrate: close db: %w", dbErr)
	}
	return nil
}

// Up applies every pending migration. Returns nil on success,
// ErrNoChange when the database is already up to date, or a
// wrapped error on failure.
func (r *Runner) Up() error {
	if err := r.m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("migrate up: %w", err)
	}
	return nil
}

// Steps moves the schema by N migrations. Positive N applies; negative
// N rolls back. Returns nil (not ErrNoChange) when nothing matches the
// requested direction so command-line wrappers can treat re-runs as
// no-ops.
//
// Edge case: when the schema is already at version 0 (no migrations
// applied) and the caller asks for a negative step, the iofs source
// surfaces a "file does not exist" error because golang-migrate
// tries to read the migration file at version 0 (which doesn't
// exist) before noticing there's nothing to do. We intercept that
// error explicitly and convert it to a no-op, matching the
// semantics of migrate.ErrNoChange.
func (r *Runner) Steps(n int) error {
	if n == 0 {
		return nil
	}
	// Stepping backwards from version 0 races the iofs source's
	// file lookup; short-circuit cleanly.
	if n < 0 {
		v, _, statusErr := r.Status()
		if statusErr == nil && v == 0 {
			return nil
		}
	}
	err := r.m.Steps(n)
	if err == nil || errors.Is(err, migrate.ErrNoChange) {
		return nil
	}
	// iofs surfaces "file does not exist" when stepping past the
	// beginning of the migration set. Treat this as ErrNoChange.
	if strings.Contains(err.Error(), "file does not exist") {
		return nil
	}
	return fmt.Errorf("migrate steps %d: %w", n, err)
}

// Down rolls back the schema by N steps. N must be positive; passing
// zero is a no-op.
func (r *Runner) Down(steps int) error {
	if steps <= 0 {
		return nil
	}
	return r.Steps(-steps)
}

// Status returns the current schema version, whether it is dirty
// (mid-migration), and any error from the underlying driver. A
// fresh database (no migrations table yet) returns (0, false, nil)
// so callers can distinguish "fresh" from "version 1" without
// re-running migrations.
func (r *Runner) Status() (version uint, dirty bool, err error) {
	v, d, err := r.m.Version()
	switch {
	case err == nil:
		return v, d, nil
	case errors.Is(err, migrate.ErrNilVersion):
		return 0, false, nil
	default:
		return 0, false, fmt.Errorf("migrate version: %w", err)
	}
}

// Force sets the schema version without running any SQL. Used
// strictly for recovery from a dirty state. Pass 0 to mark the
// database as never-migrated.
func (r *Runner) Force(version int) error {
	if version < 0 {
		return fmt.Errorf("migrate force: version must be non-negative, got %d", version)
	}
	if err := r.m.Force(version); err != nil {
		return fmt.Errorf("migrate force %d: %w", version, err)
	}
	return nil
}
