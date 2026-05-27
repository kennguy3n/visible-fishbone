//go:build integration

package postgres_test

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/kennguy3n/visible-fishbone/internal/migrate"
	"github.com/kennguy3n/visible-fishbone/internal/repository/postgres"
)

// appRole is the non-superuser role the test pool runs as. Mirrors
// the production "sng_app" runtime role. Postgres `FORCE ROW LEVEL
// SECURITY` does NOT apply to superusers (bootstrap testcontainers
// user), so we must SET ROLE to a non-superuser before exercising
// the tenant queries.
const appRole = "sng_app"

// startPostgres boots a postgres:16-alpine container, applies the
// embedded migrations as superuser, then creates a non-superuser
// app role with the same DML grants the production runtime role
// has. The returned *Store is configured to `SET SESSION ROLE
// sng_app` on every new connection — so every query the
// application issues runs as a non-superuser and is subject to
// RLS, matching production behaviour exactly.
func startPostgres(t *testing.T) (*postgres.Store, func()) {
	t.Helper()
	ctx := context.Background()

	const (
		dbName = "sng"
		user   = "sng"
		pass   = "sng"
	)

	container, err := tcpostgres.Run(ctx,
		"postgres:16-alpine",
		tcpostgres.WithDatabase(dbName),
		tcpostgres.WithUsername(user),
		tcpostgres.WithPassword(pass),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(60*time.Second),
		),
	)
	if err != nil {
		t.Fatalf("start postgres container: %v", err)
	}

	host, err := container.Host(ctx)
	if err != nil {
		t.Fatalf("container host: %v", err)
	}
	port, err := container.MappedPort(ctx, "5432/tcp")
	if err != nil {
		t.Fatalf("container port: %v", err)
	}

	// Apply migrations via the embedded runner.
	migrateDSN := fmt.Sprintf(
		"pgx5://%s@%s/%s?sslmode=disable",
		url.UserPassword(user, pass).String(),
		net.JoinHostPort(host, port.Port()),
		dbName,
	)
	runner, err := migrate.New(migrateDSN)
	if err != nil {
		t.Fatalf("migrate runner: %v", err)
	}
	if err := runner.Up(); err != nil {
		_ = runner.Close()
		t.Fatalf("migrate up: %v", err)
	}
	if err := runner.Close(); err != nil {
		t.Fatalf("close runner: %v", err)
	}

	// Bootstrap a non-superuser app role and grant it DML on every
	// public table (the migrations created all tables in `public`).
	bootstrapDSN := fmt.Sprintf(
		"postgres://%s@%s/%s?sslmode=disable",
		url.UserPassword(user, pass).String(),
		net.JoinHostPort(host, port.Port()),
		dbName,
	)
	bootstrap, err := pgxpool.New(ctx, bootstrapDSN)
	if err != nil {
		t.Fatalf("open bootstrap pool: %v", err)
	}
	if err := bootstrapAppRole(ctx, bootstrap, appRole); err != nil {
		bootstrap.Close()
		t.Fatalf("bootstrap app role: %v", err)
	}
	bootstrap.Close()

	// Open the production pool, configured so every connection
	// adopts the app role for its session lifetime. `SET SESSION
	// ROLE` is sticky for the connection (not transaction-local),
	// so subsequent set_config('sng.tenant_id', ...) calls run
	// under the non-superuser identity and RLS is enforced.
	poolCfg, err := pgxpool.ParseConfig(bootstrapDSN)
	if err != nil {
		t.Fatalf("parse pool cfg: %v", err)
	}
	poolCfg.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		_, err := conn.Exec(ctx, fmt.Sprintf("SET SESSION ROLE %s", appRole))
		return err
	}
	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		t.Fatalf("open pool: %v", err)
	}

	cleanup := func() {
		pool.Close()
		_ = container.Terminate(context.Background())
	}
	return postgres.NewStore(pool), cleanup
}

// bootstrapAppRole creates the runtime role and grants it the
// schema-level + table-level + sequence-level permissions the
// repository layer needs. Idempotent — re-running on an existing
// role is a no-op (Postgres "already exists" is silently swallowed).
func bootstrapAppRole(ctx context.Context, pool *pgxpool.Pool, role string) error {
	// CREATE ROLE doesn't support IF NOT EXISTS; wrap in DO block.
	createRole := fmt.Sprintf(`
		DO $$
		BEGIN
			IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '%s') THEN
				CREATE ROLE %s NOINHERIT NOLOGIN;
			END IF;
		END $$;
	`, role, role)
	if _, err := pool.Exec(ctx, createRole); err != nil {
		return fmt.Errorf("create role: %w", err)
	}

	// Grant the role permission to be assumed by the bootstrap user.
	grantToBootstrap := fmt.Sprintf("GRANT %s TO %s", role, "sng")
	if _, err := pool.Exec(ctx, grantToBootstrap); err != nil &&
		!strings.Contains(err.Error(), "already a member") {
		return fmt.Errorf("grant role to bootstrap user: %w", err)
	}

	stmts := []string{
		fmt.Sprintf("GRANT USAGE ON SCHEMA public TO %s", role),
		fmt.Sprintf("GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO %s", role),
		fmt.Sprintf("GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO %s", role),
	}
	for _, stmt := range stmts {
		if _, err := pool.Exec(ctx, stmt); err != nil {
			return fmt.Errorf("grant: %s: %w", stmt, err)
		}
	}
	return nil
}
