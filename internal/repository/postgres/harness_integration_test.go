//go:build integration

package postgres_test

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/kennguy3n/visible-fishbone/internal/migrate"
	"github.com/kennguy3n/visible-fishbone/internal/repository/postgres"
	"github.com/kennguy3n/visible-fishbone/internal/testutil/pgrole"
)

// appRole is the non-superuser role the test pool runs as. Mirrors
// the production "sng_app" runtime role. Postgres `FORCE ROW LEVEL
// SECURITY` does NOT apply to superusers (bootstrap testcontainers
// user), so we must SET ROLE to a non-superuser before exercising
// the tenant queries.
const appRole = "sng_app"

// startPostgres boots a postgres:16-alpine container, provisions
// the non-superuser app role, applies the embedded migrations as
// superuser (the migrations include 002_role_bootstrap which
// GRANTs DML to sng_app), then opens a connection pool configured
// to `SET SESSION ROLE sng_app` on every new connection — so every
// query the application issues runs as a non-superuser and is
// subject to RLS, matching production behaviour exactly.
//
// Role provisioning happens BEFORE migrations because
// 002_role_bootstrap.up.sql refuses to run if `sng_app` is
// missing (it surfaces the runbook in docs/deploy.md as a hint).
// This ordering mirrors a real deploy: ops creates the role once,
// then schema migrations follow.
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

	bootstrapDSN := fmt.Sprintf(
		"postgres://%s@%s/%s?sslmode=disable",
		url.UserPassword(user, pass).String(),
		net.JoinHostPort(host, port.Port()),
		dbName,
	)

	// Provision the runtime role BEFORE running migrations so
	// 002_role_bootstrap can find it. In production ops creates
	// the role out-of-band; testcontainers is ephemeral, so we
	// inline the same provisioning here via the shared helper.
	bootstrap, err := pgxpool.New(ctx, bootstrapDSN)
	if err != nil {
		t.Fatalf("open bootstrap pool: %v", err)
	}
	if err := pgrole.Provision(ctx, bootstrap, appRole, user); err != nil {
		bootstrap.Close()
		t.Fatalf("provision app role: %v", err)
	}
	bootstrap.Close()

	// Apply migrations via the embedded runner. 002 will GRANT
	// DML on every table created by 001 to `sng_app`, and install
	// ALTER DEFAULT PRIVILEGES so any future migration's tables
	// inherit DML without per-table repetition.
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

	// Open the production pool, configured so every connection
	// adopts the app role for its session lifetime. `SET SESSION
	// ROLE` is sticky for the connection (not transaction-local),
	// so subsequent set_config('sng.tenant_id', ...) calls run
	// under the non-superuser identity and RLS is enforced.
	poolCfg, err := pgxpool.ParseConfig(bootstrapDSN)
	if err != nil {
		t.Fatalf("parse pool cfg: %v", err)
	}
	// Mirror the production pool's AfterConnect identifier handling
	// (cmd/sng-control/main.go:openPostgres → afterConnectSetRole)
	// so this harness exercises the same SQL the runtime emits.
	// `appRole` is a hardcoded constant today, but using
	// pgx.Identifier.Sanitize() instead of bare interpolation
	// keeps the test pattern aligned with prod and avoids the
	// silent-divergence trap if the constant is ever changed to a
	// name requiring quoting.
	roleIdent := pgx.Identifier{appRole}.Sanitize()
	poolCfg.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		_, err := conn.Exec(ctx, fmt.Sprintf("SET SESSION ROLE %s", roleIdent))
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
