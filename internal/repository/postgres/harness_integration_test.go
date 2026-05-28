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
	// inline the same provisioning here.
	bootstrap, err := pgxpool.New(ctx, bootstrapDSN)
	if err != nil {
		t.Fatalf("open bootstrap pool: %v", err)
	}
	if err := provisionAppRole(ctx, bootstrap, appRole, user); err != nil {
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

// provisionAppRole creates the runtime role (idempotent — re-running
// on an existing role is a no-op via the DO-block guard) and grants
// the bootstrap superuser membership in it so `SET ROLE sng_app`
// works under the test connection pool.
//
// Privilege-level grants (schema/table/sequence) are the migration's
// job — see `migrations/002_role_bootstrap.up.sql` and
// `docs/deploy.md` for the production runbook.
func provisionAppRole(ctx context.Context, pool *pgxpool.Pool, role, bootstrapUser string) error {
	// Existence check is parameterized; CREATE ROLE / GRANT
	// interpolate via pgx.Identifier.Sanitize(). Today's callers pass
	// hardcoded constants but treating the parameters as untrusted is
	// the right long-term posture for a shared test helper.
	var exists bool
	if err := pool.QueryRow(
		ctx,
		"SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $1)",
		role,
	).Scan(&exists); err != nil {
		return fmt.Errorf("check role existence: %w", err)
	}
	roleIdent := pgx.Identifier{role}.Sanitize()
	if !exists {
		if _, err := pool.Exec(ctx, fmt.Sprintf(
			"CREATE ROLE %s NOINHERIT NOLOGIN",
			roleIdent,
		)); err != nil {
			return fmt.Errorf("create role: %w", err)
		}
	}

	// Grant the bootstrap superuser membership in the runtime role
	// so `SET ROLE sng_app` succeeds on the prod pool's per-conn
	// AfterConnect hook. "already a member" is benign on re-runs.
	grantMembership := fmt.Sprintf("GRANT %s TO %s", roleIdent, pgx.Identifier{bootstrapUser}.Sanitize())
	if _, err := pool.Exec(ctx, grantMembership); err != nil &&
		!strings.Contains(err.Error(), "already a member") {
		return fmt.Errorf("grant role to bootstrap user: %w", err)
	}
	return nil
}
