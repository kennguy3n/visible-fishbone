//go:build integration

package main

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/kennguy3n/visible-fishbone/internal/migrate"
	"github.com/kennguy3n/visible-fishbone/internal/testutil/pgrole"
)

const appRole = "sng_app"

// startPostgres boots postgres:16-alpine, provisions the non-superuser
// app role, applies the SNG migrations as superuser, and returns the
// bootstrap (superuser) DSN. The bench opens its own pools from this
// DSN. Role provisioning happens BEFORE migrations because
// 002_role_bootstrap refuses to run if sng_app is missing — the same
// ordering the repository harness uses.
func startPostgres(t *testing.T) (string, func()) {
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

	bootstrap, err := pgxpool.New(ctx, bootstrapDSN)
	if err != nil {
		t.Fatalf("open bootstrap pool: %v", err)
	}
	if err := pgrole.Provision(ctx, bootstrap, appRole, user); err != nil {
		bootstrap.Close()
		t.Fatalf("provision app role: %v", err)
	}
	bootstrap.Close()

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

	cleanup := func() { _ = container.Terminate(context.Background()) }
	return bootstrapDSN, cleanup
}

func TestPostgresScaleBenchEndToEnd(t *testing.T) {
	dsn, cleanup := startPostgres(t)
	defer cleanup()

	cfg := DefaultPostgresScaleConfig(dsn)
	// Keep the seed small so the integration test stays under the
	// 600s CI budget while still exercising every measurement path.
	cfg.TenantCount = 200
	cfg.PoolSize = 16
	cfg.SampleQueries = 200

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	section, err := RunPostgresScaleBench(ctx, cfg)
	if err != nil {
		t.Fatalf("RunPostgresScaleBench: %v", err)
	}

	if section.TenantCount != 200 {
		t.Fatalf("TenantCount = %d, want 200", section.TenantCount)
	}
	if got := section.RowCounts["tenants"]; got != 200 {
		t.Fatalf("seeded tenants = %d, want 200", got)
	}
	if got := section.RowCounts["sites"]; got != 600 {
		t.Fatalf("seeded sites = %d, want 600 (200x3)", got)
	}
	if section.RLS.WithRLSP99Ms <= 0 || section.RLS.WithoutRLSP99Ms <= 0 {
		t.Fatalf("RLS p99s should be positive: %+v", section.RLS)
	}
	if section.Pool.MaxQueriesPerSec <= 0 {
		t.Fatalf("pool throughput should be positive, got %f", section.Pool.MaxQueriesPerSec)
	}
	if section.Migration.RowCount != 600 {
		t.Fatalf("migration row count = %d, want 600", section.Migration.RowCount)
	}
	if len(section.IndexSizeBytes) == 0 {
		t.Fatal("expected at least one index size")
	}
}

func TestSeedScaleDataIsTenantScoped(t *testing.T) {
	dsn, cleanup := startPostgres(t)
	defer cleanup()

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("open pool: %v", err)
	}
	defer pool.Close()

	ids, err := seedScaleData(ctx, pool, 10)
	if err != nil {
		t.Fatalf("seedScaleData: %v", err)
	}
	if len(ids) != 10 {
		t.Fatalf("seeded %d tenant ids, want 10", len(ids))
	}

	// Under the app role with the GUC set to one tenant, RLS must
	// scope the sites table to exactly that tenant's 3 rows.
	appPool, err := openAppPool(ctx, dsn, appRole, 4)
	if err != nil {
		t.Fatalf("open app pool: %v", err)
	}
	defer appPool.Close()

	conn, err := appPool.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, "SELECT set_config('sng.tenant_id', $1, false)", ids[0].String()); err != nil {
		t.Fatalf("set guc: %v", err)
	}
	var visible int
	if err := conn.QueryRow(ctx, "SELECT count(*) FROM sites").Scan(&visible); err != nil {
		t.Fatalf("count sites: %v", err)
	}
	if visible != 3 {
		t.Fatalf("RLS scoped sites = %d, want 3 (one tenant's sites)", visible)
	}
}
