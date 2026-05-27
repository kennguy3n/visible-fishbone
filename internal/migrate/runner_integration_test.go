//go:build integration

package migrate_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/testcontainers/testcontainers-go"
	tcpg "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/kennguy3n/visible-fishbone/internal/migrate"
)

// startPostgres spins up a fresh postgres:16-alpine container,
// provisions the `sng_app` runtime role (so 002_role_bootstrap
// can find it), and returns a URL suitable for golang-migrate's
// pgx/v5 driver (`pgx5://`). The container is torn down at test
// cleanup.
//
// Tests are tagged `integration` because they require Docker.
func startPostgres(t *testing.T) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	ctr, err := tcpg.Run(ctx,
		"postgres:16-alpine",
		tcpg.WithDatabase("sng"),
		tcpg.WithUsername("sng"),
		tcpg.WithPassword("sng"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(60*time.Second),
		),
	)
	if err != nil {
		t.Fatalf("start postgres: %v", err)
	}
	t.Cleanup(func() {
		// Best-effort termination — the test process is on its
		// way out and we don't want the cleanup error to mask
		// the test failure we actually care about.
		_ = ctr.Terminate(context.Background())
	})
	connStr, err := ctr.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatalf("conn string: %v", err)
	}

	// Provision the runtime role BEFORE the test runs migrations.
	// 002_role_bootstrap fails fast if `sng_app` does not exist,
	// mirroring the production runbook in docs/deploy.md.
	if err := provisionAppRole(ctx, connStr, "sng_app", "sng"); err != nil {
		t.Fatalf("provision sng_app: %v", err)
	}

	// testcontainers returns a `postgres://` URL; golang-migrate's
	// pgx/v5 driver expects `pgx5://`.
	return "pgx5" + connStr[len("postgres"):]
}

// provisionAppRole creates the runtime role used by
// 002_role_bootstrap and grants the bootstrap superuser membership
// in it. Idempotent — re-running on an existing role is a no-op.
func provisionAppRole(ctx context.Context, dsn, role, bootstrapUser string) error {
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer conn.Close(ctx)

	createRole := fmt.Sprintf(`
		DO $$
		BEGIN
			IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '%s') THEN
				CREATE ROLE %s NOINHERIT NOLOGIN;
			END IF;
		END $$;
	`, role, role)
	if _, err := conn.Exec(ctx, createRole); err != nil {
		return fmt.Errorf("create role: %w", err)
	}
	if _, err := conn.Exec(ctx, fmt.Sprintf("GRANT %s TO %s", role, bootstrapUser)); err != nil &&
		!strings.Contains(err.Error(), "already a member") {
		return fmt.Errorf("grant membership: %w", err)
	}
	return nil
}

func TestRunner_UpDownStatus(t *testing.T) {
	url := startPostgres(t)

	// Initial: no migrations applied -> version=0, dirty=false.
	r0, err := migrate.New(url)
	if err != nil {
		t.Fatalf("new runner: %v", err)
	}
	v, dirty, err := r0.Status()
	if err != nil {
		t.Fatalf("initial status: %v", err)
	}
	if v != 0 || dirty {
		t.Errorf("initial status: want 0/false, got %d/%v", v, dirty)
	}
	if err := r0.Close(); err != nil {
		t.Fatalf("close r0: %v", err)
	}

	// Apply all migrations.
	r1, err := migrate.New(url)
	if err != nil {
		t.Fatalf("new runner up: %v", err)
	}
	if err := r1.Up(); err != nil {
		t.Fatalf("up: %v", err)
	}
	v, dirty, err = r1.Status()
	if err != nil {
		t.Fatalf("post-up status: %v", err)
	}
	if v < 1 || dirty {
		t.Errorf("post-up status: want >=1/false, got %d/%v", v, dirty)
	}
	if err := r1.Close(); err != nil {
		t.Fatalf("close r1: %v", err)
	}

	// Re-running up is a no-op (migrate returns ErrNoChange,
	// runner converts to nil).
	r2, err := migrate.New(url)
	if err != nil {
		t.Fatalf("new runner reup: %v", err)
	}
	if err := r2.Up(); err != nil {
		t.Errorf("re-up should be no-op, got: %v", err)
	}
	if err := r2.Close(); err != nil {
		t.Fatalf("close r2: %v", err)
	}

	// Roll all the way back.
	r3, err := migrate.New(url)
	if err != nil {
		t.Fatalf("new runner down: %v", err)
	}
	finalV, _, err := r3.Status()
	if err != nil {
		t.Fatalf("pre-down status: %v", err)
	}
	if err := r3.Down(int(finalV)); err != nil {
		t.Fatalf("down %d: %v", finalV, err)
	}
	v, dirty, err = r3.Status()
	if err != nil {
		t.Fatalf("post-down status: %v", err)
	}
	if v != 0 || dirty {
		t.Errorf("post-down status: want 0/false, got %d/%v", v, dirty)
	}
	if err := r3.Close(); err != nil {
		t.Fatalf("close r3: %v", err)
	}

	// Re-running down with nothing left is also a no-op.
	r4, err := migrate.New(url)
	if err != nil {
		t.Fatalf("new runner redown: %v", err)
	}
	if err := r4.Down(1); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		t.Errorf("re-down should be no-op or ErrNoChange, got: %v", err)
	}
	if err := r4.Close(); err != nil {
		t.Fatalf("close r4: %v", err)
	}
}
