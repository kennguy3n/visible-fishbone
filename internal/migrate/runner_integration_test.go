//go:build integration

package migrate_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	tcpg "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/kennguy3n/visible-fishbone/internal/migrate"
)

// startPostgres spins up a fresh postgres:16-alpine container and
// returns a URL suitable for golang-migrate's pgx/v5 driver
// (`pgx5://`). The container is torn down at test cleanup.
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
	url, err := ctr.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatalf("conn string: %v", err)
	}
	// testcontainers returns a `postgres://` URL; golang-migrate's
	// pgx/v5 driver expects `pgx5://`.
	return "pgx5" + url[len("postgres"):]
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
