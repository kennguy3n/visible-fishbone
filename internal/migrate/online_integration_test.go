//go:build integration

package migrate_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/kennguy3n/visible-fishbone/internal/migrate"
)

// connectRaw opens a single dedicated *pgx.Conn against the same
// container startPostgres provisioned. OnlineMigrator.Apply requires
// a single connection (not a pool) so session lock_timeout and
// CREATE INDEX CONCURRENTLY share one backend.
func connectRaw(t *testing.T, migrateURL string) *pgx.Conn {
	t.Helper()
	// startPostgres hands back a pgx5:// URL; pgx.Connect wants the
	// canonical postgres:// scheme.
	pgURL := "postgres" + strings.TrimPrefix(migrateURL, "pgx5")
	conn, err := pgx.Connect(context.Background(), pgURL)
	if err != nil {
		t.Fatalf("connect raw: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close(context.Background()) })
	return conn
}

func mustExec(t *testing.T, conn *pgx.Conn, sql string, args ...any) {
	t.Helper()
	if _, err := conn.Exec(context.Background(), sql, args...); err != nil {
		t.Fatalf("exec %q: %v", sql, err)
	}
}

// TestOnlineMigrator_AddColumnAndIndex applies the two
// rewrite-avoiding primitives against a populated table and verifies
// the schema and data land as expected.
func TestOnlineMigrator_AddColumnAndIndex(t *testing.T) {
	ctx := context.Background()
	conn := connectRaw(t, startPostgres(t))

	mustExec(t, conn, `CREATE TABLE widgets (id serial PRIMARY KEY, name text)`)
	mustExec(t, conn, `INSERT INTO widgets (name) SELECT 'w' || g FROM generate_series(1, 50) g`)

	m := migrate.NewOnlineMigrator(migrate.NewLockMonitor(migrate.LockMonitorConfig{}))

	// ADD COLUMN with a default + NOT NULL: O(1) catalog change on
	// PG11+, so every existing row reads back the default.
	if err := m.Apply(ctx, conn, migrate.AddColumnOp{
		TableName: "widgets", Column: "region", Type: "text",
		Default: "'us'", NotNull: true,
	}); err != nil {
		t.Fatalf("AddColumn: %v", err)
	}
	var nonDefault int
	if err := conn.QueryRow(ctx, `SELECT count(*) FROM widgets WHERE region <> 'us'`).Scan(&nonDefault); err != nil {
		t.Fatalf("count region: %v", err)
	}
	if nonDefault != 0 {
		t.Errorf("expected all rows to carry the default region, got %d non-default", nonDefault)
	}

	// CREATE INDEX CONCURRENTLY.
	if err := m.Apply(ctx, conn, migrate.CreateIndexOp{
		IndexName: "idx_widgets_region", TableName: "widgets",
		Columns: []string{"region"},
	}); err != nil {
		t.Fatalf("CreateIndex: %v", err)
	}
	var idxCount int
	if err := conn.QueryRow(ctx,
		`SELECT count(*) FROM pg_indexes WHERE tablename='widgets' AND indexname='idx_widgets_region'`,
	).Scan(&idxCount); err != nil {
		t.Fatalf("check index: %v", err)
	}
	if idxCount != 1 {
		t.Errorf("expected idx_widgets_region to exist, got count=%d", idxCount)
	}
}

// TestOnlineMigrator_ChangeColumnTypeShadow drives the full shadow
// pattern: build shadow, mirror a concurrent write through the
// trigger, backfill, swap, and verify the column type changed while
// data (including the write made mid-migration) is preserved.
func TestOnlineMigrator_ChangeColumnTypeShadow(t *testing.T) {
	ctx := context.Background()
	conn := connectRaw(t, startPostgres(t))

	mustExec(t, conn, `CREATE TABLE events (id bigint PRIMARY KEY, seq integer NOT NULL)`)
	mustExec(t, conn, `INSERT INTO events (id, seq) SELECT g, g FROM generate_series(1, 25) g`)

	op := migrate.ChangeColumnTypeOp{
		TableName: "events", Column: "seq", NewType: "bigint",
		PrimaryKey: "id", NotNull: true, BatchSize: 10,
	}
	steps, err := op.Steps()
	if err != nil {
		t.Fatalf("Steps: %v", err)
	}

	m := migrate.NewOnlineMigrator(migrate.NewLockMonitor(migrate.LockMonitorConfig{}))

	// Run step 1 (shadow + alter) and step 2 (trigger) explicitly so
	// we can insert a row AFTER the trigger exists but BEFORE the
	// backfill — exercising the live-mirroring path.
	if err := m.ApplyStep(ctx, conn, steps[0]); err != nil {
		t.Fatalf("create shadow: %v", err)
	}
	if err := m.ApplyStep(ctx, conn, steps[1]); err != nil {
		t.Fatalf("install trigger: %v", err)
	}
	// Concurrent write mirrored by the trigger.
	mustExec(t, conn, `INSERT INTO events (id, seq) VALUES (26, 26)`)
	// Remaining steps: backfill + swap.
	if err := m.ApplyStep(ctx, conn, steps[2]); err != nil {
		t.Fatalf("backfill: %v", err)
	}
	if err := m.ApplyStep(ctx, conn, steps[3]); err != nil {
		t.Fatalf("swap: %v", err)
	}

	// The promoted table is named `events` and its seq column is now
	// bigint.
	var dataType string
	if err := conn.QueryRow(ctx,
		`SELECT data_type FROM information_schema.columns WHERE table_name='events' AND column_name='seq'`,
	).Scan(&dataType); err != nil {
		t.Fatalf("inspect column type: %v", err)
	}
	if dataType != "bigint" {
		t.Errorf("expected seq to be bigint, got %q", dataType)
	}

	// All 26 rows (25 backfilled + 1 mirrored) survived.
	var n int
	if err := conn.QueryRow(ctx, `SELECT count(*) FROM events`).Scan(&n); err != nil {
		t.Fatalf("count events: %v", err)
	}
	if n != 26 {
		t.Errorf("expected 26 rows after swap, got %d", n)
	}

	// The original is kept aside for the deprecation window.
	var oldExists bool
	if err := conn.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name='events__old_seq')`,
	).Scan(&oldExists); err != nil {
		t.Fatalf("check old table: %v", err)
	}
	if !oldExists {
		t.Error("expected original table to be renamed aside as events__old_seq")
	}
}

// TestLockMonitor_Integration exercises CountActiveLockers,
// ApplyLockTimeout, and the contention wait against a real lock held
// by a second connection.
func TestLockMonitor_Integration(t *testing.T) {
	ctx := context.Background()
	url := startPostgres(t)
	conn := connectRaw(t, url)
	mustExec(t, conn, `CREATE TABLE hot (id int PRIMARY KEY)`)

	// Threshold of 1: a single locker is tolerated, two are not. This
	// keeps the zero-value-usable contract of NewLockMonitor intact
	// (a config field of 0 means "use the default", not "tolerate
	// zero"), while still exercising the contention path.
	lm := migrate.NewLockMonitor(migrate.LockMonitorConfig{
		MaxActiveTxns:      1,
		LockTimeout:        7 * time.Second,
		BaseBackoff:        5 * time.Millisecond,
		MaxBackoff:         10 * time.Millisecond,
		MaxBackoffAttempts: 3,
	})

	// ApplyLockTimeout is observable via SHOW.
	if err := lm.ApplyLockTimeout(ctx, conn); err != nil {
		t.Fatalf("ApplyLockTimeout: %v", err)
	}
	var shown string
	if err := conn.QueryRow(ctx, `SHOW lock_timeout`).Scan(&shown); err != nil {
		t.Fatalf("SHOW lock_timeout: %v", err)
	}
	if shown != "7s" {
		t.Errorf("expected lock_timeout=7s, got %q", shown)
	}

	// Two concurrent connections each hold ACCESS SHARE on `hot`
	// (which, unlike ACCESS EXCLUSIVE, several sessions can hold at
	// once), pushing the active-locker count to 2 > threshold.
	var txs []pgx.Tx
	for i := 0; i < 2; i++ {
		blocker := connectRaw(t, url)
		tx, err := blocker.Begin(ctx)
		if err != nil {
			t.Fatalf("blocker %d begin: %v", i, err)
		}
		if _, err := tx.Exec(ctx, `LOCK TABLE hot IN ACCESS SHARE MODE`); err != nil {
			t.Fatalf("blocker %d lock: %v", i, err)
		}
		txs = append(txs, tx)
	}

	// The monitor sees the contention and exhausts its budget.
	n, err := lm.CountActiveLockers(ctx, conn, "hot")
	if err != nil {
		t.Fatalf("CountActiveLockers: %v", err)
	}
	if n < 2 {
		t.Errorf("expected at least two active lockers, got %d", n)
	}
	if err := lm.WaitForLowContention(ctx, conn, "hot"); !errors.Is(err, migrate.ErrContention) {
		t.Errorf("expected ErrContention while two sessions lock the table, got %v", err)
	}

	// Release the locks; contention clears and the wait succeeds.
	for i, tx := range txs {
		if err := tx.Rollback(ctx); err != nil {
			t.Fatalf("blocker %d rollback: %v", i, err)
		}
	}
	if err := lm.WaitForLowContention(ctx, conn, "hot"); err != nil {
		t.Errorf("expected contention to clear after release, got %v", err)
	}
}

// TestWithLockTimeout_AppliesViaDSN proves the DSN helper actually
// sets lock_timeout on the resulting connection — the mechanism the
// `--online` CLI path relies on to bound every statement
// golang-migrate runs.
func TestWithLockTimeout_AppliesViaDSN(t *testing.T) {
	ctx := context.Background()
	migrateURL := startPostgres(t)
	pgURL := "postgres" + strings.TrimPrefix(migrateURL, "pgx5")

	withTimeout, err := migrate.WithLockTimeout(pgURL, 3*time.Second)
	if err != nil {
		t.Fatalf("WithLockTimeout: %v", err)
	}
	conn, err := pgx.Connect(ctx, withTimeout)
	if err != nil {
		t.Fatalf("connect with timeout dsn: %v", err)
	}
	defer func() { _ = conn.Close(ctx) }()

	var shown string
	if err := conn.QueryRow(ctx, `SHOW lock_timeout`).Scan(&shown); err != nil {
		t.Fatalf("SHOW lock_timeout: %v", err)
	}
	if shown != "3s" {
		t.Errorf("expected lock_timeout=3s from DSN options, got %q", shown)
	}
}
