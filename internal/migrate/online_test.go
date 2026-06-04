package migrate

import (
	"net/url"
	"strings"
	"testing"
	"time"
)

func onlySteps(t *testing.T, op Operation) []Step {
	t.Helper()
	steps, err := op.Steps()
	if err != nil {
		t.Fatalf("Steps() error: %v", err)
	}
	return steps
}

func TestAddColumnOp_SafeDefault(t *testing.T) {
	op := AddColumnOp{TableName: "devices", Column: "region", Type: "text", Default: "'us'", NotNull: true}
	steps := onlySteps(t, op)
	if len(steps) != 1 || !steps[0].Transactional {
		t.Fatalf("want 1 transactional step, got %+v", steps)
	}
	got := steps[0].Statements[0]
	want := `ALTER TABLE "devices" ADD COLUMN "region" text DEFAULT 'us' NOT NULL`
	if got != want {
		t.Fatalf("unexpected SQL:\n got: %s\nwant: %s", got, want)
	}
}

func TestAddColumnOp_NotNullWithoutDefaultRejected(t *testing.T) {
	op := AddColumnOp{TableName: "devices", Column: "region", Type: "text", NotNull: true}
	if _, err := op.Steps(); err == nil {
		t.Fatal("expected error: NOT NULL without DEFAULT")
	}
}

func TestAddColumnOp_RejectsInjection(t *testing.T) {
	op := AddColumnOp{TableName: "devices", Column: "region", Type: "text; DROP TABLE devices"}
	if _, err := op.Steps(); err == nil {
		t.Fatal("expected error for statement terminator in type fragment")
	}
}

func TestCreateIndexOp_Concurrent(t *testing.T) {
	op := CreateIndexOp{
		IndexName: "idx_devices_region", TableName: "devices",
		Columns: []string{"region", "lower(name)"}, Unique: true,
		Method: "btree", Where: "deleted_at IS NULL", IfNotExists: true,
	}
	steps := onlySteps(t, op)
	if len(steps) != 1 || steps[0].Transactional {
		t.Fatalf("CREATE INDEX CONCURRENTLY must be a single non-transactional step, got %+v", steps)
	}
	got := steps[0].Statements[0]
	want := `CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS "idx_devices_region" ON "devices" USING btree (region, lower(name)) WHERE deleted_at IS NULL`
	if got != want {
		t.Fatalf("unexpected SQL:\n got: %s\nwant: %s", got, want)
	}
	if !strings.Contains(got, "CONCURRENTLY") {
		t.Error("index DDL missing CONCURRENTLY")
	}
}

func TestChangeColumnTypeOp_Plan(t *testing.T) {
	op := ChangeColumnTypeOp{
		TableName: "events", Column: "seq", NewType: "bigint",
		PrimaryKey: "id", NotNull: true,
	}
	steps := onlySteps(t, op)
	if len(steps) != 4 {
		t.Fatalf("want 4 steps (create, trigger, backfill, swap), got %d", len(steps))
	}

	// Step 1: shadow table + altered type + not null.
	create := strings.Join(steps[0].Statements, "\n")
	for _, want := range []string{
		`CREATE TABLE "events__shadow_seq" (LIKE "events" INCLUDING ALL)`,
		`ALTER TABLE "events__shadow_seq" ALTER COLUMN "seq" TYPE bigint`,
		`ALTER TABLE "events__shadow_seq" ALTER COLUMN "seq" SET NOT NULL`,
	} {
		if !strings.Contains(create, want) {
			t.Errorf("create step missing %q\ngot:\n%s", want, create)
		}
	}

	// Step 2: trigger mirrors writes.
	trig := strings.Join(steps[1].Statements, "\n")
	if !strings.Contains(trig, "CREATE OR REPLACE FUNCTION") || !strings.Contains(trig, "AFTER INSERT OR UPDATE OR DELETE") {
		t.Errorf("trigger step malformed:\n%s", trig)
	}
	// The trigger must upsert (ON CONFLICT ... DO UPDATE) so its row —
	// the newest copy — wins over the backfill's ON CONFLICT DO NOTHING
	// instead of colliding with it (the duplicate-key race).
	for _, want := range []string{
		`ON CONFLICT ("id") DO UPDATE SET`,
		"FROM pg_attribute",
		`'"events__shadow_seq"'::regclass`,
	} {
		if !strings.Contains(trig, want) {
			t.Errorf("trigger step missing %q\ngot:\n%s", want, trig)
		}
	}
	if strings.Contains(trig, "INSERT INTO \"events__shadow_seq\" SELECT (NEW).*;") {
		t.Errorf("trigger still uses bare INSERT (no ON CONFLICT):\n%s", trig)
	}

	// Step 3: backfill plan.
	if steps[2].Backfill == nil {
		t.Fatal("step 3 should be a backfill")
	}
	// First batch: no cursor bound, batch size is $1, and the
	// data-modifying CTE returns max(pk) so the caller can advance.
	bfFirst := backfillSQL(steps[2].Backfill, true, false)
	for _, want := range []string{
		"WITH batch AS",
		"ON CONFLICT",
		"ORDER BY",
		"LIMIT $1",
		`SELECT max("id") FROM batch`,
	} {
		if !strings.Contains(bfFirst, want) {
			t.Errorf("first-batch backfill SQL missing %q: %s", want, bfFirst)
		}
	}
	if strings.Contains(bfFirst, "WHERE") {
		t.Errorf("first-batch backfill SQL should have no cursor bound: %s", bfFirst)
	}
	// Subsequent batches are keyset-paginated: bound below by the
	// cursor (pk > $1), batch size is $2. No NOT EXISTS anti-join (the
	// old approach that re-scanned copied rows every batch).
	bfNext := backfillSQL(steps[2].Backfill, true, true)
	for _, want := range []string{`WHERE s."id" > $1`, "LIMIT $2", "ON CONFLICT"} {
		if !strings.Contains(bfNext, want) {
			t.Errorf("keyset backfill SQL missing %q: %s", want, bfNext)
		}
	}
	if strings.Contains(bfNext, "NOT EXISTS") {
		t.Errorf("backfill SQL should use keyset pagination, not a NOT EXISTS anti-join: %s", bfNext)
	}

	// Step 4: swap renames original aside, promotes shadow, drops trigger/fn.
	swap := strings.Join(steps[3].Statements, "\n")
	for _, want := range []string{
		`ALTER TABLE "events" RENAME TO "events__old_seq"`,
		`ALTER TABLE "events__shadow_seq" RENAME TO "events"`,
		`DROP TRIGGER "events__sync_seq" ON "events"`,
		`DROP FUNCTION "events__sync_fn_seq"()`,
	} {
		if !strings.Contains(swap, want) {
			t.Errorf("swap step missing %q\ngot:\n%s", want, swap)
		}
	}
}

func TestChangeColumnTypeOp_Validation(t *testing.T) {
	if _, err := (ChangeColumnTypeOp{TableName: "t", Column: "c", NewType: "bigint"}).Steps(); err == nil {
		t.Error("expected error when PrimaryKey is missing")
	}
	if _, err := (ChangeColumnTypeOp{TableName: "t", Column: "c", NewType: "big;int", PrimaryKey: "id"}).Steps(); err == nil {
		t.Error("expected error for injection in NewType")
	}
}

func TestDryRun_RendersSQL(t *testing.T) {
	m := NewOnlineMigrator(nil)
	op := ChangeColumnTypeOp{TableName: "events", Column: "seq", NewType: "bigint", PrimaryKey: "id"}
	lines, err := m.DryRun(op)
	if err != nil {
		t.Fatalf("DryRun: %v", err)
	}
	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, "CREATE TABLE") || !strings.Contains(joined, "INSERT INTO") {
		t.Fatalf("dry-run output missing expected DDL:\n%s", joined)
	}
}

func TestWithLockTimeout(t *testing.T) {
	base := "pgx5://u:p@localhost:5432/db?sslmode=disable"
	got, err := WithLockTimeout(base, 5*time.Second)
	if err != nil {
		t.Fatalf("WithLockTimeout: %v", err)
	}
	if !strings.Contains(got, "options=") || !strings.Contains(got, "lock_timeout%3D5000") {
		t.Fatalf("expected options with lock_timeout=5000 ms, got %s", got)
	}
	// Idempotent for non-positive duration.
	same, err := WithLockTimeout(base, 0)
	if err != nil || same != base {
		t.Fatalf("zero duration should return base unchanged, got %q (%v)", same, err)
	}

	// A pre-existing `options` must be preserved, not overwritten:
	// our `-c lock_timeout` is appended after the caller's settings.
	withOpts := "pgx5://u:p@localhost:5432/db?options=-c%20search_path%3Dsng"
	merged, err := WithLockTimeout(withOpts, 5*time.Second)
	if err != nil {
		t.Fatalf("WithLockTimeout (merge): %v", err)
	}
	u, err := url.Parse(merged)
	if err != nil {
		t.Fatalf("parse merged dsn: %v", err)
	}
	gotOpts := u.Query().Get("options")
	if want := "-c search_path=sng -c lock_timeout=5000"; gotOpts != want {
		t.Fatalf("expected merged options %q, got %q", want, gotOpts)
	}
}

func TestPendingUp(t *testing.T) {
	// Embedded migrations start at version 1; with current=0 every
	// migration is pending and sorted ascending.
	pend, err := PendingUp(0)
	if err != nil {
		t.Fatalf("PendingUp: %v", err)
	}
	if len(pend) == 0 {
		t.Fatal("expected at least one pending migration")
	}
	if pend[0].Version != 1 {
		t.Errorf("first pending version should be 1, got %d", pend[0].Version)
	}
	for i := 1; i < len(pend); i++ {
		if pend[i].Version <= pend[i-1].Version {
			t.Errorf("pending migrations not sorted ascending at %d", i)
		}
	}
	// A high current version leaves nothing pending.
	pend2, err := PendingUp(100000)
	if err != nil {
		t.Fatalf("PendingUp high: %v", err)
	}
	if len(pend2) != 0 {
		t.Errorf("expected no pending migrations, got %d", len(pend2))
	}
}
