package migrate

// online.go implements lock-safe schema-change primitives. Raw DDL
// against a hot, multi-tenant table takes ACCESS EXCLUSIVE for the
// length of a table rewrite; at 5,000 tenants that is a global
// outage. The OnlineMigrator expresses each common change as an
// ordered plan of steps that either avoid the rewrite entirely
// (Postgres 11+ fast-default ADD COLUMN, CREATE INDEX CONCURRENTLY)
// or move the rewrite off the hot path (shadow table + trigger +
// batched backfill + rename, the pg-osc pattern).
//
// Every plan is inspectable without touching a database (Steps()),
// which powers `sng-migrate --dry-run`, and executable against a
// single dedicated connection (Apply), which the `--online` path
// uses. A single connection is required so the session-level
// lock_timeout and CREATE INDEX CONCURRENTLY land on the same
// backend — a pgxpool.Pool would scatter them across connections.

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// Conn is the single-connection surface OnlineMigrator.Apply needs.
// *pgx.Conn satisfies it directly; callers holding a *pgxpool.Pool
// must Acquire a connection and pass conn.Conn() so session state
// (lock_timeout) and non-transactional DDL share one backend.
type Conn interface {
	Querier
	Begin(ctx context.Context) (pgx.Tx, error)
}

// Step is one unit of an online-migration plan. A step is either a
// batched backfill (Backfill != nil) or a set of Statements that run
// together inside one transaction (Transactional) or each on its own
// (used for CREATE INDEX CONCURRENTLY, which Postgres forbids inside
// a transaction block).
type Step struct {
	Description   string
	Statements    []string
	Transactional bool
	Backfill      *BackfillPlan
}

// BackfillPlan describes a keyset-paginated copy from Source into
// Shadow ordered by PrimaryKey, in batches of BatchSize rows. Each
// batch commits independently so the backfill never holds a single
// long transaction (which would pin vacuum and bloat the table).
type BackfillPlan struct {
	Source     string
	Shadow     string
	PrimaryKey string
	BatchSize  int
}

// Operation is a schema change that can be rendered to a plan and
// reports the table whose contention Apply should check first.
type Operation interface {
	Table() string
	Steps() ([]Step, error)
}

// reUnsafeToken rejects a semicolon or comment introducer inside a
// caller-supplied SQL fragment (type, default expression, index
// predicate). These fragments cannot be passed as bind parameters
// (they are DDL), so the API refuses anything that could smuggle a
// second statement past the single-statement contract.
var reUnsafeToken = regexp.MustCompile(`;|--|/\*`)

func checkFragment(kind, frag string) error {
	if reUnsafeToken.MatchString(frag) {
		return fmt.Errorf("online: %s fragment %q contains a statement terminator or comment", kind, frag)
	}
	return nil
}

func ident(name string) string { return pgx.Identifier{name}.Sanitize() }

// --- AddColumnOp -----------------------------------------------------------

// AddColumnOp adds a column. When NotNull is set a Default is
// mandatory: Postgres 11+ records the default in the catalog and
// skips the row rewrite, so `ADD COLUMN ... DEFAULT ... NOT NULL` is
// O(1). NOT NULL without a default would rewrite every row under
// ACCESS EXCLUSIVE, so it is rejected at plan time.
type AddColumnOp struct {
	TableName   string
	Column      string
	Type        string
	Default     string
	NotNull     bool
	IfNotExists bool
}

// Table reports the target table.
func (o AddColumnOp) Table() string { return o.TableName }

// Steps renders the single-statement plan.
func (o AddColumnOp) Steps() ([]Step, error) {
	if o.TableName == "" || o.Column == "" || strings.TrimSpace(o.Type) == "" {
		return nil, errors.New("online: AddColumnOp requires TableName, Column, and Type")
	}
	if err := checkFragment("type", o.Type); err != nil {
		return nil, err
	}
	if o.Default != "" {
		if err := checkFragment("default", o.Default); err != nil {
			return nil, err
		}
	}
	if o.NotNull && strings.TrimSpace(o.Default) == "" {
		return nil, errors.New("online: AddColumnOp with NotNull requires a Default to avoid a table rewrite")
	}

	var b strings.Builder
	fmt.Fprintf(&b, "ALTER TABLE %s ADD COLUMN ", ident(o.TableName))
	if o.IfNotExists {
		b.WriteString("IF NOT EXISTS ")
	}
	fmt.Fprintf(&b, "%s %s", ident(o.Column), strings.TrimSpace(o.Type))
	if o.Default != "" {
		fmt.Fprintf(&b, " DEFAULT %s", strings.TrimSpace(o.Default))
	}
	if o.NotNull {
		b.WriteString(" NOT NULL")
	}
	return []Step{{
		Description:   fmt.Sprintf("add column %s.%s", o.TableName, o.Column),
		Statements:    []string{b.String()},
		Transactional: true,
	}}, nil
}

// --- CreateIndexOp ---------------------------------------------------------

// CreateIndexOp builds an index with CONCURRENTLY so writes are not
// blocked while the index builds. The resulting step is
// non-transactional because Postgres forbids CREATE INDEX
// CONCURRENTLY inside a transaction block.
type CreateIndexOp struct {
	IndexName   string
	TableName   string
	Columns     []string
	Unique      bool
	Method      string
	Where       string
	IfNotExists bool
}

// Table reports the target table.
func (o CreateIndexOp) Table() string { return o.TableName }

// Steps renders the single-statement, non-transactional plan.
func (o CreateIndexOp) Steps() ([]Step, error) {
	if o.IndexName == "" || o.TableName == "" || len(o.Columns) == 0 {
		return nil, errors.New("online: CreateIndexOp requires IndexName, TableName, and at least one Column")
	}
	for _, c := range o.Columns {
		if strings.TrimSpace(c) == "" {
			return nil, errors.New("online: CreateIndexOp has an empty column expression")
		}
		if err := checkFragment("column", c); err != nil {
			return nil, err
		}
	}
	if o.Where != "" {
		if err := checkFragment("where", o.Where); err != nil {
			return nil, err
		}
	}
	if o.Method != "" {
		if err := checkFragment("method", o.Method); err != nil {
			return nil, err
		}
	}

	var b strings.Builder
	b.WriteString("CREATE ")
	if o.Unique {
		b.WriteString("UNIQUE ")
	}
	b.WriteString("INDEX CONCURRENTLY ")
	if o.IfNotExists {
		b.WriteString("IF NOT EXISTS ")
	}
	fmt.Fprintf(&b, "%s ON %s ", ident(o.IndexName), ident(o.TableName))
	if o.Method != "" {
		fmt.Fprintf(&b, "USING %s ", strings.TrimSpace(o.Method))
	}
	fmt.Fprintf(&b, "(%s)", strings.Join(o.Columns, ", "))
	if o.Where != "" {
		fmt.Fprintf(&b, " WHERE %s", strings.TrimSpace(o.Where))
	}
	return []Step{{
		Description:   fmt.Sprintf("create index %s on %s", o.IndexName, o.TableName),
		Statements:    []string{b.String()},
		Transactional: false,
	}}, nil
}

// --- ChangeColumnTypeOp ----------------------------------------------------

// DefaultBackfillBatchSize is the row count copied per backfill
// transaction when a ChangeColumnTypeOp does not specify one.
const DefaultBackfillBatchSize = 1000

// ChangeColumnTypeOp changes a column's type using the shadow-table
// pattern: a like-for-like shadow table receives the altered column,
// a trigger mirrors live writes from the source, a batched backfill
// copies existing rows, and a final rename swaps the tables. The
// original table is renamed aside (not dropped) so the swap is
// reversible and the drop can wait for a deprecation window.
type ChangeColumnTypeOp struct {
	TableName  string
	Column     string
	NewType    string
	Using      string
	PrimaryKey string
	NotNull    bool
	BatchSize  int
}

// Table reports the target table.
func (o ChangeColumnTypeOp) Table() string { return o.TableName }

func (o ChangeColumnTypeOp) shadowName() string   { return o.TableName + "__shadow_" + o.Column }
func (o ChangeColumnTypeOp) oldName() string      { return o.TableName + "__old_" + o.Column }
func (o ChangeColumnTypeOp) triggerName() string  { return o.TableName + "__sync_" + o.Column }
func (o ChangeColumnTypeOp) functionName() string { return o.TableName + "__sync_fn_" + o.Column }

// Steps renders the full shadow-table plan.
func (o ChangeColumnTypeOp) Steps() ([]Step, error) {
	if o.TableName == "" || o.Column == "" || strings.TrimSpace(o.NewType) == "" || o.PrimaryKey == "" {
		return nil, errors.New("online: ChangeColumnTypeOp requires TableName, Column, NewType, and PrimaryKey")
	}
	if err := checkFragment("type", o.NewType); err != nil {
		return nil, err
	}
	if o.Using != "" {
		if err := checkFragment("using", o.Using); err != nil {
			return nil, err
		}
	}
	batch := o.BatchSize
	if batch <= 0 {
		batch = DefaultBackfillBatchSize
	}

	src := ident(o.TableName)
	shadow := ident(o.shadowName())
	col := ident(o.Column)
	pk := ident(o.PrimaryKey)
	fn := ident(o.functionName())
	trg := ident(o.triggerName())

	// Step 1: build the shadow table and apply the type change to it
	// while it is empty (instant), inside one transaction.
	alter := fmt.Sprintf("ALTER TABLE %s ALTER COLUMN %s TYPE %s", shadow, col, strings.TrimSpace(o.NewType))
	if o.Using != "" {
		alter += " USING " + strings.TrimSpace(o.Using)
	}
	create := []string{
		fmt.Sprintf("CREATE TABLE %s (LIKE %s INCLUDING ALL)", shadow, src),
		alter,
	}
	if o.NotNull {
		create = append(create, fmt.Sprintf("ALTER TABLE %s ALTER COLUMN %s SET NOT NULL", shadow, col))
	}

	// Step 2: a trigger that mirrors every write on the source into
	// the shadow. INSERT/UPDATE upsert NEW so the trigger's row — the
	// newest copy — always wins: the backfill (step 3) inserts with
	// ON CONFLICT DO NOTHING, so without DO UPDATE here a write that
	// fires the trigger while a backfill batch holds an uncommitted
	// row on the same PK would hit a duplicate-key violation and roll
	// back the user's DML (the very writability the pattern exists to
	// preserve). The SET list is built at trigger-fire time from the
	// shadow's live columns (pg_attribute), so the trigger needs no
	// compile-time column list and the assignment casts that coerce
	// the changed column to its new type apply on the INSERT. A
	// leading DELETE by OLD PK still runs on UPDATE/DELETE so a row
	// whose primary key changed does not leave a stale shadow row.
	fnBody := fmt.Sprintf(`CREATE OR REPLACE FUNCTION %s() RETURNS trigger
LANGUAGE plpgsql AS $sng_online$
DECLARE
    set_clause text;
BEGIN
    IF (TG_OP = 'DELETE' OR TG_OP = 'UPDATE') THEN
        DELETE FROM %s WHERE %s = OLD.%s;
    END IF;
    IF (TG_OP = 'INSERT' OR TG_OP = 'UPDATE') THEN
        SELECT string_agg(format('%%I = EXCLUDED.%%I', attname, attname), ', ')
          INTO set_clause
          FROM pg_attribute
         WHERE attrelid = '%s'::regclass
           AND attnum > 0
           AND NOT attisdropped;
        EXECUTE format(
            'INSERT INTO %s SELECT ($1).* ON CONFLICT (%s) DO UPDATE SET %%s',
            set_clause
        ) USING NEW;
    END IF;
    RETURN COALESCE(NEW, OLD);
END;
$sng_online$`, fn, shadow, pk, pk, shadow, shadow, pk)
	trigger := fmt.Sprintf(
		"CREATE TRIGGER %s AFTER INSERT OR UPDATE OR DELETE ON %s FOR EACH ROW EXECUTE FUNCTION %s()",
		trg, src, fn)

	// Step 3: batched backfill of pre-existing rows.
	backfill := &BackfillPlan{
		Source:     o.TableName,
		Shadow:     o.shadowName(),
		PrimaryKey: o.PrimaryKey,
		BatchSize:  batch,
	}

	// Step 4: swap. Rename the source aside (kept for the
	// deprecation window), promote the shadow, and tear down the
	// sync trigger/function — all in one transaction so readers
	// never see a missing table.
	swap := []string{
		fmt.Sprintf("DROP TRIGGER %s ON %s", trg, src),
		fmt.Sprintf("ALTER TABLE %s RENAME TO %s", src, ident(o.oldName())),
		fmt.Sprintf("ALTER TABLE %s RENAME TO %s", shadow, ident(o.TableName)),
		fmt.Sprintf("DROP FUNCTION %s()", fn),
	}

	return []Step{
		{Description: "create shadow table with altered column", Statements: create, Transactional: true},
		{Description: "install write-mirroring trigger", Statements: []string{fnBody, trigger}, Transactional: true},
		{Description: "backfill existing rows in batches", Backfill: backfill},
		{Description: "swap shadow into place (original kept as " + o.oldName() + ")", Statements: swap, Transactional: true},
	}, nil
}

// --- OnlineMigrator --------------------------------------------------------

// OnlineMigrator executes operation plans with lock safety: it sets
// a bounded lock_timeout, waits out table contention via the
// LockMonitor, and runs each step under the correct transaction mode.
type OnlineMigrator struct {
	monitor *LockMonitor
}

// NewOnlineMigrator returns an OnlineMigrator using monitor for
// contention checks and lock_timeout. A nil monitor gets the
// defaults.
func NewOnlineMigrator(monitor *LockMonitor) *OnlineMigrator {
	if monitor == nil {
		monitor = NewLockMonitor(LockMonitorConfig{})
	}
	return &OnlineMigrator{monitor: monitor}
}

// DryRun renders op's plan to SQL text without touching a database.
// Backfill steps are rendered as a representative batch statement so
// the operator sees the shape of the work.
func (m *OnlineMigrator) DryRun(op Operation) ([]string, error) {
	steps, err := op.Steps()
	if err != nil {
		return nil, err
	}
	var out []string
	for _, st := range steps {
		if st.Backfill != nil {
			out = append(out, "-- "+st.Description, backfillSQL(st.Backfill, false))
			continue
		}
		if st.Description != "" {
			out = append(out, "-- "+st.Description)
		}
		mode := "standalone"
		if st.Transactional {
			mode = "transaction"
		}
		out = append(out, fmt.Sprintf("-- (%s)", mode))
		for _, s := range st.Statements {
			out = append(out, s+";")
		}
	}
	return out, nil
}

// Apply executes op's plan against conn. conn MUST be a single
// dedicated connection. Apply first waits for table contention to
// fall below the monitor's threshold, then runs each step: backfills
// loop batch-by-batch, transactional steps run under one
// transaction with SET LOCAL lock_timeout, and non-transactional
// steps (CREATE INDEX CONCURRENTLY) run on the session after setting
// lock_timeout on it.
func (m *OnlineMigrator) Apply(ctx context.Context, conn Conn, op Operation) error {
	steps, err := op.Steps()
	if err != nil {
		return err
	}
	if op.Table() != "" {
		if err := m.monitor.WaitForLowContention(ctx, conn, op.Table()); err != nil {
			return err
		}
	}
	for _, st := range steps {
		if err := m.ApplyStep(ctx, conn, st); err != nil {
			return err
		}
	}
	return nil
}

// ApplyStep executes a single plan step against conn under the
// correct mode: a backfill loops batch-by-batch, a transactional
// step runs its statements in one transaction with SET LOCAL
// lock_timeout, and any other step runs its statements standalone on
// the session (the CREATE INDEX CONCURRENTLY case) after setting
// lock_timeout. It is exported so callers that interleave their own
// work between steps — and tests exercising the live-mirroring
// trigger — can drive the plan one step at a time.
func (m *OnlineMigrator) ApplyStep(ctx context.Context, conn Conn, st Step) error {
	switch {
	case st.Backfill != nil:
		if err := m.runBackfill(ctx, conn, st.Backfill); err != nil {
			return fmt.Errorf("backfill %s->%s: %w", st.Backfill.Source, st.Backfill.Shadow, err)
		}
	case st.Transactional:
		if err := m.runTransactional(ctx, conn, st); err != nil {
			return fmt.Errorf("step %q: %w", st.Description, err)
		}
	default:
		if err := m.runStandalone(ctx, conn, st); err != nil {
			return fmt.Errorf("step %q: %w", st.Description, err)
		}
	}
	return nil
}

func (m *OnlineMigrator) runTransactional(ctx context.Context, conn Conn, st Step) error {
	tx, err := conn.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()
	// SET LOCAL bounds lock acquisition for the life of this
	// transaction only; it reverts automatically on commit/rollback.
	if _, err := tx.Exec(ctx, fmt.Sprintf("SET LOCAL lock_timeout = %d", m.monitor.LockTimeout().Milliseconds())); err != nil {
		return fmt.Errorf("set local lock_timeout: %w", err)
	}
	for _, s := range st.Statements {
		if _, err := tx.Exec(ctx, s); err != nil {
			return err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	committed = true
	return nil
}

func (m *OnlineMigrator) runStandalone(ctx context.Context, conn Conn, st Step) error {
	if err := m.monitor.ApplyLockTimeout(ctx, conn); err != nil {
		return err
	}
	for _, s := range st.Statements {
		if _, err := conn.Exec(ctx, s); err != nil {
			return err
		}
	}
	return nil
}

// runBackfill copies rows from Source into Shadow ordered by the
// primary key, BatchSize rows per committed batch, until a batch
// copies nothing. It sets a session lock_timeout once up front (each
// batch is an autocommit statement on the same connection, so the
// session setting bounds every batch) so a batch INSERT cannot block
// indefinitely on a row lock held by a concurrent writer, and uses
// ON CONFLICT DO NOTHING so rows the sync trigger already mirrored
// are not duplicated.
func (m *OnlineMigrator) runBackfill(ctx context.Context, conn Conn, p *BackfillPlan) error {
	if err := m.monitor.ApplyLockTimeout(ctx, conn); err != nil {
		return err
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		tag, err := conn.Exec(ctx, backfillSQL(p, true), p.BatchSize)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return nil
		}
	}
}

// backfillSQL renders the keyset-paginated copy. When parametrised
// is true the batch size is bound as $1; otherwise it is inlined for
// dry-run display. The "next unsynced PK" is found with a NOT EXISTS
// anti-join against the shadow so each call advances and the loop
// terminates.
func backfillSQL(p *BackfillPlan, parametrised bool) string {
	src := ident(p.Source)
	shadow := ident(p.Shadow)
	pk := ident(p.PrimaryKey)
	limit := "$1"
	if !parametrised {
		limit = strconv.Itoa(p.BatchSize)
	}
	return fmt.Sprintf(
		"INSERT INTO %s SELECT s.* FROM %s s WHERE NOT EXISTS "+
			"(SELECT 1 FROM %s d WHERE d.%s = s.%s) ORDER BY s.%s LIMIT %s ON CONFLICT (%s) DO NOTHING",
		shadow, src, shadow, pk, pk, pk, limit, pk)
}

// --- DSN + pending-migration helpers (used by the CLI) ---------------------

// WithLockTimeout returns baseURL with a Postgres `options` startup
// parameter that sets lock_timeout for every statement on the
// connection. golang-migrate's pgx5 driver passes the parameter
// through to pgx, so migrations applied via the runner inherit the
// bound even though the runner owns the connection. A non-positive
// duration returns baseURL unchanged.
func WithLockTimeout(baseURL string, d time.Duration) (string, error) {
	if d <= 0 {
		return baseURL, nil
	}
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", fmt.Errorf("parse dsn: %w", err)
	}
	q := u.Query()
	// `-c lock_timeout=<ms>` is the PGOPTIONS form Postgres applies
	// at connection start; url encoding handles the embedded space
	// and equals sign.
	q.Set("options", fmt.Sprintf("-c lock_timeout=%d", d.Milliseconds()))
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// PendingMigration is one not-yet-applied up migration.
type PendingMigration struct {
	Version uint
	Name    string
	UpSQL   string
}

var reUpName = regexp.MustCompile(`^(\d+)_([a-z0-9_]+)\.up\.sql$`)

// PendingUp returns every embedded up migration whose numeric
// version is greater than currentVersion, sorted ascending. It backs
// `sng-migrate --dry-run`, which prints the SQL that an `up` would
// apply without applying it.
func PendingUp(currentVersion uint) ([]PendingMigration, error) {
	entries, err := fs.ReadDir(SourceFS(), ".")
	if err != nil {
		return nil, fmt.Errorf("read embedded migrations: %w", err)
	}
	var out []PendingMigration
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		mm := reUpName.FindStringSubmatch(e.Name())
		if mm == nil {
			continue
		}
		v64, err := strconv.ParseUint(mm[1], 10, 32)
		if err != nil {
			return nil, fmt.Errorf("parse version from %q: %w", e.Name(), err)
		}
		v := uint(v64)
		if v <= currentVersion {
			continue
		}
		b, err := fs.ReadFile(SourceFS(), e.Name())
		if err != nil {
			return nil, fmt.Errorf("read %q: %w", e.Name(), err)
		}
		out = append(out, PendingMigration{Version: v, Name: e.Name(), UpSQL: string(b)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Version < out[j].Version })
	return out, nil
}
