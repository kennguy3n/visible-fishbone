package clickhouse

import (
	"io"
	"log/slog"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/nats/schema"
)

// quietLogger discards every log record. The requeue path emits
// slog.Info / slog.Warn lines per shed row, which would flood
// the test runner's stdout otherwise.
func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// mkEnv builds a minimally-valid Envelope for the requeue tests.
// The Envelope's actual contents do not matter for the tests
// below — they exercise the slice plumbing in requeueBatch, not
// the per-row Append path.
func mkEnv() schema.Envelope {
	return schema.Envelope{
		EventID:  uuid.New(),
		TenantID: uuid.New(),
		DeviceID: uuid.New(),
	}
}

// TestWriter_StatsHoldsMutex exercises the Stats() method under
// the race detector to confirm that all four counters are read
// under the same mutex acquisition. The previous implementation
// released the mutex after reading len(w.pending) and then read
// flushed / flushErrors without the lock, producing a race
// against the flush goroutine's increment paths. Run this test
// with `go test -race` to detect any regression.
func TestWriter_StatsHoldsMutex(t *testing.T) {
	t.Parallel()
	w := &Writer{
		// Pending is populated below by the writer goroutine; no
		// need for a conn / loop in this unit test because Stats
		// does not touch them.
		pending: make([]schema.Envelope, 0, 16),
	}
	var wg sync.WaitGroup
	stop := make(chan struct{})

	// Writer goroutine: mutate every counter Stats reads, under
	// the mutex, exactly as flushOnce does in production.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			w.mu.Lock()
			w.flushed++
			w.flushErrors++
			w.consecutiveErrors++
			w.pending = append(w.pending, schema.Envelope{})
			if len(w.pending) > 1 {
				w.pending = w.pending[:0]
			}
			w.mu.Unlock()
		}
	}()

	// Reader goroutine: call Stats() in a tight loop. With
	// -race, any unsynchronised read of flushed / flushErrors /
	// consecutiveErrors would be flagged.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 50_000; i++ {
			s := w.Stats()
			// Touch every field so the compiler can't elide them.
			_ = s.Pending + int(s.Flushed) + int(s.FlushErrors) + int(s.ConsecutiveErrors)
		}
		close(stop)
	}()

	wg.Wait()
}

// TestWriter_StatsResetsConsecutiveOnSuccess pins the
// ConsecutiveErrors reset contract: a successful flush resets
// the counter to zero, while a failure leaves it incrementing.
// Operators rely on this signal to alert on a sustained outage
// (consecutive failures > N) versus transient noise. We exercise
// it through the counter directly because flushOnce requires a
// real driver.Conn; the production path mirrors the same
// increment / reset semantics.
func TestWriter_StatsResetsConsecutiveOnSuccess(t *testing.T) {
	t.Parallel()
	w := &Writer{pending: make([]schema.Envelope, 0)}
	// Simulate three failed flushes.
	for i := 0; i < 3; i++ {
		w.mu.Lock()
		w.flushErrors++
		w.consecutiveErrors++
		w.mu.Unlock()
	}
	if got := w.Stats().ConsecutiveErrors; got != 3 {
		t.Fatalf("after 3 fails: want 3, got %d", got)
	}
	// Simulate a successful flush.
	w.mu.Lock()
	w.flushed += 5
	w.consecutiveErrors = 0
	w.mu.Unlock()
	s := w.Stats()
	if s.ConsecutiveErrors != 0 {
		t.Errorf("after success: ConsecutiveErrors want 0, got %d", s.ConsecutiveErrors)
	}
	if s.FlushErrors != 3 {
		t.Errorf("after success: FlushErrors must be sticky, want 3, got %d", s.FlushErrors)
	}
	if s.Flushed != 5 {
		t.Errorf("after success: Flushed want 5, got %d", s.Flushed)
	}
}

// TestConfig_Validate guards the operator-config SQL-identifier
// invariant. The Writer interpolates Config.Database and
// Config.Table into the generated DDL/DML via fmt.Sprintf, so any
// value that escapes the unquoted-identifier syntax — semicolons,
// quotes, comments, backticks, newlines — opens a SQL injection
// surface for whoever controls the deployment config. validate()
// must reject every such value and must accept the boring
// identifier shapes the platform actually uses (DefaultTable,
// custom suffixed names like sng_telemetry_dev).
func TestConfig_Validate(t *testing.T) {
	t.Parallel()
	ok := []string{
		DefaultTable,
		"sng_telemetry_dev",
		"_internal",
		"A1",
	}
	for _, name := range ok {
		c := Config{Database: "default", Table: name}
		if err := c.validate(); err != nil {
			t.Errorf("validate(%q) unexpectedly failed: %v", name, err)
		}
	}
	bad := []string{
		"",                    // empty
		"1name",               // leading digit
		"sng_telemetry; DROP", // statement injection
		"sng_telemetry`",      // backtick
		"sng_telemetry--",     // comment marker
		"sng telemetry",       // space
		"sng_telemetry\nDROP", // newline
		"\"sng_telemetry\"",   // quoted
		"db.sng_telemetry",    // dotted (cross-db)
	}
	for _, name := range bad {
		c := Config{Database: "default", Table: name}
		if err := c.validate(); err == nil {
			t.Errorf("validate(Table=%q) should have failed but did not", name)
		}
	}
	// Database must be validated symmetrically: a malicious
	// Database value would land in the driver's Auth handshake
	// and is also embedded by the migration runner.
	bad = []string{"", "1db", "db; DROP", "db`", "db\nx"}
	for _, name := range bad {
		c := Config{Database: name, Table: DefaultTable}
		if err := c.validate(); err == nil {
			t.Errorf("validate(Database=%q) should have failed but did not", name)
		}
	}
}

// TestQuoteIdentifier exercises the quoting helper directly. The
// production validate() path rejects any caller-supplied
// identifier with a backtick, so the escape branch is dead code
// against today's validator — but the helper still must produce
// correctly-quoted output if a future validator broadens the
// accepted character set (e.g. to accept dot-separated db.table
// paths). Pin the behaviour explicitly here so a regression in
// either direction is loud.
func TestQuoteIdentifier(t *testing.T) {
	t.Parallel()
	cases := []struct{ in, out string }{
		{"sng_telemetry", "`sng_telemetry`"},
		{"my_db", "`my_db`"},
		// backtick escape: doubled inside quotes
		{"weird`name", "`weird``name`"},
		{"`leading", "```leading`"},
		{"", "``"},
	}
	for _, c := range cases {
		got := quoteIdentifier(c.in)
		if got != c.out {
			t.Errorf("quoteIdentifier(%q): want %q, got %q", c.in, c.out, got)
		}
	}
}

// TestQualifiedTable_LiteralWriter exercises the use-site
// validation behaviour: a Writer built via a struct literal
// (bypassing New) must still hit identifier validation when its
// table accessor is called. This catches a class of bug where a
// future caller — internal test code, a misguided wiring change —
// constructs a Writer{} directly and skips the constructor's
// guard. The accessor must reject the bad identifier rather than
// silently quote it.
func TestQualifiedTable_LiteralWriter(t *testing.T) {
	t.Parallel()
	// Literal Writer with validated == false (zero value). A bad
	// identifier must be rejected at the use site.
	bad := &Writer{cfg: Config{Table: "sng_telemetry; DROP"}}
	if _, err := bad.qualifiedTable(); err == nil {
		t.Errorf("qualifiedTable on unvalidated Writer with bad Table should have failed")
	}
	// Literal Writer with a good identifier. Should return the
	// quoted form.
	good := &Writer{cfg: Config{Table: "sng_telemetry"}}
	q, err := good.qualifiedTable()
	if err != nil {
		t.Fatalf("qualifiedTable on unvalidated Writer with good Table failed: %v", err)
	}
	if q != "`sng_telemetry`" {
		t.Errorf("qualifiedTable: want `sng_telemetry`, got %s", q)
	}
	// Writer that has gone through New() (validated == true).
	// The accessor must skip the redundant re-validation and
	// just return the quoted form.
	trusted := &Writer{cfg: Config{Table: "sng_telemetry"}, validated: true}
	q, err = trusted.qualifiedTable()
	if err != nil {
		t.Fatalf("qualifiedTable on validated Writer failed: %v", err)
	}
	if q != "`sng_telemetry`" {
		t.Errorf("qualifiedTable: want `sng_telemetry`, got %s", q)
	}
}

// TestWriter_DroppedRowsCounterSurfacesViaStats pins the
// observability contract for the new partial-batch-drop
// behaviour: flushOnce skips individual rows whose Append() the
// driver rejects (rather than losing the whole batch as the
// previous behaviour did), and the per-row drops accumulate into
// Writer.droppedRows which surfaces in Stats().DroppedRows for
// dashboards / alerting. The counter is sticky across flushes so
// a sustained non-zero increment rate signals schema / producer
// drift; a single one-off drop on a malformed envelope is
// expected noise. Exercises the counter via direct mutation
// (mirroring TestWriter_StatsResetsConsecutiveOnSuccess) because
// flushOnce requires a real driver.Conn.
func TestWriter_DroppedRowsCounterSurfacesViaStats(t *testing.T) {
	t.Parallel()
	w := &Writer{pending: make([]schema.Envelope, 0)}
	if got := w.Stats().DroppedRows; got != 0 {
		t.Fatalf("fresh writer: DroppedRows want 0, got %d", got)
	}
	// First flush: 2 rows dropped out of a batch of 10, the
	// other 8 sent successfully (we record both the drop count
	// and the flushed count).
	w.mu.Lock()
	w.droppedRows += 2
	w.flushed += 8
	w.consecutiveErrors = 0
	w.mu.Unlock()
	s := w.Stats()
	if s.DroppedRows != 2 {
		t.Errorf("after partial-drop flush: DroppedRows want 2, got %d", s.DroppedRows)
	}
	if s.Flushed != 8 {
		t.Errorf("after partial-drop flush: Flushed want 8, got %d", s.Flushed)
	}
	// Second flush: 0 drops, all 10 rows succeed. DroppedRows
	// is sticky (cumulative), Flushed accumulates.
	w.mu.Lock()
	w.flushed += 10
	w.consecutiveErrors = 0
	w.mu.Unlock()
	s = w.Stats()
	if s.DroppedRows != 2 {
		t.Errorf("after clean flush: DroppedRows must be sticky, want 2, got %d", s.DroppedRows)
	}
	if s.Flushed != 18 {
		t.Errorf("after clean flush: Flushed want 18, got %d", s.Flushed)
	}
	// Third flush: every row in the batch was rejected — the
	// flushOnce path also increments flushErrors and
	// consecutiveErrors on the all-rejected case, because no
	// rows reached the wire.
	w.mu.Lock()
	w.droppedRows += 5
	w.flushErrors++
	w.consecutiveErrors++
	w.mu.Unlock()
	s = w.Stats()
	if s.DroppedRows != 7 {
		t.Errorf("after all-rejected flush: DroppedRows want 7, got %d", s.DroppedRows)
	}
	if s.FlushErrors != 1 {
		t.Errorf("after all-rejected flush: FlushErrors want 1, got %d", s.FlushErrors)
	}
	if s.ConsecutiveErrors != 1 {
		t.Errorf("after all-rejected flush: ConsecutiveErrors want 1, got %d", s.ConsecutiveErrors)
	}
}

// TestRequeueBatch_PrependsToHeadOfPending pins the FIFO ordering
// contract: a failed-batch requeue lands at the HEAD of pending
// (oldest-first), with any rows that arrived during the failed
// flush attempt following behind. Without this ordering, a
// requeued batch would jump the queue and be sent ahead of rows
// the producer wrote later than the original batch, breaking the
// per-writer FIFO guarantee the cold-path / aggregate
// dashboards depend on for chronological event ordering.
func TestRequeueBatch_PrependsToHeadOfPending(t *testing.T) {
	t.Parallel()
	failedA, failedB := mkEnv(), mkEnv()
	concurrentC := mkEnv()
	w := &Writer{
		cfg:     Config{BatchSize: 1024, MaxBacklogMultiplier: 4},
		logger:  quietLogger(),
		pending: []schema.Envelope{concurrentC},
	}
	w.requeueBatch([]schema.Envelope{failedA, failedB}, "test", requeueDrops{})
	if got, want := len(w.pending), 3; got != want {
		t.Fatalf("len(pending): got %d, want %d", got, want)
	}
	if w.pending[0].EventID != failedA.EventID {
		t.Errorf("head: want failedA, got %s", w.pending[0].EventID)
	}
	if w.pending[1].EventID != failedB.EventID {
		t.Errorf("second: want failedB, got %s", w.pending[1].EventID)
	}
	if w.pending[2].EventID != concurrentC.EventID {
		t.Errorf("tail: want concurrentC, got %s", w.pending[2].EventID)
	}
	s := w.Stats()
	if s.RequeuedBatches != 1 {
		t.Errorf("RequeuedBatches: want 1, got %d", s.RequeuedBatches)
	}
	if s.BacklogDrops != 0 {
		t.Errorf("BacklogDrops on a non-overflow requeue: want 0, got %d", s.BacklogDrops)
	}
	// Single-lock invariant: every requeue is a failure-path
	// call, so flushErrors and consecutiveErrors must rise in
	// lockstep with RequeuedBatches. A concurrent Stats() reader
	// can no longer observe RequeuedBatches=1 while FlushErrors=0.
	if s.FlushErrors != 1 {
		t.Errorf("FlushErrors must rise in lockstep with RequeuedBatches: want 1, got %d", s.FlushErrors)
	}
	if s.ConsecutiveErrors != 1 {
		t.Errorf("ConsecutiveErrors must rise in lockstep with RequeuedBatches: want 1, got %d", s.ConsecutiveErrors)
	}
}

// TestRequeueBatch_ShedsOldestPastBacklogCap pins the cap-shed
// contract: when a requeue would push len(pending) past
// BatchSize * MaxBacklogMultiplier, the OLDEST rows are dropped
// FIFO-style. Both droppedRows and backlogDrops are credited so
// dashboards distinguish "in-line bad-row drops" (DroppedRows
// rising, BacklogDrops flat) from "sustained-outage overrun"
// (BacklogDrops also rising). The shed rows are the head of the
// merged slice — i.e., the oldest entries of the requeued batch,
// not the newest concurrent writes — so producers' freshest data
// is preserved in the failover-to-cold-path window.
func TestRequeueBatch_ShedsOldestPastBacklogCap(t *testing.T) {
	t.Parallel()
	// Backlog cap = 4. We requeue 3 + already have 3 pending → 6
	// total, must shed 2.
	w := &Writer{
		cfg:     Config{BatchSize: 2, MaxBacklogMultiplier: 2},
		logger:  quietLogger(),
		pending: []schema.Envelope{mkEnv(), mkEnv(), mkEnv()},
	}
	failed := []schema.Envelope{mkEnv(), mkEnv(), mkEnv()}
	// Mark the third (newest) failed envelope so we can prove the
	// shed pass dropped from the HEAD, not the tail.
	keepEvent := failed[2]
	w.requeueBatch(failed, "test", requeueDrops{})
	if got, want := len(w.pending), 4; got != want {
		t.Fatalf("len(pending) after cap shed: got %d, want %d (backlogCap)", got, want)
	}
	// First entry of the resulting pending must be the third
	// (newest of failed-batch) failed envelope: oldest two of
	// the merged slice (failed[0], failed[1]) were shed.
	if w.pending[0].EventID != keepEvent.EventID {
		t.Errorf("head after shed: want failed[2] (newest of failed batch), got %s", w.pending[0].EventID)
	}
	s := w.Stats()
	if s.BacklogDrops != 2 {
		t.Errorf("BacklogDrops: want 2, got %d", s.BacklogDrops)
	}
	if s.DroppedRows != 2 {
		t.Errorf("DroppedRows must include BacklogDrops: want 2, got %d", s.DroppedRows)
	}
	if s.RequeuedBatches != 1 {
		t.Errorf("RequeuedBatches: want 1, got %d", s.RequeuedBatches)
	}
	if s.FlushErrors != 1 {
		t.Errorf("FlushErrors must rise with cap-shed requeue: want 1, got %d", s.FlushErrors)
	}
	if s.ConsecutiveErrors != 1 {
		t.Errorf("ConsecutiveErrors must rise with cap-shed requeue: want 1, got %d", s.ConsecutiveErrors)
	}
}

// TestRequeueBatch_EmptyBatchStillBumpsFailureCounters pins the
// single-lock-acquisition invariant for the empty-batch path.
// requeueBatch is the consolidated entry point for every flush-
// failure code path; even when there's nothing to put back on
// `pending` (an unreachable case in production today, but a
// possible future call site with an already-empty good-rows
// sub-slice), the failure-bookkeeping side of the contract MUST
// still run — otherwise a concurrent Stats() reader could see
// FlushErrors stale relative to the actual flush outcome. The
// requeue-side state (pending, RequeuedBatches, BacklogDrops)
// is correctly NOT mutated since there were no rows to put back.
func TestRequeueBatch_EmptyBatchStillBumpsFailureCounters(t *testing.T) {
	t.Parallel()
	w := &Writer{
		cfg:     Config{BatchSize: 1024, MaxBacklogMultiplier: 4},
		logger:  quietLogger(),
		pending: []schema.Envelope{mkEnv()},
	}
	w.requeueBatch(nil, "test", requeueDrops{})
	w.requeueBatch([]schema.Envelope{}, "test", requeueDrops{appendRejected: 3})
	if got, want := len(w.pending), 1; got != want {
		t.Errorf("len(pending) must be unchanged on empty requeue: got %d, want %d", got, want)
	}
	s := w.Stats()
	if s.RequeuedBatches != 0 {
		t.Errorf("RequeuedBatches on empty requeue: want 0, got %d", s.RequeuedBatches)
	}
	if s.FlushErrors != 2 {
		t.Errorf("FlushErrors must bump on every requeueBatch call (failure path): want 2, got %d", s.FlushErrors)
	}
	if s.ConsecutiveErrors != 2 {
		t.Errorf("ConsecutiveErrors must bump on every requeueBatch call: want 2, got %d", s.ConsecutiveErrors)
	}
	if s.DroppedRows != 3 {
		t.Errorf("DroppedRows must include requeueDrops.appendRejected: want 3, got %d", s.DroppedRows)
	}
}

// TestBacklogCapacity_FallsBackToDefaultsForStructLiterals pins
// the defense-in-depth contract for the requeue-cap accessor.
// `Writer.requeueBatch` reads its backlog cap through
// `backlogCapacity()` so a Writer constructed via a struct
// literal (bypassing `New()` / `fillDefaults()`) cannot
// accidentally collapse the cap to 0 — which would shed every
// row on every requeue, silently turning the in-memory shield
// into a row-loss amplifier during a sustained ClickHouse
// outage. Mirrors the same `guard-at-use-site` pattern used by
// `qualifiedTable()` for identifier validation.
func TestBacklogCapacity_FallsBackToDefaultsForStructLiterals(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		cfg  Config
		want int
	}{
		{
			name: "both fields zero falls back to defaults",
			cfg:  Config{},
			want: DefaultBatchSize * DefaultMaxBacklogMultiplier,
		},
		{
			name: "BatchSize zero falls back to default",
			cfg:  Config{MaxBacklogMultiplier: 2},
			want: DefaultBatchSize * 2,
		},
		{
			name: "MaxBacklogMultiplier zero falls back to default",
			cfg:  Config{BatchSize: 16},
			want: 16 * DefaultMaxBacklogMultiplier,
		},
		{
			name: "negative BatchSize is treated as missing",
			cfg:  Config{BatchSize: -1, MaxBacklogMultiplier: 2},
			want: DefaultBatchSize * 2,
		},
		{
			name: "both fields positive — no fallback",
			cfg:  Config{BatchSize: 16, MaxBacklogMultiplier: 2},
			want: 32,
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			w := &Writer{cfg: tc.cfg, logger: quietLogger()}
			if got := w.backlogCapacity(); got != tc.want {
				t.Errorf("backlogCapacity for cfg=%+v: got %d, want %d", tc.cfg, got, tc.want)
			}
		})
	}
}

// TestRequeueBatch_StructLiteralWithZeroCapDoesNotShedEverything
// is the integration-level pin for the same contract: a struct-
// literal Writer with zero-valued cap fields must still honour
// the default cap rather than collapsing the backlog to 0 (which
// the pre-guard implementation would have done — shedding every
// row on every requeue).
func TestRequeueBatch_StructLiteralWithZeroCapDoesNotShedEverything(t *testing.T) {
	t.Parallel()
	// Struct literal — BatchSize and MaxBacklogMultiplier both
	// zero — simulating a future caller that bypasses New() /
	// fillDefaults() (e.g. a test harness wiring a Writer
	// directly).
	w := &Writer{
		cfg:    Config{},
		logger: quietLogger(),
	}
	// 100 rows is well under the default cap
	// (DefaultBatchSize × DefaultMaxBacklogMultiplier =
	// 1024 × 4 = 4096), so the requeue must place every row on
	// `pending` without shedding any.
	batch := make([]schema.Envelope, 100)
	for i := range batch {
		batch[i] = mkEnv()
	}
	w.requeueBatch(batch, "struct-literal-test", requeueDrops{})
	if got, want := len(w.pending), 100; got != want {
		t.Fatalf("len(pending) for struct-literal Writer: got %d, want %d (guard collapsed cap to 0)", got, want)
	}
	s := w.Stats()
	if s.BacklogDrops != 0 {
		t.Errorf("BacklogDrops must be 0 when row count is under default cap: got %d", s.BacklogDrops)
	}
	if s.DroppedRows != 0 {
		t.Errorf("DroppedRows must be 0 when row count is under default cap: got %d", s.DroppedRows)
	}
}

// TestStats_PartialDropFlushesIsExposed pins that the
// per-flush partial-drop counter is surfaced through Stats so
// dashboards can alert on `rate(PartialDropFlushes[5m]) >
// threshold` without conflating the signal with the
// (semantically distinct) ConsecutiveErrors / DroppedRows
// counters. ConsecutiveErrors is ClickHouse-health (resets on
// every successful Send); DroppedRows is per-row data loss;
// PartialDropFlushes is per-flush "the producer is emitting
// bad envelopes". Tested by direct counter mutation because
// the full flushOnce path requires a mock ClickHouse driver
// (out of scope for this unit test; the requeueBatch suite
// above covers the failure-path counter contract end-to-end).
func TestStats_PartialDropFlushesIsExposed(t *testing.T) {
	t.Parallel()
	w := &Writer{
		cfg:    Config{BatchSize: 1024, MaxBacklogMultiplier: 4},
		logger: quietLogger(),
	}
	w.mu.Lock()
	w.partialDropFlushes = 7
	w.mu.Unlock()
	s := w.Stats()
	if s.PartialDropFlushes != 7 {
		t.Errorf("Stats must expose partialDropFlushes: got %d, want 7", s.PartialDropFlushes)
	}
	// Pin that PartialDropFlushes is INDEPENDENT of
	// ConsecutiveErrors so dashboards can alert on the two
	// separately. ConsecutiveErrors stays at 0 even when
	// partialDropFlushes is rising (which is the documented
	// semantic split — see writer.go on droppedRows).
	if s.ConsecutiveErrors != 0 {
		t.Errorf("PartialDropFlushes must not couple to ConsecutiveErrors: got %d, want 0", s.ConsecutiveErrors)
	}
}
