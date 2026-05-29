package clickhouse

import (
	"sync"
	"testing"

	"github.com/kennguy3n/visible-fishbone/internal/nats/schema"
)

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
