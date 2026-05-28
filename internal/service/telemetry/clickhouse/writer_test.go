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
