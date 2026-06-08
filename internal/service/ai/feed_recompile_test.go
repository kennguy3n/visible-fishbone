package ai

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// TestRecompilerRunsOnTrigger verifies a single Trigger drives exactly
// one recompile and that Stats reflects it.
func TestRecompilerRunsOnTrigger(t *testing.T) {
	t.Parallel()
	ran := make(chan struct{}, 1)
	r := NewRecompiler(func(context.Context) error {
		ran <- struct{}{}
		return nil
	})
	r.Start(context.Background())
	defer r.Stop()

	r.Trigger()
	select {
	case <-ran:
	case <-time.After(2 * time.Second):
		t.Fatal("recompile did not run after Trigger")
	}
	// Allow runRecompile to finish recording before reading Stats.
	waitFor(t, func() bool { return r.Stats().Runs == 1 })
	if got := r.Stats().Runs; got != 1 {
		t.Fatalf("Runs = %d, want 1", got)
	}
}

// TestRecompilerCoalescesBurst proves the core debounce contract: any
// number of triggers arriving while a recompile is in flight collapse
// into exactly one follow-up recompile, regardless of burst size.
func TestRecompilerCoalescesBurst(t *testing.T) {
	t.Parallel()

	var clk struct {
		sync.Mutex
		t time.Time
	}
	clk.t = time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	now := func() time.Time {
		clk.Lock()
		defer clk.Unlock()
		return clk.t
	}
	advance := func(d time.Duration) {
		clk.Lock()
		defer clk.Unlock()
		clk.t = clk.t.Add(d)
	}

	var mu sync.Mutex
	count := 0
	firstBlocked := make(chan struct{})
	release := make(chan struct{})
	ranTwice := make(chan struct{})

	minInterval := time.Minute
	r := NewRecompiler(func(context.Context) error {
		mu.Lock()
		count++
		c := count
		mu.Unlock()
		switch c {
		case 1:
			close(firstBlocked)
			<-release // hold the worker so triggers stack
		case 2:
			close(ranTwice)
		}
		return nil
	},
		WithRecompileMinInterval(minInterval),
		withRecompileClock(now),
	)
	r.Start(context.Background())
	defer r.Stop()

	// Kick off run #1 and wait until it is in flight.
	r.Trigger()
	select {
	case <-firstBlocked:
	case <-time.After(2 * time.Second):
		t.Fatal("first recompile never started")
	}

	// Stack a burst while run #1 holds the worker. These must
	// coalesce into a single pending recompile (buffered cap 1).
	for i := 0; i < 25; i++ {
		r.Trigger()
	}

	// Move the clock past the min-interval so the follow-up's
	// waitForSlot returns immediately, then let run #1 finish.
	advance(2 * minInterval)
	close(release)

	select {
	case <-ranTwice:
	case <-time.After(2 * time.Second):
		t.Fatal("coalesced follow-up recompile did not run")
	}

	// Give the worker a beat to settle back into select; assert no
	// third recompile was queued by the 25-trigger burst.
	waitFor(t, func() bool { return r.Stats().Runs == 2 })
	time.Sleep(50 * time.Millisecond)
	mu.Lock()
	got := count
	mu.Unlock()
	if got != 2 {
		t.Fatalf("recompile ran %d times, want 2 (burst must coalesce)", got)
	}
}

// TestRecompilerRecordsErrorsAndObserver verifies failed recompiles
// increment the error counter and surface the outcome to the observer.
func TestRecompilerRecordsErrorsAndObserver(t *testing.T) {
	t.Parallel()
	wantErr := errors.New("compile boom")
	outcomes := make(chan string, 1)
	r := NewRecompiler(func(context.Context) error {
		return wantErr
	},
		WithRecompileObserver(func(outcome string, _ time.Duration) {
			outcomes <- outcome
		}),
	)
	r.Start(context.Background())
	defer r.Stop()

	r.Trigger()
	select {
	case got := <-outcomes:
		if got != "error" {
			t.Fatalf("observer outcome = %q, want \"error\"", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("observer not called")
	}
	waitFor(t, func() bool { return r.Stats().Errors == 1 })
	st := r.Stats()
	if st.Errors != 1 || st.LastErr != wantErr.Error() {
		t.Fatalf("Stats = %+v, want Errors=1 LastErr=%q", st, wantErr.Error())
	}
}

// TestRecompilerStopBeforeStartIsNoop verifies Stop is safe before
// Start (it must not block waiting on a worker that never launched).
func TestRecompilerStopBeforeStartIsNoop(t *testing.T) {
	t.Parallel()
	r := NewRecompiler(func(context.Context) error { return nil })
	done := make(chan struct{})
	go func() {
		r.Stop()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Stop blocked before Start")
	}
}

// waitFor polls cond up to ~2s; fails the test if it never holds.
func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !cond() {
		t.Fatal("condition not met within timeout")
	}
}
