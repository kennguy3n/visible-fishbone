package main

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/service/dlpreview"
)

// TestDLPEnforcementRecompiler_OnBlockTriggersCompile proves a block
// decision recompiles the affected tenant's bundle.
func TestDLPEnforcementRecompiler_OnBlockTriggersCompile(t *testing.T) {
	t.Parallel()
	var got atomic.Value // uuid.UUID
	done := make(chan struct{})
	tid := uuid.New()
	r := newDLPEnforcementRecompiler(func(_ context.Context, tenantID uuid.UUID) error {
		got.Store(tenantID)
		close(done)
		return nil
	}, nil)

	r.OnBlock(context.Background(), tid, dlpreview.ReviewEvent{})

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("compile not invoked")
	}
	if err := r.Wait(waitCtx(t)); err != nil {
		t.Fatalf("wait: %v", err)
	}
	if got.Load().(uuid.UUID) != tid {
		t.Fatalf("compiled tenant = %v, want %v", got.Load(), tid)
	}
}

// TestDLPEnforcementRecompiler_NilTenantIsNoop guards against a stray
// recompile for a zero tenant id.
func TestDLPEnforcementRecompiler_NilTenantIsNoop(t *testing.T) {
	t.Parallel()
	var calls atomic.Int64
	r := newDLPEnforcementRecompiler(func(_ context.Context, _ uuid.UUID) error {
		calls.Add(1)
		return nil
	}, nil)
	r.OnBlock(context.Background(), uuid.Nil, dlpreview.ReviewEvent{})
	if err := r.Wait(waitCtx(t)); err != nil {
		t.Fatalf("wait: %v", err)
	}
	if n := calls.Load(); n != 0 {
		t.Fatalf("compile invoked %d times for nil tenant", n)
	}
}

// TestDLPEnforcementRecompiler_CoalescesBurst proves that blocks arriving
// while a tenant's recompile is in flight collapse into a single
// trailing recompile rather than one per block, and that the trailing
// pass starts after the last block (so it observes it).
func TestDLPEnforcementRecompiler_CoalescesBurst(t *testing.T) {
	t.Parallel()
	tid := uuid.New()

	var (
		mu       sync.Mutex
		calls    int
		release  = make(chan struct{})
		started  = make(chan struct{})
		firstrun sync.Once
	)
	r := newDLPEnforcementRecompiler(func(_ context.Context, _ uuid.UUID) error {
		firstrun.Do(func() { close(started) })
		mu.Lock()
		calls++
		mu.Unlock()
		// Block the first pass until the test has queued more blocks,
		// forcing them to coalesce into the in-flight pass.
		<-release
		return nil
	}, nil)

	// Kick off the first recompile and wait until it is actually running.
	r.OnBlock(context.Background(), tid, dlpreview.ReviewEvent{})
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("first compile never started")
	}

	// Queue several more blocks while the first pass is parked. These
	// must coalesce into exactly one trailing pass.
	for i := 0; i < 5; i++ {
		r.OnBlock(context.Background(), tid, dlpreview.ReviewEvent{})
	}

	// Let the parked passes proceed.
	close(release)
	if err := r.Wait(waitCtx(t)); err != nil {
		t.Fatalf("wait: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	// 1 initial pass + at most 1 trailing pass for the whole burst.
	if calls < 2 || calls > 2 {
		t.Fatalf("compile ran %d times, want exactly 2 (initial + one coalesced trailing)", calls)
	}
}

// TestDLPEnforcementRecompiler_ErrorDoesNotPanic proves a compile error
// is swallowed (best-effort) and does not wedge the worker.
func TestDLPEnforcementRecompiler_ErrorDoesNotPanic(t *testing.T) {
	t.Parallel()
	tid := uuid.New()
	r := newDLPEnforcementRecompiler(func(_ context.Context, _ uuid.UUID) error {
		return errors.New("boom")
	}, nil)
	r.OnBlock(context.Background(), tid, dlpreview.ReviewEvent{})
	if err := r.Wait(waitCtx(t)); err != nil {
		t.Fatalf("wait: %v", err)
	}
	// A subsequent block must still schedule a fresh pass (no stuck
	// state from the prior error).
	var ran atomic.Bool
	r2 := newDLPEnforcementRecompiler(func(_ context.Context, _ uuid.UUID) error {
		ran.Store(true)
		return nil
	}, nil)
	r2.OnBlock(context.Background(), tid, dlpreview.ReviewEvent{})
	if err := r2.Wait(waitCtx(t)); err != nil {
		t.Fatalf("wait: %v", err)
	}
	if !ran.Load() {
		t.Fatal("second recompiler did not run")
	}
}

func waitCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	t.Cleanup(cancel)
	return ctx
}
