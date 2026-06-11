package activity

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

// fakeToucher records every TouchLastActive call and can be made to
// fail or block, for exercising the drain worker.
type fakeToucher struct {
	mu      sync.Mutex
	calls   []call
	err     error
	block   chan struct{}  // when non-nil, each touch waits on it
	started chan uuid.UUID // when non-nil, signals the id of each touch as it begins
}

type call struct {
	id   uuid.UUID
	seen time.Time
}

func (f *fakeToucher) TouchLastActive(ctx context.Context, id uuid.UUID, seen time.Time) error {
	if f.started != nil {
		select {
		case f.started <- id:
		default:
		}
	}
	if f.block != nil {
		select {
		case <-f.block:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, call{id: id, seen: seen})
	return f.err
}

func (f *fakeToucher) snapshot() []call {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]call, len(f.calls))
	copy(out, f.calls)
	return out
}

// drainUntil polls cond up to timeout, returning whether it held.
func drainUntil(timeout time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(time.Millisecond)
	}
	return cond()
}

func TestRecorder_PersistsObservedActivity(t *testing.T) {
	f := &fakeToucher{}
	r := NewRecorder(f, WithMinInterval(time.Hour))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go r.Run(ctx)

	id := uuid.New()
	seen := time.Date(2026, 6, 11, 12, 0, 0, 0, time.UTC)
	r.Observe(id, seen)

	if !drainUntil(time.Second, func() bool { return len(f.snapshot()) == 1 }) {
		t.Fatalf("touch never persisted: %+v", f.snapshot())
	}
	got := f.snapshot()[0]
	if got.id != id || !got.seen.Equal(seen) {
		t.Fatalf("persisted %v@%v, want %v@%v", got.id, got.seen, id, seen)
	}
}

func TestRecorder_DebouncesWithinInterval(t *testing.T) {
	f := &fakeToucher{}
	now := time.Date(2026, 6, 11, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	r := NewRecorder(f, WithMinInterval(5*time.Minute), WithClock(clock))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go r.Run(ctx)

	id := uuid.New()
	r.Observe(id, now)
	if !drainUntil(time.Second, func() bool { return len(f.snapshot()) == 1 }) {
		t.Fatalf("first touch not persisted")
	}

	// Second observe within the debounce window must be suppressed.
	r.Observe(id, now.Add(time.Minute))
	// Give the worker a chance to (incorrectly) write.
	time.Sleep(20 * time.Millisecond)
	if n := len(f.snapshot()); n != 1 {
		t.Fatalf("debounce failed: got %d touches, want 1", n)
	}
	if s := r.Stats(); s.Debounced != 1 {
		t.Fatalf("Debounced = %d, want 1", s.Debounced)
	}

	// Advancing past the window admits the next touch.
	now = now.Add(6 * time.Minute)
	r.Observe(id, now)
	if !drainUntil(time.Second, func() bool { return len(f.snapshot()) == 2 }) {
		t.Fatalf("touch after window not persisted: %d", len(f.snapshot()))
	}
}

func TestRecorder_DistinctTenantsNotDebouncedTogether(t *testing.T) {
	f := &fakeToucher{}
	now := time.Now()
	r := NewRecorder(f, WithMinInterval(time.Hour), WithClock(func() time.Time { return now }))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go r.Run(ctx)

	a, b := uuid.New(), uuid.New()
	r.Observe(a, now)
	r.Observe(b, now)
	if !drainUntil(time.Second, func() bool { return len(f.snapshot()) == 2 }) {
		t.Fatalf("both tenants should be persisted, got %d", len(f.snapshot()))
	}
}

func TestRecorder_NilAndZeroAreSafe(t *testing.T) {
	var r *Recorder
	r.Observe(uuid.New(), time.Now()) // nil receiver: must not panic
	if got := r.Stats(); got != (Stats{}) {
		t.Fatalf("nil Stats = %+v, want zero", got)
	}

	f := &fakeToucher{}
	now := time.Date(2026, 6, 11, 12, 0, 0, 0, time.UTC)
	r2 := NewRecorder(f, WithClock(func() time.Time { return now }))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go r2.Run(ctx)

	r2.Observe(uuid.Nil, now) // nil tenant: no-op
	time.Sleep(20 * time.Millisecond)
	if n := len(f.snapshot()); n != 0 {
		t.Fatalf("nil tenant produced %d touches, want 0", n)
	}

	// Zero seen is replaced with now.
	id := uuid.New()
	r2.Observe(id, time.Time{})
	if !drainUntil(time.Second, func() bool { return len(f.snapshot()) == 1 }) {
		t.Fatalf("zero-seen touch not persisted")
	}
	if got := f.snapshot()[0].seen; !got.Equal(now) {
		t.Fatalf("zero seen persisted as %v, want now %v", got, now)
	}
}

func TestRecorder_DropsWhenQueueFull(t *testing.T) {
	block := make(chan struct{})
	f := &fakeToucher{block: block}
	// Queue size 1 + a worker blocked on the first write means the
	// second distinct enqueue fills the buffer and the third drops.
	r := NewRecorder(f, WithMinInterval(time.Hour), WithQueueSize(1))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go r.Run(ctx)

	// First touch is pulled by the worker and blocks there.
	r.Observe(uuid.New(), time.Now())
	if !drainUntil(time.Second, func() bool { return r.Stats().Enqueued >= 1 }) {
		t.Fatalf("first touch not enqueued")
	}
	// Fill the 1-slot buffer, then overflow it. Distinct tenants so
	// debounce never suppresses.
	for i := 0; i < 50; i++ {
		r.Observe(uuid.New(), time.Now())
	}
	if s := r.Stats(); s.Dropped == 0 {
		t.Fatalf("expected drops with a saturated queue, stats=%+v", s)
	}
	close(block) // let the worker finish so the deferred cancel is clean
}

func TestRecorder_DropDoesNotSilenceTenant(t *testing.T) {
	block := make(chan struct{})
	f := &fakeToucher{block: block, started: make(chan uuid.UUID, 8)}
	now := time.Now()
	clk := func() time.Time { return now }
	r := NewRecorder(f, WithMinInterval(5*time.Minute), WithQueueSize(1), WithClock(clk))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go r.Run(ctx)

	// A: worker pulls this and blocks inside the write, leaving the
	// 1-slot buffer empty.
	a := uuid.New()
	r.Observe(a, now)
	select {
	case <-f.started:
	case <-time.After(time.Second):
		t.Fatal("worker never started the first write")
	}
	// B fills the 1-slot buffer; X then drops. X has never been seen,
	// so the only thing that can keep it out of the next window is a
	// (wrongly) set debounce marker.
	x := uuid.New()
	r.Observe(uuid.New(), now)
	r.Observe(x, now) // queue full -> drop, must NOT mark x
	if s := r.Stats(); s.Dropped == 0 {
		t.Fatalf("expected a drop, stats=%+v", s)
	}
	// Unblock and let the backlog drain.
	close(block)
	if !drainUntil(time.Second, func() bool { return r.Stats().Written >= 2 }) {
		t.Fatalf("queue did not drain, stats=%+v", r.Stats())
	}
	// A fresh Observe for the dropped tenant within the same window
	// must still be accepted: the drop left no debounce marker.
	before := r.Stats().Enqueued
	r.Observe(x, now)
	if !drainUntil(time.Second, func() bool { return r.Stats().Enqueued == before+1 }) {
		t.Fatalf("dropped tenant was silenced for the whole window, stats=%+v", r.Stats())
	}
}

func TestRecorder_WriteFailureCounted(t *testing.T) {
	f := &fakeToucher{err: errors.New("boom")}
	r := NewRecorder(f, WithMinInterval(time.Hour))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go r.Run(ctx)

	r.Observe(uuid.New(), time.Now())
	if !drainUntil(time.Second, func() bool { return r.Stats().Failed == 1 }) {
		t.Fatalf("write failure not counted, stats=%+v", r.Stats())
	}
	if got := r.Stats().Written; got != 0 {
		t.Fatalf("Written = %d on failure, want 0", got)
	}
}

func TestNewRecorder_NilRepoPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic on nil repo")
		}
	}()
	NewRecorder(nil)
}
